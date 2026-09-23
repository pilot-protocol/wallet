package main

import (
	"context"
	"log"
	"os"
	"time"
)

// parentPollInterval is how often the wallet checks whether the process
// that spawned it is still alive. One getppid(2) per second is free, and
// bounds how long an orphaned wallet keeps its socket, ledger and
// cap-state file open after the daemon is gone.
const parentPollInterval = time.Second

// getppid is swapped out by tests.
var getppid = os.Getppid

// startPPID is the parent pid captured as early as possible in main(), so
// a daemon that dies while the wallet is still starting up (opening the
// ledger, loading keys) is still noticed.
var startPPID = os.Getppid()

// watchParent cancels the wallet's run context once the process that
// spawned it exits, so the wallet shuts down through its normal SIGTERM
// path (stop accepting, drain, close the ledger, unlink the socket).
//
// The pilot daemon's app-store supervisor starts each app in its own
// process group. On Linux it also sets Pdeathsig=SIGKILL, but macOS has
// no parent-death signal, and anything that bypasses the daemon's
// shutdown path (the rx watchdog's os.Exit, SIGKILL, a crash, launchd
// restarting the service) leaves the wallet reparented to launchd, still
// serving its socket and holding its sqlite ledger and cap-state log open
// next to the instance the respawned daemon starts. Watching our own
// parent closes that gap on every platform without cooperation from the
// supervisor.
//
// A wallet started directly by init/launchd (ppid 1 at startup) has no
// parent to watch and is left alone.
func watchParent(ctx context.Context, cancel context.CancelFunc, ppid int, interval time.Duration, logger *log.Logger) bool {
	if ppid <= 1 {
		return false
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			if now := getppid(); now != ppid {
				logger.Printf("parent pid %d exited (reparented to %d); shutting down", ppid, now)
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return true
}
