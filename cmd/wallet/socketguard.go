package main

import (
	"log"
	"net"
	"os"
)

// ownedUnixListener is the wallet's listener. Closing it unlinks the
// socket path only while that path still names the socket this process
// bound.
//
// Go's UnixListener.Close unlinks the path by name. That is wrong once
// another wallet instance has taken the path over, which is exactly what
// happens when an instance shuts down late: the daemon (or the app-store
// supervisor after a daemon restart) starts a replacement, which removes
// the old socket file and binds a new one at the same path, and then the
// old instance exits — after noticing its parent died, or on a SIGTERM
// that arrives after the replacement is up. Without this check the old
// instance's Close deletes the replacement's socket and leaves the live
// wallet running but unreachable.
type ownedUnixListener struct {
	*net.UnixListener
	path   string
	bound  os.FileInfo // the socket file as bound; nil if it could not be stat'ed
	logger *log.Logger
}

// ownSocket wraps l so that Close leaves path alone once it no longer
// refers to l's socket. Call it right after Listen.
func ownSocket(l *net.UnixListener, path string, logger *log.Logger) *ownedUnixListener {
	fi, err := os.Stat(path)
	if err != nil {
		fi = nil // cannot tell later; fall back to Go's default unlink-on-close
	}
	return &ownedUnixListener{UnixListener: l, path: path, bound: fi, logger: logger}
}

// stillOurs reports whether path still names the socket this listener
// bound.
func (o *ownedUnixListener) stillOurs() bool {
	if o.bound == nil {
		return true
	}
	fi, err := os.Stat(o.path)
	return err == nil && os.SameFile(o.bound, fi)
}

func (o *ownedUnixListener) Close() error {
	if !o.stillOurs() {
		o.UnixListener.SetUnlinkOnClose(false)
		if o.logger != nil {
			o.logger.Printf("socket %s now belongs to another instance; leaving it in place", o.path)
		}
	}
	return o.UnixListener.Close()
}
