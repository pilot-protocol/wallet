// Command wallet runs the io.pilot.wallet app as a standalone process.
//
// It listens on a unix-domain socket and dispatches each incoming
// connection to the wallet's IPC handler set. Persistent state lives in
// the sqlite ledger; the wallet's signing identity is a single ed25519
// keypair on disk.
//
// Lifecycle:
//
//   - On start: load/create identity, open sqlite store, bind socket,
//     accept connections in a loop.
//   - On SIGINT/SIGTERM: stop accepting, drain in-flight connections
//     with a deadline, close the store, exit 0.
//
// In the integrated runtime the daemon would spawn this binary with a
// socket FD passed via SCM_RIGHTS; --socket=path is the dev-mode
// equivalent (and what the daemon's compat path can also use).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/app-store/pkg/manifest"
	"github.com/pilot-protocol/wallet/pkg/wallet"
	"github.com/pilot-protocol/wallet/pkg/walletipc"
)

// shutdownGrace is how long we wait for in-flight Serve goroutines to
// finish after the listener is closed. After this elapses, the process
// exits even if connections are still active.
const shutdownGrace = 5 * time.Second

// Version is the wallet binary's release tag. Kept in sync with the
// app_version field in manifest.json — `manifest_test.go` cross-checks
// they agree, so a release without bumping both fails CI.
const Version = "0.3.0"

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
		log.Fatalf("wallet: %v", err)
	}
}

// run parses args, sets up state, and serves until ctx is canceled or a
// fatal error happens. main() wraps the OS signal handler; tests drive
// the lifecycle directly via their own cancellable ctx.
func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("wallet", flag.ContinueOnError)
	var (
		addr      = fs.String("addr", "", "pilot address (e.g. 0:0001.HHHH.LLLL); required")
		dbPath    = fs.String("db", defaultPath("data.db"), "sqlite ledger path")
		sockPath  = fs.String("socket", defaultPath("wallet.sock"), "unix socket to listen on")
		idPath    = fs.String("identity", defaultPath("identity.json"), "ed25519 identity file (created on first start)")
		mfPath    = fs.String("manifest", "", "path to manifest.json; when set, key.sign:cap grants activate runtime spend caps")
		capState  = fs.String("cap-state", "", "JSONL spend log; persists rolling-window cap state across wallet restarts so caps aren't bypassable by daemon-restart")
		showVer   = fs.Bool("version", false, "print version and exit")
	)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVer {
		// --version short-circuits all the other validation (no
		// --addr required) so packagers / ops can probe the binary
		// from anywhere. Output is just the bare semver — easy to
		// pipe into `grep` or compare in CI.
		fmt.Println(Version)
		return nil
	}
	if *addr == "" {
		return errors.New("--addr is required")
	}

	logger := log.New(os.Stderr, "wallet ", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("starting addr=%s db=%s socket=%s identity=%s", *addr, *dbPath, *sockPath, *idPath)

	signer, err := wallet.LoadOrCreateLocalSigner(*idPath)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	store, err := openStore(*dbPath)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Printf("store close: %v", err)
		}
	}()

	w := wallet.New(wallet.Address(*addr), signer, store)
	defer w.Close()

	// Arm spend-cap persistence BEFORE configuring caps, so any
	// rolling-window history from a previous run is replayed into
	// the in-memory log and counts against the cap at the first
	// post-startup Pay. Without this, a daemon restart silently
	// resets the cap counter — a hard bypass.
	if *capState != "" {
		if err := w.UseCapStateFile(*capState); err != nil {
			return fmt.Errorf("cap-state: %w", err)
		}
		logger.Printf("cap-state: persisting to %s", *capState)
	}

	// Activate manifest-declared spend caps. The supervisor lays the
	// manifest down next to the binary at <install_dir>/manifest.json
	// and passes that path via --manifest. Standalone / dev runs
	// (e.g. `go run ./cmd/wallet`) skip --manifest and run without
	// caps, matching the pre-cap behavior. Parse failures here are
	// fatal: a corrupt manifest means we don't know whether the user
	// consented to broader spend authority than the file claims.
	if *mfPath != "" {
		raw, err := os.ReadFile(*mfPath)
		if err != nil {
			return fmt.Errorf("read manifest %s: %w", *mfPath, err)
		}
		m, err := manifest.Parse(raw)
		if err != nil {
			return fmt.Errorf("parse manifest %s: %w", *mfPath, err)
		}
		caps := wallet.ParseSpendCapsFromManifest(m.Grants)
		w.SetSpendCaps(caps...)
		logger.Printf("spend caps: %d active from %s", len(caps), *mfPath)
	}

	dispatcher := walletipc.NewDispatcher(w)

	// If a stale socket exists from a previous crash, drop it. unix sockets
	// can't be re-bound while the inode still exists.
	if _, err := os.Stat(*sockPath); err == nil {
		_ = os.Remove(*sockPath)
	}
	if err := os.MkdirAll(filepath.Dir(*sockPath), 0o700); err != nil {
		return fmt.Errorf("socket dir: %w", err)
	}
	// Set umask to 0o177 before Listen so the unix-domain socket
	// is created as 0o600 atomically — no TOCTOU window between
	// socket creation and a post-hoc Chmod.
	oldMask := syscall.Umask(0o177)
	listener, err := net.Listen("unix", *sockPath)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *sockPath, err)
	}
	// Chmod is a belt-and-suspenders backup; the umask above covers
	// the primary case. On the off-chance a platform doesn't apply
	// umask to unix sockets, the explicit chmod is the fallback.
	if err := os.Chmod(*sockPath, 0o600); err != nil {
		logger.Printf("chmod socket: %v", err)
	}
	logger.Printf("listening on %s methods=%d", *sockPath, len(dispatcher.Methods()))

	return serve(ctx, listener, dispatcher, logger)
}

// serve is the accept loop. Returns nil on clean shutdown.
func serve(ctx context.Context, listener net.Listener, d *ipc.Dispatcher, logger *log.Logger) error {
	// Close the listener when ctx is canceled. On macOS Close() alone
	// doesn't always unblock a pending Accept(); a past-deadline pokes it.
	go func() {
		<-ctx.Done()
		logger.Printf("shutting down")
		if ul, ok := listener.(*net.UnixListener); ok {
			_ = ul.SetDeadline(time.Now())
		}
		_ = listener.Close()
	}()

	var wg sync.WaitGroup
acceptLoop:
	for {
		conn, err := listener.Accept()
		if err != nil {
			// Whether the error is net.ErrClosed, a wrapped syscall, or
			// something else, ctx being done is the authoritative signal
			// that this was an intentional shutdown.
			select {
			case <-ctx.Done():
				break acceptLoop
			default:
			}
			logger.Printf("accept error: %v", err)
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			// Force-close the conn when ctx is canceled so a peer that
			// opened the socket and went silent doesn't block shutdown.
			// ipc.Serve's blocking ReadFrame will then return with an error.
			stop := make(chan struct{})
			defer close(stop)
			go func() {
				select {
				case <-ctx.Done():
					_ = c.Close()
				case <-stop:
				}
			}()
			logger.Printf("conn open from=%s", c.RemoteAddr())
			if err := ipc.Serve(ctx, c, d); err != nil {
				logger.Printf("serve: %v", err)
			}
			logger.Printf("conn closed")
		}(conn)
	}

	// Drain in-flight connections, with a deadline.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		logger.Printf("graceful shutdown complete")
	case <-time.After(shutdownGrace):
		logger.Printf("shutdown timeout after %s — %d connections still open", shutdownGrace, openConns(&wg))
	}
	return nil
}

// openConns reports the number of in-flight goroutines. Crude (sync.WaitGroup
// doesn't expose a counter publicly), but the import dance via the Add/Done
// of conn goroutines means we can sample after Wait — for the timeout-log
// path we just return -1 to be honest about not knowing the exact count.
func openConns(_ *sync.WaitGroup) int { return -1 }

// openStore opens the sqlite ledger at path, creating parent dirs as needed.
func openStore(path string) (wallet.Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	return wallet.OpenSQLiteStore(path)
}

// defaultPath returns ~/.pilot/apps/io.pilot.wallet/<name>. Mirrors where
// the daemon would mount the wallet's data root in the integrated runtime
// so that pilotctl ops on the integrated app land in the same place as
// the standalone dev runs.
func defaultPath(name string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return name
	}
	return filepath.Join(home, ".pilot", "apps", "io.pilot.wallet", name)
}
