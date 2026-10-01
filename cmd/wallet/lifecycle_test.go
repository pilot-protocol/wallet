//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

// The test binary doubles as the processes of the parent-death test:
//
//	WALLET_TEST_ROLE=parent  stands in for the pilot daemon: starts the
//	                         wallet (own process group, no Pdeathsig — the
//	                         supervisor's macOS setup), prints its pid,
//	                         then blocks until it is killed.
//	WALLET_TEST_ROLE=wallet  runs the real main() with WALLET_TEST_ARGS.
func TestMain(m *testing.M) {
	switch os.Getenv("WALLET_TEST_ROLE") {
	case "parent":
		os.Exit(fakeDaemon())
	case "wallet":
		var args []string
		if err := json.Unmarshal([]byte(os.Getenv("WALLET_TEST_ARGS")), &args); err != nil {
			fmt.Fprintln(os.Stderr, "WALLET_TEST_ARGS:", err)
			os.Exit(2)
		}
		os.Args = append([]string{os.Args[0]}, args...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeDaemon() int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	logf, err := os.Create(os.Getenv("WALLET_TEST_LOG"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), "WALLET_TEST_ROLE=wallet")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Println(cmd.Process.Pid)
	// Stay alive until the test SIGKILLs us, like a daemon that dies hard.
	// (A bare select{} would trip the runtime's deadlock detector.)
	time.Sleep(time.Hour)
	return 0
}

// processGone reports whether pid has exited. A zombie counts as gone: in
// a container whose pid 1 does not reap, the reparented wallet stays a
// zombie after it exits.
func processGone(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	}
	out, err := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
	return err == nil && strings.HasPrefix(strings.TrimSpace(string(out)), "Z")
}

// The daemon dying without stopping its apps (SIGKILL, crash, watchdog
// exit) must not leave the wallet running as an orphan: it has to notice,
// shut down through its normal path and remove its socket.
func TestWalletExitsWhenParentDies(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns processes")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := shortSockDir(t)
	sock := filepath.Join(dir, "app.sock")
	logPath := filepath.Join(t.TempDir(), "wallet.log")
	args, _ := json.Marshal([]string{
		"--addr", "0:0001.0001.0001",
		"--db", filepath.Join(dir, "data.db"),
		"--socket", sock,
		"--identity", filepath.Join(dir, "identity.json"),
		"--cap-state", filepath.Join(dir, "cap-state.jsonl"),
		"--no-evm",
	})

	parent := exec.Command(exe, "-test.run=^$")
	parent.Env = append(os.Environ(),
		"WALLET_TEST_ROLE=parent",
		"WALLET_TEST_ARGS="+string(args),
		"WALLET_TEST_LOG="+logPath,
	)
	parent.Stderr = os.Stderr
	out, err := parent.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Process.Kill(); _ = parent.Wait() })

	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("read wallet pid from fake daemon: %v", err)
	}
	walletPID, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("wallet pid %q: %v", line, err)
	}
	t.Cleanup(func() {
		if !processGone(walletPID) {
			_ = syscall.Kill(walletPID, syscall.SIGKILL)
		}
	})

	walletLog := func() string { b, _ := os.ReadFile(logPath); return string(b) }
	deadline := time.Now().Add(15 * time.Second)
	for {
		if c, err := net.DialTimeout("unix", sock, 100*time.Millisecond); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wallet socket never came up; log:\n%s", walletLog())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The daemon dies hard.
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	killed := time.Now()

	for !processGone(walletPID) {
		if time.Since(killed) > 10*time.Second {
			t.Fatalf("wallet pid %d still running %s after its parent was killed (orphaned); log:\n%s",
				walletPID, time.Since(killed).Round(time.Millisecond), walletLog())
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("wallet exited %s after its parent was killed", time.Since(killed).Round(time.Millisecond))

	logs := walletLog()
	for _, want := range []string{"exited (reparented to", "graceful shutdown complete"} {
		if !strings.Contains(logs, want) {
			t.Errorf("wallet log lacks %q; log:\n%s", want, logs)
		}
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Errorf("socket %s left behind after the wallet exited (stat err=%v)", sock, err)
	}
}

// serve must not write a log line per IPC call by default: the supervisor
// wires the wallet's stderr into the daemon log, so per-call lines grow
// that log without bound.
func TestServeLogsConnectionsOnlyWhenAsked(t *testing.T) {
	for _, tc := range []struct {
		logConns bool
		want     int // "conn open"/"conn closed" lines for n calls
	}{
		{logConns: false, want: 0},
		{logConns: true, want: 2 * 25},
	} {
		t.Run(fmt.Sprintf("log-conns=%v", tc.logConns), func(t *testing.T) {
			const n = 25
			sock := filepath.Join(shortSockDir(t), "s.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			d := ipc.NewDispatcher()
			d.Register("t.ping", func(context.Context, *ipc.Envelope) (json.RawMessage, error) {
				return json.RawMessage(`{"ok":true}`), nil
			})
			var buf syncBuffer
			logger := log.New(&buf, "", 0)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- serve(ctx, ln, d, logger, tc.logConns) }()

			for i := 0; i < n; i++ {
				c, err := net.Dial("unix", sock)
				if err != nil {
					t.Fatal(err)
				}
				var out map[string]any
				if err := ipc.Call(c, "t.ping", nil, &out); err != nil {
					t.Fatal(err)
				}
				c.Close()
			}
			// Let the last connection's goroutine finish logging.
			time.Sleep(50 * time.Millisecond)
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			got := strings.Count(buf.String(), "conn open") + strings.Count(buf.String(), "conn closed")
			if got != tc.want {
				t.Errorf("%d per-connection log lines for %d calls, want %d; log:\n%s", got, n, tc.want, buf.String())
			}
		})
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var _ io.Writer = (*syncBuffer)(nil)
