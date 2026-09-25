package walletipc

import (
	"testing"

	"github.com/pilot-protocol/app-store/pkg/ipc"
)

// wallet.help is the discovery contract: it must describe every method the
// dispatcher actually serves, no more and no less.
func TestHelpListsEveryRegisteredMethod(t *testing.T) {
	conn, w := servedWallet(t, addrAlice)
	var resp struct {
		App     string `json:"app"`
		Version string `json:"version"`
		Methods []struct {
			Method string `json:"method"`
		} `json:"methods"`
	}
	if err := ipc.Call(conn, MethodHelp, nil, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.App != "io.pilot.wallet" || resp.Version != Version || len(resp.Methods) == 0 {
		t.Errorf("app/version = %q/%q", resp.App, resp.Version)
	}
	listed := map[string]bool{}
	for _, m := range resp.Methods {
		listed[m.Method] = true
	}
	for _, m := range NewDispatcher(w).Methods() {
		if !listed[m] {
			t.Errorf("registered method %q missing from wallet.help", m)
		}
		delete(listed, m)
	}
	for m := range listed {
		t.Errorf("wallet.help lists %q, which is not registered", m)
	}
}
