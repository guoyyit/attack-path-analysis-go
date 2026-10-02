package attackpath

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentReadersAndWriters(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	if err := svc.Update(seedBatch()); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Single writer producing monotonically versioned states.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			cs := ChangeSet{
				UpsertVulns: []Vulnerability{{
					ID: fmt.Sprintf("dyn-%d", i%8), AssetID: "web",
					Exploitability: 0.1 + float64(i%9)/10,
				}},
			}
			if err := svc.Update(cs); err != nil {
				t.Errorf("update %d: %v", i, err)
				return
			}
			if i > 400 {
				return
			}
		}
	}()

	// Many readers: every observed snapshot must be internally consistent.
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				select {
				case <-stop:
					return
				default:
				}
				snap := svc.Current()
				if snap == nil {
					t.Errorf("nil snapshot")
					return
				}
				// Reached nodes must be derivable: consistent edges/report.
				rep := snap.report
				if rep == nil || rep.Version != snap.version {
					t.Errorf("torn snapshot read")
					return
				}
				for id, risk := range rep.Risks {
					for _, p := range risk.Paths {
						if len(p.Nodes) < 2 {
							t.Errorf("invalid path for %s: %v", id, p.Nodes)
							return
						}
					}
				}
				_ = svc.Query(Constraint{})
			}
		}()
	}
	wg.Wait()
	close(stop)

	// Final committed version survives a reopen.
	wantVersion := svc.Current().version
	wantReachable := append([]string(nil), svc.Current().report.Reachable...)

	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Current().version != wantVersion {
		t.Fatalf("version after reopen = %d, want %d", reopened.Current().version, wantVersion)
	}
	if !equalStrings(reopened.Current().report.Reachable, wantReachable) {
		t.Fatalf("reachable mismatch after reopen")
	}
}

func TestCrashRecoveryCommitsWAL(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Update(seedBatch()); err != nil {
		t.Fatal(err)
	}
	if err := svc.Update(ChangeSet{
		UpsertVulns: []Vulnerability{{ID: "extra", AssetID: "web", Exploitability: 0.3}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}

	// Append a partial, torn frame as if the process died mid-write.
	walPath := filepath.Join(dir, walFile)
	f, err := os.OpenFile(walPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	torn := []byte{0, 0, 0, 0, 0, 0, 0, 99, 1, 2, 3, 4, 5}
	if _, err := f.Write(torn); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	// Both committed changes survive; the torn frame is ignored and pruned.
	snap := reopened.Current()
	if _, ok := snap.vulns["extra"]; !ok {
		t.Fatalf("committed vulnerability missing after recovery")
	}
	if !snap.reached["db"] {
		t.Fatalf("committed state lost after recovery")
	}

	data, err := os.ReadFile(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 0 && string(data[len(data)-len(torn):]) == string(torn) {
		t.Fatalf("torn frame was not pruned on replay")
	}

	// The store keeps working and re-serialises versions correctly.
	if err := reopened.Update(ChangeSet{
		UpsertAssets: []Asset{{ID: "late", Critical: true}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotCompactionAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	svc, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Update(seedBatch()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < compactInterval+10; i++ {
		if err := svc.Update(ChangeSet{
			UpsertVulns: []Vulnerability{{
				ID: fmt.Sprintf("v%d", i), AssetID: "web", Exploitability: 0.5,
			}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	want := svc.Current().version
	if err := svc.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, snapshotFile)); err != nil {
		t.Fatalf("snapshot file expected: %v", err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Current().version != want {
		t.Fatalf("version after compaction+reopen = %d, want %d", reopened.Current().version, want)
	}
	if !reopened.Current().reached["db"] {
		t.Fatalf("state lost after compaction")
	}
}

func TestRepeatedCompactionAcrossReopens(t *testing.T) {
	dir := t.TempDir()

	runPhase := func(round int) int64 {
		svc, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		if round == 0 {
			if err := svc.Update(seedBatch()); err != nil {
				t.Fatal(err)
			}
		}
		n := compactInterval + 20
		for i := 0; i < n; i++ {
			if err := svc.Update(ChangeSet{
				UpsertAssets: []Asset{{
					ID:       fmt.Sprintf("round%d-node%d", round, i%5),
					Critical: i == n-1,
				}},
			}); err != nil {
				t.Fatal(err)
			}
		}
		v := svc.Current().version
		if err := svc.Close(); err != nil {
			t.Fatal(err)
		}
		return v
	}

	v0 := runPhase(0)
	v1 := runPhase(1)
	if v1 <= v0 {
		t.Fatalf("version should advance across reopened rounds: %d -> %d", v0, v1)
	}

	svc, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if svc.Current().version != v1 {
		t.Fatalf("recovered version = %d, want %d", svc.Current().version, v1)
	}
	if _, ok := svc.Current().assets["db"]; !ok {
		t.Fatalf("data folded into an earlier snapshot was lost")
	}
	if _, ok := svc.Current().assets["round1-node0"]; !ok {
		t.Fatalf("latest-round data missing after recovery")
	}
}

func seedBatch() ChangeSet {
	return ChangeSet{
		UpsertAssets: []Asset{
			{ID: "web", External: true, Grants: []string{"web-shell"}},
			{ID: "app", Grants: []string{"app-creds"}},
			{ID: "db", Critical: true},
		},
		UpsertVulns: []Vulnerability{
			{ID: "cve-web", AssetID: "web", Exploitability: 0.8},
			{ID: "cve-app", AssetID: "app", Exploitability: 0.5, Requires: []string{"web-shell"}},
			{ID: "cve-db", AssetID: "db", Exploitability: 0.25, Requires: []string{"app-creds"}},
		},
		UpsertRules: []ConnectRule{
			{SrcID: InternetID, DstID: "web", Protocol: "tcp", Port: 443},
			{SrcID: "web", DstID: "app"},
			{SrcID: "app", DstID: "db"},
		},
	}
}
