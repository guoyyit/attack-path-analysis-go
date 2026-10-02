package attackpath

import (
	"os"
	"path/filepath"
	"testing"
)

func sampleCommittedOps() [][]Op {
	return [][]Op{
		{
			{Kind: OpUpsertAsset, Asset: &Asset{ID: "e", External: true}},
			{Kind: OpUpsertAsset, Asset: &Asset{ID: "k", Critical: true}},
		},
		{
			{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "r", From: "e", To: "k"}},
			{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v", Asset: "k", Exploitability: 0.42}},
		},
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range sampleCommittedOps() {
		if err := s.Apply(batch); err != nil {
			t.Fatal(err)
		}
	}
	before := s.Risk("k")
	if before == nil || !approx(before.Score, 0.42) {
		t.Fatalf("pre-restart state wrong: %+v", before)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a process restart: reopen the same directory.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	after := s2.Risk("k")
	if after == nil || !approx(after.Score, 0.42) || after.PathCount != 1 {
		t.Fatalf("committed data not recovered: %+v", after)
	}
	if !s2.Compromised("k") {
		t.Fatalf("compromise conclusion not recovered")
	}
}

func TestCrashTruncatedTailIsIgnored(t *testing.T) {
	dir := t.TempDir()

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, batch := range sampleCommittedOps() {
		if err := s.Apply(batch); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash mid-write: append a partial record (a length prefix
	// promising a payload that never fully landed) plus some garbage bytes.
	path := filepath.Join(dir, walName)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	garbage := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0xff, 0xff, 0xab}
	if _, err := f.Write(garbage); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("recovery should ignore the torn tail, got error: %v", err)
	}
	defer s2.Close()

	r := s2.Risk("k")
	if r == nil || !approx(r.Score, 0.42) {
		t.Fatalf("committed state lost after torn-tail recovery: %+v", r)
	}

	// The log must be reusable after recovery: new commits append cleanly and
	// survive yet another restart.
	if err := s2.Apply([]Op{
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v", Asset: "k", Exploitability: 0.7}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	s3, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if r3 := s3.Risk("k"); r3 == nil || !approx(r3.Score, 0.7) {
		t.Fatalf("post-recovery commit not durable: %+v", r3)
	}
}

func TestRejectedBatchNotPersisted(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply([]Op{
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "e", External: true}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply([]Op{
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "bad", From: "e", To: "missing"}},
	}); err == nil {
		t.Fatal("expected rejection")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Compromised("missing") {
		t.Fatal("rejected batch leaked into the log")
	}
	if _, err := os.Stat(filepath.Join(dir, walName)); err != nil {
		t.Fatalf("wal should still exist: %v", err)
	}
}

func TestInMemoryServiceNoPersistenceRequired(t *testing.T) {
	s := NewService()
	if err := s.Apply(sampleCommittedOps()[0]); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
