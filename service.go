package attackpath

import (
	"sync"
	"sync/atomic"
)

// Service serializes updates while serving lock-free queries against
// immutable snapshots.
type Service struct {
	store    *Store
	current  atomic.Pointer[Snapshot]
	updateMu sync.Mutex
}

// Open loads committed state and returns a ready service. Passing an empty
// directory keeps everything in memory.
func Open(dir string) (*Service, error) {
	s := &Service{}
	if dir != "" {
		store, err := OpenStore(dir)
		if err != nil {
			return nil, err
		}
		s.store = store
	}
	m := newMaterial()
	var version int64
	if s.store != nil {
		loaded, v, err := s.store.loadState()
		if err != nil {
			return nil, err
		}
		m, version = loaded, v
	}
	s.current.Store(buildSnapshot(version, m))
	return s, nil
}

// Close flushes and releases persistence resources.
func (s *Service) Close() error {
	if s.store != nil {
		return s.store.Close()
	}
	return nil
}

// Update validates, persists and atomically applies one batch.
func (s *Service) Update(cs ChangeSet) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()

	old := s.current.Load()
	newM := cloneMaterial(old.material)
	touched, err := applyMaterial(newM, cs)
	if err != nil {
		return err
	}
	version := old.version + 1
	if s.store != nil {
		if err := s.store.commit(version, cs); err != nil {
			return err
		}
	}
	s.current.Store(advanceSnapshot(old, newM, touched, version))
	return nil
}

// Current returns the latest committed snapshot.
func (s *Service) Current() *Snapshot {
	return s.current.Load()
}

// Query evaluates a constrained path query on a consistent snapshot.
func (s *Service) Query(c Constraint) QueryResult {
	return queryPaths(s.current.Load(), c)
}

// Report returns the full risk report of the current snapshot.
func (s *Service) Report() *Report {
	return s.current.Load().report
}
