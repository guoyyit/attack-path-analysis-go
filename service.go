package attackpath

import (
	"os"
	"sync"
	"sync/atomic"
)

// Service is the entry point of the analysis engine. A zero value is not
// usable; create it with Open or NewService.
type Service struct {
	mu    sync.Mutex // serializes committed updates
	state atomic.Pointer[graph]
	store *wal
}

// NewService creates an in-memory, non-persistent service.
func NewService() *Service {
	s := &Service{}
	s.state.Store(emptyGraph(0))
	return s
}

// Open opens (creating if necessary) a persistent service backed by a
// write-ahead log in dir. All previously committed data is recovered before
// the service becomes usable.
func Open(dir string) (*Service, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	w, batches, err := openWAL(dir)
	if err != nil {
		return nil, err
	}
	s := &Service{store: w}
	g := emptyGraph(0)
	for _, ops := range batches {
		var err error
		g, err = g.apply(g.version+1, ops)
		if err != nil {
			return nil, err
		}
	}
	s.state.Store(g)
	return s, nil
}

// Close releases persistence resources.
func (s *Service) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		err := s.store.close()
		s.store = nil
		return err
	}
	return nil
}

// Apply commits a batch of mutations atomically. Readers either observe the
// pre-update or the post-update snapshot, never an intermediate state.
func (s *Service) Apply(ops []Op) error {
	if len(ops) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.state.Load()
	// Validate and compute entirely against the old snapshot. On failure
	// nothing is logged and nothing is swapped in.
	next, err := old.apply(old.version+1, ops)
	if err != nil {
		return err
	}
	// Durability precedes visibility: the batch is fully on disk before the
	// atomic pointer swap.
	if s.store != nil {
		if _, err := s.store.append(ops); err != nil {
			return err
		}
	}
	s.state.Store(next)
	return nil
}

// Query evaluates q against a consistent snapshot.
func (s *Service) Query(q Query) []*AssetRisk {
	return s.state.Load().query(q)
}

// Compromised reports whether assetID is reachable by the attacker.
func (s *Service) Compromised(assetID string) bool {
	return s.state.Load().compromised[assetID]
}

// Risk returns the aggregated risk for assetID, or nil when the asset does
// not exist / is not reachable.
func (s *Service) Risk(assetID string) *AssetRisk {
	return s.state.Load().risks[assetID]
}

// snapshot returns the current immutable graph snapshot.
func (s *Service) snapshot() *graph {
	return s.state.Load()
}

// swap installs g as the new committed snapshot.
func (s *Service) swap(g *graph) {
	s.state.Store(g)
}

// emptyGraph is the initial snapshot with no data.
func emptyGraph(version uint64) *graph {
	return newGraph(version, nil, nil, nil)
}
