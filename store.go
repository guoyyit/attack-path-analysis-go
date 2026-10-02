package attackpath

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
)

const (
	snapshotFile = "state.snap"
	walFile      = "wal.log"
	// compactInterval triggers a fresh snapshot after this many new frames.
	compactInterval = 64
)

type snapshotRecord struct {
	Version  int64    `json:"version"`
	Material material `json:"material"`
}

type walRecord struct {
	Version int64     `json:"version"`
	Change  ChangeSet `json:"change"`
}

// Store provides atomic, durable persistence using an atomically replaced
// full snapshot plus an append-only write ahead log.
//
// Durability protocol:
//   - Every committed Update is one CRC-protected WAL frame, fsync'ed before
//     the update becomes visible. A torn trailing frame (crash mid-write) is
//     detected via length/CRC and discarded on replay, so it never commits.
//   - Periodically the state is folded into state.snap via a temp file +
//     fsync + atomic rename, after which older WAL frames are dropped. The
//     surviving frames keep their global version numbers, so replay is
//     always contiguous with the snapshot's baseline version.
type Store struct {
	dir          string
	wal          *os.File
	snapV        int64 // version represented by state.snap
	tailStart    int64 // byte offset of the first frame newer than state.snap
	nextV        int64 // next global version to write
	sinceCompact int
}

// OpenStore opens (or creates) the persistence directory.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	if _, _, err := s.loadState(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, walFile), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	s.wal = f
	return s, nil
}

// Close releases backing files.
func (s *Store) Close() error {
	if s.wal == nil {
		return nil
	}
	err := s.wal.Sync()
	if cerr := s.wal.Close(); err == nil {
		err = cerr
	}
	s.wal = nil
	return err
}

// loadState replays the snapshot and committed WAL frames. A torn trailing
// frame is truncated away so uncommitted writes never take effect.
func (s *Store) loadState() (material, int64, error) {
	m := newMaterial()
	var snapVersion int64

	if data, err := os.ReadFile(filepath.Join(s.dir, snapshotFile)); err == nil {
		rec, err := decodeSnapshot(data)
		if err != nil {
			return m, 0, err
		}
		m = rec.Material
		snapVersion = rec.Version
	} else if !errors.Is(err, os.ErrNotExist) {
		return m, 0, err
	}

	frames, tailOffset, err := readWAL(filepath.Join(s.dir, walFile))
	if err != nil {
		return m, 0, err
	}
	version := snapVersion
	for _, fr := range frames {
		if fr.Version <= snapVersion {
			continue // frame already folded into an older/newer snapshot
		}
		if fr.Version != version+1 {
			return m, 0, fmt.Errorf("wal version gap: expected %d, got %d", version+1, fr.Version)
		}
		if _, err := applyMaterial(m, fr.Change); err != nil {
			return m, 0, err
		}
		version = fr.Version
	}

	s.snapV = snapVersion
	s.nextV = version + 1
	s.sinceCompact = 0
	for _, fr := range frames {
		if fr.Version > snapVersion {
			s.sinceCompact++
		}
	}
	s.tailStart = tailOffset
	return m, version, nil
}

type walFrame struct {
	Version int64
	Change  ChangeSet
}

// readWAL parses the WAL, returning committed frames and the byte length of
// their contiguous valid prefix. Any torn/corrupt tail is excluded.
func readWAL(path string) ([]walFrame, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	var frames []walFrame
	offset := int64(0)
	validLen := int64(0)
	for len(data) >= 12 {
		plen := int(binary.BigEndian.Uint64(data[0:8]))
		if plen <= 0 || 12+plen > len(data) {
			break // truncated header/body: torn trailing write
		}
		payload := data[12 : 12+plen]
		if crc32.ChecksumIEEE(payload) != binary.BigEndian.Uint32(data[8:12]) {
			break // corrupt tail: commit never completed
		}
		var rec walRecord
		if err := json.Unmarshal(payload, &rec); err != nil {
			break
		}
		frames = append(frames, walFrame{Version: rec.Version, Change: rec.Change})
		consumed := int64(12 + plen)
		validLen += consumed
		offset += consumed
		data = data[12+plen:]
	}
	total, statErr := os.Stat(path)
	if statErr == nil && total.Size() != validLen {
		// Drop the torn tail so future appends start at a frame boundary.
		if err := os.Truncate(path, validLen); err != nil {
			return frames, validLen, err
		}
	}
	return frames, validLen, nil
}

// commit durably appends one committed change set.
func (s *Store) commit(version int64, cs ChangeSet) error {
	if version != s.nextV {
		return fmt.Errorf("commit version %d out of order (next %d)", version, s.nextV)
	}
	payload, err := json.Marshal(walRecord{Version: version, Change: cs})
	if err != nil {
		return err
	}
	if _, err := s.wal.Write(encodeFrame(payload)); err != nil {
		return err
	}
	if err := s.wal.Sync(); err != nil {
		return err
	}
	s.nextV = version + 1
	s.sinceCompact++
	if s.sinceCompact >= compactInterval {
		return s.compact(version)
	}
	return nil
}

var _ io.Closer = (*Store)(nil)

func encodeFrame(payload []byte) []byte {
	frame := make([]byte, 8+4+len(payload))
	binary.BigEndian.PutUint64(frame[0:8], uint64(len(payload)))
	binary.BigEndian.PutUint32(frame[8:12], crc32.ChecksumIEEE(payload))
	copy(frame[12:], payload)
	return frame
}

// compact folds the current committed state into state.snap, then rewrites
// the WAL to contain only frames newer than the snapshot. All steps are
// crash safe: a crash before the rename replays the full WAL; a crash after
// the rename but before the WAL rewrite skips folded frames on replay.
func (s *Store) compact(version int64) error {
	frames, _, err := readWAL(filepath.Join(s.dir, walFile))
	if err != nil {
		return err
	}
	m := newMaterial()
	var snapVersion int64
	if data, rerr := os.ReadFile(filepath.Join(s.dir, snapshotFile)); rerr == nil {
		rec, derr := decodeSnapshot(data)
		if derr != nil {
			return derr
		}
		m = rec.Material
		snapVersion = rec.Version
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return rerr
	}
	cur := snapVersion
	var tail []walFrame
	for _, fr := range frames {
		if fr.Version <= snapVersion {
			continue
		}
		if fr.Version != cur+1 {
			return fmt.Errorf("compact version gap: expected %d, got %d", cur+1, fr.Version)
		}
		if _, err := applyMaterial(m, fr.Change); err != nil {
			return err
		}
		cur = fr.Version
		tail = append(tail, fr)
	}
	if cur != version {
		return fmt.Errorf("compact version mismatch %d != %d", cur, version)
	}

	data, err := encodeSnapshot(version, m)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, snapshotFile+".tmp")
	if err := writeFileAtomic(tmp, data); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, snapshotFile)); err != nil {
		return err
	}
	if dir, err := os.Open(s.dir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}

	// Rewrite the WAL tail through a temp file, then atomically swap.
	var tailBytes bytes.Buffer
	for _, fr := range tail {
		payload, err := json.Marshal(walRecord{Version: fr.Version, Change: fr.Change})
		if err != nil {
			return err
		}
		tailBytes.Write(encodeFrame(payload))
	}
	walTmp := filepath.Join(s.dir, walFile+".tmp")
	if err := writeFileAtomic(walTmp, tailBytes.Bytes()); err != nil {
		return err
	}
	if err := s.wal.Close(); err != nil {
		return err
	}
	if err := os.Rename(walTmp, filepath.Join(s.dir, walFile)); err != nil {
		return err
	}
	if dir, err := os.Open(s.dir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	f, err := os.OpenFile(filepath.Join(s.dir, walFile), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	s.wal = f
	s.snapV = version
	s.sinceCompact = 0
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func encodeSnapshot(version int64, m material) ([]byte, error) {
	rec := snapshotRecord{Version: version, Material: m}
	return json.MarshalIndent(rec, "", "  ")
}

func decodeSnapshot(data []byte) (snapshotRecord, error) {
	var rec snapshotRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return rec, err
	}
	return rec, nil
}
