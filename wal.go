package attackpath

import (
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
	walName      = "attackpath.wal"
	walMagic     = "APWL"
	walHeaderLen = 12 // 4 magic bytes + 8 format version
	walRecordMin = 16 // seq + payload length + crc
)

// wal is an append-only write-ahead log. Each committed batch is one framed
// record containing a sequence number, a length, a JSON payload and a
// trailing CRC; the file is fsynced before the batch is acknowledged. On
// recovery, a torn/partial tail (an uncommitted write) is ignored, so every
// recovered record is complete and committed and no partial batch can take
// effect.
type wal struct {
	dir    string
	file   *os.File
	seq    uint64
	closed bool
}

type walRecord struct {
	Seq uint64 `json:"seq"`
	Ops []Op   `json:"ops"`
}

var errTruncated = errors.New("truncated wal record")

// openWAL opens or creates the log in dir and returns it together with every
// complete committed batch in commit order.
func openWAL(dir string) (*wal, [][]Op, error) {
	path := filepath.Join(dir, walName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, nil, err
	}
	w := &wal{dir: dir, file: f}

	data, err := io.ReadAll(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if len(data) == 0 {
		header := make([]byte, walHeaderLen)
		copy(header[:4], walMagic)
		binary.BigEndian.PutUint64(header[4:12], 1)
		if _, err := f.Write(header); err != nil {
			f.Close()
			return nil, nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, nil, err
		}
		return w, nil, nil
	}

	if len(data) < walHeaderLen || string(data[:4]) != walMagic {
		f.Close()
		return nil, nil, fmt.Errorf("corrupt wal header")
	}
	pos := walHeaderLen

	var batches [][]Op
	for pos < len(data) {
		rec, consumed, rerr := readRecord(data[pos:])
		if errors.Is(rerr, errTruncated) {
			// A torn tail is the on-disk image of a crash before the record
			// write finished: truncate it away and replay everything before
			// it.
			if terr := f.Truncate(int64(pos)); terr != nil {
				f.Close()
				return nil, nil, terr
			}
			break
		}
		if rerr != nil {
			f.Close()
			return nil, nil, rerr
		}
		pos += consumed
		batches = append(batches, rec.Ops)
		if rec.Seq > w.seq {
			w.seq = rec.Seq
		}
	}

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, nil, err
	}
	return w, batches, nil
}

// append durably records one batch as a single record and returns its
// sequence number.
func (w *wal) append(ops []Op) (uint64, error) {
	if w.closed {
		return 0, errors.New("wal is closed")
	}
	w.seq++
	payload, err := json.Marshal(walRecord{Seq: w.seq, Ops: ops})
	if err != nil {
		return 0, err
	}
	frame := make([]byte, walRecordMin+len(payload))
	binary.BigEndian.PutUint64(frame[0:8], w.seq)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(payload)))
	copy(frame[12:12+len(payload)], payload)
	crc := crc32.ChecksumIEEE(frame[:12+len(payload)])
	binary.BigEndian.PutUint32(frame[12+len(payload):], crc)

	// One sequential write followed by fsync: a crash can leave the complete
	// record (replayed) or a short tail (detected and dropped on open).
	if _, err := w.file.Write(frame); err != nil {
		return 0, err
	}
	if err := w.file.Sync(); err != nil {
		return 0, err
	}
	return w.seq, nil
}

// close releases the underlying file.
func (w *wal) close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.file.Sync(); err != nil {
		w.file.Close()
		return err
	}
	return w.file.Close()
}

// readRecord decodes one frame from the head of buf and returns its length.
// Any incomplete or checksum-mismatching frame reports errTruncated; such a
// frame can only be the tail of the log.
func readRecord(buf []byte) (*walRecord, int, error) {
	if len(buf) < walRecordMin {
		return nil, 0, errTruncated
	}
	seq := binary.BigEndian.Uint64(buf[0:8])
	plen := int(binary.BigEndian.Uint32(buf[8:12]))
	if plen < 0 {
		return nil, 0, errTruncated
	}
	total := 12 + plen + 4
	if total > len(buf) {
		return nil, 0, errTruncated
	}
	want := binary.BigEndian.Uint32(buf[12+plen : total])
	got := crc32.ChecksumIEEE(buf[:12+plen])
	if want != got {
		return nil, 0, errTruncated
	}
	var rec walRecord
	if err := json.Unmarshal(buf[12:12+plen], &rec); err != nil {
		return nil, 0, fmt.Errorf("corrupt wal payload: %w", err)
	}
	if rec.Seq != seq {
		return nil, 0, fmt.Errorf("corrupt wal record: seq mismatch")
	}
	return &rec, total, nil
}
