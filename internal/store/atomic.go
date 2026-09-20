package store

import (
	"os"
	"path/filepath"
)

// writeAtomic writes data to path via tmp file + fsync + rename + dir fsync.
// A crash at any point leaves either the previous complete file or the new
// complete file, never a partial one at the destination.
func (s *Store) writeAtomic(rel string, data []byte) error {
	dir := filepath.Join(s.root, filepath.Dir(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(s.root, "tmp"), "doc-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	dst := filepath.Join(s.root, rel)
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	dh, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = dh.Sync()
	dh.Close()
	if err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (s *Store) remove(rel string) error {
	err := os.Remove(filepath.Join(s.root, rel))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
