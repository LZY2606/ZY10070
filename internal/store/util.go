package store

import "os"

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

func removeIfExists(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
