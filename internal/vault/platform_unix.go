//go:build linux || darwin

package vault

import (
	"os"
	"syscall"
)

// syncDir fsyncs a directory so a rename inside it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Lock takes an exclusive advisory lock on path (created 0600) and returns the
// function that releases it. It serialises read-modify-write cycles between
// concurrent kist processes; atomic rename alone prevents corruption but not
// lost updates.
func Lock(path string) (unlock func() error, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() error {
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return f.Close()
	}, nil
}
