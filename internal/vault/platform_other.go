//go:build !(linux || darwin)

package vault

// kist supports Linux and macOS. These stubs exist only so the pure logic can
// be built and unit-tested on other platforms during development; they provide
// no durability or locking guarantees.

func syncDir(string) error { return nil }

func Lock(string) (func() error, error) { return func() error { return nil }, nil }
