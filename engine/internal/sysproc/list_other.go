//go:build !linux

package sysproc

// List on non-Linux platforms returns an empty slice. The engine still
// compiles cleanly on macOS for development; the choke console's process
// picker just shows "no processes — host not Linux" until deployed.
func List() ([]Entry, error) { return nil, nil }
