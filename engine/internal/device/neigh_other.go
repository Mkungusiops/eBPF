//go:build !linux

package device

// PollNeigh is a no-op on non-Linux dev hosts: there is no kernel neighbour
// table to read in the form we parse. Returns (nil, nil) so the caller's
// ticker loop is a harmless no-op during macOS UI iteration.
func PollNeigh() ([]Device, error) { return nil, nil }
