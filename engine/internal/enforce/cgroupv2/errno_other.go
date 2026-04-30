//go:build !linux

package cgroupv2

func isESRCH(err error) bool { return false }
