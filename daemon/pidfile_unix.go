//go:build !windows

package daemon

import "syscall"

// platformPIDOpenFlags returns extra OpenFile flags used to harden the PID
// file write against symlink-redirect attacks (H-9).
func platformPIDOpenFlags() int {
	return syscall.O_NOFOLLOW
}
