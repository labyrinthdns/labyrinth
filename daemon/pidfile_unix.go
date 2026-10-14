//go:build !windows

package daemon

import "syscall"

// platformPIDOpenFlags returns extra OpenFile flags used to harden the PID
// file write against symlink-redirect attacks (H-9).
func platformPIDOpenFlags() int {
	return syscall.O_NOFOLLOW
}

// pidBelongsToLabyrinth reports whether pid is a running labyrinth process
// (by /proc/<pid>/comm on Linux, liveness elsewhere — see
// verifyPIDIsLabyrinth).
func pidBelongsToLabyrinth(pid int) bool {
	return verifyPIDIsLabyrinth(pid) == nil
}
