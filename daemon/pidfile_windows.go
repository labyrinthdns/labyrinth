//go:build windows

package daemon

// Windows has no O_NOFOLLOW; symlink semantics differ. We rely on the
// configured PID directory permissions instead.
func platformPIDOpenFlags() int { return 0 }

// pidBelongsToLabyrinth reports whether pid is a running process. Windows has
// no /proc to confirm the image name, so liveness is the best available check.
func pidBelongsToLabyrinth(pid int) bool {
	return IsRunning(pid)
}
