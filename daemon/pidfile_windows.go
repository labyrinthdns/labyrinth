//go:build windows

package daemon

// Windows has no O_NOFOLLOW; symlink semantics differ. We rely on the
// configured PID directory permissions instead.
func platformPIDOpenFlags() int { return 0 }
