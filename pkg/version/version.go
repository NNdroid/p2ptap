package version

import (
	"fmt"
	"runtime"
)

// These variables are injected at compile time via -ldflags
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func Full() string {
	return fmt.Sprintf("p2ptap %s (commit: %s, built: %s, %s/%s, %s)",
		Version, short(GitCommit, 9), BuildTime, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func Short() string {
	return fmt.Sprintf("p2ptap %s", Version)
}

func short(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
