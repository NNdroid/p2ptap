package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestFullContainsVersion(t *testing.T) {
	v := Full()
	t.Logf("[version] Full() = %q", v)
	if !strings.Contains(v, Version) {
		t.Errorf("Full() = %q, expected to contain Version %q", v, Version)
	}
	if !strings.HasPrefix(v, "p2ptap ") {
		t.Errorf("Full() = %q, expected prefix \"p2ptap \"", v)
	}
}

func TestFullContainsGitCommit(t *testing.T) {
	v := Full()
	t.Logf("[version] Full() = %q GitCommit=%q", v, GitCommit)
	if !strings.Contains(v, GitCommit) {
		t.Errorf("Full() = %q, expected to contain GitCommit %q", v, GitCommit)
	}
}

func TestFullContainsRuntime(t *testing.T) {
	v := Full()
	t.Logf("[version] Full() = %q GOOS=%s", v, runtime.GOOS)
	if !strings.Contains(v, runtime.GOOS) {
		t.Errorf("Full() = %q, expected to contain GOOS", v)
	}
}

func TestShortFormatting(t *testing.T) {
	// Short() is "p2ptap <version>" and does NOT embed the commit.
	want := "p2ptap " + Version
	if got := Short(); got != want {
		t.Errorf("Short() = %q, want %q", got, want)
	} else {
		t.Logf("[version] ✓ Short() = %q", got)
	}
}

func TestShortOverriddenVersion(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()
	Version = "v9.9.9"
	t.Log("[version] override Version=v9.9.9")
	if got := Short(); got != "p2ptap v9.9.9" {
		t.Errorf("Short() with custom version = %q, want %q", got, "p2ptap v9.9.9")
	} else {
		t.Logf("[version] ✓ Short() = %q", got)
	}
}

func TestShortTruncationHelper(t *testing.T) {
	t.Log("[version] short() truncation helper")
	// The unexported short() helper truncates to n chars.
	if got := short("abcdefg", 4); got != "abcd" {
		t.Errorf("short(\"abcdefg\",4) = %q, want %q", got, "abcd")
	}
	if got := short("ab", 9); got != "ab" {
		t.Errorf("short(\"ab\",9) = %q, want %q", got, "ab")
	}
}
