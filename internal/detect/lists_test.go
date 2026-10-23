package detect

import (
	"strings"
	"testing"
)

func TestTLDKnown(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"com", true},
		{"COM", true},
		{"io", true},
		{"comm", false},
		{"", false},
	} {
		if got := tldKnown(c.in); got != c.want {
			t.Errorf("tldKnown(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsStreetSuffix(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"st", true},
		{"avenue", true},
		{"blvd", true},
		{"apple", false},
		{"", false},
	} {
		if got := isStreetSuffix(c.in); got != c.want {
			t.Errorf("isStreetSuffix(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestListSizes holds the embedded lists to the minimums the generator
// (scripts/gen_lists.py) enforces.
func TestListSizes(t *testing.T) {
	for _, c := range []struct {
		name string
		data string
		min  int
	}{
		{"tlds.txt", tldsTXT, 1000},
		{"street_suffixes.txt", streetSuffixesTXT, 300},
	} {
		if !strings.HasSuffix(c.data, "\n") {
			t.Errorf("%s: no trailing newline", c.name)
		}
		if n := strings.Count(c.data, "\n"); n < c.min {
			t.Errorf("%s: %d entries, want >= %d", c.name, n, c.min)
		}
	}
}
