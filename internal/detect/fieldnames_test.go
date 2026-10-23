package detect

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

const fixtureDir = "../../testdata/golden"

func TestMergeMatches(t *testing.T) {
	m := func(start, end int, score float64, field string) Match {
		return Match{Type: TypeAddress, Start: start, End: end, Score: score, Detector: "d", Field: field}
	}
	tests := []struct {
		name string
		in   []Match
		want []Match
	}{
		{"nested higher score keeps the union",
			[]Match{m(0, 10, .5, "a"), m(5, 8, .9, "b"), m(20, 25, .5, "c")},
			[]Match{m(0, 10, .9, "b"), m(20, 25, .5, "c")}},
		{"several nested",
			[]Match{m(0, 10, .5, "a"), m(2, 4, .9, "b"), m(5, 8, .4, "c")},
			[]Match{m(0, 10, .9, "b")}},
		{"chain",
			[]Match{m(0, 10, .5, "a"), m(5, 15, .9, "b"), m(12, 20, .7, "c")},
			[]Match{m(0, 20, .9, "b")}},
		{"larger span with the higher score",
			[]Match{m(0, 10, .9, "a"), m(5, 8, .5, "b")},
			[]Match{m(0, 10, .9, "a")}},
		{"equal score keeps the earlier start",
			[]Match{m(0, 6, .8, "a"), m(4, 9, .8, "b")},
			[]Match{m(0, 9, .8, "a")}},
		{"adjacent spans stay apart",
			[]Match{m(0, 5, .5, "a"), m(5, 9, .9, "b")},
			[]Match{m(0, 5, .5, "a"), m(5, 9, .9, "b")}},
		{"disjoint", []Match{m(20, 25, .5, "c"), m(0, 3, .5, "a")}, []Match{m(0, 3, .5, "a"), m(20, 25, .5, "c")}},
		{"empty", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// every input order gives the same result
			orders := [][]Match{tt.in}
			if len(tt.in) > 1 {
				rev := append([]Match(nil), tt.in...)
				slices.Reverse(rev)
				orders = append(orders, rev)
			}
			for _, in := range orders {
				got := mergeMatches(append([]Match(nil), in...))
				if len(got) == 0 && len(tt.want) == 0 {
					continue
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("mergeMatches(%v) = %v, want %v", in, got, tt.want)
				}
			}
		})
	}
}

// render lists matches one per line, with a trailing newline, for golden files.
func render(text string, ms []Match) string {
	var sb strings.Builder
	for _, m := range ms {
		label := "field=" + m.Field
		if m.Field == "" && m.Rule != "" {
			label = "rule=" + m.Rule
		}
		fmt.Fprintf(&sb, "%d-%d %s %.2f %s %s %q\n",
			m.Start, m.End, m.Type, m.Score, m.Detector, label, text[m.Start:m.End])
	}
	return sb.String()
}

// fixtures returns the paths of the fixture files, golden files excluded.
func fixtures(t testing.TB) []string {
	t.Helper()
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range entries {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), ".golden") {
			paths = append(paths, filepath.Join(fixtureDir, e.Name()))
		}
	}
	return paths
}

const cleanDir = "../../testdata/values/clean"

// cleanFixtures returns the paths of the files that hold no PII.
func cleanFixtures(t testing.TB) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(cleanDir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	return paths
}

// TestNoPIIGuard asserts that All finds nothing at 0.9 or above in text that
// holds no PII. A failure names the file, rule and score, never the value.
func TestNoPIIGuard(t *testing.T) {
	paths := cleanFixtures(t)
	if len(paths) == 0 {
		t.Fatal("no clean fixtures found")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range (All{}).Find(string(data)) {
				if m.Score >= 0.9 {
					t.Errorf("%s: %s match with score %.2f, field %q, rule %q, span %d-%d (%d bytes)",
						filepath.Base(path), m.Type, m.Score, m.Field, m.Rule, m.Start, m.End, m.End-m.Start)
				}
			}
		})
	}
}

func TestFieldAndValueMerge(t *testing.T) {
	text := `{"card_number": "4111 1111 1111 1111"}`
	ms := All{}.Find(text)
	if len(ms) != 1 {
		t.Fatalf("got %d matches, want 1: %v", len(ms), ms)
	}
	if got := text[ms[0].Start:ms[0].End]; got != "4111 1111 1111 1111" {
		t.Errorf("match covers %q, want the card number", got)
	}
}

func TestGolden(t *testing.T) {
	paths := fixtures(t)
	if len(paths) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			got := render(text, All{}.Find(text))
			golden := path + ".golden"
			if *update {
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("%s differs from golden\n--- got\n%s--- want\n%s", path, got, want)
			}
		})
	}
}

func FuzzAll(f *testing.F) {
	for _, path := range append(fixtures(f), cleanFixtures(f)...) {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(data))
	}
	f.Fuzz(func(t *testing.T, text string) {
		ms := All{}.Find(text)
		prev := 0
		for i, m := range ms {
			if m.Start < 0 || m.Start >= m.End || m.End > len(text) {
				t.Fatalf("match %d has bad span %d-%d for text of %d bytes", i, m.Start, m.End, len(text))
			}
			if m.Start < prev {
				t.Fatalf("match %d at %d-%d is unsorted or overlaps the previous match, which ended at %d", i, m.Start, m.End, prev)
			}
			prev = m.End
		}
	})
}
