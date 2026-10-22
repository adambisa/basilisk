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

const fixtureDir = "../../testdata/fieldnames"

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
		fmt.Fprintf(&sb, "%d-%d %s %.2f %s field=%s %q\n",
			m.Start, m.End, m.Type, m.Score, m.Detector, m.Field, text[m.Start:m.End])
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

func TestFieldNamesGolden(t *testing.T) {
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
			got := render(text, FieldNames{}.Find(text))
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

func FuzzFieldNames(f *testing.F) {
	for _, path := range fixtures(f) {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(string(data))
	}
	f.Fuzz(func(t *testing.T, text string) {
		ms := FieldNames{}.Find(text)
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
