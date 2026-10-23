package detect

import (
	"cmp"
	"slices"
)

// FieldNames finds values by the name of the field that holds them: JSON keys
// and the headers of CSV, TSV, psql and markdown tables.
type FieldNames struct{}

// Find returns the matches of the JSON and table scanners, sorted by Start,
// with overlapping spans merged into their union.
func (FieldNames) Find(text string) []Match {
	return mergeMatches(append(scanJSON(text), scanTables(text)...))
}

// mergeMatches sorts ms by Start, in place, and merges overlapping matches
// into one that covers their union, so no matched byte is left uncovered. The
// Type, Score, Detector, Field and Rule come from the highest-scored match of the
// group, the one with the earliest Start on a tie.
func mergeMatches(ms []Match) []Match {
	slices.SortStableFunc(ms, func(a, b Match) int { return cmp.Compare(a.Start, b.Start) })
	out := ms[:0]
	for _, m := range ms {
		last := len(out) - 1
		if last < 0 || m.Start >= out[last].End {
			out = append(out, m)
			continue
		}
		g := &out[last]
		start, end := g.Start, max(g.End, m.End)
		if m.Score > g.Score {
			*g = m
		}
		g.Start, g.End = start, end
	}
	return out
}
