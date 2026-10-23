package detect

import (
	"fmt"
	"math"
	"strings"
)

// minScore is the lowest score a candidate needs to be emitted.
const minScore = 0.30

// evidence is a log-odds score: a prior plus the weight of each piece of
// evidence found. Items keep the order they were added in.
type evidence struct {
	sum   float64
	items []evidenceItem
}

type evidenceItem struct {
	name string
	w    float64
}

// newEvidence starts a candidate with prior as its log-odds.
func newEvidence(prior float64) *evidence {
	return &evidence{
		sum:   prior,
		items: []evidenceItem{{name: "prior", w: prior}},
	}
}

// add records one piece of evidence with weight w. A negative w is
// counter-evidence.
func (e *evidence) add(name string, w float64) {
	e.sum += w
	e.items = append(e.items, evidenceItem{name: name, w: w})
}

// score returns the logistic of the summed log-odds, in (0, 1).
func (e *evidence) score() float64 {
	return 1 / (1 + math.Exp(-e.sum))
}

// String lists the evidence as "prior-2.5 name+w ...", with one decimal and a
// sign on every weight, in the order added.
func (e *evidence) String() string {
	var b strings.Builder
	for i, it := range e.items {
		if i > 0 {
			b.WriteByte(' ')
		}
		if i == 0 {
			b.WriteString("prior")
		} else {
			b.WriteString(it.name)
		}
		fmt.Fprintf(&b, "%+.1f", it.w)
	}
	return b.String()
}

// match builds the Match for text[start:end] with this evidence. It returns
// false when the score is below minScore.
func (e *evidence) match(t EntityType, start, end int, detector, rule string) (Match, bool) {
	s := e.score()
	if s < minScore {
		return Match{}, false
	}
	return Match{
		Type:     t,
		Start:    start,
		End:      end,
		Score:    s,
		Detector: detector,
		Rule:     rule,
		Evidence: e.String(),
	}, true
}
