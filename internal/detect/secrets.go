package detect

//go:generate uv run --script ../../scripts/gen_secret_rules.py

import (
	_ "embed"
	"encoding/json"
	"math"
	"regexp"
	"strings"
	"sync"
)

func init() { valueFinders = append(valueFinders, findSecrets) }

//go:embed secret_rules.json
var secretRulesJSON []byte

// secretRules are gitleaks' rules, converted by scripts/gen_secret_rules.py.
// The regexes are compiled once, at first use.
type secretRules struct {
	Version    string            `json:"version"`
	Allowlists []secretAllowlist `json:"allowlists"`
	Rules      []secretRule      `json:"rules"`

	once sync.Once
}

type secretRule struct {
	ID          string            `json:"id"`
	Regex       string            `json:"regex"`
	SecretGroup int               `json:"secretGroup"`
	Entropy     float64           `json:"entropy"`
	Keywords    []string          `json:"keywords"`
	Allowlists  []secretAllowlist `json:"allowlists"`

	re *regexp.Regexp // nil when Regex does not compile
}

// secretAllowlist drops a match when a regex matches its target or a stopword
// occurs in the secret. RegexTarget is "secret" (the default), "match" (the
// whole regex match) or "line" (the whole line holding the match).
type secretAllowlist struct {
	RegexTarget string   `json:"regexTarget"`
	Regexes     []string `json:"regexes"`
	Stopwords   []string `json:"stopwords"`

	res   []*regexp.Regexp // the Regexes that compile
	stops []string         // Stopwords, lower-cased once by compile
}

// embeddedSecrets parses the embedded rules, once.
var embeddedSecrets = sync.OnceValue(func() *secretRules {
	rs := new(secretRules)
	if err := json.Unmarshal(secretRulesJSON, rs); err != nil {
		return new(secretRules) // the embedded JSON is tested; never fail a scan
	}
	return rs
})

// compile compiles every regex. A rule whose regex does not compile is
// skipped; TestSecretRulesCompile reports it.
func (rs *secretRules) compile() {
	rs.once.Do(func() {
		for i := range rs.Allowlists {
			rs.Allowlists[i].compile()
		}
		for i := range rs.Rules {
			r := &rs.Rules[i]
			r.re, _ = regexp.Compile(r.Regex)
			for j := range r.Allowlists {
				r.Allowlists[j].compile()
			}
		}
	})
}

func (a *secretAllowlist) compile() {
	for _, w := range a.Stopwords {
		a.stops = append(a.stops, strings.ToLower(w))
	}
	for _, e := range a.Regexes {
		if re, err := regexp.Compile(e); err == nil {
			a.res = append(a.res, re)
		}
	}
}

// findSecrets finds secrets with the embedded gitleaks rules.
func findSecrets(text string) []Match {
	return scanSecrets(text, embeddedSecrets())
}

// scanSecrets runs the rules over text as gitleaks does. For each rule: skip
// it unless one of its keywords occurs in the text (case-insensitive); run the
// regex; take the secret from the capture group named by secretGroup, else
// the first non-empty capture group, else the whole match; drop the match when
// its entropy is below the rule's minimum or an allowlist covers it.
func scanSecrets(text string, rs *secretRules) []Match {
	rs.compile()
	lower := strings.ToLower(text)
	var ms []Match
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.re == nil || !hasKeyword(lower, r.Keywords) {
			continue
		}
		for _, loc := range r.re.FindAllStringSubmatchIndex(text, -1) {
			start, end := secretSpan(loc, r.SecretGroup)
			if start < 0 || start == end {
				continue
			}
			secret := text[start:end]
			if r.Entropy > 0 && shannonEntropy(secret) < r.Entropy {
				continue
			}
			if allowed(text, loc, secret, rs.Allowlists) || allowed(text, loc, secret, r.Allowlists) {
				continue
			}
			ms = append(ms, Match{
				Type: TypeSecret, Start: start, End: end, Score: secretScore(r.ID, secret),
				Detector: "value/secret", Rule: "gitleaks/" + r.ID,
			})
		}
	}
	return ms
}

// secretScore is the score of a secret found by rule ruleID. Provider rules
// score 0.95. generic-api-key scores 0.7, as it matches many strings that are
// not keys. sourcegraph-access-token also has a bare 40-hex alternative that
// matches every git SHA, so a match without the sgp_ prefix (any case) scores 0.6.
func secretScore(ruleID, secret string) float64 {
	switch ruleID {
	case "generic-api-key":
		return 0.7
	case "sourcegraph-access-token":
		if !(len(secret) >= 4 && strings.EqualFold(secret[:4], "sgp_")) {
			return 0.6
		}
	}
	return 0.95
}

func hasKeyword(lower string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	for _, k := range keywords {
		if strings.Contains(lower, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

// secretSpan picks the secret out of a FindStringSubmatchIndex result. It
// returns -1, -1 when the chosen group did not take part in the match.
func secretSpan(loc []int, group int) (int, int) {
	if group > 0 {
		if 2*group+1 >= len(loc) {
			return -1, -1
		}
		return loc[2*group], loc[2*group+1]
	}
	for g := 1; 2*g+1 < len(loc); g++ {
		if loc[2*g] >= 0 && loc[2*g] != loc[2*g+1] {
			return loc[2*g], loc[2*g+1]
		}
	}
	return loc[0], loc[1]
}

// allowed reports whether an allowlist covers the match at loc, whose secret
// is secret.
func allowed(text string, loc []int, secret string, lists []secretAllowlist) bool {
	var lowerSecret string
	for i := range lists {
		a := &lists[i]
		for _, w := range a.stops {
			if lowerSecret == "" {
				lowerSecret = strings.ToLower(secret)
			}
			if strings.Contains(lowerSecret, w) {
				return true
			}
		}
		if len(a.res) == 0 {
			continue
		}
		target := secret
		switch a.RegexTarget {
		case "match":
			target = text[loc[0]:loc[1]]
		case "line":
			target = lineAround(text, loc[0], loc[1])
		}
		for _, re := range a.res {
			if re.MatchString(target) {
				return true
			}
		}
	}
	return false
}

// lineAround returns the whole line or lines holding text[start:end].
func lineAround(text string, start, end int) string {
	lo := strings.LastIndexByte(text[:start], '\n') + 1
	hi := len(text)
	if i := strings.IndexByte(text[end:], '\n'); i >= 0 {
		hi = end + i
	}
	return text[lo:hi]
}

// shannonEntropy is the Shannon entropy of s, in bits per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	n := 0
	for _, c := range s {
		counts[c]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}
