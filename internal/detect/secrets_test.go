package detect

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestSecretRulesCompile(t *testing.T) {
	rs := embeddedSecrets()
	if len(rs.Rules) == 0 {
		t.Fatal("no embedded rules")
	}
	var failed []string
	check := func(where, expr string) {
		if _, err := regexp.Compile(expr); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", where, err))
		}
	}
	for _, a := range rs.Allowlists {
		for _, e := range a.Regexes {
			check("global allowlist", e)
		}
	}
	for _, r := range rs.Rules {
		check(r.ID, r.Regex)
		for _, a := range r.Allowlists {
			for _, e := range a.Regexes {
				check(r.ID+" allowlist", e)
			}
		}
	}
	if len(failed) > 0 {
		t.Errorf("%d regexes do not compile:\n%s", len(failed), strings.Join(failed, "\n"))
	}
}

// ruleIDWithKeyword returns the id of the embedded rule that has keyword, so a
// test follows the JSON rather than a copy of a rule's name.
func ruleIDWithKeyword(t *testing.T, keyword string) string {
	t.Helper()
	for _, r := range embeddedSecrets().Rules {
		for _, k := range r.Keywords {
			if strings.EqualFold(k, keyword) {
				return r.ID
			}
		}
	}
	t.Fatalf("no embedded rule has keyword %q", keyword)
	return ""
}

// TestSecretRulesVersion keeps the embedded rules in step with the pinned
// gitleaks tag.
func TestSecretRulesVersion(t *testing.T) {
	data, err := os.ReadFile("../../third_party/gitleaks/VERSION")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(data))
	if want == "" {
		t.Fatal("third_party/gitleaks/VERSION is empty")
	}
	if got := embeddedSecrets().Version; got != want {
		t.Errorf("embedded rules version = %q, want %q (run go generate)", got, want)
	}
}

// Test tokens are built from each rule's documented shape, never written out
// as literals.
func TestFindSecrets(t *testing.T) {
	var (
		ghp       = "ghp" + "_" + strings.Repeat("a1B2c3D4e", 4)
		akia      = "AKIA" + "ABCDEFGHIJKLMNOP"
		slack     = "xoxb" + "-1234567890123-2345678901234-" + strings.Repeat("aB3dE5gH", 3)
		stripe    = "sk" + "_live_" + strings.Repeat("aB3dE5gH", 3)
		anthropic = "sk-ant" + "-api03-" + strings.Repeat("aB3dE5gH_-", 9) + "xyz" + "AA"
		generic   = "zX9qL2mN8vB4cR7tY1wE5uI3oP6aS0dF"
		openai    = "sk" + "-" + "aB3dE5gH7jK9mN2pQ4rS" + "T3Blbk" + "FJ" + "tU6vW8xY0zA1bC3dE5fG"
		sgp       = "sgp" + "_" + "0123456789abcdef" + "_" + "7e73806c0d3c9a1b2e4f5a6b7c8d9e0f1a2b3c4d"
		sha       = "7e73806c0d3c9a1b2e4f5a6b7c8d9e0f1a2b3c4d"
	)
	for _, tc := range []struct {
		name  string
		input string
		want  string // Rule@Score:secret, or "" for none
	}{
		{"github pat", "token " + ghp + " end", "gitleaks/github-pat@0.95:" + ghp},
		{"aws access key id", "id " + akia + "\n", "gitleaks/aws-access-token@0.95:" + akia},
		{"slack bot token", slack, "gitleaks/slack-bot-token@0.95:" + slack},
		{"stripe secret key", "billing " + stripe + " ", "gitleaks/stripe-access-token@0.95:" + stripe},
		{"anthropic api key", "ANTHROPIC " + anthropic + " ", "gitleaks/anthropic-api-key@0.95:" + anthropic},
		{"generic api key", `api_key = "` + generic + `"`, "gitleaks/generic-api-key@0.7:" + generic},
		{"sourcegraph bare sha", "github.com/sourcegraph/conc\ncommit " + sha, "gitleaks/sourcegraph-access-token@0.6:" + sha},
		{"sourcegraph sgp token", "token " + sgp + " end", "gitleaks/sourcegraph-access-token@0.95:" + sgp},
		{"openai api key", "openai " + openai + "\n", "gitleaks/" + ruleIDWithKeyword(t, "t3blbkfj") + "@0.95:" + openai},
		{"sourcegraph upper case sgp token", "token " + strings.ToUpper(sgp) + " end", "gitleaks/sourcegraph-access-token@0.95:" + strings.ToUpper(sgp)},
		{"generic low entropy", `api_key = "` + strings.Repeat("a", 32) + `"`, ""},
		{"github pat low entropy", "ghp" + "_" + strings.Repeat("a", 36), ""},
		{"plain prose", "the quick brown fox jumps over the lazy dog", ""},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ms := findSecrets(tc.input)
			var got []string
			for _, m := range ms {
				if m.Type != TypeSecret || m.Detector != "value/secret" || m.Field != "" {
					t.Errorf("bad type/detector/field: %+v", m)
				}
				got = append(got, fmt.Sprintf("%s@%g:%s", m.Rule, m.Score, tc.input[m.Start:m.End]))
			}
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("got %v, want none", got)
				}
				return
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("got %v, want [%s]", got, tc.want)
			}
		})
	}
}

func TestScanSecretsAllowlists(t *testing.T) {
	const tok = "tok_abcdef123456"
	rule := func(al ...secretAllowlist) *secretRules {
		return &secretRules{Rules: []secretRule{{ID: "t", Regex: `(tok_[a-z0-9]+)`, Allowlists: al}}}
	}
	for _, tc := range []struct {
		name  string
		text  string
		rs    *secretRules
		found bool
	}{
		{"no allowlist", "x " + tok, rule(), true},
		{"stopword is case-insensitive substring", "x " + tok, rule(secretAllowlist{Stopwords: []string{"ABCDEF"}}), false},
		{"regex on secret", "x " + tok, rule(secretAllowlist{RegexTarget: "secret", Regexes: []string{`^tok_abc`}}), false},
		{"secret regex does not see the line", "x " + tok, rule(secretAllowlist{RegexTarget: "secret", Regexes: []string{`^x `}}), true},
		{"default target is the secret", "x " + tok, rule(secretAllowlist{Regexes: []string{`^x `}}), true},
		{"line regex", "x " + tok + " # example", rule(secretAllowlist{RegexTarget: "line", Regexes: []string{`# example$`}}), false},
		{"line is only the matched line", "# example\n" + tok, rule(secretAllowlist{RegexTarget: "line", Regexes: []string{`# example`}}), true},
		{"match regex", "x " + tok, rule(secretAllowlist{RegexTarget: "match", Regexes: []string{`^tok_`}}), false},
		{"global allowlist", "x " + tok, func() *secretRules {
			rs := rule()
			rs.Allowlists = []secretAllowlist{{Stopwords: []string{"abcdef"}}}
			return rs
		}(), false},
		{"entropy below minimum", "x " + tok, func() *secretRules {
			rs := rule()
			rs.Rules[0].Entropy = 5
			return rs
		}(), false},
		{"entropy at minimum", "x " + tok, func() *secretRules {
			rs := rule()
			rs.Rules[0].Entropy = 3
			return rs
		}(), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ms := scanSecrets(tc.text, tc.rs)
			if (len(ms) > 0) != tc.found {
				t.Fatalf("matches = %v, want found = %v", ms, tc.found)
			}
			if tc.found && tc.text[ms[0].Start:ms[0].End] != tok {
				t.Errorf("span = %q, want %q", tc.text[ms[0].Start:ms[0].End], tok)
			}
		})
	}
}

func TestScanSecretsSecretGroup(t *testing.T) {
	rs := &secretRules{Rules: []secretRule{
		{ID: "explicit", Regex: `(a+)=(b+)`, SecretGroup: 2},
		{ID: "first", Regex: `(?:x=)(c+)`},
		{ID: "whole", Regex: `d+`},
	}}
	for _, tc := range []struct{ text, want string }{
		{"aa=bbb", "gitleaks/explicit:bbb"},
		{"x=cc", "gitleaks/first:cc"},
		{"ddd", "gitleaks/whole:ddd"},
	} {
		var got []string
		for _, m := range scanSecrets(tc.text, rs) {
			got = append(got, m.Rule+":"+tc.text[m.Start:m.End])
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%q: got %v, want [%s]", tc.text, got, tc.want)
		}
	}
}

func TestSecretKeywordPrefilter(t *testing.T) {
	rs := &secretRules{Rules: []secretRule{{ID: "t", Regex: `bar[0-9]+`, Keywords: []string{"foo"}}}}
	if ms := scanSecrets("bar123", rs); len(ms) != 0 {
		t.Errorf("without the keyword: got %v, want none", ms)
	}
	if ms := scanSecrets("foo bar123", rs); len(ms) != 1 {
		t.Errorf("with the keyword: got %v, want one match", ms)
	}
	if ms := scanSecrets("FOO bar123", rs); len(ms) != 1 {
		t.Errorf("with the keyword in upper case: got %v, want one match", ms)
	}
}

func TestSecretsInValues(t *testing.T) {
	tok := "ghp" + "_" + strings.Repeat("a1B2c3D4e", 4)
	ms := Values{}.Find("export GH=" + tok)
	if len(ms) != 1 || ms[0].Rule != "gitleaks/github-pat" {
		t.Fatalf("got %v", ms)
	}
}

func TestSecretStopwordsLowercasedOnce(t *testing.T) {
	rs := &secretRules{
		Allowlists: []secretAllowlist{{Stopwords: []string{"ExAmPlE"}}},
		Rules:      []secretRule{{ID: "t", Allowlists: []secretAllowlist{{Stopwords: []string{"FOO", "Bar"}}}}},
	}
	rs.compile()
	if got := rs.Allowlists[0].stops; len(got) != 1 || got[0] != "example" {
		t.Errorf("global stops = %q, want [example]", got)
	}
	if got := rs.Rules[0].Allowlists[0].stops; len(got) != 2 || got[0] != "foo" || got[1] != "bar" {
		t.Errorf("rule stops = %q, want [foo bar]", got)
	}
	if got := rs.Rules[0].Allowlists[0].Stopwords; got[0] != "FOO" {
		t.Errorf("Stopwords were modified: %q", got)
	}
}
