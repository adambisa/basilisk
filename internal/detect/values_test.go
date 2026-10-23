package detect

import (
	"reflect"
	"strings"
	"testing"
)

func TestKeywordBefore(t *testing.T) {
	words := []string{"card", "cc"}
	tests := []struct {
		name string
		text string
		want bool
	}{
		{"keyword and colon", "card: 4111", true},
		{"case-insensitive", "CC 4111", true},
		{"not a whole word", "discard 4111", false},
		{"different line", "card\n4111", false},
		{"more than 32 bytes back", "card" + strings.Repeat(" ", 40) + "4111", false},
		{"no gap before the candidate", "card4111", false},
		{"word cut by the window start", "xcard" + strings.Repeat(" ", 27) + "4111", false},
		{"word at the window start", "card" + strings.Repeat(" ", 28) + "4111", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := strings.LastIndex(tt.text, "4111")
			if got := keywordBefore(tt.text, start, words); got != tt.want {
				t.Errorf("keywordBefore(%q, %d) = %v, want %v", tt.text, start, got, tt.want)
			}
		})
	}
}

func TestAtBoundary(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		start, end int
		want       bool
	}{
		{"letters on both sides", "x4111y", 1, 5, false},
		{"letter before only", "x4111 ", 1, 5, false},
		{"digit after only", " 41112", 1, 5, false},
		{"spaces around", " 4111 ", 1, 5, true},
		{"multibyte neighbour", "€4111", len("€"), len("€4111"), true},
		{"whole text", "4111", 0, 4, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := atBoundary(tt.text, tt.start, tt.end); got != tt.want {
				t.Errorf("atBoundary(%q, %d, %d) = %v, want %v", tt.text, tt.start, tt.end, got, tt.want)
			}
		})
	}
}

func TestAllEqualsFieldNamesWithoutValues(t *testing.T) {
	text := "name,email\nJane,j@x.com\n"
	got, want := All{}.Find(text), FieldNames{}.Find(text)
	if len(want) == 0 {
		t.Fatal("FieldNames found nothing")
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("All.Find = %v, want %v", got, want)
	}
}

func TestValuesRunsRegisteredFinders(t *testing.T) {
	saved := valueFinders
	t.Cleanup(func() { valueFinders = saved })
	valueFinders = []func(string) []Match{
		func(string) []Match { return []Match{{Type: TypeCard, Start: 5, End: 9, Score: .6, Rule: "a"}} },
		func(string) []Match { return []Match{{Type: TypeSecret, Start: 0, End: 7, Score: .9, Rule: "b"}} },
	}
	got := Values{}.Find("0123456789")
	want := []Match{{Type: TypeSecret, Start: 0, End: 9, Score: .9, Rule: "b"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Values.Find = %v, want %v", got, want)
	}
}
