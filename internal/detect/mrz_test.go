package detect

import (
	"fmt"
	"strings"
	"testing"
)

func TestMRZCheck(t *testing.T) {
	for _, tc := range []struct {
		field string
		want  int
	}{
		{"L898902C3", 6},
		{"740812", 2},
		{"120415", 9},
	} {
		if got := mrzCheck(tc.field); got != tc.want {
			t.Errorf("mrzCheck(%q) = %d, want %d", tc.field, got, tc.want)
		}
	}
}

func TestFindMRZ(t *testing.T) {
	const (
		line1    = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
		line2    = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
		specimen = line1 + "\n" + line2
	)
	filler := strings.Repeat("<", 44)
	for _, tc := range []struct {
		name  string
		input string
		want  string // Rule@Score:value, or "" for none
	}{
		{"specimen", specimen, "mrz/td3@0.95:" + specimen},
		{"embedded", "Passport scan:\n" + specimen + "\nend of page\n", "mrz/td3@0.95:" + specimen},
		{"crlf", line1 + "\r\n" + line2 + "\r\n", "mrz/td3@0.95:" + line1 + "\r\n" + line2},
		{"trailing spaces", line1 + "  \n" + line2 + "   \n", "mrz/td3@0.95:" + line1 + "  \n" + line2},
		{"indented by spaces", "    " + line1 + "\n    " + line2, "mrz/td3@0.95:" + line1 + "\n    " + line2},
		{"indented by tabs", "\t" + line1 + "\n\t" + line2 + "\t", "mrz/td3@0.95:" + line1 + "\n\t" + line2},
		{"composite fails", line1 + "\n" + line2[:43] + "1", ""},
		{"document check fails", line1 + "\nL898902C37" + line2[10:], ""},
		{"dob check fails", line1 + "\n" + line2[:19] + "3" + line2[20:], ""},
		{"expiry check fails", line1 + "\n" + line2[:27] + "8" + line2[28:], ""},
		{"check digit is <", line1 + "\n" + line2[:43] + "<", ""},
		{"line 1 not P", "X" + line1[1:] + "\n" + line2, ""},
		{"filler lines", filler + "\n" + filler, ""},
		{"one line", line2, ""},
		{"line 1 too short", line1[:43] + "\n" + line2, ""},
		{"line 2 too long", line1 + "\n" + line2 + "<", ""},
		{"lower case", line1 + "\n" + strings.ToLower(line2), ""},
		{"line 1 repeated", line1 + "\n" + line1 + "\n" + line2, "mrz/td3@0.95:" + line1 + "\n" + line2},
		{"two documents", specimen + "\n" + specimen, "mrz/td3@0.95:" + specimen + ",mrz/td3@0.95:" + specimen},
		{"second line first", line2 + "\n" + line1 + "\n" + line2, "mrz/td3@0.95:" + line1 + "\n" + line2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, m := range findMRZ(tc.input) {
				if m.Type != TypePassport || m.Detector != "value/mrz" {
					t.Errorf("match %+v: want type PASSPORT and detector value/mrz", m)
				}
				got = append(got, fmt.Sprintf("%s@%.2f:%s", m.Rule, m.Score, tc.input[m.Start:m.End]))
			}
			if g := strings.Join(got, ","); g != tc.want {
				t.Errorf("got %q, want %q", g, tc.want)
			}
		})
	}
}

func TestFindMRZIndentedSpanStartsAtP(t *testing.T) {
	const (
		line1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
		line2 = "L898902C36UTO7408122F1204159ZE184226B<<<<<10"
	)
	text := "    " + line1 + "\n    " + line2
	ms := findMRZ(text)
	if len(ms) != 1 {
		t.Fatalf("got %d matches, want 1", len(ms))
	}
	if ms[0].Start != 4 || text[ms[0].Start] != 'P' {
		t.Errorf("span starts at %d (%q), want 4 at 'P'", ms[0].Start, text[ms[0].Start])
	}
}

func TestFindMRZNoPanicOnOddInput(t *testing.T) {
	for _, in := range []string{"", "\n", "\r\n\r\n", "P", strings.Repeat("<", 44), strings.Repeat("<", 44) + "\n"} {
		findMRZ(in)
	}
}
