package detect

import (
	"reflect"
	"testing"
)

// got renders matches as "TYPE:value" for readable assertions.
func got(text string, ms []Match) []string {
	var out []string
	for _, m := range ms {
		out = append(out, string(m.Type)+":"+text[m.Start:m.End])
	}
	return out
}

func TestScanJSON(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"flat", `{"email": "a@x.com", "id": 7}`, []string{"EMAIL:a@x.com"}},
		{"skipped values", `{"email_verified": true, "phone": null, "name": ""}`, nil},
		{"number", `{"ssn": 123456789}`, []string{"SSN:123456789"}},
		{"array", `{"emails": ["a@x.com", "b@y.com"]}`, []string{"EMAIL:a@x.com", "EMAIL:b@y.com"}},
		{"inherited object with skip key",
			`{"address": {"line1": "1 Main St", "city": "Springfield", "file_name": "x.txt"}}`,
			[]string{"ADDRESS:1 Main St", "ADDRESS:Springfield"}},
		{"inner key overrides inheritance",
			`{"address": {"line1": "1 Main St", "email": "a@x.com"}}`,
			[]string{"ADDRESS:1 Main St", "EMAIL:a@x.com"}},
		{"json in log line", `2026-10-22 INFO user={"name":"Jane Roe","plan":"pro"}`, []string{"PERSON:Jane Roe"}},
		{"ndjson", "{\"name\":\"Jane Roe\"}\n{\"name\":\"Bob Poe\"}", []string{"PERSON:Jane Roe", "PERSON:Bob Poe"}},
		{"truncated", `{"name": "Jane Ro`, []string{"PERSON:Jane Ro"}},
		{"escaped quotes raw", `{"name": "Jane \"JR\" Roe"}`, []string{`PERSON:Jane \"JR\" Roe`}},
		{"multibyte", `{"name": "Zoë Ångström"}`, []string{"PERSON:Zoë Ångström"}},
		{"key lookalike inside string", `{"note": "use \"email\": here", "id": 1}`, nil},
		{"newline ends string", "{\"note\": \"abc\n\"email\": \"a@x.com\"}", []string{"EMAIL:a@x.com"}},
		{"stray closers", `{"user": {"name": "Jane"}}]]}`, []string{"PERSON:Jane"}},
		{"only closers", `]}"`, nil},
		{"key then eof", `{"name":`, nil},
		{"pretty printed", "{\n  \"email\"\n  :\n  \"a@x.com\"\n}", []string{"EMAIL:a@x.com"}},
		{"unterminated stops at newline", "{\"name\": \"Jane\n}", []string{"PERSON:Jane"}},
		{"sibling after container is not inherited", `{"address": {"x": "y"}, "id": "z"}`, []string{"ADDRESS:y"}},
		{"nested array of objects", `{"phones": [{"number": "1"}, {"tel": "555-0100"}]}`, []string{"PHONE:1", "PHONE:555-0100"}},
		{"cut string in open container resets the stack",
			"{\"emails\": [\"a@x.com\", \"b@\n{\"id\": 1, \"plan\": \"pro\"}\n2026-10-22 INFO started id=1\n",
			[]string{"EMAIL:a@x.com", "EMAIL:b@"}},
		{"cut string then plain log line", "{\"emails\": [\"a@x.com\", \"b@\n2026-10-22 INFO x=1 \"pro\"\n",
			[]string{"EMAIL:a@x.com", "EMAIL:b@"}},
		{"cut string at eof resets nothing visible", `{"emails": ["a@x.com", "b@`, []string{"EMAIL:a@x.com", "EMAIL:b@"}},
		{"cut string then own sensitive key", "{\"emails\": [\"b@\n  \"name\": \"Jane\"}\n",
			[]string{"EMAIL:b@", "PERSON:Jane"}},
		{"column 0 opener resets after a cut outside a string",
			"{\"emails\": [\"a@x.com\"\n{\"id\": 1, \"plan\": \"pro\"}\n",
			[]string{"EMAIL:a@x.com"}},
		{"column 0 array opener resets", "{\"emails\": [\"a@x.com\"\n[1, \"x\"]\n", []string{"EMAIL:a@x.com"}},
		{"column 0 opener drops a dangling key", "{\"email\":\n{\"id\": 1}\n", nil},
		{"indented opener keeps the context", "{\"emails\": [\n  [\"a@x.com\"]\n]}", []string{"EMAIL:a@x.com"}},
		{"crlf excluded from unterminated string", "{\"name\": \"Jane\r\n", []string{"PERSON:Jane"}},
		{"number at end of input", `{"ssn": 123`, []string{"SSN:123"}},
		{"escaped backslash before closing quote", `{"name": "a\\"}`, []string{`PERSON:a\\`}},
		{"notebook cells are not phones", `{"cells": [{"source": ["x = 1"]}]}`, nil},
		{"negative and exponent number", `{"ssn": -1.5e+3}`, []string{"SSN:-1.5e+3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := got(tt.in, scanJSON(tt.in))
			if !reflect.DeepEqual(g, tt.want) {
				t.Errorf("scanJSON(%q) = %q, want %q", tt.in, g, tt.want)
			}
		})
	}
}

func TestScanJSONMatchFields(t *testing.T) {
	in := `{"address": {"line1": "1 Main St", "email": "a@x.com"}}`
	ms := scanJSON(in)
	if len(ms) != 2 {
		t.Fatalf("got %d matches, want 2: %q", len(ms), got(in, ms))
	}
	if m := ms[0]; m.Score != 0.7 || m.Field != "address" || m.Detector != "fieldname/json" || m.Type != TypeAddress {
		t.Errorf("inherited match = %+v", m)
	}
	if m := ms[1]; m.Score != 0.9 || m.Field != "email" || m.Type != TypeEmail {
		t.Errorf("override match = %+v", m)
	}
}

func TestScanJSONUnterminatedEnd(t *testing.T) {
	in := "{\"name\": \"Jane\n}"
	ms := scanJSON(in)
	if len(ms) != 1 || ms[0].End != 14 || in[ms[0].End] != '\n' {
		t.Errorf("End = %+v, want index of the newline", ms)
	}
	in = `{"name": "Jane`
	ms = scanJSON(in)
	if len(ms) != 1 || ms[0].End != len(in) {
		t.Errorf("End = %+v, want len(text)", ms)
	}
}
