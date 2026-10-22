package detect

import (
	"reflect"
	"strings"
	"testing"
)

func TestScanTables(t *testing.T) {
	psql := " id |   name   |   email\n" +
		"----+----------+------------\n" +
		"  1 | Jane Roe | jane@x.com\n" +
		"(1 row)\n"
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"csv", "id,name,email\n1,Jane Roe,jane@x.com\n", []string{"PERSON:Jane Roe", "EMAIL:jane@x.com"}},
		{"csv quoted cell", "id,name\n1,\"Roe, Jane\"\n", []string{"PERSON:Roe, Jane"}},
		{"tsv", "id\tname\n1\tJane Roe\n", []string{"PERSON:Jane Roe"}},
		{"semicolon", "id;email\n1;j@x.com\n", []string{"EMAIL:j@x.com"}},
		{"psql", psql, []string{"PERSON:Jane Roe", "EMAIL:jane@x.com"}},
		{"markdown", "| name | email |\n|---|---|\n| Jane | j@x.com |\n", []string{"PERSON:Jane", "EMAIL:j@x.com"}},
		{"utf-8 bom", "\xef\xbb\xbfname,email\nJane,j@x.com\n", []string{"PERSON:Jane", "EMAIL:j@x.com"}},
		{"no sensitive header", "id,plan\n1,pro\n", nil},
		{"empty and NULL cells", "name,email\nNULL,\n", nil},
		{"lowercase null", "name,email\nnull,j@x.com\n", []string{"EMAIL:j@x.com"}},
		{"header only", "name,email\n", nil},
		{"short row ends table", "name,email\nJane,j@x.com\nfoo\nBob,b@x.com\n", []string{"PERSON:Jane", "EMAIL:j@x.com"}},
		{"crlf", "name,email\r\nJane,j@x.com\r\n", []string{"PERSON:Jane", "EMAIL:j@x.com"}},
		{"quoted header", "\"name\",\"email\"\n\"Jane\",\"j@x.com\"\n", []string{"PERSON:Jane", "EMAIL:j@x.com"}},
		{"escaped quote stays in span", "name,id\n\"Jane \"\"JJ\"\" Roe\",1\n", []string{"PERSON:Jane \"\"JJ\"\" Roe"}},
		{"cells trimmed", "name , email\n Jane ,  j@x.com \n", []string{"PERSON:Jane", "EMAIL:j@x.com"}},
		{"no trailing newline", "name,email\nJane,j@x.com", []string{"PERSON:Jane", "EMAIL:j@x.com"}},
		{"new header ends table", "name,id\nJane,1\nemail,id,x\nj@x.com,2,3\n", []string{"PERSON:Jane", "EMAIL:j@x.com"}},
		{"blank line ends table", "name,id\nJane,1\n\nBob,2\n", []string{"PERSON:Jane"}},
		{"separator inside table", "| name | id |\n|---|---|\n| Jane | 1 |\n|---|---|\n| Bob | 2 |\n", []string{"PERSON:Jane", "PERSON:Bob"}},
		{"header with non identifier cell", "name,1abc\nJane,x\n", nil},
		{"single column", "name\nJane\n", nil},
		{"unclosed quote", "name,id\n\"Jane,1\n", nil},
		{"empty", "", nil},
		{"lone delimiters", ",\n|\n\t\n", nil},
		{"psql empty last value", " id | name | email\n----+------+------\n  1 | Jane | \n  2 | Bob | b@x.com\n(2 rows)\n", []string{"PERSON:Jane", "PERSON:Bob", "EMAIL:b@x.com"}},
		{"psql empty middle value", " id | email | name\n----+-------+------\n  1 | a@x.com | \n  2 | b@x.com | Bob\n", []string{"EMAIL:a@x.com", "EMAIL:b@x.com", "PERSON:Bob"}},
		{"markdown empty last cell", "| id | name |\n|---|---|\n| 1 | |\n", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if g := got(tt.text, scanTables(tt.text)); !reflect.DeepEqual(g, tt.want) {
				t.Errorf("scanTables(%q) = %q, want %q", tt.text, g, tt.want)
			}
		})
	}
}

func TestScanTablesMetadata(t *testing.T) {
	text := "id,Name,email\n1,Jane Roe,jane@x.com\n"
	ms := scanTables(text)
	if len(ms) != 2 {
		t.Fatalf("got %d matches, want 2", len(ms))
	}
	for i, want := range []struct {
		field string
		score float64
	}{{"Name", 0.7}, {"email", 0.9}} {
		m := ms[i]
		if m.Field != want.field || m.Score != want.score || m.Detector != "fieldname/table" {
			t.Errorf("match %d = %+v, want field %q score %v detector fieldname/table", i, m, want.field, want.score)
		}
	}
}

func TestScanTablesSpansAvoidCRAndQuotes(t *testing.T) {
	text := "name,email\r\n\"Jane\",j@x.com\r\n"
	for _, m := range scanTables(text) {
		if s := text[m.Start:m.End]; strings.ContainsAny(s, "\r\"") {
			t.Errorf("span %q contains CR or quote", s)
		}
	}
}

func TestScanTablesOddInputDoesNotPanic(t *testing.T) {
	for _, text := range []string{"\"", "\"\"\n\"", "|", "||\n||", "name,\"", "name,email\n\"", "name|email\n|\n||\n|||", "\r", "\r\n\r\n", "name,email\n,\n\"\",\"\"\n"} {
		ms := scanTables(text)
		for _, m := range ms {
			if m.Start < 0 || m.End > len(text) || m.Start >= m.End {
				t.Errorf("scanTables(%q): bad span %+v", text, m)
			}
		}
	}
}
