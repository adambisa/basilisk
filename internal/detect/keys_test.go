package detect

import (
	"reflect"
	"testing"
)

func TestSplitWords(t *testing.T) {
	cases := map[string][]string{
		"customerEmail":   {"customer", "email"},
		"SSNNumber":       {"ssn", "number"},
		"address2":        {"address", "2"},
		"HOME-PHONE":      {"home", "phone"},
		"billing_address": {"billing", "address"},
		"userID":          {"user", "id"},
		"XMLHttpRequest":  {"xml", "http", "request"},
		"e-mail":          {"e", "mail"},
		"":                nil,
	}
	for in, want := range cases {
		if got := splitWords(in); !reflect.DeepEqual(got, want) {
			t.Errorf("splitWords(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		key   string
		typ   EntityType
		score float64
		ok    bool
	}{
		{"customerEmail", TypeEmail, 0.9, true},
		{"emailAddress", TypeEmail, 0.9, true},
		{"e-mail", TypeEmail, 0.9, true},
		{"SSNNumber", TypeSSN, 0.95, true}, // filler fallback
		{"account_number", TypeBankAccount, 0.9, true},
		{"address_line_2", TypeAddress, 0.7, true},
		{"addresses", TypeAddress, 0.7, true},
		{"city", TypeAddress, 0.5, true},
		{"HOME-PHONE", TypePhone, 0.9, true},
		{"cells", "", 0, false},
		{"cell", "", 0, false},
		{"cellphone", TypePhone, 0.9, true},
		{"cell_phone", TypePhone, 0.9, true},
		{"cellPhone", TypePhone, 0.9, true},
		{"firstName", TypePerson, 0.7, true},
		{"display_name", TypePerson, 0.7, true},
		{"userName", TypeUsername, 0.6, true},
		{"password", TypeSecret, 0.9, true},
		{"email_verified", "", 0, false},
		{"file_name", "", 0, false},
		{"filename", "", 0, false},
		{"mac_address", "", 0, false},
		{"state", "", 0, false},
		{"password_hash", "", 0, false},
		{"", "", 0, false},
	}
	for _, c := range cases {
		typ, score, ok := Classify(c.key)
		if typ != c.typ || score != c.score || ok != c.ok {
			t.Errorf("Classify(%q) = (%q, %v, %v), want (%q, %v, %v)",
				c.key, typ, score, ok, c.typ, c.score, c.ok)
		}
	}
}

func TestLookup(t *testing.T) {
	r, found := lookup("file_name")
	if !found || !r.skip {
		t.Errorf("lookup(file_name) = (%+v, %v), want found skip rule", r, found)
	}
	if r, found := lookup("line1"); found {
		t.Errorf("lookup(line1) = (%+v, true), want not found", r)
	}
	r, found = lookup("customerEmail")
	if !found || r.skip || r.typ != TypeEmail || r.score != 0.9 {
		t.Errorf("lookup(customerEmail) = (%+v, %v), want EMAIL 0.9", r, found)
	}
}
