package detect

import "strings"

// rule is what a field-name keyword maps to: an entity type with a score, or
// a skip marker for names that look sensitive but are not (file_name).
type rule struct {
	typ   EntityType
	score float64
	skip  bool
}

// keywords maps a space-joined word sequence to its rule. It is the en-US
// keyword table from docs/specs/2026-10-22-field-names.md.
var keywords = buildKeywords()

func buildKeywords() map[string]rule {
	m := make(map[string]rule)
	add := func(typ EntityType, score float64, skip bool, seqs string) {
		for _, seq := range strings.Split(seqs, ", ") {
			m[seq] = rule{typ: typ, score: score, skip: skip}
		}
	}
	add(TypeSSN, 0.95, false, "ssn, social security, social security number")
	add(TypeITIN, 0.95, false, "itin")
	add(TypeEIN, 0.9, false, "ein, employer identification number")
	add(TypePassport, 0.9, false, "passport, passport number, passport no")
	add(TypeDriverLicense, 0.9, false, "driver license, drivers license, driving license, dl number")
	add(TypeMedicare, 0.9, false, "medicare number, mbi")
	add(TypeCard, 0.95, false, "card number, credit card, credit card number, cc number, cvv, cvc")
	add(TypeBankAccount, 0.9, false, "account number, acct number, iban")
	add(TypeRoutingNumber, 0.9, false, "routing number, aba")
	add(TypeSecret, 0.9, false, "password, passwd, pwd, secret, client secret, api key, apikey, access token, auth token, refresh token, token, private key, credential")
	add(TypeEmail, 0.9, false, "email, e mail, email address")
	add(TypePhone, 0.9, false, "phone, phone number, telephone, tel, mobile, cell phone, cellphone, fax")
	add(TypeDOB, 0.9, false, "dob, birthdate, birth date, date of birth, birthday")
	add(TypeIPAddress, 0.6, false, "ip, ip address, ipaddr")
	add(TypePerson, 0.7, false, "name, firstname, lastname, fullname, surname, given name, family name, middle name, maiden name")
	add(TypeUsername, 0.6, false, "username, user name, screen name")
	add(TypeAddress, 0.7, false, "address, street, street address, address line, zip, zipcode, zip code, postal code, postcode")
	add(TypeAddress, 0.5, false, "city")
	add("", 0, true, "file name, host name, server name, domain name, table name, column name, field name, class name, type name, key name, bucket name, branch name, repo name, image name, package name, module name, function name, method name, event name, tag name, app name, project name, product name, service name, device name, queue name, topic name, index name, cluster name, region name, node name, param name, variable name, env name, dir name, folder name, path name, model name, brand name, category name, role name, plan name, template name, feature name, metric name, label name, company name, org name, organization name, business name, secret name, mac address, wallet address, memory address, web address, server address")
	return m
}

// fillers are trailing words dropped when nothing else matched.
var fillers = map[string]bool{"number": true, "num": true, "no": true, "nr": true}

// Classify reports whether a field name (a JSON key or table header) names
// sensitive data, and if so which entity type and with what score. Names
// that map to a skip rule, and names that match nothing, return false.
func Classify(key string) (EntityType, float64, bool) {
	r, found := lookup(key)
	if !found || r.skip {
		return "", 0, false
	}
	return r.typ, r.score, true
}

// lookup runs the keyword matching for key. The bool is true for any table
// hit, skip rows included, so callers can tell a skip key from an unknown one.
func lookup(key string) (rule, bool) {
	words := splitWords(key)
	for len(words) > 0 && isDigits(words[len(words)-1]) {
		words = words[:len(words)-1]
	}
	if len(words) == 0 {
		return rule{}, false
	}
	words[len(words)-1] = singular(words[len(words)-1])

	if r, ok := longestSuffix(words); ok {
		return r, true
	}
	n := len(words)
	for n > 0 && fillers[words[n-1]] {
		n--
	}
	if n < len(words) && n > 0 {
		return longestSuffix(words[:n])
	}
	return rule{}, false
}

// longestSuffix finds the longest word sequence ending the key that is in the
// keyword table.
func longestSuffix(words []string) (rule, bool) {
	for i := range words {
		if r, ok := keywords[strings.Join(words[i:], " ")]; ok {
			return r, true
		}
	}
	return rule{}, false
}

// singular reduces a plural word: addresses to address, emails to email.
func singular(w string) string {
	if strings.HasSuffix(w, "sses") {
		return w[:len(w)-2]
	}
	if len(w) > 3 && strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss") {
		return w[:len(w)-1]
	}
	return w
}

func isDigits(w string) bool {
	for i := 0; i < len(w); i++ {
		if !isDigit(w[i]) {
			return false
		}
	}
	return w != ""
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }

// splitWords breaks a field name into lower-case words. It splits on any
// non-alphanumeric byte, on lower-to-upper changes (customerEmail), before the
// last capital of an acronym followed by lower case (SSNNumber), and on
// letter-to-digit changes (address2).
func splitWords(key string) []string {
	var words []string
	start := -1 // start of the current word, -1 when between words
	flush := func(end int) {
		if start >= 0 {
			words = append(words, strings.ToLower(key[start:end]))
			start = -1
		}
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !isDigit(c) && !isUpper(c) && !isLower(c) {
			flush(i)
			continue
		}
		if start >= 0 {
			p := key[i-1]
			switch {
			case isDigit(c) != isDigit(p):
				flush(i)
			case isUpper(c) && isLower(p):
				flush(i)
			case isUpper(c) && isUpper(p) && i+1 < len(key) && isLower(key[i+1]):
				flush(i)
			}
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(key))
	return words
}
