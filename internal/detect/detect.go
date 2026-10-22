// Package detect finds PII and secrets in text.
package detect

// EntityType names a kind of sensitive data.
type EntityType string

// The entity types detectors can report.
const (
	TypeSSN           EntityType = "SSN"
	TypeITIN          EntityType = "ITIN"
	TypeEIN           EntityType = "EIN"
	TypePassport      EntityType = "PASSPORT"
	TypeDriverLicense EntityType = "DRIVER_LICENSE"
	TypeMedicare      EntityType = "MEDICARE"
	TypeCard          EntityType = "CARD"
	TypeBankAccount   EntityType = "BANK_ACCOUNT"
	TypeRoutingNumber EntityType = "ROUTING_NUMBER"
	TypeSecret        EntityType = "SECRET"
	TypeEmail         EntityType = "EMAIL"
	TypePhone         EntityType = "PHONE"
	TypeDOB           EntityType = "DOB"
	TypeIPAddress     EntityType = "IP_ADDRESS"
	TypePerson        EntityType = "PERSON"
	TypeUsername      EntityType = "USERNAME"
	TypeAddress       EntityType = "ADDRESS"
)

// Match is one piece of sensitive data found in a text.
type Match struct {
	Type     EntityType
	Start    int     // byte offset of the value, inclusive
	End      int     // byte offset of the value, exclusive
	Score    float64 // confidence, 0..1
	Detector string  // which detector found it, e.g. "fieldname/json"
	Field    string  // the key or header that triggered the match, if any
}

// Detector finds sensitive data in a text. Spans in the returned matches are
// byte offsets into text.
type Detector interface {
	Find(text string) []Match
}
