package detect

// ibanLengths maps an IBAN country code to the total length of an IBAN of that
// country. Source: the SWIFT IBAN Registry, TXT release 99 ("IBAN length" row,
// 89 countries), from the copy kept as a test resource by Apache Commons
// Validator:
// https://github.com/apache/commons-validator/blob/2c1898f65ed46aa5c0f340f63b5e1f4a8b86e4f0/src/test/resources/org/apache/commons/validator/routines/iban_registry_v99.txt
// (swift.com refuses automated downloads). Cross-checked against python-stdnum's
// stdnum/iban.dat, generated from registry release 101 (commit 6070c60af5,
// 2026-01-04): the same 89 countries and lengths. The lengths are not typed by
// hand: regenerate them from a newer registry release rather than editing them.
var ibanLengths = map[string]int{
	"AD": 24, // Andorra
	"AE": 23, // United Arab Emirates (The)
	"AL": 28, // Albania
	"AT": 20, // Austria
	"AZ": 28, // Azerbaijan
	"BA": 20, // Bosnia and Herzegovina
	"BE": 16, // Belgium
	"BG": 22, // Bulgaria
	"BH": 22, // Bahrain
	"BI": 27, // Burundi
	"BR": 29, // Brazil
	"BY": 28, // Republic of Belarus
	"CH": 21, // Switzerland
	"CR": 22, // Costa Rica
	"CY": 28, // Cyprus
	"CZ": 24, // Czechia
	"DE": 22, // Germany
	"DJ": 27, // Djibouti
	"DK": 18, // Denmark
	"DO": 28, // Dominican Republic
	"EE": 20, // Estonia
	"EG": 29, // Egypt
	"ES": 24, // Spain
	"FI": 18, // Finland
	"FK": 18, // Falkland Islands
	"FO": 18, // Faroe Islands
	"FR": 27, // France
	"GB": 22, // United Kingdom
	"GE": 22, // Georgia
	"GI": 23, // Gibraltar
	"GL": 18, // Greenland
	"GR": 27, // Greece
	"GT": 28, // Guatemala
	"HN": 28, // Honduras
	"HR": 21, // Croatia
	"HU": 28, // Hungary
	"IE": 22, // Ireland
	"IL": 23, // Israel
	"IQ": 23, // Iraq
	"IS": 26, // Iceland
	"IT": 27, // Italy
	"JO": 30, // Jordan
	"KW": 30, // Kuwait
	"KZ": 20, // Kazakhstan
	"LB": 28, // Lebanon
	"LC": 32, // Saint Lucia
	"LI": 21, // Liechtenstein
	"LT": 20, // Lithuania
	"LU": 20, // Luxembourg
	"LV": 21, // Latvia
	"LY": 25, // Libya
	"MC": 27, // Monaco
	"MD": 24, // Moldova
	"ME": 22, // Montenegro
	"MK": 19, // Macedonia
	"MN": 20, // Mongolia
	"MR": 27, // Mauritania
	"MT": 31, // Malta
	"MU": 30, // Mauritius
	"NI": 28, // Nicaragua
	"NL": 18, // Netherlands (The)
	"NO": 15, // Norway
	"OM": 23, // Oman
	"PK": 24, // Pakistan
	"PL": 28, // Poland
	"PS": 29, // "Palestine, State of"
	"PT": 25, // Portugal
	"QA": 29, // Qatar
	"RO": 24, // Romania
	"RS": 22, // Serbia
	"RU": 33, // Russia
	"SA": 24, // Saudi Arabia
	"SC": 31, // Seychelles
	"SD": 18, // Sudan
	"SE": 24, // Sweden
	"SI": 19, // Slovenia
	"SK": 24, // Slovakia
	"SM": 27, // San Marino
	"SO": 23, // Somalia
	"ST": 25, // Sao Tome and Principe
	"SV": 28, // El Salvador
	"TL": 23, // Timor-Leste
	"TN": 24, // Tunisia
	"TR": 26, // Turkey
	"UA": 29, // Ukraine
	"VA": 22, // Vatican City State
	"VG": 24, // Virgin Islands
	"XK": 20, // Kosovo
	"YE": 30, // Yemen
}
