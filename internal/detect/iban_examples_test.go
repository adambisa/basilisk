package detect

// ibanExamples are the "IBAN electronic format example" entries of the SWIFT
// IBAN Registry, TXT release 99 (the same source as ibanLengths), one per
// country. Test data only.
var ibanExamples = []string{
	"AD1200012030200359100100",          // Andorra
	"AE070331234567890123456",           // United Arab Emirates (The)
	"AL47212110090000000235698741",      // Albania
	"AT611904300234573201",              // Austria
	"AZ21NABZ00000000137010001944",      // Azerbaijan
	"BA391290079401028494",              // Bosnia and Herzegovina
	"BE68539007547034",                  // Belgium
	"BG80BNBG96611020345678",            // Bulgaria
	"BH67BMAG00001299123456",            // Bahrain
	"BI4210000100010000332045181",       // Burundi
	"BR1800360305000010009795493C1",     // Brazil
	"BY13NBRB3600900000002Z00AB00",      // Republic of Belarus
	"CH9300762011623852957",             // Switzerland
	"CR05015202001026284066",            // Costa Rica
	"CY17002001280000001200527600",      // Cyprus
	"CZ6508000000192000145399",          // Czechia
	"DE89370400440532013000",            // Germany
	"DJ2100010000000154000100186",       // Djibouti
	"DK5000400440116243",                // Denmark
	"DO28BAGR00000001212453611324",      // Dominican Republic
	"EE382200221020145685",              // Estonia
	"EG380019000500000000263180002",     // Egypt
	"ES9121000418450200051332",          // Spain
	"FI2112345600000785",                // Finland
	"FK88SC123456789012",                // Falkland Islands
	"FO6264600001631634",                // Faroe Islands
	"FR1420041010050500013M02606",       // France
	"GB29NWBK60161331926819",            // United Kingdom
	"GE29NB0000000101904917",            // Georgia
	"GI75NWBK000000007099453",           // Gibraltar
	"GL8964710001000206",                // Greenland
	"GR1601101250000000012300695",       // Greece
	"GT82TRAJ01020000001210029690",      // Guatemala
	"HN88CABF00000000000250005469",      // Honduras
	"HR1210010051863000160",             // Croatia
	"HU42117730161111101800000000",      // Hungary
	"IE29AIBK93115212345678",            // Ireland
	"IL620108000000099999999",           // Israel
	"IQ98NBIQ850123456789012",           // Iraq
	"IS140159260076545510730339",        // Iceland
	"IT60X0542811101000000123456",       // Italy
	"JO94CBJO0010000000000131000302",    // Jordan
	"KW81CBKU0000000000001234560101",    // Kuwait
	"KZ86125KZT5004100100",              // Kazakhstan
	"LB62099900000001001901229114",      // Lebanon
	"LC55HEMM000100010012001200023015",  // Saint Lucia
	"LI21088100002324013AA",             // Liechtenstein
	"LT121000011101001000",              // Lithuania
	"LU280019400644750000",              // Luxembourg
	"LV80BANK0000435195001",             // Latvia
	"LY83002048000020100120361",         // Libya
	"MC5811222000010123456789030",       // Monaco
	"MD24AG000225100013104168",          // Moldova
	"ME25505000012345678951",            // Montenegro
	"MK07250120000058984",               // Macedonia
	"MN121234123456789123",              // Mongolia
	"MR1300020001010000123456753",       // Mauritania
	"MT84MALT011000012345MTLCAST001S",   // Malta
	"MU17BOMM0101101030300200000MUR",    // Mauritius
	"NI45BAPR00000013000003558124",      // Nicaragua
	"NL91ABNA0417164300",                // Netherlands (The)
	"NO9386011117947",                   // Norway
	"OM810180000001299123456",           // Oman
	"PK36SCBL0000001123456702",          // Pakistan
	"PL61109010140000071219812874",      // Poland
	"PS92PALS000000000400123456702",     // "Palestine, State of"
	"PT50000201231234567890154",         // Portugal
	"QA58DOHB00001234567890ABCDEFG",     // Qatar
	"RO49AAAA1B31007593840000",          // Romania
	"RS35260005601001611379",            // Serbia
	"RU0304452522540817810538091310419", // Russia
	"SA0380000000608010167519",          // Saudi Arabia
	"SC18SSCB11010000000000001497USD",   // Seychelles
	"SD2129010501234001",                // Sudan
	"SE4550000000058398257466",          // Sweden
	"SI56263300012039086",               // Slovenia
	"SK3112000000198742637541",          // Slovakia
	"SM86U0322509800000000270100",       // San Marino
	"SO211000001001000100141",           // Somalia
	"ST23000100010051845310146",         // Sao Tome and Principe
	"SV62CENR00000000000000700025",      // El Salvador
	"TL380080012345678910157",           // Timor-Leste
	"TN5910006035183598478831",          // Tunisia
	"TR330006100519786457841326",        // Turkey
	"UA213223130000026007233566001",     // Ukraine
	"VA59001123000012345678",            // Vatican City State
	"VG96VPVG0000012345678901",          // Virgin Islands
	"XK051212012345678906",              // Kosovo
	"YE15CBYE0001018861234567891234",    // Yemen
}
