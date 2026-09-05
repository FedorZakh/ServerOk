package whois

// whois_test.go — разбор пользовательского ввода и свободного текста WHOIS.
// Оба места работают с тем, что пришло снаружи: строка от человека и ответ
// чужого сервера, — поэтому проверяются на реальных, а не удобных примерах.

import (
	"strings"
	"testing"
	"time"
)

// Normalize обязан вытащить домен из всего, что люди вставляют в ответ на
// вопрос, и отказать всему, что доменом не является: имя уходит и в URL, и в
// запрос на порт 43.
func TestNormalize(t *testing.T) {
	ok := []struct{ in, want string }{
		{"example.com", "example.com"},
		{"  Example.COM  ", "example.com"},
		{"https://www.example.com/path?q=1#frag", "example.com"},
		{"http://example.com:8080/", "example.com"},
		{"user@example.com", "example.com"},
		{"example.com.", "example.com"},
		{"sub.example.co.uk", "sub.example.co.uk"},
		{"пример.рф", "xn--e1afmkfd.xn--p1ai"},
	}
	for _, c := range ok {
		got, _, err := Normalize(c.in)
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// IDN сохраняет исходное написание — оно печатается рядом с punycode.
	if _, unicodeName, _ := Normalize("пример.рф"); unicodeName != "пример.рф" {
		t.Errorf("unicode name lost: %q", unicodeName)
	}

	bad := []string{"", "   ", "com", "локалхост", "example .com", "-example.com", "example-.com", "8.8.8.8", "exa mple.com"}
	for _, in := range bad {
		if got, _, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want an error", in, got)
		}
	}
}

// Ответ реестра gTLD в шаблоне ICANN — основной случай.
const comRecord = `
   Domain Name: EXAMPLE.COM
   Registrar WHOIS Server: whois.example-registrar.com
   Registrar URL: http://www.example-registrar.com
   Updated Date: 2024-08-14T07:01:44Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2027-08-13T04:00:00Z
   Registrar: Example Registrar, LLC
   Registrar IANA ID: 376
   Registrar Abuse Contact Email: abuse@example-registrar.com
   Registrar Abuse Contact Phone: +1.5555550100
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
   Registrant Organization: Example Holdings
   Registrant Country: US
   Registrant Email: REDACTED FOR PRIVACY
   Admin Email: https://example-registrar.com/contact
>>> Last update of whois database: 2026-09-05T10:00:00Z <<<
`

func TestParseRawGTLD(t *testing.T) {
	d := parseRaw(comRecord)
	if d.Available {
		t.Error("a full record must not be read as an available domain")
	}
	if d.Registrar == nil || d.Registrar.Name != "Example Registrar, LLC" || d.Registrar.IANAID != "376" {
		t.Fatalf("registrar not parsed: %+v", d.Registrar)
	}
	if d.Registrar.AbuseEmail != "abuse@example-registrar.com" || d.Registrar.AbusePhone != "+1.5555550100" {
		t.Errorf("abuse contact not parsed: %+v", d.Registrar)
	}
	if d.Registrar.WhoisServer != "whois.example-registrar.com" {
		t.Errorf("registrar whois server = %q", d.Registrar.WhoisServer)
	}
	if d.Registered != "1995-08-14" || d.Expires != "2027-08-13" || d.Updated != "2024-08-14" {
		t.Errorf("dates: registered=%q expires=%q updated=%q", d.Registered, d.Expires, d.Updated)
	}
	// Ссылка на описание статуса не должна попадать в сам статус.
	if len(d.Status) != 2 || d.Status[0] != "clientTransferProhibited" {
		t.Errorf("status = %v", d.Status)
	}
	if strings.Join(d.NameServers, ",") != "a.iana-servers.net,b.iana-servers.net" {
		t.Errorf("name servers = %v", d.NameServers)
	}
	if d.DNSSEC != "signedDelegation" {
		t.Errorf("dnssec = %q", d.DNSSEC)
	}
	var registrant, admin bool
	for _, c := range d.Contacts {
		switch c.Role {
		case "registrant":
			registrant = true
			if c.Org != "Example Holdings" || c.Country != "US" {
				t.Errorf("registrant = %+v", c)
			}
			// «REDACTED FOR PRIVACY» — заглушка, а не адрес.
			if c.Email != "" {
				t.Errorf("redacted email leaked into the report: %q", c.Email)
			}
		case "admin":
			admin = true
			if c.Web != "https://example-registrar.com/contact" || c.Email != "" {
				t.Errorf("a contact form must not become an e-mail: %+v", c)
			}
		}
	}
	if !registrant || !admin {
		t.Errorf("contacts not parsed: %+v", d.Contacts)
	}
}

// Ответ .ru устроен иначе: свои подписи полей, статусы через запятую и адрес
// сервера имён в одной строке с его именем.
const ruRecord = `% TCI Whois Service. Terms of use:
% https://tcinet.ru/documents/whois_ru_rf.pdf (in Russian)

domain:        EXAMPLE.RU
nserver:       ns1.example.ru. 192.0.2.1, 2001:db8::1
state:         REGISTERED, DELEGATED, VERIFIED
org:           Example LLC
registrar:     RU-CENTER-RU
admin-contact: https://www.nic.ru/whois
created:       1997-09-23T09:45:07Z
paid-till:     2027-09-30T21:00:00Z
source:        TCI
`

func TestParseRawCCTLD(t *testing.T) {
	d := parseRaw(ruRecord)
	if d.Registrar == nil || d.Registrar.Name != "RU-CENTER-RU" {
		t.Fatalf("registrar not parsed: %+v", d.Registrar)
	}
	if d.Registered != "1997-09-23" || d.Expires != "2027-09-30" {
		t.Errorf("dates: registered=%q expires=%q", d.Registered, d.Expires)
	}
	if strings.Join(d.Status, "|") != "REGISTERED|DELEGATED|VERIFIED" {
		t.Errorf("status = %v", d.Status)
	}
	// В строке nserver после имени идёт ещё и адрес — в отчёт идёт только имя.
	if len(d.NameServers) != 1 || d.NameServers[0] != "ns1.example.ru" {
		t.Errorf("name servers = %v", d.NameServers)
	}
	if len(d.Contacts) == 0 || d.Contacts[0].Org != "Example LLC" {
		t.Errorf("registrant not parsed: %+v", d.Contacts)
	}
	// Комментарии реестра (строки с %) не должны разбираться как поля.
	if d.Updated != "" {
		t.Errorf("updated = %q, want empty", d.Updated)
	}
}

// Свободный домен — это ответ, а не сбой: тест обязан отличать его от записи.
func TestParseRawAvailable(t *testing.T) {
	for _, raw := range []string{
		"No match for \"NOSUCHDOMAIN.COM\".",
		"NOT FOUND\n",
		"%% No entries found in the AFNIC Database.",
	} {
		if d := parseRaw(raw); !d.Available {
			t.Errorf("%q must be read as an available domain", raw)
		}
	}
	if d := parseRaw(comRecord); d.Available {
		t.Error("a registered domain reported as available")
	}
}

// Даты в WHOIS записаны десятком разных способов, а в отчёте нужен один.
func TestNormalizeDate(t *testing.T) {
	cases := map[string]string{
		"2007-10-09T18:20:50Z":      "2007-10-09",
		"2007-10-09 18:20:50":       "2007-10-09",
		"2007-10-09":                "2007-10-09",
		"09-Oct-2007":               "2007-10-09",
		"2007.10.09":                "2007-10-09",
		"09.10.2007":                "2007-10-09",
		"20071009":                  "2007-10-09",
		"whenever the mood strikes": "whenever the mood strikes",
	}
	for in, want := range cases {
		if got := normalizeDate(in); got != want {
			t.Errorf("normalizeDate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDaysUntil(t *testing.T) {
	future := time.Now().AddDate(0, 0, 10).Format("2006-01-02")
	if d := daysUntil(future); d < 8 || d > 10 {
		t.Errorf("daysUntil(+10d) = %d", d)
	}
	past := time.Now().AddDate(0, 0, -5).Format("2006-01-02")
	if d := daysUntil(past); d > -4 || d < -6 {
		t.Errorf("daysUntil(-5d) = %d", d)
	}
	if d := daysUntil("not a date"); d != 0 {
		t.Errorf("daysUntil(garbage) = %d, want 0", d)
	}
}
