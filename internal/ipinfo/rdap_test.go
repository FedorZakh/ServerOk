package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rdap_test.go — разбор ответа RDAP на фикстуре, повторяющей реальный ответ
// RIPE (события, cidr0_cidrs, вложенные vCard, служебный объект -MNT).

const rdapSample = `{
  "handle": "203.0.113.0 - 203.0.113.255",
  "startAddress": "203.0.113.0",
  "endAddress": "203.0.113.255",
  "name": "EXAMPLE-NET",
  "type": "ASSIGNED PA",
  "country": "DE",
  "port43": "whois.ripe.net",
  "cidr0_cidrs": [{"v4prefix": "203.0.113.0", "length": 24}],
  "events": [
    {"eventAction": "registration", "eventDate": "2025-11-19T10:22:33Z"},
    {"eventAction": "last changed", "eventDate": "2025-12-25T08:00:00Z"}
  ],
  "remarks": [{"description": ["Example remark"]}],
  "entities": [
    {"handle": "EXAMPLE-MNT", "roles": ["registrant"],
     "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "EXAMPLE-MNT"]]]},
    {"handle": "ORG-EX1-RIPE", "roles": ["registrant"],
     "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Hosting Ltd"]]]},
    {"handle": "AB123-RIPE", "roles": ["abuse"],
     "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Abuse"],
       ["email", {}, "text", "abuse@example.net"], ["tel", {}, "text", "+49 555 1234"]]]}
  ]
}`

// Проверяем извлечение всех полей, которые попадают в отчёт, и фильтрацию
// служебных maintainer-объектов.
func TestLookupRDAPParsesRecord(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(rdapSample))
	}))
	defer srv.Close()

	old := rdapEndpoints
	rdapEndpoints = []struct {
		name string
		url  string
	}{{"test", srv.URL + "/ip/%s"}}
	defer func() { rdapEndpoints = old }()

	rec, err := LookupRDAP(context.Background(), "203.0.113.7")
	if err != nil {
		t.Fatalf("LookupRDAP: %v", err)
	}
	if rec.Name != "EXAMPLE-NET" || rec.Registry != "RIPE NCC" || rec.Type != "ASSIGNED PA" {
		t.Errorf("record = %+v", rec)
	}
	if len(rec.CIDR) != 1 || rec.CIDR[0] != "203.0.113.0/24" {
		t.Errorf("CIDR = %v", rec.CIDR)
	}
	if rec.Registered != "2025-11-19" || rec.Updated != "2025-12-25" {
		t.Errorf("dates = %q / %q", rec.Registered, rec.Updated)
	}
	if rec.Abuse == nil || rec.Abuse.Email != "abuse@example.net" {
		t.Errorf("abuse contact = %+v", rec.Abuse)
	}
	// Maintainer-объекты не несут сведений о владельце и должны отсеиваться.
	for _, e := range rec.Entities {
		if e.Handle == "EXAMPLE-MNT" {
			t.Errorf("maintainer entity leaked into the report: %+v", e)
		}
	}
	if len(rec.Entities) == 0 || rec.Entities[0].Name != "Example Hosting Ltd" {
		t.Errorf("entities = %+v", rec.Entities)
	}
}

// Адрес попадает в URL и в argv whois, поэтому некорректное значение не должно
// проходить дальше входа — и запрос с ним не должен уходить вовсе.
func TestLookupRDAPRejectsMalformedAddress(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte(rdapSample))
	}))
	defer srv.Close()

	old := rdapEndpoints
	rdapEndpoints = []struct {
		name string
		url  string
	}{{"test", srv.URL + "/ip/%s"}}
	defer func() { rdapEndpoints = old }()

	for _, bad := range []string{"-h attacker.example", "203.0.113.7/../../admin", "example.com", ""} {
		if _, err := LookupRDAP(context.Background(), bad); err == nil {
			t.Errorf("LookupRDAP accepted %q", bad)
		}
	}
	if called {
		t.Error("a request was issued for a malformed address")
	}
}
