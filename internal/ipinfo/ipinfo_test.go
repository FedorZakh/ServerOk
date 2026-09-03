package ipinfo

import (
	"encoding/json"
	"net"
	"testing"
)

// ipinfo_test.go — разбор данных, приходящих от внешних сервисов: строки ASN,
// обратная запись адреса для чёрных списков и визитки vCard из ответа RDAP.

func TestSplitAS(t *testing.T) {
	cases := []struct{ in, asn, name string }{
		{"AS212743 ETERNITY INTERNATIONAL LIMITED", "AS212743", "ETERNITY INTERNATIONAL LIMITED"},
		{"AS13335", "AS13335", ""},
		{"Hetzner Online GmbH", "", "Hetzner Online GmbH"},
		{"", "", ""},
	}
	for _, c := range cases {
		asn, name := splitAS(c.in)
		if asn != c.asn || name != c.name {
			t.Errorf("splitAS(%q) = %q, %q; want %q, %q", c.in, asn, name, c.asn, c.name)
		}
	}
}

func TestReverseIPv4(t *testing.T) {
	got := reverseIPv4(net.ParseIP("192.0.2.10").To4())
	if got != "10.2.0.192" {
		t.Errorf("reverseIPv4 = %q, want 10.2.0.192", got)
	}
}

// vCard — вложенные JSON-массивы, разбираемые вручную; тест фиксирует, что
// имя, почта, телефон и страна достаются из правильных позиций.
func TestParseVCard(t *testing.T) {
	raw := json.RawMessage(`["vcard",[["version",{},"text","4.0"],
		["fn",{},"text","Example Hosting Ltd"],
		["email",{},"text","abuse@example.net"],
		["tel",{},"text","+49 555 1234"],
		["adr",{"label":"x"},"text",["","","Street","City","","12345","Germany"]]]]`)
	name, email, phone, country := parseVCard(raw)
	if name != "Example Hosting Ltd" {
		t.Errorf("name = %q", name)
	}
	if email != "abuse@example.net" {
		t.Errorf("email = %q", email)
	}
	if phone != "+49 555 1234" {
		t.Errorf("phone = %q", phone)
	}
	if country != "Germany" {
		t.Errorf("country = %q", country)
	}
}

func TestShortDate(t *testing.T) {
	if got := shortDate("2025-11-19T10:22:33Z"); got != "2025-11-19" {
		t.Errorf("shortDate = %q", got)
	}
	if got := shortDate("2025-11-19"); got != "2025-11-19" {
		t.Errorf("shortDate = %q", got)
	}
}

// Служебные объекты RIPE (FOO-MNT) не должны попадать в отчёт, а настоящая
// организация — должна.
func TestIsMaintainer(t *testing.T) {
	if !isMaintainer("NUXTCLOUD-MNT", "NUXTCLOUD-MNT") {
		t.Error("maintainer object should be filtered out")
	}
	if isMaintainer("ORG-NUXT1-RIPE", "nuxt.cloud hosting provider") {
		t.Error("real organization must be kept")
	}
}
