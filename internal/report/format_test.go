package report

// format_test.go — форматирование величин отчёта. Значения сверены с выводом
// оригинального bench.sh, поэтому тесты фиксируют именно его формат.

import (
	"strings"
	"testing"
)

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 KB"},
		{512 << 10, "512.0 KB"},
		{2 << 20, "2.0 MB"},
		{32105906176, "29.9 GB"},
	}
	for _, c := range cases {
		if got := HumanBytes(c.in); got != c.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUptime(t *testing.T) {
	if got := Uptime(300); got != "0 days, 0 hour 5 min" {
		t.Errorf("Uptime(300) = %q", got)
	}
	if got := Uptime(3*86400 + 4*3600 + 12*60); got != "3 days, 4 hour 12 min" {
		t.Errorf("Uptime = %q", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("abcdefgh", 4); got != "abc…" {
		t.Errorf("Truncate = %q", got)
	}
	if got := Truncate("abc", 10); got != "abc" {
		t.Errorf("Truncate = %q", got)
	}
}

func TestJoinNonEmpty(t *testing.T) {
	if got := JoinNonEmpty(", ", "Berlin", "", "DE"); got != "Berlin, DE" {
		t.Errorf("JoinNonEmpty = %q", got)
	}
}

func TestSpeedMethodLabel(t *testing.T) {
	if got := SpeedMethodLabel(MethodOokla, "eu"); got != "Ookla (speedtest.net) · nodes: eu" {
		t.Errorf("ookla label = %q", got)
	}
	// Пустой способ — это способ по умолчанию, а не «неизвестно».
	if got := SpeedMethodLabel("", ""); got != "Ookla (speedtest.net) · nodes: default" {
		t.Errorf("default label = %q", got)
	}
	// У Cloudflare узел всегда один, набор точек к нему неприменим.
	if got := SpeedMethodLabel(MethodCloudflare, "eu"); got != "Cloudflare (nearest edge)" {
		t.Errorf("cloudflare label = %q", got)
	}
}

// Отчёт по домену должен доезжать до Markdown целиком: и запись реестра, и
// ответы DNS, и сырой текст — именно этот формат пользователь несёт в тикет.
func TestMarkdownDomain(t *testing.T) {
	r := &Report{Domain: &DomainInfo{
		Domain:      "example.com",
		Registered:  "2007-10-09",
		Expires:     "2027-10-09",
		ExpiresDays: 400,
		Registrar:   &Registrar{Name: "Example Registrar", AbuseEmail: "abuse@example.com"},
		Status:      []string{"clientTransferProhibited"},
		NameServers: []string{"ns1.example.net"},
		Contacts:    []DomainContact{{Role: "registrant", Org: "Example Holdings", Country: "US"}},
		DNS:         &DomainDNS{A: []string{"192.0.2.1"}, MX: []string{"10 mx.example.com"}},
		Raw:         "domain: EXAMPLE.COM",
		Sources:     []string{"whois.com"},
	}}
	md := Markdown(r)
	for _, want := range []string{
		"## Domain", "example.com", "2027-10-09 (in 400 days)", "Example Registrar",
		"abuse@example.com", "clientTransferProhibited", "ns1.example.net",
		"Example Holdings", "### DNS records", "192.0.2.1", "10 mx.example.com",
		"### Raw WHOIS record", "domain: EXAMPLE.COM",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}
}

// Просроченный домен — главное, ради чего смотрят дату: он должен читаться
// как просроченный, а не как «истекает через минус триста дней».
func TestExpiryPlain(t *testing.T) {
	if got := expiryPlain("2020-01-01", -300); got != "2020-01-01 (expired 300 days ago)" {
		t.Errorf("expired = %q", got)
	}
	if got := expiryPlain("2027-01-01", 0); got != "2027-01-01" {
		t.Errorf("unknown remaining days = %q", got)
	}
}
