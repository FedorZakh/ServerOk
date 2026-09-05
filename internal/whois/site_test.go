package whois

// site_test.go — разбор страницы whois.com. Фрагмент HTML взят с настоящей
// страницы (лишние меню и реклама убраны): разметка чужая, и тест нужен
// именно затем, чтобы её изменение было видно сразу, а не по пустому отчёту.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const samplePage = `<html><body><main>
<div class="whois-data"><div class="head"><div><h1>example.com</h1></div></div>
<div class="df-block"><div class="df-heading"><span class="df-ico-domain"></span>Domain Information</div>
<div class="df-row"><div class="df-label">Domain:</div><div class="df-value">example.com</div></div>
<div class="df-row"><div class="df-label">Registered On:</div><div class="df-value">2007-10-09</div></div>
<div class="df-row"><div class="df-label">Expires On:</div><div class="df-value">2027-10-09</div></div>
<div class="df-row"><div class="df-label">Updated On:</div><div class="df-value">2024-09-07</div></div>
<div class="df-row"><div class="df-label">Status:</div><div class="df-value">client delete prohibited<br>client transfer prohibited</div></div>
<div class="df-row"><div class="df-label">Name Servers:</div><div class="df-value">NS1.EXAMPLE.NET.<br>ns2.example.net</div></div></div>
<div class="df-block"><div class="df-heading"><span class="df-ico-rar"></span>Registrar Information</div>
<div class="df-row"><div class="df-label">Registrar:</div><div class="df-value">Example Registrar &amp; Co.</div></div>
<div class="df-row"><div class="df-label">IANA ID:</div><div class="df-value">292</div></div>
<div class="df-row"><div class="df-label">Email:</div><div class="df-value">https://example-registrar.com/contact-us/</div></div>
<div class="df-row"><div class="df-label">Abuse Email:</div><div class="df-value">abuse@example-registrar.com</div></div>
<div class="df-row"><div class="df-label">Abuse Phone:</div><div class="df-value">+1.2086851750</div></div></div>
<div class="df-block"><div class="df-heading"><span class="df-ico-regcon"></span>Registrant Contact</div>
<div class="df-row"><div class="df-label">Organization:</div><div class="df-value">Example Holdings, Inc.</div></div>
<div class="df-row"><div class="df-label">Country:</div><div class="df-value">US</div></div></div>
<div class="df-block"><div class="df-heading">Raw Whois Data</div>
<pre class="df-raw" id="registryData">domain:        EXAMPLE.COM
registrar:     Example Registrar &amp; Co.</pre></div>
</div></main></body></html>`

func TestParseSite(t *testing.T) {
	d, err := parseSite(samplePage)
	if err != nil {
		t.Fatal(err)
	}
	if d.Registered != "2007-10-09" || d.Expires != "2027-10-09" || d.Updated != "2024-09-07" {
		t.Errorf("dates: %+v", d)
	}
	if d.Registrar == nil || d.Registrar.Name != "Example Registrar & Co." || d.Registrar.IANAID != "292" {
		t.Fatalf("registrar: %+v", d.Registrar)
	}
	// Подпись «Email» в блоке регистратора — это ссылка на форму, а не почта;
	// почта для жалоб приходит отдельной строкой.
	if d.Registrar.URL != "https://example-registrar.com/contact-us/" || d.Registrar.AbuseEmail != "abuse@example-registrar.com" {
		t.Errorf("registrar contacts: %+v", d.Registrar)
	}
	// Значения, разделённые <br>, — это список, а не одна строка.
	if len(d.Status) != 2 || d.Status[1] != "client transfer prohibited" {
		t.Errorf("status = %v", d.Status)
	}
	if strings.Join(d.NameServers, ",") != "ns1.example.net,ns2.example.net" {
		t.Errorf("name servers = %v", d.NameServers)
	}
	if len(d.Contacts) != 1 || d.Contacts[0].Role != "registrant" || d.Contacts[0].Org != "Example Holdings, Inc." {
		t.Errorf("contacts = %+v", d.Contacts)
	}
	if !strings.Contains(d.Raw, "domain:        EXAMPLE.COM") || strings.Contains(d.Raw, "&amp;") {
		t.Errorf("raw record not decoded: %q", d.Raw)
	}
}

// Страницу с проверкой «вы не робот» whois.com отдаёт с кодом 200 и без
// единого поля. Принять её за пустую запись нельзя: это ошибка источника, по
// которой Lookup идёт на порт 43.
func TestParseSiteBlocked(t *testing.T) {
	if _, err := parseSite(`<html><body><main><h1>Security Check</h1></main></body></html>`); err == nil {
		t.Error("a page without a record must be an error")
	}
}

func TestFetchSite(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, samplePage)
	}))
	defer srv.Close()

	old := siteURL
	siteURL = srv.URL + "/whois/%s"
	defer func() { siteURL = old }()

	d, err := fetchSite(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/whois/example.com" {
		t.Errorf("requested %q", gotPath)
	}
	if d.Registrar == nil || d.Registrar.IANAID != "292" {
		t.Errorf("record not parsed: %+v", d)
	}
}
