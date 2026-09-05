package ipinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
)

// geo_test.go — разбор ответов геолокации и, главное, защита от недоверенных
// данных: адрес от внешнего сервиса уходит в URL, DNS-запрос и argv whois.

// serveJSON направляет всех провайдеров геолокации на один тестовый обработчик.
func serveJSON(t *testing.T, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	oldAPI, oldInfo, oldWho, oldByIP := ipAPIURL, ipInfoURL, ipWhoIsURL, ipAPIByIP
	ipAPIURL, ipInfoURL, ipWhoIsURL, ipAPIByIP = srv.URL, srv.URL, srv.URL, srv.URL+"/"
	ResetCache()
	t.Cleanup(func() {
		ipAPIURL, ipInfoURL, ipWhoIsURL, ipAPIByIP = oldAPI, oldInfo, oldWho, oldByIP
		ResetCache()
	})
}

func TestLookupGeoParsesIPAPI(t *testing.T) {
	serveJSON(t, `{"status":"success","query":"203.0.113.7","country":"Germany","countryCode":"DE",
		"regionName":"Hesse","city":"Frankfurt","lat":50.11,"lon":8.68,"timezone":"Europe/Berlin",
		"isp":"Example ISP","org":"Example Org","as":"AS64500 EXAMPLE-AS","asname":"EXAMPLE",
		"hosting":true,"proxy":false,"mobile":false}`)

	g, err := LookupGeo(context.Background(), netutil.IPv4)
	if err != nil {
		t.Fatalf("LookupGeo: %v", err)
	}
	if g.IP != "203.0.113.7" || g.ASN != "AS64500" || g.ASName != "EXAMPLE-AS" {
		t.Errorf("parsed geo = %+v", g)
	}
	if !g.Hosting || g.City != "Frankfurt" || g.CountryCode != "DE" {
		t.Errorf("parsed geo = %+v", g)
	}

	org, location, region := SummaryFields(g)
	if org != "AS64500 EXAMPLE-AS" || location != "Frankfurt / DE" || region != "Hesse" {
		t.Errorf("SummaryFields = %q, %q, %q", org, location, region)
	}
}

// Ответ провайдера для нас — потенциально враждебный ввод: ip-api.com
// опрашивается по обычному HTTP, а возвращённый адрес попадает в URL запроса
// RDAP и в аргументы whois (ведущий дефис там стал бы флагом).
func TestLookupGeoRejectsMalformedAddress(t *testing.T) {
	for _, bad := range []string{"-h attacker.example", "203.0.113.7 --flag", "../../etc/passwd", ""} {
		serveJSON(t, `{"status":"success","query":"`+bad+`","country":"X","countryCode":"XX"}`)
		if g, err := LookupGeo(context.Background(), netutil.IPv4); err == nil {
			t.Errorf("LookupGeo accepted %q and returned %+v", bad, g)
		}
	}
}

func TestLookupGeoIPValidatesItsArgument(t *testing.T) {
	// Сервер не нужен: проверка обязана отбраковать аргумент до запроса.
	if _, err := LookupGeoIP(context.Background(), "-h attacker.example"); err == nil {
		t.Error("LookupGeoIP accepted a non-address argument")
	}
}

// Результат должен запрашиваться один раз: шапка отчёта и тест IP спрашивают
// одно и то же, а лимиты бесплатных API невелики.
func TestLookupGeoMemoizes(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"status":"success","query":"198.51.100.9"}`))
	}))
	defer srv.Close()

	old := ipAPIURL
	ipAPIURL = srv.URL
	ResetCache()
	defer func() { ipAPIURL = old; ResetCache() }()

	for i := 0; i < 3; i++ {
		if _, err := LookupGeo(context.Background(), netutil.IPv4); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Errorf("provider called %d times, want 1 (result must be memoized)", calls)
	}
}
