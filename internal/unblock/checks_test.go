package unblock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

// checks_test.go — проверки сервисов на локальном httptest-сервере.
// Фикстуры повторяют ключевые фрагменты настоящих ответов, поэтому тесты
// ловят регрессии разбора, не выходя в интернет.

// serve поднимает сервер: bodies задаёт тело по пути, codes — код ответа
// (по умолчанию 200).
func serve(t *testing.T, bodies map[string]string, codes map[string]int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code, ok := codes[r.URL.Path]; ok {
			w.WriteHeader(code)
		}
		_, _ = w.Write([]byte(bodies[r.URL.Path]))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// swap подменяет адрес сервиса на тестовый и восстанавливает его после теста,
// чтобы проверки не зависели от фикстур друг друга.
func swap(t *testing.T, target *string, value string) {
	t.Helper()
	old := *target
	*target = value
	t.Cleanup(func() { *target = old })
}

func TestNetflixFullCatalogue(t *testing.T) {
	srv := serve(t, map[string]string{
		"/licensed": `<html>"requestCountry":{"supportedLocales":["de"],"id":"DE","countryName":"Germany"}</html>`,
		"/original": "ok",
	}, nil)
	swap(t, &netflixLicensedURL, srv.URL+"/licensed")
	swap(t, &netflixOriginalURL, srv.URL+"/original")

	got := checkNetflix(context.Background(), srv.Client())
	if got.Status != statusYes || got.Region != "DE" || got.Detail != "full catalogue" {
		t.Errorf("checkNetflix = %+v", got)
	}
}

func TestNetflixGeoBlocked(t *testing.T) {
	srv := serve(t, map[string]string{"/licensed": "", "/original": ""},
		map[string]int{"/licensed": 403, "/original": 403})
	swap(t, &netflixLicensedURL, srv.URL+"/licensed")
	swap(t, &netflixOriginalURL, srv.URL+"/original")

	got := checkNetflix(context.Background(), srv.Client())
	if got.Status != statusNo {
		t.Errorf("checkNetflix = %+v, want status %q", got, statusNo)
	}
}

// 404 на лицензионный фильм при доступном оригинале — это «только
// собственные проекты Netflix».
func TestNetflixOriginalsOnly(t *testing.T) {
	srv := serve(t, map[string]string{"/licensed": "", "/original": "ok"},
		map[string]int{"/licensed": 404})
	swap(t, &netflixLicensedURL, srv.URL+"/licensed")
	swap(t, &netflixOriginalURL, srv.URL+"/original")

	got := checkNetflix(context.Background(), srv.Client())
	if got.Status != statusRestricted {
		t.Errorf("checkNetflix = %+v, want status %q", got, statusRestricted)
	}
}

// Ответ 200 доказывает лишь достижимость, но не доступ: Disney+ и подобные
// отвечают 200 из любой страны и решают вопрос доступности уже в браузере.
// Регресс-тест на найденное при ревью ложное «Yes».
func TestReachableWithoutRegionIsNotAYes(t *testing.T) {
	srv := serve(t, map[string]string{"/": "<html>nothing useful here</html>"}, nil)
	for _, target := range []*string{&disneyURL, &tiktokURL, &steamURL, &primeVideoURL} {
		swap(t, target, srv.URL+"/")
	}

	checks := map[string]func(context.Context, *http.Client) (result string){
		"disney": func(ctx context.Context, c *http.Client) string { return checkDisney(ctx, c).Status },
		"tiktok": func(ctx context.Context, c *http.Client) string { return checkTikTok(ctx, c).Status },
		"steam":  func(ctx context.Context, c *http.Client) string { return checkSteam(ctx, c).Status },
		"prime":  func(ctx context.Context, c *http.Client) string { return checkPrimeVideo(ctx, c).Status },
	}
	for name, run := range checks {
		if got := run(context.Background(), srv.Client()); got != statusUnknown {
			t.Errorf("%s returned %q for a page with no region marker, want %q", name, got, statusUnknown)
		}
	}
}

// Обратный случай: если регион в ответе есть, вердикт должен быть «yes».
func TestRegionMarkerYieldsYes(t *testing.T) {
	srv := serve(t, map[string]string{"/": `{"region":"NL","countrycode":"NL","currentTerritory":"NL"}`}, nil)
	for _, target := range []*string{&disneyURL, &tiktokURL, &steamURL, &primeVideoURL} {
		swap(t, target, srv.URL+"/")
	}

	if got := checkTikTok(context.Background(), srv.Client()); got.Status != statusYes || got.Region != "NL" {
		t.Errorf("checkTikTok = %+v", got)
	}
	if got := checkSteam(context.Background(), srv.Client()); got.Status != statusYes || got.Region != "NL" {
		t.Errorf("checkSteam = %+v", got)
	}
	if got := checkPrimeVideo(context.Background(), srv.Client()); got.Status != statusYes || got.Region != "NL" {
		t.Errorf("checkPrimeVideo = %+v", got)
	}
}

// Заглушка Cloudflare ничего не говорит о доступности по региону: её нельзя
// показывать как блокировку, но код страны из trace при этом сохраняется.
func TestBotChallengeIsNotABlock(t *testing.T) {
	srv := serve(t, map[string]string{
		"/trace": "loc=DE\n",
		"/":      `<html><title>Just a moment...</title></html>`,
	}, map[string]int{"/": 403})
	swap(t, &claudeTraceURL, srv.URL+"/trace")
	swap(t, &claudeURL, srv.URL+"/")

	got := checkClaude(context.Background(), srv.Client())
	if got.Status != statusFailed || got.Detail != "bot challenge" {
		t.Errorf("checkClaude = %+v, want a failed/bot-challenge verdict", got)
	}
	if got.Region != "DE" {
		t.Errorf("edge location should still be reported, got %q", got.Region)
	}
}

func TestYouTubeUnavailable(t *testing.T) {
	srv := serve(t, map[string]string{"/": `Premium is not available in your country "countryCode":"CN"`}, nil)
	swap(t, &youtubePremiumURL, srv.URL+"/")

	got := checkYouTube(context.Background(), srv.Client())
	if got.Status != statusNo {
		t.Errorf("checkYouTube = %+v", got)
	}
}

// Паника в разборе чужого HTML не должна ронять прогон: проверка обязана
// превратиться в обычную неудачу.
func TestRunIsolatesPanics(t *testing.T) {
	got := runOne(context.Background(), Check{
		Name: "boom",
		Run:  func(context.Context, *http.Client) report.UnblockItem { panic("boom") },
	})
	if got.Status != statusFailed || got.Service != "boom" {
		t.Errorf("runOne = %+v, want an isolated failure", got)
	}
}
