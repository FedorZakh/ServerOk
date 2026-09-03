package unblock

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/FedorZakh/ServerOk/internal/netutil"
	"github.com/FedorZakh/ServerOk/internal/report"
)

// checks.go — сами проверки сервисов, по одной функции на сервис.
//
// Адреса вынесены в переменные: так тесты подменяют их на локальный
// httptest-сервер (checks_test.go), а при изменении чужого API правится
// одна строка. Ниже — единственное место в проекте, которое приходится
// обновлять вслед за сторонними сервисами.
var (
	netflixLicensedURL = "https://www.netflix.com/title/70143836" // licensed title (Breaking Bad)
	netflixOriginalURL = "https://www.netflix.com/title/81280792" // Netflix original
	youtubePremiumURL  = "https://www.youtube.com/premium"
	disneyURL          = "https://www.disneyplus.com/"
	primeVideoURL      = "https://www.primevideo.com/"
	spotifySignupURL   = "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=test%40example.com"
	openAITraceURL     = "https://chatgpt.com/cdn-cgi/trace"
	openAIComplyURL    = "https://api.openai.com/compliance/cookie_requirements"
	claudeTraceURL     = "https://claude.ai/cdn-cgi/trace"
	claudeURL          = "https://claude.ai/"
	tiktokURL          = "https://www.tiktok.com/"
	steamURL           = "https://store.steampowered.com/"
)

// AllChecks возвращает список проверок в порядке вывода. Добавить сервис =
// дописать одну строку сюда и одну функцию ниже; каркас и рендер трогать не
// нужно.
func AllChecks() []Check {
	return []Check{
		{"Netflix", checkNetflix},
		{"YouTube Premium", checkYouTube},
		{"Disney+", checkDisney},
		{"Amazon Prime Video", checkPrimeVideo},
		{"Spotify", checkSpotify},
		{"ChatGPT (OpenAI)", checkOpenAI},
		{"Claude (Anthropic)", checkClaude},
		{"TikTok", checkTikTok},
		{"Steam Store", checkSteam},
	}
}

// Возможные вердикты.
//
// Статус unknown появился по итогам ревью и принципиально важен: несколько
// сервисов (тот же disneyplus.com) отвечают 200 из любой страны и решают
// вопрос доступности уже в браузере. Раньше это давало уверенное «Yes» там,
// где на деле ничего не проверено. Теперь «Yes» ставится только при
// подтверждённом регионе или явном признаке доступа.
const (
	statusYes        = "yes"
	statusNo         = "no"
	statusRestricted = "restricted"
	statusUnknown    = "unknown"
	statusFailed     = "failed"
)

// Регулярные выражения для поиска маркеров региона в ответах сервисов.
var (
	reNetflixLocale = regexp.MustCompile(`netflix\.com/([a-z]{2})(?:-[a-z]{2})?/`)
	reNetflixRegion = regexp.MustCompile(`"requestCountry"\s*:\s*\{[^}]*"id"\s*:\s*"([A-Z]{2})"`)
	reYTCountry     = regexp.MustCompile(`"countryCode"\s*:\s*"([A-Z]{2})"`)
	rePrimeTerr     = regexp.MustCompile(`"currentTerritory"\s*:\s*"([A-Z]{2})"`)
	reSpotifyCC     = regexp.MustCompile(`"country"\s*:\s*"([A-Z]{2})"`)
	reTikTokRegion  = regexp.MustCompile(`"region"\s*:\s*"([A-Z]{2})"`)
	reSteamCC       = regexp.MustCompile(`"countrycode"\s*:\s*"([A-Z]{2})"`)
	reTraceLoc      = regexp.MustCompile(`(?m)^loc=([A-Z]{2})$`)
	reDisneyRegion  = regexp.MustCompile(`"(?:region|countryCode)"\s*:\s*"([A-Z]{2})"`)
)

// checkNetflix различает три состояния — полный каталог, только собственные
// проекты и блокировку. Метод стандартный для таких чекеров: запрашиваются
// два фильма, лицензионный (его нет в «урезанных» регионах) и собственного
// производства Netflix.
func checkNetflix(ctx context.Context, c *http.Client) report.UnblockItem {
	licensed, err := netutil.Get(ctx, c, netflixLicensedURL, 2<<20, nil)
	if err != nil {
		return failed(err)
	}
	original, err := netutil.Get(ctx, c, netflixOriginalURL, 64<<10, nil)
	if err != nil {
		return failed(err)
	}

	// Регион берём из поля requestCountry в теле: именно оно отражает
	// геолокацию. Локаль в URL (…/de-en/title/…) зависит от заголовка
	// Accept-Language, а не от страны, поэтому она — только запасной вариант.
	// На этом уже обжигались: с нашим Accept-Language ответ приходил как
	// "us-en" при немецком адресе.
	region := ""
	if m := reNetflixRegion.FindStringSubmatch(licensed.Text()); len(m) > 1 {
		region = m[1]
	}
	if region == "" {
		if m := reNetflixLocale.FindStringSubmatch(licensed.FinalURL()); len(m) > 1 {
			region = strings.ToUpper(m[1])
		}
	}

	switch {
	case licensed.Status == 200 && original.Status == 200:
		return report.UnblockItem{Status: statusYes, Region: region, Detail: "full catalogue"}
	case original.Status == 200 || licensed.Status == 404:
		return report.UnblockItem{Status: statusRestricted, Region: region, Detail: "originals only"}
	case licensed.Status == 403 || original.Status == 403:
		return report.UnblockItem{Status: statusNo, Detail: "geo blocked"}
	case strings.Contains(licensed.Text(), "not available in your country"):
		return report.UnblockItem{Status: statusNo, Detail: "not available"}
	default:
		return report.UnblockItem{Status: statusFailed, Detail: httpNote(licensed.Status)}
	}
}

// checkYouTube запрашивает страницу Premium. Cookies нужны, чтобы обойти
// страницу согласия на cookies (без них приходит редирект на consent-домен и
// регион определить невозможно).
func checkYouTube(ctx context.Context, c *http.Client) report.UnblockItem {
	resp, err := netutil.Get(ctx, c, youtubePremiumURL, 3<<20,
		map[string]string{"Cookie": "SOCS=CAI; YSC=BiCUU3-5Gdk; CONSENT=YES+cb; VISITOR_INFO1_LIVE=4VwPMkB7W5A; PREF=f6=40000000&hl=en"})
	if err != nil {
		return failed(err)
	}
	body := resp.Text()
	region := firstMatch(reYTCountry, body)
	switch {
	case strings.Contains(body, "Premium is not available in your country"),
		strings.Contains(body, "YouTube Premium is not available"):
		return report.UnblockItem{Status: statusNo, Region: region, Detail: "not available"}
	case region == "CN":
		return report.UnblockItem{Status: statusNo, Region: region, Detail: "mainland China"}
	case resp.Status == 200 && region != "":
		return report.UnblockItem{Status: statusYes, Region: region}
	case resp.Status == 200:
		return report.UnblockItem{Status: statusUnknown, Detail: "no region in response"}
	default:
		return report.UnblockItem{Status: statusFailed, Detail: httpNote(resp.Status)}
	}
}

// checkDisney: по одной посадочной странице ответить нельзя — disneyplus.com
// отвечает 200 отовсюду и решает вопрос доступности на клиенте. Поэтому
// ответом считается только явная блокировка или явно указанный регион, всё
// остальное — unknown.
func checkDisney(ctx context.Context, c *http.Client) report.UnblockItem {
	resp, err := netutil.Get(ctx, c, disneyURL, 2<<20, nil)
	if err != nil {
		return failed(err)
	}
	body := resp.Text()
	lower := strings.ToLower(body)
	region := firstMatch(reDisneyRegion, body)
	switch {
	case resp.Status == 403,
		strings.Contains(lower, "unavailable-in-your-region"),
		strings.Contains(lower, "not available in your region"):
		return report.UnblockItem{Status: statusNo, Detail: "geo blocked"}
	case isBotChallenge(lower):
		return report.UnblockItem{Status: statusFailed, Detail: "bot challenge"}
	case resp.Status == 200 && region != "":
		return report.UnblockItem{Status: statusYes, Region: region}
	case resp.Status == 200:
		return report.UnblockItem{Status: statusUnknown, Detail: "reachable, region unconfirmed"}
	default:
		return report.UnblockItem{Status: statusFailed, Detail: httpNote(resp.Status)}
	}
}

// checkPrimeVideo ищет в теле страницы поле currentTerritory — регион, в
// котором Amazon обслуживает этот адрес.
func checkPrimeVideo(ctx context.Context, c *http.Client) report.UnblockItem {
	resp, err := netutil.Get(ctx, c, primeVideoURL, 3<<20, nil)
	if err != nil {
		return failed(err)
	}
	body := resp.Text()
	region := firstMatch(rePrimeTerr, body)
	switch {
	case strings.Contains(body, "isServiceRestricted"):
		return report.UnblockItem{Status: statusNo, Detail: "service restricted"}
	case resp.Status == 200 && region != "":
		return report.UnblockItem{Status: statusYes, Region: region}
	case resp.Status == 200:
		return report.UnblockItem{Status: statusUnknown, Detail: "reachable, region unconfirmed"}
	default:
		return report.UnblockItem{Status: statusFailed, Detail: httpNote(resp.Status)}
	}
}

// checkSpotify использует эндпоинт валидации регистрации: он отвечает, можно
// ли завести аккаунт с этого адреса, и в какой стране.
func checkSpotify(ctx context.Context, c *http.Client) report.UnblockItem {
	resp, err := netutil.Get(ctx, c, spotifySignupURL, 64<<10, nil)
	if err != nil {
		return failed(err)
	}
	body := resp.Text()
	region := firstMatch(reSpotifyCC, body)
	switch {
	case strings.Contains(body, "not available in your country"), resp.Status == 403:
		return report.UnblockItem{Status: statusNo, Detail: "registration blocked"}
	case resp.Status == 200 && region != "":
		return report.UnblockItem{Status: statusYes, Region: region}
	case resp.Status == 200:
		return report.UnblockItem{Status: statusUnknown, Detail: "reachable, region unconfirmed"}
	default:
		return report.UnblockItem{Status: statusFailed, Detail: httpNote(resp.Status)}
	}
}

// checkOpenAI совмещает два источника: cdn-cgi/trace даёт страну, которую
// видит Cloudflare, а служебный эндпоинт compliance сообщает, поддерживается
// ли эта страна (при отказе он отвечает unsupported_country).
func checkOpenAI(ctx context.Context, c *http.Client) report.UnblockItem {
	region := cfTraceLoc(ctx, c, openAITraceURL)
	resp, err := netutil.Get(ctx, c, openAIComplyURL, 32<<10,
		map[string]string{"Origin": "https://platform.openai.com", "Referer": "https://platform.openai.com/"})
	if err != nil {
		item := failed(err)
		item.Region = region
		return item
	}
	body := strings.ToLower(resp.Text())
	switch {
	case strings.Contains(body, "unsupported_country"):
		return report.UnblockItem{Status: statusNo, Region: region, Detail: "unsupported country"}
	case isBotChallenge(body):
		return report.UnblockItem{Status: statusFailed, Region: region, Detail: "bot challenge"}
	case resp.Status == 403:
		return report.UnblockItem{Status: statusNo, Region: region, Detail: "blocked"}
	case resp.Status < 400:
		return report.UnblockItem{Status: statusYes, Region: region}
	default:
		return report.UnblockItem{Status: statusFailed, Region: region, Detail: httpNote(resp.Status)}
	}
}

// checkClaude: как и у OpenAI, страна берётся из cdn-cgi/trace. Сама claude.ai
// закрыта антибот-защитой Cloudflare, поэтому её заглушка отделяется от
// настоящей региональной блокировки.
func checkClaude(ctx context.Context, c *http.Client) report.UnblockItem {
	region := cfTraceLoc(ctx, c, claudeTraceURL)
	resp, err := netutil.Get(ctx, c, claudeURL, 256<<10, nil)
	if err != nil {
		item := failed(err)
		item.Region = region
		return item
	}
	body := strings.ToLower(resp.Text())
	switch {
	case strings.Contains(body, "not available in your region"),
		strings.Contains(body, "unavailable in your country"):
		return report.UnblockItem{Status: statusNo, Region: region, Detail: "geo blocked"}
	case isBotChallenge(body):
		// Заглушка Cloudflare («Just a moment…») не говорит ничего о
		// доступности по региону — это защита от ботов. Выдавать её за
		// блокировку нельзя, поэтому статус failed.
		return report.UnblockItem{Status: statusFailed, Region: region, Detail: "bot challenge"}
	case resp.Status == 403:
		return report.UnblockItem{Status: statusNo, Region: region, Detail: "geo blocked"}
	case resp.Status < 400:
		return report.UnblockItem{Status: statusYes, Region: region}
	default:
		return report.UnblockItem{Status: statusFailed, Region: region, Detail: httpNote(resp.Status)}
	}
}

// checkTikTok определяет регион по полю region в теле главной страницы.
func checkTikTok(ctx context.Context, c *http.Client) report.UnblockItem {
	resp, err := netutil.Get(ctx, c, tiktokURL, 2<<20, nil)
	if err != nil {
		return failed(err)
	}
	region := firstMatch(reTikTokRegion, resp.Text())
	switch {
	case resp.Status >= 400:
		return report.UnblockItem{Status: statusNo, Detail: httpNote(resp.Status)}
	case region != "":
		return report.UnblockItem{Status: statusYes, Region: region}
	default:
		return report.UnblockItem{Status: statusUnknown, Detail: "reachable, region unconfirmed"}
	}
}

// checkSteam определяет страну магазина: от неё зависят цены и доступность игр.
func checkSteam(ctx context.Context, c *http.Client) report.UnblockItem {
	resp, err := netutil.Get(ctx, c, steamURL, 2<<20, nil)
	if err != nil {
		return failed(err)
	}
	region := firstMatch(reSteamCC, resp.Text())
	switch {
	case resp.Status >= 400:
		return report.UnblockItem{Status: statusFailed, Detail: httpNote(resp.Status)}
	case region != "":
		return report.UnblockItem{Status: statusYes, Region: region}
	default:
		return report.UnblockItem{Status: statusUnknown, Detail: "reachable, region unconfirmed"}
	}
}

// cfTraceLoc читает двухбуквенный код страны из служебного эндпоинта
// Cloudflare (строка loc=XX).
func cfTraceLoc(ctx context.Context, c *http.Client, url string) string {
	resp, err := netutil.Get(ctx, c, url, 8<<10, nil)
	if err != nil {
		return ""
	}
	return firstMatch(reTraceLoc, resp.Text())
}

// isBotChallenge распознаёт страницу-заглушку антибот-защиты. Такой ответ не
// должен выдаваться за региональную блокировку.
func isBotChallenge(lowerBody string) bool {
	for _, marker := range []string{"just a moment", "cf-browser-verification", "challenge-platform", "enable javascript and cookies"} {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}
	return false
}

// firstMatch возвращает первую подгруппу совпадения или пустую строку.
func firstMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return m[1]
	}
	return ""
}

// failed оформляет сетевую ошибку как результат проверки.
func failed(err error) report.UnblockItem {
	return report.UnblockItem{Status: statusFailed, Detail: report.Truncate(err.Error(), 30)}
}

// httpNote печатает неожиданный код ответа в колонку примечания.
func httpNote(code int) string { return "HTTP " + strconv.Itoa(code) }
