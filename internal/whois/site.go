package whois

// site.go — разбор страницы www.whois.com/whois/<домен>.
//
// Почему разбирается HTML, а не какой-нибудь API: публичного API у whois.com
// нет, зато разметка страницы предельно регулярная — блоки «df-block» с
// заголовком «df-heading» и парами «df-label»/«df-value»:
//
//	<div class="df-block">
//	  <div class="df-heading"><span class="df-ico-domain"></span>Domain Information</div>
//	  <div class="df-row"><div class="df-label">Registrar:</div><div class="df-value">…</div></div>
//
// Значение поля — то, что смысл строки задаёт не только подпись, но и
// заголовок блока: «Email» в блоке регистратора и «Email» в блоке владельца
// — разные вещи. Поэтому строки разбираются в контексте своего блока.
//
// Осторожно: whois.com иногда отдаёт страницу с проверкой «вы не робот»,
// причём с кодом 200. Отличается она отсутствием блока whois-data — тогда
// функция возвращает ошибку, и данные добираются через порт 43 (см. Lookup).

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
	"github.com/Zagorsky17/ServerOk/internal/report"
)

// siteURL вынесен в переменную ради тестов: site_test.go подставляет сюда
// адрес httptest-сервера с сохранённой страницей.
var siteURL = "https://www.whois.com/whois/%s"

const siteName = "whois.com"

// Страница со всей рекламой и меню весит около 40 КБ, но у доменов с длинной
// сырой записью (ccTLD печатают её целиком) доходит до сотен килобайт.
const siteMaxBytes = 1 << 20

var (
	reSiteData    = regexp.MustCompile(`(?is)<div class="whois-data">(.*?)(?:</main>|\z)`)
	reSiteHeading = regexp.MustCompile(`(?is)<div class="df-heading">(.*?)</div>`)
	reSiteRow     = regexp.MustCompile(`(?is)<div class="df-label">(.*?)</div>\s*<div class="df-value">(.*?)</div>`)
	reSiteCaptcha = regexp.MustCompile(`(?i)security check|altcha`)
	reSiteRaw     = regexp.MustCompile(`(?is)<pre[^>]*class="df-raw"[^>]*>(.*?)</pre>`)
	reTag         = regexp.MustCompile(`(?is)<[^>]*>`)
	reBreak       = regexp.MustCompile(`(?i)<br\s*/?>`)
)

// fetchSite запрашивает страницу и разбирает её.
func fetchSite(ctx context.Context, domain string) (*report.DomainInfo, error) {
	client := netutil.Client(netutil.Any, 20*time.Second)
	defer client.CloseIdleConnections()

	// Домен уже прошёл Normalize, но в URL он всё равно экранируется: путь
	// формируется подстановкой, и полагаться на одну проверку не стоит.
	resp, err := netutil.Get(ctx, client, fmt.Sprintf(siteURL, url.PathEscape(domain)), siteMaxBytes, nil)
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.Status)
	}
	return parseSite(resp.Text())
}

// parseSite превращает HTML страницы в модель отчёта.
func parseSite(page string) (*report.DomainInfo, error) {
	m := reSiteData.FindStringSubmatch(page)
	if m == nil {
		// Проверку «вы не робот» whois.com отдаёт с кодом 200 и без данных;
		// чаще всего под неё попадают запросы о свободных доменах.
		if reSiteCaptcha.MatchString(page) {
			return nil, errors.New("the page asked for a captcha")
		}
		return nil, errors.New("no record on the page")
	}
	data := m[1]

	d := &report.DomainInfo{}
	if raw := reSiteRaw.FindStringSubmatch(data); raw != nil {
		d.Raw = strings.TrimSpace(text(raw[1]))
	}
	// Первый кусок до первого df-block — шапка страницы, полей в нём нет.
	for _, block := range strings.Split(data, `<div class="df-block">`)[1:] {
		heading := ""
		if h := reSiteHeading.FindStringSubmatch(block); h != nil {
			heading = strings.ToLower(text(h[1]))
		}
		for _, row := range reSiteRow.FindAllStringSubmatch(block, -1) {
			label := strings.ToLower(strings.TrimRight(strings.TrimSpace(text(row[1])), ":"))
			applyRow(d, heading, label, values(row[2]))
		}
	}
	if d.Registrar == nil && d.Registered == "" && len(d.NameServers) == 0 && d.Raw == "" {
		return nil, errors.New("the page carries no domain fields")
	}
	return d, nil
}

// applyRow раскладывает одну строку «подпись: значение» по полям отчёта.
// Смысл подписи зависит от блока, в котором она стоит, поэтому heading —
// такой же ключ разбора, как и label.
func applyRow(d *report.DomainInfo, heading, label string, vals []string) {
	if len(vals) == 0 {
		return
	}
	v := vals[0]
	switch {
	case strings.Contains(heading, "registrar"):
		if d.Registrar == nil {
			d.Registrar = &report.Registrar{}
		}
		r := d.Registrar
		switch label {
		case "registrar", "name":
			r.Name = v
		case "iana id":
			r.IANAID = v
		case "email":
			r.URL, r.AbuseEmail = pickContact(r.URL, r.AbuseEmail, v)
		case "abuse email":
			r.AbuseEmail = v
		case "abuse phone":
			r.AbusePhone = v
		case "website", "url":
			r.URL = v
		case "whois server":
			r.WhoisServer = v
		}
	case strings.Contains(heading, "contact"):
		applyContact(d, contactRole(heading), label, v)
	default: // «Domain Information» и всё, что не удалось узнать
		switch label {
		case "registered on", "created on", "creation date":
			d.Registered = normalizeDate(v)
		case "expires on", "expiry date", "expiration date":
			d.Expires = normalizeDate(v)
		case "updated on", "last updated":
			d.Updated = normalizeDate(v)
		case "status":
			// Значения разделены то тегом <br> (gTLD, по коду EPP на
			// строку), то запятой в одной ячейке (так отвечает .ru).
			for _, s := range vals {
				for _, part := range strings.Split(s, ",") {
					if part = strings.TrimSpace(part); part != "" {
						d.Status = append(d.Status, part)
					}
				}
			}
		case "name servers", "name server":
			d.NameServers = hosts(vals)
		case "dnssec":
			d.DNSSEC = v
		}
	}
}

// contactRole определяет роль контакта по заголовку блока.
func contactRole(heading string) string {
	switch {
	case strings.Contains(heading, "registrant"):
		return "registrant"
	case strings.Contains(heading, "admin"):
		return "admin"
	case strings.Contains(heading, "tech"):
		return "tech"
	case strings.Contains(heading, "billing"):
		return "billing"
	}
	return "contact"
}

// applyContact дописывает поле контакта, заводя запись при первом упоминании.
func applyContact(d *report.DomainInfo, role, label, v string) {
	var c *report.DomainContact
	for i := range d.Contacts {
		if d.Contacts[i].Role == role {
			c = &d.Contacts[i]
			break
		}
	}
	if c == nil {
		d.Contacts = append(d.Contacts, report.DomainContact{Role: role})
		c = &d.Contacts[len(d.Contacts)-1]
	}
	switch label {
	case "name":
		c.Name = v
	case "organization", "org":
		c.Org = v
	case "email":
		c.Web, c.Email = pickContact(c.Web, c.Email, v)
	case "phone":
		c.Phone = v
	case "country":
		c.Country = v
	case "state", "state/province", "city":
		c.Location = report.JoinNonEmpty(", ", c.Location, v)
	}
}

// pickContact раскладывает значение подписи «Email»: у половины регистраторов
// там стоит не адрес, а ссылка на веб-форму (GDPR), и записывать её в поле
// почты — значит подсунуть пользователю неработающий адрес для связи.
func pickContact(url, email, v string) (string, string) {
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
		if url == "" {
			url = v
		}
		return url, email
	}
	if email == "" {
		email = v
	}
	return url, email
}

// values разбивает содержимое ячейки на строки: многозначные поля (статусы,
// NS-записи) разделены внутри одной ячейки тегами <br>.
func values(cell string) []string {
	var out []string
	for _, part := range strings.Split(reBreak.ReplaceAllString(cell, "\n"), "\n") {
		if s := strings.TrimSpace(text(part)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// text убирает теги и раскодирует HTML-сущности (&amp;, &#39; и прочие).
func text(s string) string {
	return strings.TrimSpace(html.UnescapeString(reTag.ReplaceAllString(s, "")))
}

// hosts приводит список серверов имён к нижнему регистру и убирает точку в
// конце: реестры пишут их то как "NS1.EXAMPLE.COM.", то как "ns1.example.com".
// В ответе .ru после имени идёт ещё и адрес — берётся только имя.
func hosts(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		f := strings.Fields(s)
		if len(f) == 0 {
			continue
		}
		h := strings.ToLower(strings.Trim(f[0], "."))
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}
