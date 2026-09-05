package ipinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
	"github.com/Zagorsky17/ServerOk/internal/report"
)

// rdap.go — получение регистрационной записи адреса по протоколу RDAP
// (RFC 7483/9083), пришедшему на смену текстовому whois.
//
// Зачем это нужно: RDAP отвечает JSON-ом, поэтому не требует ни бинарника
// whois на сервере, ни разбора свободного текста, который у каждого реестра
// свой. Из ответа извлекаются: имя и диапазон сети, тип выделения, реестр,
// даты, организация-владелец и контакт для жалоб.
//
// rdapEndpoints перебираются по порядку: rdap.org сам определяет нужный
// региональный реестр, остальные — прямые адреса RIR на случай, если
// bootstrap недоступен. Переменная, а не константа, чтобы тесты могли
// подставить httptest-сервер.
var rdapEndpoints = []struct {
	name string
	url  string
}{
	{"rdap.org", "https://rdap.org/ip/%s"},
	{"ARIN bootstrap", "https://rdap-bootstrap.arin.net/bootstrap/ip/%s"},
	{"RIPE NCC", "https://rdap.db.ripe.net/ip/%s"},
	{"ARIN", "https://rdap.arin.net/registry/ip/%s"},
	{"APNIC", "https://rdap.apnic.net/ip/%s"},
	{"LACNIC", "https://rdap.lacnic.net/rdap/ip/%s"},
	{"AFRINIC", "https://rdap.afrinic.net/rdap/ip/%s"},
}

// LookupRDAP получает регистрационную запись адреса.
//
// Если ни один RDAP-сервер не ответил, используется системный whois (если он
// установлен) — так на старых серверах без доступа к RDAP хотя бы часть
// данных всё равно попадёт в отчёт.
func LookupRDAP(ctx context.Context, ip string) (*report.RDAP, error) {
	// Адрес приходит из стороннего API (ip-api.com — по открытому HTTP), а
	// отсюда попадает и в URL, и в аргументы whois. Поэтому он проверяется и
	// канонизируется до любых действий; в URL дополнительно экранируется.
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return nil, fmt.Errorf("refusing to look up a malformed address %q", report.Truncate(ip, 40))
	}
	ip = parsed.String()

	client := netutil.Client(netutil.Any, 10*time.Second)
	defer client.CloseIdleConnections()
	var lastErr error
	for _, ep := range rdapEndpoints {
		if ctx.Err() != nil {
			break
		}
		rec, err := fetchRDAP(ctx, client, fmt.Sprintf(ep.url, url.PathEscape(ip)), ip)
		if err == nil && rec != nil {
			if rec.Source == "" {
				rec.Source = ep.name
			}
			return rec, nil
		}
		lastErr = err
	}
	if rec := whoisFallback(ctx, ip); rec != nil {
		return rec, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no RDAP data")
	}
	return nil, lastErr
}

// rdapEntity — контакт или организация в ответе RDAP. Сущности вложены друг
// в друга, поэтому тип рекурсивный.
type rdapEntity struct {
	Handle     string          `json:"handle"`
	Roles      []string        `json:"roles"`
	VCardArray json.RawMessage `json:"vcardArray"`
	Entities   []rdapEntity    `json:"entities"`
}

// rdapPayload — та часть ответа RDAP, которая нам нужна. Остальные поля
// (ссылки, уведомления, история) игнорируются.
type rdapPayload struct {
	Handle       string `json:"handle"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Country      string `json:"country"`
	Port43       string `json:"port43"`
	Events       []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []rdapEntity `json:"entities"`
	Remarks  []struct {
		Title       string   `json:"title"`
		Description []string `json:"description"`
	} `json:"remarks"`
	CIDRs []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
}

// fetchRDAP выполняет один запрос и превращает ответ в модель отчёта.
func fetchRDAP(ctx context.Context, c *http.Client, endpoint, ip string) (*report.RDAP, error) {
	resp, err := netutil.Get(ctx, c, endpoint, 512<<10, map[string]string{"Accept": "application/rdap+json"})
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("rdap %s: HTTP %d", endpoint, resp.Status)
	}
	var p rdapPayload
	if err := json.Unmarshal(resp.Body, &p); err != nil {
		return nil, err
	}
	if p.StartAddress == "" && p.Handle == "" && p.Name == "" {
		return nil, errors.New("rdap: empty record")
	}

	rec := &report.RDAP{
		Query:   ip,
		Handle:  p.Handle,
		Name:    p.Name,
		StartIP: p.StartAddress,
		EndIP:   p.EndAddress,
		Type:    p.Type,
		Country: p.Country,
	}
	for _, c := range p.CIDRs {
		switch {
		case c.V4Prefix != "":
			rec.CIDR = append(rec.CIDR, fmt.Sprintf("%s/%d", c.V4Prefix, c.Length))
		case c.V6Prefix != "":
			rec.CIDR = append(rec.CIDR, fmt.Sprintf("%s/%d", c.V6Prefix, c.Length))
		}
	}
	for _, e := range p.Events {
		switch strings.ToLower(e.Action) {
		case "registration":
			rec.Registered = shortDate(e.Date)
		case "last changed", "last update of rdap database":
			if rec.Updated == "" {
				rec.Updated = shortDate(e.Date)
			}
		}
	}
	rec.Registry = registryFromPort43(p.Port43)
	if rec.Registry == "" && resp.URL != nil {
		rec.Registry = resp.URL.Host
	}
	for _, r := range p.Remarks {
		if len(r.Description) > 0 {
			rec.Remarks = append(rec.Remarks, strings.Join(r.Description, " "))
		}
	}
	if len(rec.Remarks) > 3 {
		rec.Remarks = rec.Remarks[:3]
	}

	// Собираем участников записи, отбрасывая дубликаты и maintainer-объекты.
	seen := map[string]bool{}
	for _, e := range p.Entities {
		name, _, _, country := parseVCard(e.VCardArray)
		if isMaintainer(e.Handle, name) {
			// Объекты-maintainer (FOO-MNT) не несут сведений о владельце.
			continue
		}
		key := e.Handle + "|" + name
		if !seen[key] && (name != "" || e.Handle != "") {
			seen[key] = true
			rec.Entities = append(rec.Entities, report.RDAPEntity{
				Handle: e.Handle, Name: name, Roles: e.Roles, Country: country,
			})
		}
	}
	// Больше четырёх участников в отчёт не помещается и не читается.
	if len(rec.Entities) > 4 {
		rec.Entities = rec.Entities[:4]
	}
	if a := findAbuse(p.Entities); a != nil {
		rec.Abuse = a
	}
	return rec, nil
}

// findAbuse рекурсивно ищет контакт с ролью abuse.
// Обход именно рекурсивный: у RIPE такой контакт часто вложен в организацию,
// а не лежит на верхнем уровне записи.
func findAbuse(entities []rdapEntity) *report.RDAPContact {
	for _, e := range entities {
		for _, r := range e.Roles {
			if strings.EqualFold(r, "abuse") {
				name, email, phone, _ := parseVCard(e.VCardArray)
				if email != "" || phone != "" || name != "" {
					return &report.RDAPContact{Name: name, Email: email, Phone: phone}
				}
			}
		}
		if a := findAbuse(e.Entities); a != nil {
			return a
		}
	}
	return nil
}

// parseVCard достаёт имя, почту, телефон и страну из jCard (RFC 7095) —
// это визитка в виде вложенных JSON-массивов вида
// ["vcard", [["fn", {}, "text", "Имя"], ["email", {}, "text", "a@b"], …]].
// Разбираем вручную: описывать такую структуру типами дороже, чем читать её
// по индексам.
func parseVCard(raw json.RawMessage) (name, email, phone, country string) {
	if len(raw) == 0 {
		return
	}
	var outer []json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil || len(outer) < 2 {
		return
	}
	var props [][]json.RawMessage
	if err := json.Unmarshal(outer[1], &props); err != nil {
		return
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		var key string
		if err := json.Unmarshal(p[0], &key); err != nil {
			continue
		}
		switch strings.ToLower(key) {
		case "fn":
			if name == "" {
				name = asString(p[3])
			}
		case "email":
			if email == "" {
				email = asString(p[3])
			}
		case "tel":
			if phone == "" {
				phone = asString(p[3])
			}
		case "adr":
			if country == "" {
				country = lastAddressPart(p[3])
			}
		}
	}
	return
}

// asString приводит значение jCard к строке: оно бывает и строкой, и
// массивом строк (например, многострочный адрес).
func asString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return strings.TrimSpace(strings.Join(nonEmpty(arr), ", "))
	}
	return ""
}

// lastAddressPart возвращает последний непустой элемент адреса из jCard —
// это страна. Формат adr — массив из семи полей, часть которых обычно пуста.
func lastAddressPart(raw json.RawMessage) string {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return ""
	}
	for i := len(arr) - 1; i >= 0; i-- {
		if s := asString(arr[i]); s != "" {
			return s
		}
	}
	return ""
}

// nonEmpty убирает пустые элементы и лишние пробелы.
func nonEmpty(in []string) []string {
	out := in[:0:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

// isMaintainer распознаёт служебные объекты RIPE вида FOO-MNT: они не несут
// сведений о владельце и только засоряют отчёт повторами.
func isMaintainer(handle, name string) bool {
	h := strings.ToUpper(handle)
	return strings.HasSuffix(h, "-MNT") && (name == "" || strings.EqualFold(name, handle))
}

// registryFromPort43 определяет реестр по адресу whois-сервера из поля port43
// ответа (whois.ripe.net -> RIPE NCC). Если хост незнакомый, возвращается как
// есть.
func registryFromPort43(p string) string {
	switch {
	case strings.Contains(p, "ripe"):
		return "RIPE NCC"
	case strings.Contains(p, "arin"):
		return "ARIN"
	case strings.Contains(p, "apnic"):
		return "APNIC"
	case strings.Contains(p, "lacnic"):
		return "LACNIC"
	case strings.Contains(p, "afrinic"):
		return "AFRINIC"
	}
	return p
}

// shortDate оставляет от даты только YYYY-MM-DD: время регистрации сети в
// отчёте не нужно.
func shortDate(s string) string {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.Format("2006-01-02")
	}
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}

// whoisFallback вызывает системный whois, когда RDAP недоступен, и вытаскивает
// из текстового ответа те же поля, что даёт RDAP.
//
// ip обязан быть уже проверенным адресом: whois трактует ведущий дефис как
// флаг, а -h перенаправляет запрос на чужой сервер. Проверка продублирована
// здесь намеренно — функция не должна зависеть от того, что её вызвали
// правильно.
func whoisFallback(ctx context.Context, ip string) *report.RDAP {
	if net.ParseIP(ip) == nil {
		return nil
	}
	bin, err := exec.LookPath("whois")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, ip).Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	rec := &report.RDAP{Query: ip, Source: "whois (" + bin + ")"}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch k {
		case "netname", "inetnum", "netrange":
			if k == "netname" && rec.Name == "" {
				rec.Name = v
			} else if rec.StartIP == "" {
				if s, e, ok := strings.Cut(v, "-"); ok {
					rec.StartIP, rec.EndIP = strings.TrimSpace(s), strings.TrimSpace(e)
				}
			}
		case "cidr":
			rec.CIDR = append(rec.CIDR, v)
		case "org-name", "orgname", "organization", "owner", "descr":
			if len(rec.Entities) == 0 {
				rec.Entities = append(rec.Entities, report.RDAPEntity{Name: v, Roles: []string{"registrant"}})
			}
		case "country":
			if rec.Country == "" {
				rec.Country = v
			}
		case "status", "nettype":
			if rec.Type == "" {
				rec.Type = v
			}
		case "abuse-mailbox", "orgabuseemail":
			if rec.Abuse == nil {
				rec.Abuse = &report.RDAPContact{Email: v}
			}
		case "created", "regdate":
			if rec.Registered == "" {
				rec.Registered = shortDate(v)
			}
		case "last-modified", "updated":
			if rec.Updated == "" {
				rec.Updated = shortDate(v)
			}
		}
	}
	if rec.Name == "" && len(rec.Entities) == 0 {
		return nil
	}
	return rec
}
