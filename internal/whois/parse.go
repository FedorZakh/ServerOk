package whois

// parse.go — разбор ответа WHOIS, который приходит свободным текстом.
//
// Единого формата у WHOIS нет: gTLD более или менее следуют шаблону ICANN
// («Registrar:», «Creation Date:»), европейские реестры пишут по-своему
// («changed:», «nserver:»), .ru — по-третьему («paid-till:», «state:»).
// Поэтому подписи полей приводятся к общему виду (нижний регистр, дефисы —
// в пробелы) и сопоставляются по списку синонимов.
//
// Правило разбора одно: первое встреченное значение выигрывает. Ответы
// реестра и регистратора склеены в один текст, реестр идёт первым и он
// авторитетнее в датах и статусах, а у регистратора берётся то, чего реестр
// не хранит, — контакты и NS.

import (
	"regexp"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

// reNoMatch — ответы «такого домена нет». Формулировка у каждого реестра
// своя, общего кода ответа в протоколе не предусмотрено.
var reNoMatch = regexp.MustCompile(`(?i)(no match for|not found|no entries found|no data found|no object found|domain .* is (available|free)|status:\s*(available|free))`)

// parseRaw разбирает текст ответа WHOIS в модель отчёта.
func parseRaw(raw string) *report.DomainInfo {
	d := &report.DomainInfo{Raw: raw}
	if reNoMatch.MatchString(raw) {
		d.Available = true
	}
	seenStatus, seenNS := map[string]bool{}, map[string]bool{}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		// Комментарии и юридические примечания: у реестров они начинаются с
		// %, # или >>>, и внутри встречаются двоеточия, похожие на поля.
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		rawKey, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k := normalizeKey(rawKey)
		v = strings.TrimSpace(v)
		if v == "" || isRedacted(v) {
			continue
		}

		switch k {
		case "registrar", "registrar name", "sponsoring registrar":
			registrar(d).Name = first(registrar(d).Name, v)
		case "registrar iana id", "sponsoring registrar iana id":
			registrar(d).IANAID = first(registrar(d).IANAID, v)
		case "registrar url", "registrar website":
			registrar(d).URL = first(registrar(d).URL, v)
		case "registrar whois server", "whois server":
			registrar(d).WhoisServer = first(registrar(d).WhoisServer, v)
		case "registrar abuse contact email", "abuse contact email", "abuse mailbox":
			registrar(d).AbuseEmail = first(registrar(d).AbuseEmail, v)
		case "registrar abuse contact phone", "abuse contact phone":
			registrar(d).AbusePhone = first(registrar(d).AbusePhone, v)

		case "creation date", "created", "created on", "created date", "registered on",
			"registration date", "registration time", "domain registration date":
			d.Registered = first(d.Registered, normalizeDate(v))
		case "updated date", "update date", "last updated", "last update", "last modified",
			"changed", "modified", "last updated on":
			d.Updated = first(d.Updated, normalizeDate(v))
		case "registry expiry date", "expiry date", "expiration date", "expires on", "expire date",
			"paid till", "registrar registration expiration date", "expiration time", "renewal date":
			d.Expires = first(d.Expires, normalizeDate(v))

		case "domain status", "status", "state":
			// Реестры пишут статус то по одному в строке со ссылкой на его
			// описание («clientHold https://icann.org/epp#clientHold»), то
			// списком через запятую (так делает .ru).
			for _, part := range strings.Split(v, ",") {
				f := strings.Fields(part)
				if len(f) == 0 {
					continue
				}
				s := f[0]
				if !seenStatus[strings.ToLower(s)] {
					seenStatus[strings.ToLower(s)] = true
					d.Status = append(d.Status, s)
				}
			}
		case "name server", "nameserver", "nserver", "name servers", "host name":
			for _, h := range hosts([]string{v}) {
				if !seenNS[h] {
					seenNS[h] = true
					d.NameServers = append(d.NameServers, h)
				}
			}
		case "dnssec":
			d.DNSSEC = first(d.DNSSEC, v)

		// .ru и другие реестры без ролевых префиксов: организация владельца
		// пишется просто как «org».
		case "org", "organization":
			setContact(d, "registrant", "organization", v)
		case "person":
			setContact(d, "registrant", "name", v)
		case "admin contact":
			setContact(d, "admin", "email", v)

		default:
			if role, field, ok := contactField(k); ok {
				setContact(d, role, field, v)
			}
		}
	}
	return d
}

// contactField распознаёт поля вида «registrant organization», «admin email»,
// «tech phone» и возвращает роль и поле по отдельности.
func contactField(k string) (role, field string, ok bool) {
	prefixes := map[string]string{
		"registrant ": "registrant", "holder ": "registrant", "owner ": "registrant",
		"admin ": "admin", "administrative ": "admin",
		"tech ": "tech", "technical ": "tech",
		"billing ": "billing",
	}
	for p, r := range prefixes {
		rest, found := strings.CutPrefix(k, p)
		if !found {
			continue
		}
		switch rest {
		case "name", "organization", "org", "email", "e mail", "phone", "country", "city", "state province", "state":
			return r, rest, true
		}
	}
	return "", "", false
}

// setContact дописывает поле контакта, заводя запись при первом упоминании.
func setContact(d *report.DomainInfo, role, field, v string) {
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
	switch field {
	case "name":
		c.Name = first(c.Name, v)
	case "organization", "org":
		c.Org = first(c.Org, v)
	case "email", "e mail":
		// Ссылку на веб-форму (её пишут вместо адреса после GDPR) кладём в
		// отдельное поле, чтобы она не выдавала себя за рабочий e-mail.
		if strings.Contains(v, "@") {
			c.Email = first(c.Email, v)
		} else if strings.HasPrefix(v, "http") {
			c.Web = first(c.Web, v)
		}
	case "phone":
		c.Phone = first(c.Phone, v)
	case "country":
		c.Country = first(c.Country, v)
	case "city", "state", "state province":
		c.Location = first(c.Location, v)
	}
}

// registrar возвращает блок регистратора, создавая его при первом обращении.
func registrar(d *report.DomainInfo) *report.Registrar {
	if d.Registrar == nil {
		d.Registrar = &report.Registrar{}
	}
	return d.Registrar
}

// first реализует правило «первое значение выигрывает».
func first(have, v string) string {
	if have != "" {
		return have
	}
	return strings.TrimSpace(v)
}

// isRedacted отсеивает заглушки, которыми реестры заменяют скрытые по GDPR
// данные: записать их в отчёт — значит показать «Registrant: REDACTED FOR
// PRIVACY» вместо честного отсутствия поля.
func isRedacted(v string) bool {
	l := strings.ToLower(v)
	for _, m := range []string{"redacted", "data protected", "not disclosed", "privacy", "statutory masking", "gdpr masked"} {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}

// normalizeKey приводит подпись поля к общему виду: нижний регистр, дефисы и
// подчёркивания — в пробелы, повторные пробелы схлопываются. Так «Registrar
// Abuse Contact Email», «registrar-abuse-contact-email» и «abuse-mailbox»
// сравниваются с одним и тем же списком синонимов.
func normalizeKey(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	k = strings.NewReplacer("-", " ", "_", " ", ".", " ").Replace(k)
	return strings.Join(strings.Fields(k), " ")
}

// dateLayouts — форматы дат, встречающиеся в ответах WHOIS. Список именно
// такой длины не от любви к перечислениям: сколько реестров, столько и
// привычек записывать дату.
var dateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05.000Z",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05 MST",
	"2006-01-02",
	"02-Jan-2006 15:04:05 MST",
	"02-Jan-2006",
	"2006.01.02 15:04:05",
	"2006.01.02",
	"02.01.2006 15:04:05",
	"02.01.2006",
	"Mon Jan 2 15:04:05 MST 2006",
	"20060102",
}

// normalizeDate приводит дату к YYYY-MM-DD. Нераспознанное значение
// возвращается как есть: показать непривычный формат лучше, чем потерять дату.
func normalizeDate(v string) string {
	v = strings.TrimSpace(v)
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, v); err == nil {
			return t.Format("2006-01-02")
		}
	}
	if len(v) >= 10 {
		if t, err := time.Parse("2006-01-02", v[:10]); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return v
}

// daysUntil считает, сколько дней осталось до даты. Ноль означает «дата
// неизвестна или сегодня»; отрицательное число — домен уже просрочен.
func daysUntil(date string) int {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return 0
	}
	return int(time.Until(t).Hours() / 24)
}
