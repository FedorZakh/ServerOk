// Пакет whois — сбор всего, что известно о домене: регистрационная запись
// (кто регистратор, когда домен создан и когда истекает, какие у него NS) и
// то, что домен отвечает в DNS прямо сейчас.
//
// Источников два, и они дополняют друг друга:
//
//  1. www.whois.com — отдаёт уже разобранную запись, одинаково выглядящую для
//     всех TLD, и заодно сырой текст ответа реестра. Это основной источник:
//     он же указан в задаче и он единственный, кто нормализует поля ccTLD.
//  2. WHOIS на порту 43 (RFC 3912) — прямой запрос к реестру и регистратору.
//     Нужен потому, что whois.com периодически прячет страницу за проверкой
//     «вы не робот»: тогда в HTML нет ни одного поля, и без второго источника
//     тест возвращал бы пустой отчёт.
//
// Порядок именно такой, а не наоборот: у whois.com одна страница на домен, а
// цепочка port 43 — это два-три TCP-соединения к разным серверам.
package whois

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

// Lookup собирает отчёт по домену. Ошибка возвращается только если данных нет
// вообще: частичный результат (скажем, whois.com отказал, но реестр ответил)
// полезнее пустого, а о том, что именно не сложилось, говорит поле Notes.
func Lookup(ctx context.Context, input string, status func(string, ...any)) (*report.DomainInfo, error) {
	name, unicodeName, err := Normalize(input)
	if err != nil {
		return nil, err
	}
	info := &report.DomainInfo{Domain: name, Unicode: unicodeName}

	status("whois: querying whois.com for %s", name)
	site, err := fetchSite(ctx, name)
	switch {
	case err != nil:
		info.Notes = append(info.Notes, "whois.com: "+err.Error())
	case site != nil:
		merge(info, site)
		info.Sources = append(info.Sources, siteName)
	}

	// К реестру идём, если whois.com не дал главного — регистратора и дат.
	// Полный ответ обоих источников совпадает, лишний обход сети ни к чему.
	if needsRegistry(info) {
		raw, servers, err := queryChain(ctx, name, status)
		switch {
		case err != nil:
			info.Notes = append(info.Notes, "whois port 43: "+err.Error())
		case raw != "":
			rec := parseRaw(raw)
			merge(info, rec)
			if info.Raw == "" {
				info.Raw = raw
			}
			info.Sources = append(info.Sources, servers...)
		}
	}

	status("whois: resolving DNS records for %s", name)
	info.DNS = lookupDNS(ctx, name)
	info.ExpiresDays = daysUntil(info.Expires)

	if !info.Available && info.Registrar == nil && info.Registered == "" && len(info.NameServers) == 0 {
		if len(info.Notes) > 0 {
			return nil, errors.New(strings.Join(info.Notes, "; "))
		}
		return nil, fmt.Errorf("no WHOIS data for %s", name)
	}
	return info, nil
}

// needsRegistry решает, стоит ли идти на порт 43 после whois.com.
// Свободный домен переспрашивать не нужно: «нет записи» — это уже ответ.
func needsRegistry(d *report.DomainInfo) bool {
	if d.Available {
		return false
	}
	return d.Registrar == nil || d.Registered == "" || d.Expires == "" || d.Raw == ""
}

// merge переносит в отчёт всё, чего в нём ещё нет. Первый источник главнее:
// поля whois.com уже нормализованы, а свободный текст реестра разобран
// эвристиками, и переписывать им готовое значение — только терять точность.
func merge(dst, src *report.DomainInfo) {
	if src == nil {
		return
	}
	if src.Available {
		dst.Available = true
	}
	setIfEmpty(&dst.Registered, src.Registered)
	setIfEmpty(&dst.Updated, src.Updated)
	setIfEmpty(&dst.Expires, src.Expires)
	setIfEmpty(&dst.DNSSEC, src.DNSSEC)
	setIfEmpty(&dst.Raw, src.Raw)
	if len(dst.Status) == 0 {
		dst.Status = src.Status
	}
	if len(dst.NameServers) == 0 {
		dst.NameServers = src.NameServers
	}
	if src.Registrar != nil {
		if dst.Registrar == nil {
			dst.Registrar = &report.Registrar{}
		}
		setIfEmpty(&dst.Registrar.Name, src.Registrar.Name)
		setIfEmpty(&dst.Registrar.IANAID, src.Registrar.IANAID)
		setIfEmpty(&dst.Registrar.URL, src.Registrar.URL)
		setIfEmpty(&dst.Registrar.WhoisServer, src.Registrar.WhoisServer)
		setIfEmpty(&dst.Registrar.AbuseEmail, src.Registrar.AbuseEmail)
		setIfEmpty(&dst.Registrar.AbusePhone, src.Registrar.AbusePhone)
	}
	for _, c := range src.Contacts {
		if !hasContact(dst.Contacts, c.Role) {
			dst.Contacts = append(dst.Contacts, c)
		}
	}
}

func setIfEmpty(dst *string, v string) {
	if *dst == "" {
		*dst = strings.TrimSpace(v)
	}
}

func hasContact(list []report.DomainContact, role string) bool {
	for _, c := range list {
		if strings.EqualFold(c.Role, role) {
			return true
		}
	}
	return false
}

// Normalize приводит введённое пользователем к имени домена в ASCII и
// возвращает вторым значением исходное написание, если домен интернационален
// (пример.рф -> xn--e1afmkfd.xn--p1ai).
//
// Функция намеренно строгая: это имя уходит и в URL whois.com, и в запрос на
// порт 43, где ответ сервера — свободный текст, который потом разбирается
// эвристиками. Всё, что не является доменным именем (пробелы, слэши,
// управляющие символы), отсекается здесь, а не «где-нибудь дальше».
func Normalize(input string) (ascii, unicodeName string, err error) {
	s := strings.TrimSpace(input)
	// Люди вставляют ссылку целиком: "https://example.com/path?a=b".
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	if _, rest, ok := strings.Cut(s, "@"); ok { // "user@host" и почтовый адрес
		s = rest
	}
	s, _, _ = strings.Cut(s, "/")
	s, _, _ = strings.Cut(s, "?")
	s, _, _ = strings.Cut(s, "#")
	s, _, _ = strings.Cut(s, ":") // порт
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "."))
	if s == "" {
		return "", "", errors.New("no domain given")
	}
	// IP-адрес — частая оговорка: его регистрационная запись есть, но лежит
	// она в RDAP, а не в WHOIS домена, и её показывает тест «ip».
	if net.ParseIP(s) != nil {
		return "", "", fmt.Errorf("%s is an address, not a domain (use the ip test)", s)
	}
	// www — не регистрируемое имя, а поддомен: у реестра записи о нём нет.
	s = strings.TrimPrefix(s, "www.")

	ascii = s
	if !isASCII(s) {
		// idna.Lookup — профиль для поиска: он проверяет имя строже, чем
		// профиль регистрации, и именно так домен ищут резолверы.
		ascii, err = idna.Lookup.ToASCII(s)
		if err != nil {
			return "", "", fmt.Errorf("%q is not a valid domain name", report.Truncate(input, 40))
		}
		unicodeName = s
	}
	if err := validate(ascii); err != nil {
		return "", "", err
	}
	return ascii, unicodeName, nil
}

// validate проверяет имя по синтаксису DNS: метки из букв, цифр и дефисов,
// не длиннее 63 символов, дефис не с краю, минимум две метки (TLD целиком
// спрашивать бессмысленно — у него нет регистрационной записи).
func validate(name string) error {
	bad := func() error {
		return fmt.Errorf("%q is not a valid domain name", report.Truncate(name, 40))
	}
	if len(name) > 253 {
		return bad()
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%q looks like a TLD, not a domain (try example.%s)", report.Truncate(name, 20), name)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return bad()
		}
		for _, r := range l {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return bad()
			}
		}
	}
	return nil
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}
