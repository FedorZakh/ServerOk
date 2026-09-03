package netcheck

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// cymru.go — определение автономной системы (ASN) по IP-адресу через
// DNS-интерфейс проекта Team Cymru.
//
// Зачем: сами по себе адреса хопов в трассировке мало что говорят, а вот
// «AS1299 Telia» или «AS4134 China Telecom» сразу показывают, через каких
// транзитных операторов идёт трафик — это главное, ради чего смотрят
// трассировку при выборе хостера.
//
// Запрос — обычный TXT к origin.asn.cymru.com; отдельным запросом
// расшифровывается название AS. Результаты кэшируются: в одной трассировке
// соседние хопы часто принадлежат одной сети, а сервис ограничивает частоту.
var (
	asnMu    sync.Mutex
	asnCache = map[string]asnInfo{}
)

type asnInfo struct {
	ASN string
	Org string
}

// LookupASN возвращает номер и название автономной системы для IPv4-адреса.
// При любой неудаче возвращаются пустые строки — это не ошибка, просто в
// отчёте у хопа не будет подписи.
func LookupASN(ctx context.Context, ip string) (asn, org string) {
	asnMu.Lock()
	if v, ok := asnCache[ip]; ok {
		asnMu.Unlock()
		return v.ASN, v.Org
	}
	asnMu.Unlock()

	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", ""
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	r := &net.Resolver{}
	v4 := parsed.To4()
	q := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	txt, err := r.LookupTXT(ctx, q)
	if err != nil || len(txt) == 0 {
		return "", ""
	}
	// Формат ответа: "13335 | 1.1.1.0/24 | US | arin | 2010-07-14"
	fields := strings.Split(txt[0], "|")
	if len(fields) == 0 {
		return "", ""
	}
	num := strings.Fields(strings.TrimSpace(fields[0]))
	if len(num) == 0 {
		return "", ""
	}
	asn = "AS" + num[0]
	org = asnName(ctx, r, num[0])

	asnMu.Lock()
	asnCache[ip] = asnInfo{ASN: asn, Org: org}
	asnMu.Unlock()
	return asn, org
}

// asnName расшифровывает номер AS в название оператора.
func asnName(ctx context.Context, r *net.Resolver, num string) string {
	txt, err := r.LookupTXT(ctx, "AS"+num+".asn.cymru.com")
	if err != nil || len(txt) == 0 {
		return ""
	}
	// Формат ответа: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
	// Последнее поле — название; хвостовой код страны отбрасываем.
	fields := strings.Split(txt[0], "|")
	if len(fields) < 5 {
		return ""
	}
	name := strings.TrimSpace(fields[4])
	if i := strings.LastIndex(name, ","); i > 0 {
		name = strings.TrimSpace(name[:i])
	}
	return name
}
