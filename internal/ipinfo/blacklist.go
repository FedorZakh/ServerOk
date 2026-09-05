package ipinfo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

// blacklist.go — проверка репутации адреса по чёрным спискам (DNSBL).
//
// Как это работает: октеты адреса переворачиваются и приписываются к имени
// зоны — например, 203.0.113.7 в zen.spamhaus.org превращается в запрос A
// для 7.113.0.203.zen.spamhaus.org. Ответ 127.0.0.x означает «адрес в
// списке», NXDOMAIN — «чист».
//
// Практический смысл для владельца VPS: попадание в списки ломает исходящую
// почту и иногда доступ к сайтам за антиспам-фильтрами.
//
// dnsblZones — опрашиваемые зоны. Некоторые из них отказывают публичным
// резолверам, но это тоже полезный ответ: он честно показывается как
// «проверить не удалось».
var dnsblZones = []string{
	"zen.spamhaus.org",
	"b.barracudacentral.org",
	"bl.spamcop.net",
	"dnsbl.sorbs.net",
	"psbl.surriel.com",
	"db.wpbl.info",
	"ubl.unsubscore.com",
	"dnsbl-1.uceprotect.net",
	"bl.blocklist.de",
	"all.s5h.net",
	"truncate.gbudb.net",
	"dnsbl.dronebl.org",
	"rbl.interserver.net",
	"spam.dnsbl.anonmails.de",
}

// CheckBlacklists параллельно опрашивает все зоны для указанного IPv4.
//
// Только IPv4: подавляющее большинство списков не поддерживает IPv6.
// progress вызывается по мере готовности зон — им рисуется строка прогресса.
func CheckBlacklists(ctx context.Context, ip string, progress func(done, total int)) (*report.Blacklist, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil, fmt.Errorf("blacklist check needs an IPv4 address, got %q", ip)
	}
	rev := reverseIPv4(parsed.To4())

	out := &report.Blacklist{IP: ip, Checked: len(dnsblZones), Resolver: systemResolver()}
	entries := make([]report.BlacklistZone, len(dnsblZones))

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	for i, zone := range dnsblZones {
		wg.Add(1)
		go func(i int, zone string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			entries[i] = queryZone(ctx, rev, zone)
			mu.Lock()
			done++
			if progress != nil {
				progress(done, len(dnsblZones))
			}
			mu.Unlock()
		}(i, zone)
	}
	wg.Wait()

	for _, e := range entries {
		if e.Status == "listed" {
			out.ListedCount++
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return rank(entries[i].Status) < rank(entries[j].Status) })
	out.Entries = entries
	return out, nil
}

// rank задаёт порядок вывода: сначала попадания (главное, что нужно увидеть),
// затем неопределённые зоны, ошибки и в конце — чистые.
func rank(status string) int {
	switch status {
	case "listed":
		return 0
	case "unavailable":
		return 1
	case "error":
		return 2
	default:
		return 3
	}
}

var dnsResolver = &net.Resolver{}

// queryZone опрашивает одну зону и трактует результат.
//
// Ключевой момент: NXDOMAIN (IsNotFound) — это «адреса нет в списке», то есть
// хорошая новость, а не ошибка. Любая другая ошибка DNS — именно ошибка, и
// выдавать её за «чисто» нельзя.
func queryZone(ctx context.Context, rev, zone string) report.BlacklistZone {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	host := rev + "." + zone
	addrs, err := dnsResolver.LookupHost(ctx, host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return report.BlacklistZone{Zone: zone, Status: "clean"}
		}
		return report.BlacklistZone{Zone: zone, Status: "error", Reason: shortErr(err)}
	}
	if len(addrs) == 0 {
		return report.BlacklistZone{Zone: zone, Status: "clean"}
	}
	code := strings.Join(addrs, ",")
	// Ответ 127.255.255.x — не попадание, а отказ обслуживать запрос: так
	// Spamhaus и UCEPROTECT отвечают публичным резолверам (1.1.1.1, 8.8.8.8)
	// и при превышении лимита. Показать это как «в списке» было бы ложной
	// тревогой, поэтому статус — unavailable.
	for _, a := range addrs {
		if strings.HasPrefix(a, "127.255.255.") {
			return report.BlacklistZone{Zone: zone, Status: "unavailable", Code: a,
				Reason: "query refused (use a private resolver)"}
		}
	}
	reason := lookupTXT(ctx, host)
	return report.BlacklistZone{Zone: zone, Status: "listed", Code: code, Reason: reason}
}

// lookupTXT запрашивает TXT-запись — в ней зоны обычно объясняют причину
// попадания и дают ссылку на удаление.
func lookupTXT(ctx context.Context, host string) string {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	txt, err := dnsResolver.LookupTXT(ctx, host)
	if err != nil || len(txt) == 0 {
		return ""
	}
	return report.Truncate(txt[0], 60)
}

func shortErr(err error) string { return report.Truncate(err.Error(), 40) }

// reverseIPv4 переворачивает октеты: 203.0.113.7 -> 7.113.0.203.
func reverseIPv4(ip net.IP) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[3], ip[2], ip[1], ip[0])
}

// systemResolver возвращает первый nameserver из /etc/resolv.conf.
// Показывается в отчёте: от того, публичный резолвер или свой, зависит,
// ответят ли вообще некоторые зоны.
func systemResolver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			return fields[1]
		}
	}
	return ""
}
