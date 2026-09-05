package whois

// dns.go — то, что домен отвечает в DNS прямо сейчас. Регистрационная запись
// говорит, кому домен принадлежит и какие NS у него делегированы, но не
// говорит, работает ли он: делегирование бывает на серверы, которые давно не
// отвечают, а A-запись — на давно освободившийся адрес. Для отчёта, который
// человек читает перед покупкой домена или при разборе аварии, второе не
// менее важно, чем первое.
//
// Резолвер здесь системный, а не публичный: вопрос ровно в том, что видит
// этот сервер со своими настройками DNS.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/report"
)

const (
	dnsTimeout = 8 * time.Second
	// TXT-записей у крупных доменов десятки (SPF, DKIM, подтверждения прав
	// для десятка сервисов) — в отчёт идут только первые.
	maxTXT    = 6
	maxTXTLen = 96
)

// lookupDNS опрашивает основные типы записей параллельно: запросы независимы,
// а последовательно они складывались бы в заметную паузу на медленном
// резолвере.
func lookupDNS(ctx context.Context, domain string) *report.DomainDNS {
	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	var (
		r   net.Resolver
		out report.DomainDNS
		mu  sync.Mutex
		wg  sync.WaitGroup
	)
	run := func(f func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f()
		}()
	}

	run(func() {
		ips, err := r.LookupIP(ctx, "ip4", domain)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			// Ошибка A-записи — самая информативная из всех: именно она
			// отличает «домен не делегирован» от «делегирован, но пуст».
			out.Err = dnsError(err)
		}
		for _, ip := range ips {
			out.A = append(out.A, ip.String())
		}
	})
	run(func() {
		ips, _ := r.LookupIP(ctx, "ip6", domain)
		mu.Lock()
		defer mu.Unlock()
		for _, ip := range ips {
			out.AAAA = append(out.AAAA, ip.String())
		}
	})
	run(func() {
		ns, _ := r.LookupNS(ctx, domain)
		mu.Lock()
		defer mu.Unlock()
		for _, s := range ns {
			out.NS = append(out.NS, strings.TrimSuffix(strings.ToLower(s.Host), "."))
		}
		sort.Strings(out.NS)
	})
	run(func() {
		mx, _ := r.LookupMX(ctx, domain)
		mu.Lock()
		defer mu.Unlock()
		for _, m := range mx {
			out.MX = append(out.MX, fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(strings.ToLower(m.Host), ".")))
		}
	})
	run(func() {
		txt, _ := r.LookupTXT(ctx, domain)
		mu.Lock()
		defer mu.Unlock()
		for i, t := range txt {
			if i == maxTXT {
				out.TXTMore = len(txt) - maxTXT
				break
			}
			out.TXT = append(out.TXT, report.Truncate(t, maxTXTLen))
		}
	})
	run(func() {
		cname, err := r.LookupCNAME(ctx, domain)
		mu.Lock()
		defer mu.Unlock()
		// Резолвер возвращает сам домен, если псевдонима нет.
		if err == nil && !strings.EqualFold(strings.TrimSuffix(cname, "."), domain) {
			out.CNAME = strings.TrimSuffix(strings.ToLower(cname), ".")
		}
	})
	wg.Wait()

	if len(out.A) == 0 && len(out.AAAA) == 0 && len(out.NS) == 0 && len(out.MX) == 0 && out.Err == "" {
		out.Err = "no records"
	}
	return &out
}

// dnsError сокращает многословную ошибку резолвера до сути: строка идёт в
// отчёт, где на неё отведена одна колонка.
func dnsError(err error) string {
	var d *net.DNSError
	if errors.As(err, &d) {
		switch {
		case d.IsNotFound:
			return "NXDOMAIN (no such name)"
		case d.IsTimeout:
			return "resolver timeout"
		}
		return d.Err
	}
	return err.Error()
}
