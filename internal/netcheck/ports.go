package netcheck

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/FedorZakh/ServerOk/internal/report"
)

// ports.go — проверка исходящих TCP-портов.
//
// Смысл теста: понять, что режет провайдер. Каждый порт проверяется по хосту,
// который заведомо на нём слушает, поэтому неудача означает блокировку, а не
// «сервер на той стороне выключен». Практически важнее всего почтовые порты:
// многие хостеры закрывают 25 (и иногда 465/587) по умолчанию, и об этом
// узнают, только когда перестаёт уходить почта.

// portProbe — один порт и хост, на котором он точно открыт.
type portProbe struct {
	port    int
	service string
	host    string
}

var portProbes = []portProbe{
	{22, "SSH", "github.com"},
	{25, "SMTP", "smtp.gmail.com"},
	{53, "DNS/TCP", "8.8.8.8"},
	{80, "HTTP", "example.com"},
	{443, "HTTPS", "cloudflare.com"},
	{465, "SMTPS", "smtp.gmail.com"},
	{587, "Submission", "smtp.gmail.com"},
	{993, "IMAPS", "imap.gmail.com"},
	{8080, "HTTP-alt", "portquiz.net"},
}

// Ports параллельно (не более шести соединений сразу) проверяет доступность
// исходящих портов.
func Ports(ctx context.Context, status func(string, ...any)) []report.PortResult {
	results := make([]report.PortResult, len(portProbes))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	for i, p := range portProbes {
		wg.Add(1)
		go func(i int, p portProbe) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := report.PortResult{Port: p.port, Service: p.service, Host: p.host}
			d := &net.Dialer{Timeout: 5 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.host, strconv.Itoa(p.port)))
			if err != nil {
				r.Err = report.Truncate(err.Error(), 40)
			} else {
				r.Open = true
				_ = conn.Close()
			}
			results[i] = r

			mu.Lock()
			done++
			status("ports: %d/%d probed", done, len(portProbes))
			mu.Unlock()
		}(i, p)
	}
	wg.Wait()
	return results
}
