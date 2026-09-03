// Пакет netcheck — сетевая часть тестов:
//   - speedtest.go — скорость канала через узлы speedtest.net;
//   - latency.go   — задержки до опорных точек мира (этот файл);
//   - trace.go     — трассировки с определением автономных систем;
//   - ports.go     — доступность исходящих портов (режет ли хостер SMTP);
//   - stack.go     — возможности стека: IPv4/IPv6, MTU, BBR, резолвер;
//   - cymru.go     — определение ASN по адресу через DNS Team Cymru.
package netcheck

// latency.go — измерение времени отклика до географически разнесённых точек.
//
// Метод выбирается автоматически и указывается в отчёте:
//  1. ICMP через непривилегированный datagram-сокет (работает без root там,
//     где ядро это разрешает);
//  2. ICMP через raw-сокет (нужен root);
//  3. TCP-рукопожатие на 443 порт — если ICMP не проходит вовсе.
//
// Третий вариант завышает результат примерно на треть (рукопожатие — это
// больше одного пакета), поэтому метод обязательно печатается рядом с цифрой:
// сравнивать значения, полученные разными способами, нельзя.

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/FedorZakh/ServerOk/internal/report"
)

// protocolICMP — номер протокола ICMPv4 по IANA, нужен для разбора пакета.
const protocolICMP = 1

// replyTimeout — сколько ждём ответ на один запрос.
const replyTimeout = 3 * time.Second

// Anchor — опорная точка: известный хост в конкретном регионе.
type Anchor struct {
	Name string
	Host string
}

// anchors покрывают основные регионы, чтобы по отчёту было видно качество
// маршрутизации хостера: до Европы 5 мс и до Азии 250 мс — нормально, а вот
// 300 мс до соседней страны означают кривой транзит.
//
// Все хосты выбраны так, чтобы отвечать и на TCP/443: иначе запасной метод
// измерения был бы бесполезен.
var anchors = []Anchor{
	{"Frankfurt, DE", "speedtest.frankfurt.linode.com"},
	{"Amsterdam, NL", "speedtest.ams1.nl.leaseweb.net"},
	{"London, UK", "speedtest.london.linode.com"},
	{"Newark, US", "speedtest.newark.linode.com"},
	{"Dallas, US", "speedtest.dallas.linode.com"},
	{"Fremont, US", "speedtest.fremont.linode.com"},
	{"Toronto, CA", "speedtest.toronto1.linode.com"},
	{"Singapore, SG", "speedtest.singapore.linode.com"},
	{"Tokyo, JP", "speedtest.tokyo2.linode.com"},
	{"Mumbai, IN", "speedtest.mumbai1.linode.com"},
	{"Sydney, AU", "speedtest.syd1.linode.com"},
}

// Latency измеряет задержку до всех опорных точек.
//
// Точки опрашиваются параллельно (не более четырёх сразу), чтобы прогон не
// растянулся на минуты; результат сортируется по возрастанию задержки, а
// недоступные точки уходят в конец списка.
func Latency(ctx context.Context, status func(string, ...any)) []report.LatencyResult {
	method := probeMethod()
	results := make([]report.LatencyResult, len(anchors))

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	for i, a := range anchors {
		wg.Add(1)
		go func(i int, a Anchor) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := report.LatencyResult{Name: a.Name, Host: a.Host}
			rtt, loss, used, err := pingHost(ctx, a.Host, method, 3)
			r.Method = used
			switch {
			case err != nil:
				r.Err = report.Truncate(err.Error(), 40)
			default:
				r.RTTMs = rtt
				r.LossPc = loss
			}
			results[i] = r

			mu.Lock()
			done++
			status("latency: %d/%d anchors probed", done, len(anchors))
			mu.Unlock()
		}(i, a)
	}
	wg.Wait()
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Err != "" || results[j].Err != "" {
			return results[i].Err == "" && results[j].Err != ""
		}
		return results[i].RTTMs < results[j].RTTMs
	})
	return results
}

// probeMethod выбирает лучший доступный способ измерения.
// Порядок проб: datagram-ICMP (без root), raw-ICMP (с root), TCP.
func probeMethod() string {
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		_ = c.Close()
		return "icmp"
	}
	if os.Geteuid() == 0 {
		if c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
			_ = c.Close()
			return "icmp-raw"
		}
	}
	return "tcp:443"
}

// pingHost сначала пробует ICMP и, если ответа нет, переключается на TCP.
// Возвращает в том числе фактически сработавший метод — он попадёт в отчёт.
func pingHost(ctx context.Context, host, method string, count int) (rttMs, lossPc float64, used string, err error) {
	if method != "tcp:443" {
		if rtt, loss, err := icmpPing(ctx, host, method, count); err == nil {
			return rtt, loss, method, nil
		}
	}
	rtt, loss, err := tcpPing(ctx, host, count)
	return rtt, loss, "tcp:443", err
}

// tcpPing меряет время установления TCP-соединения на 443 порт.
// Берётся лучший результат из нескольких попыток: он ближе всего к чистому
// времени пути, без случайных задержек планировщика.
func tcpPing(ctx context.Context, host string, count int) (float64, float64, error) {
	var best time.Duration
	var ok int
	d := &net.Dialer{Timeout: 4 * time.Second}
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		start := time.Now()
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
		if err != nil {
			continue
		}
		el := time.Since(start)
		_ = conn.Close()
		ok++
		if best == 0 || el < best {
			best = el
		}
	}
	if ok == 0 {
		return 0, 100, fmt.Errorf("no TCP response")
	}
	loss := float64(count-ok) / float64(count) * 100
	return float64(best.Microseconds()) / 1000, loss, nil
}

// icmpPing отправляет несколько echo-запросов и возвращает лучший результат
// и долю потерь.
func icmpPing(ctx context.Context, host, method string, count int) (float64, float64, error) {
	network, listen := "udp4", "0.0.0.0"
	raw := method == "icmp-raw"
	if raw {
		network = "ip4:icmp"
	}
	addr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, 100, err
	}
	conn, err := icmp.ListenPacket(network, listen)
	if err != nil {
		return 0, 100, err
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	var best time.Duration
	var ok int
	for seq := 0; seq < count; seq++ {
		if ctx.Err() != nil {
			break
		}
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("servertester")},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			return 0, 100, err
		}
		var dst net.Addr = &net.UDPAddr{IP: addr.IP}
		if raw {
			dst = &net.IPAddr{IP: addr.IP}
		}
		start := time.Now()
		if _, err := conn.WriteTo(wb, dst); err != nil {
			continue
		}
		if rtt, matched := awaitReply(conn, addr.IP, id, seq, raw, start); matched {
			ok++
			if best == 0 || rtt < best {
				best = rtt
			}
		}
	}
	if ok == 0 {
		return 0, 100, fmt.Errorf("no ICMP reply")
	}
	return float64(best.Microseconds()) / 1000, float64(count-ok) / float64(count) * 100, nil
}

// awaitReply читает пакеты, пока не встретит ответ именно на наш запрос.
//
// Это не перестраховка. Raw-сокет получает вообще все ICMP-пакеты, которые
// приходят на машину, а точки опрашиваются параллельно: без проверки
// отправителя и номера последовательности горутина, пингующая Токио, могла бы
// засчитать ответ из Амстердама и показать 5 мс вместо 250. На
// datagram-сокете ядро подменяет идентификатор echo своим, поэтому там
// сверяются только отправитель и номер последовательности.
func awaitReply(conn *icmp.PacketConn, target net.IP, id, seq int, raw bool, start time.Time) (time.Duration, bool) {
	deadline := time.Now().Add(replyTimeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, false
	}
	rb := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return 0, false // deadline or socket error
		}
		if !peerIs(peer, target) {
			continue
		}
		parsed, err := icmp.ParseMessage(protocolICMP, rb[:n])
		if err != nil || parsed.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, isEcho := parsed.Body.(*icmp.Echo)
		if !isEcho || echo.Seq != seq {
			continue
		}
		if raw && echo.ID != id {
			continue
		}
		return time.Since(start), true
	}
	return 0, false
}

// peerIs проверяет, что пакет пришёл именно от опрашиваемого хоста.
// Тип адреса зависит от режима сокета: UDPAddr для datagram, IPAddr для raw.
func peerIs(peer net.Addr, target net.IP) bool {
	switch a := peer.(type) {
	case *net.UDPAddr:
		return a.IP.Equal(target)
	case *net.IPAddr:
		return a.IP.Equal(target)
	default:
		return false
	}
}
