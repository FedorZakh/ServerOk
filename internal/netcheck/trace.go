package netcheck

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/FedorZakh/ServerOk/internal/report"
)

// trace.go — трассировка маршрута с определением автономных систем.
//
// Способы, в порядке предпочтения:
//  1. свой ICMP через raw-сокет (нужен root) — даёт полный контроль;
//  2. системный traceroute/tracepath, если он установлен;
//  3. если ни того, ни другого нет — тест честно помечается как пропущенный.
//
// Каждый хоп подписывается номером и названием автономной системы, поэтому по
// выводу видно, через каких транзитных операторов идёт трафик.

// traceTargets — направления, по которым обычно и оценивают качество VPS.
var traceTargets = []struct {
	Name string
	Host string
}{
	{"Cloudflare anycast", "1.1.1.1"},
	{"Google DNS (US)", "8.8.8.8"},
	{"Hetzner (Falkenstein, DE)", "88.198.248.254"},
	{"China Telecom (Shanghai, CN)", "202.96.209.133"},
}

// Traceroute строит маршрут до каждой цели и подписывает хопы автономными
// системами. Если ни один хоп не ответил, в примечании говорится, что ICMP
// отфильтрован, — иначе пустой список выглядел бы как ошибка программы.
func Traceroute(ctx context.Context, maxHops int, status func(string, ...any)) []report.Trace {
	if maxHops <= 0 {
		maxHops = 15
	}
	sysBin := systemTraceroute()
	native := canTraceNatively()

	var out []report.Trace
	for _, t := range traceTargets {
		if ctx.Err() != nil {
			break
		}
		status("traceroute: %s", t.Name)
		tr := report.Trace{Target: t.Name, Host: t.Host}
		switch {
		case native:
			tr.Hops = nativeTrace(ctx, t.Host, maxHops)
		case sysBin != "":
			tr.Hops = systemTrace(ctx, sysBin, t.Host, maxHops)
			tr.Note = "via " + sysBin
		default:
			tr.Note = "skipped: needs root privileges or a system traceroute binary"
		}
		annotateASN(ctx, tr.Hops)
		if len(tr.Hops) > 0 && !anyHopAnswered(tr.Hops) {
			tr.Note = report.JoinNonEmpty(" — ", tr.Note,
				"no hop answered: ICMP is filtered on this host or along the path")
		}
		out = append(out, tr)
	}
	return out
}

// systemTraceroute ищет подходящий системный бинарник.
func systemTraceroute() string {
	for _, name := range []string{"traceroute", "tracepath"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// canTraceNatively проверяет, доступен ли raw-сокет ICMP.
//
// Нужен именно raw: на Linux datagram-сокет ICMP не отдаёт сообщения «время
// жизни истекло», а вся трассировка построена как раз на них.
func canTraceNatively() bool {
	if os.Geteuid() != 0 {
		return false
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// nativeTrace идёт по возрастающему TTL: пакет с TTL=n умирает на n-м
// маршрутизаторе, и тот присылает ошибку со своим адресом. Как только приходит
// эхо-ответ от самой цели, маршрут считается пройденным.
func nativeTrace(ctx context.Context, host string, maxHops int) []report.TraceHop {
	dst, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil
	}
	defer conn.Close()
	p := conn.IPv4PacketConn()

	var hops []report.TraceHop
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		if err := p.SetTTL(ttl); err != nil {
			break
		}
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: ttl, Data: []byte("servertester-trace")},
		}
		wb, err := msg.Marshal(nil)
		if err != nil {
			break
		}
		start := time.Now()
		if _, err := conn.WriteTo(wb, &net.IPAddr{IP: dst.IP}); err != nil {
			break
		}
		hop, arrived, done := awaitHop(conn, ttl, start)
		hop.N = ttl
		hops = append(hops, hop)
		if !arrived {
			continue
		}
		if done {
			break
		}
	}
	return hops
}

// awaitHop ждёт ответ именно на наш пакет: либо «время жизни истекло» с
// вложенным заголовком нашего же запроса, либо эхо-ответ от цели.
//
// Raw-сокет видит и посторонний ICMP-трафик машины, поэтому всё, что не
// содержит наши идентификатор и номер, игнорируется, а не засчитывается как
// текущий хоп. Возвращает: сам хоп, был ли ответ, и достигнута ли цель.
func awaitHop(conn *icmp.PacketConn, ttl int, start time.Time) (hop report.TraceHop, arrived, done bool) {
	id := os.Getpid() & 0xffff
	deadline := time.Now().Add(2 * time.Second)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return hop, false, false
	}
	rb := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return hop, false, false
		}
		parsed, err := icmp.ParseMessage(protocolICMP, rb[:n])
		if err != nil {
			continue
		}
		switch body := parsed.Body.(type) {
		case *icmp.TimeExceeded:
			if !quotesProbe(body.Data, id, ttl) {
				continue
			}
			return report.TraceHop{IP: peer.String(), RTTMs: msSince(start)}, true, false
		case *icmp.Echo:
			if parsed.Type != ipv4.ICMPTypeEchoReply || body.ID != id || body.Seq != ttl {
				continue
			}
			return report.TraceHop{IP: peer.String(), RTTMs: msSince(start)}, true, true
		}
	}
	return hop, false, false
}

// quotesProbe разбирает то, что маршрутизатор вернул внутри ICMP-ошибки: по
// стандарту это заголовок IPv4 исходного пакета плюс первые 8 байт нашего
// запроса, где как раз лежат идентификатор и номер последовательности.
// Длина заголовка берётся из поля IHL — нижние 4 бита первого байта, умноженные
// на 4.
func quotesProbe(data []byte, id, seq int) bool {
	if len(data) < 20 {
		return false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+8 {
		return false
	}
	inner := data[ihl:]
	if inner[0] != byte(ipv4.ICMPTypeEcho) {
		return false
	}
	gotID := int(inner[4])<<8 | int(inner[5])
	gotSeq := int(inner[6])<<8 | int(inner[7])
	return gotID == id && gotSeq == seq
}

// msSince — время с момента start в миллисекундах.
func msSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}

// systemTrace вызывает системный traceroute в числовом режиме и разбирает его
// вывод. Резолв имён отключён (-n): он медленный, а названия сетей мы всё
// равно берём из ASN.
func systemTrace(ctx context.Context, bin, host string, maxHops int) []report.TraceHop {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	args := []string{"-n", "-q", "1", "-w", "2", "-m", strconv.Itoa(maxHops), host}
	if strings.HasSuffix(bin, "tracepath") {
		args = []string{"-n", host}
	}
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	return parseTraceOutput(string(out))
}

// parseTraceOutput разбирает вывод traceroute/tracepath вида
// " 3  62.115.120.1  12.482 ms". Формат у разных реализаций слегка различается,
// поэтому парсер терпимый: берутся номер хопа, первый адрес и первое число,
// похожее на время; строки без номера (шапка, «no reply») пропускаются.
// Покрыт тестами в trace_test.go.
func parseTraceOutput(out string) []report.TraceHop {
	var hops []report.TraceHop
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
		if err != nil {
			continue
		}
		hop := report.TraceHop{N: n}
		for i := 1; i < len(fields); i++ {
			if ip := net.ParseIP(strings.Trim(fields[i], "()")); ip != nil && hop.IP == "" {
				hop.IP = strings.Trim(fields[i], "()")
				continue
			}
			if v, err := strconv.ParseFloat(fields[i], 64); err == nil && hop.RTTMs == 0 {
				hop.RTTMs = v
			}
		}
		hops = append(hops, hop)
	}
	return hops
}

// anyHopAnswered сообщает, ответил ли хоть один хоп.
func anyHopAnswered(hops []report.TraceHop) bool {
	for _, h := range hops {
		if h.IP != "" {
			return true
		}
	}
	return false
}

// annotateASN подписывает хопы автономными системами; приватные адреса
// (первые хопы внутри сети хостера) пропускаются — публичной AS у них нет.
func annotateASN(ctx context.Context, hops []report.TraceHop) {
	for i := range hops {
		if hops[i].IP == "" || isPrivate(hops[i].IP) {
			continue
		}
		hops[i].ASN, hops[i].Org = LookupASN(ctx, hops[i].IP)
	}
}

// isPrivate отсеивает приватные и служебные адреса.
func isPrivate(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}
