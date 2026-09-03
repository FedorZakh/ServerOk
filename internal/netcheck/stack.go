package netcheck

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/FedorZakh/ServerOk/internal/ipinfo"
	"github.com/FedorZakh/ServerOk/internal/netutil"
	"github.com/FedorZakh/ServerOk/internal/report"
)

// stack.go — свойства сетевого стека самой машины.
//
// Что и зачем собирается:
//   - доступность IPv4/IPv6 — базовая связность;
//   - MTU интерфейса с маршрутом по умолчанию — низкий MTU у туннельных
//     провайдеров ломает часть сайтов;
//   - алгоритм управления перегрузкой и наличие BBR — на дальних маршрутах
//     разница между cubic и bbr может быть кратной;
//   - какой резолвер нас обслуживает и где он находится — от этого зависит,
//     какой регион показывают стриминговые сервисы.

// Stack собирает перечисленные выше сведения. Все шаги независимы: неудача
// одного оставляет соответствующее поле пустым.
func Stack(ctx context.Context, skipIPv6 bool, status func(string, ...any)) *report.StackInfo {
	s := &report.StackInfo{}

	status("stack: probing address families")
	s.IPv4 = netutil.TCPReachable(ctx, netutil.IPv4, "1.1.1.1:443", 4*time.Second)
	if !skipIPv6 {
		s.IPv6 = netutil.TCPReachable(ctx, netutil.IPv6, "[2606:4700:4700::1111]:443", 4*time.Second)
	}
	s.MTU = outboundMTU()

	s.CCCurrent = readTrimmed("/proc/sys/net/ipv4/tcp_congestion_control")
	if avail := readTrimmed("/proc/sys/net/ipv4/tcp_available_congestion_control"); avail != "" {
		s.CCAvail = strings.Fields(avail)
		for _, cc := range s.CCAvail {
			if cc == "bbr" {
				s.BBR = true
			}
		}
	}

	s.Resolvers = resolvers()
	status("stack: identifying public resolver")
	if ip := publicResolver(ctx); ip != "" {
		s.ResolverIP = ip
		if g, err := ipinfo.LookupGeoIP(ctx, ip); err == nil && g != nil {
			s.ResolverCC = report.JoinNonEmpty(", ", g.City, g.CountryCode)
		}
	}
	return s
}

// readTrimmed читает однострочный файл /proc/sys; на не-Linux вернёт пустую
// строку, и поле просто не попадёт в отчёт.
func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// outboundMTU возвращает MTU интерфейса, через который уходит трафик наружу.
//
// Приём стандартный: «подключаемся» UDP-сокетом к внешнему адресу (пакеты при
// этом не отправляются), смотрим, какой локальный адрес выбрало ядро, и
// находим интерфейс с этим адресом.
func outboundMTU() int {
	conn, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return 0
	}
	defer conn.Close()
	local, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return 0
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.String() == local {
				return ifc.MTU
			}
		}
	}
	return 0
}

// resolvers возвращает первые три nameserver из /etc/resolv.conf.
func resolvers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
		if len(out) >= 3 {
			break
		}
	}
	return out
}

// publicResolver определяет адрес резолвера, который фактически ходит в
// интернет от нашего имени.
//
// Используется служебная TXT-запись Google: она возвращает адрес того, кто
// пришёл с запросом. Это не то же самое, что nameserver в resolv.conf: там
// часто стоит локальный кэш (systemd-resolved, dnsmasq), а наружу ходит уже
// провайдерский или облачный резолвер.
func publicResolver(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	r := &net.Resolver{}
	txt, err := r.LookupTXT(ctx, "o-o.myaddr.l.google.com")
	if err != nil || len(txt) == 0 {
		return ""
	}
	v := strings.TrimSpace(txt[0])
	if net.ParseIP(v) == nil {
		return ""
	}
	return v
}
