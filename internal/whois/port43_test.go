package whois

// port43_test.go — цепочка запросов IANA → реестр → регистратор.
//
// Настоящие серверы здесь не годятся: тест должен проходить на машине без
// исходящего порта 43 (его режут и в CI, и у части хостеров). Поэтому оба
// сервера поднимаются локально, а ianaServer/whoisPort на время теста
// указывают на них.

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeWhois поднимает сервер WHOIS, отвечающий по таблице «запрос → ответ»,
// и возвращает порт, на котором он слушает.
func fakeWhois(t *testing.T, answers map[string]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				// Ответ и закрытие соединения — весь протокол целиком.
				io.WriteString(conn, answers[strings.TrimSpace(string(buf[:n]))])
			}()
		}
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// Проверяется весь путь: спросить у IANA сервер зоны, сходить к нему за
// записью и не зациклиться, если тот сошлётся сам на себя.
//
// Сервер здесь один: порт WHOIS в цепочке общий, и различаются хопы не
// адресом, а запросом — TLD у IANA, полное имя домена у реестра.
func TestQueryChain(t *testing.T) {
	port := fakeWhois(t, map[string]string{
		"test": "refer:        127.0.0.1\n",
		"example.test": "Domain Name: EXAMPLE.TEST\n" +
			"Registrar WHOIS Server: 127.0.0.1\n" +
			"Creation Date: 2001-02-03T00:00:00Z\n",
	})

	oldServer, oldPort := ianaServer, whoisPort
	ianaServer, whoisPort = "127.0.0.1", port
	defer func() { ianaServer, whoisPort = oldServer, oldPort }()

	raw, servers, err := queryChain(context.Background(), "example.test", func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "EXAMPLE.TEST") {
		t.Errorf("registry answer lost: %q", raw)
	}
	if len(servers) != 1 {
		// Второй хоп ведёт на уже опрошенный сервер и должен быть пропущен:
		// иначе ссылка «сам на себя» крутила бы запросы до предела в три хопа.
		t.Errorf("servers = %v, want exactly one", servers)
	}
	if d := parseRaw(raw); d.Registered != "2001-02-03" {
		t.Errorf("chain answer not parsable: %+v", d)
	}
}

// Ошибка первого же запроса — это отсутствие данных, а не пустой ответ.
func TestQueryChainUnreachable(t *testing.T) {
	oldServer, oldPort := ianaServer, whoisPort
	// Порт 1 (tcpmux) заведомо никем не занят на loopback.
	ianaServer, whoisPort = "127.0.0.1", "1"
	defer func() { ianaServer, whoisPort = oldServer, oldPort }()

	if _, _, err := queryChain(context.Background(), "example.test", func(string, ...any) {}); err == nil {
		t.Error("expected an error when no whois server answers")
	}
}

// Адрес следующего сервера приходит из ответа предыдущего, то есть из
// недоверенного текста. Всё, что не похоже на имя хоста, обязано отсеиваться
// до попытки соединения.
func TestReferAndValidHost(t *testing.T) {
	cases := map[string]string{
		"refer:        whois.verisign-grs.com\n":            "whois.verisign-grs.com",
		"Registrar WHOIS Server: whois.markmonitor.com\r\n": "whois.markmonitor.com",
		"Whois Server: https://whois.example.com/lookup\n":  "whois.example.com",
		"refer: not a host at all\n":                        "",
		"refer: whois.example.com; rm -rf /\n":              "",
		"nothing here\n":                                    "",
	}
	for resp, want := range cases {
		if got := refer(resp); got != want {
			t.Errorf("refer(%q) = %q, want %q", resp, got, want)
		}
	}
	for _, h := range []string{"", "localhost", "-", "whois example com", "whois.example.com/x", "127.0.0.1:43"} {
		if validHost(h) {
			t.Errorf("validHost(%q) = true", h)
		}
	}
	if !validHost("whois.example.com") || !validHost("127.0.0.1") {
		t.Error("a normal host must pass")
	}
}

// У Verisign голое имя домена даёт список совпадений, поэтому для .com/.net
// запрос идёт с префиксом «domain».
func TestRequestPrefix(t *testing.T) {
	if got := request("whois.verisign-grs.com", "example.com"); got != "domain example.com" {
		t.Errorf("verisign request = %q", got)
	}
	if got := request("whois.nic.ru", "example.ru"); got != "example.ru" {
		t.Errorf("plain request = %q", got)
	}
}
