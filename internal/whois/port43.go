package whois

// port43.go — WHOIS в первозданном виде: TCP-порт 43, запрос — строка с
// именем домена, ответ — свободный текст (RFC 3912).
//
// Здесь два неочевидных момента, из-за которых это не «просто одно
// соединение»:
//
//  1. У каждого TLD свой сервер, и единственный способ узнать его, не таская
//     за собой таблицу на полторы тысячи зон, — спросить whois.iana.org: тот
//     отвечает строкой «refer: whois.<реестр>».
//  2. У gTLD реестр хранит лишь дату, статус и имя регистратора, а контакты
//     и NS лежат у регистратора. Реестр указывает его строкой «Registrar
//     WHOIS Server», по которой делается второй запрос.
//
// Адрес следующего сервера приходит из ответа предыдущего, то есть из
// недоверенного текста, — поэтому перед подключением он проверяется как
// имя хоста (validHost).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Zagorsky17/ServerOk/internal/netutil"
)

// ianaServer и whoisPort — переменные, а не константы, чтобы port43_test.go
// мог подставить локальный сервер вместо настоящего реестра.
var (
	ianaServer = "whois.iana.org"
	whoisPort  = "43"
)

const (
	queryTimeout = 12 * time.Second
	// Ответы WHOIS — это килобайты текста; сотня килобайт с запасом
	// покрывает самые многословные реестры вместе с их юридическими
	// примечаниями.
	maxResponse = 128 << 10
)

// reRefer ловит указание на следующий сервер: «refer:» у IANA,
// «Registrar WHOIS Server:» и «Whois Server:» у реестров.
var reRefer = regexp.MustCompile(`(?im)^\s*(?:refer|registrar whois server|whois server)\s*:\s*(\S+)\s*$`)

// queryChain проходит цепочку IANA → реестр → регистратор и возвращает
// склеенные ответы вместе со списком серверов, которые их дали.
func queryChain(ctx context.Context, domain string, status func(string, ...any)) (string, []string, error) {
	tld := domain[strings.LastIndex(domain, ".")+1:]
	status("whois: asking %s which registry serves .%s", ianaServer, tld)
	root, err := query(ctx, ianaServer, tld)
	if err != nil {
		return "", nil, err
	}
	server := refer(root)
	if server == "" {
		// Резервный вариант: у большинства новых gTLD сервер называется
		// именно так, даже когда IANA о нём молчит.
		server = "whois.nic." + tld
	}

	var (
		parts   []string
		servers []string
	)
	seen := map[string]bool{}
	for hop := 0; hop < 3 && server != "" && !seen[server]; hop++ {
		seen[server] = true
		status("whois: querying %s for %s", server, domain)
		resp, err := query(ctx, server, request(server, domain))
		if err != nil {
			// Обрыв на середине цепочки не страшен: то, что уже получено от
			// реестра, обычно и есть главное.
			if len(parts) == 0 {
				return "", nil, err
			}
			break
		}
		parts = append(parts, fmt.Sprintf("%% %s\n\n%s", server, strings.TrimSpace(resp)))
		servers = append(servers, server)
		server = refer(resp)
	}
	if len(parts) == 0 {
		return "", nil, errors.New("no registry answered")
	}
	return strings.Join(parts, "\n\n"), servers, nil
}

// request собирает строку запроса. Verisign (.com/.net) на голое имя домена
// отвечает списком всех совпадений, включая чужие домены с тем же префиксом;
// префикс «domain » просит точное совпадение.
func request(server, domain string) string {
	if strings.Contains(server, "verisign-grs") {
		return "domain " + domain
	}
	return domain
}

// query выполняет один запрос WHOIS. Протокол предельно простой: отправляем
// строку, читаем всё до закрытия соединения сервером.
func query(ctx context.Context, server, request string) (string, error) {
	if !validHost(server) {
		return "", fmt.Errorf("refusing to query a malformed whois host %q", server)
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	conn, err := netutil.Dialer(netutil.Any, queryTimeout).DialContext(ctx, "tcp", net.JoinHostPort(server, whoisPort))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write([]byte(request + "\r\n")); err != nil {
		return "", err
	}
	body, err := io.ReadAll(io.LimitReader(conn, maxResponse))
	if len(body) == 0 && err != nil {
		return "", err
	}
	// Ошибку чтения при непустом ответе игнорируем: часть серверов рвёт
	// соединение вместо аккуратного закрытия, но текст уже получен.
	return string(body), nil
}

// refer достаёт адрес следующего сервера из ответа.
func refer(resp string) string {
	m := reRefer.FindStringSubmatch(resp)
	if m == nil {
		return ""
	}
	host := strings.ToLower(strings.Trim(m[1], "./"))
	// Некоторые реестры пишут сюда URL веб-формы, а не хост.
	if _, rest, ok := strings.Cut(host, "://"); ok {
		host, _, _ = strings.Cut(rest, "/")
	}
	if !validHost(host) {
		return ""
	}
	return host
}

// validHost проверяет, что строка похожа на имя хоста: адрес приходит из
// ответа стороннего сервера и идёт прямиком в Dial.
func validHost(h string) bool {
	if h == "" || len(h) > 253 || !strings.Contains(h, ".") {
		return false
	}
	for _, r := range h {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}
