package netcheck

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/showwin/speedtest-go/speedtest"

	"github.com/FedorZakh/ServerOk/internal/netutil"
	"github.com/FedorZakh/ServerOk/internal/report"
)

// speedtest.go — измерение скорости канала через инфраструктуру speedtest.net
// (библиотека speedtest-go, чистый Go, без внешних бинарников).
//
// Главное отличие от bench.sh и его клонов: серверы ищутся по названию города,
// а не по «зашитым» числовым ID. Идентификаторы устаревают — спонсоры уходят,
// серверы отключают, и такие скрипты годами показывают «Test failed» для
// половины строк. Здесь на каждый город берётся до трёх кандидатов, заведомо
// мёртвые отсеиваются HTTP-пробой, а сервер, отдавший нулевую скорость,
// считается сломанным, и берётся следующий.

// node — одна точка измерения.
type node struct {
	Label   string
	Search  string // ключевое слово для поиска; пусто — «ближайший сервер»
	Country string // ожидаемая страна, ею фильтруются результаты поиска
}

// Наборы точек: fast — быстрая проверка (3 точки), default — как в bench.sh
// (9 точек по миру), full — расширенный, включая Китай и Индию.
var (
	fastSet = []node{
		{"Speedtest.net", "", ""},
		{"Los Angeles, US", "Los Angeles", "United States"},
		{"Amsterdam, NL", "Amsterdam", "Netherlands"},
	}
	defaultSet = []node{
		{"Speedtest.net", "", ""},
		{"Los Angeles, US", "Los Angeles", "United States"},
		{"Dallas, US", "Dallas", "United States"},
		{"Montreal, CA", "Montreal", "Canada"},
		{"Paris, FR", "Paris", "France"},
		{"Amsterdam, NL", "Amsterdam", "Netherlands"},
		{"Hong Kong", "Hong Kong", "Hong Kong"},
		{"Singapore, SG", "Singapore", "Singapore"},
		{"Tokyo, JP", "Tokyo", "Japan"},
	}
	fullSet = append(append([]node{}, defaultSet...), []node{
		{"Frankfurt, DE", "Frankfurt", "Germany"},
		{"London, UK", "London", "United Kingdom"},
		{"Shanghai, CN", "Shanghai", "China"},
		{"Guangzhou, CN", "Guangzhou", "China"},
		{"Mumbai, IN", "Mumbai", "India"},
		{"Sydney, AU", "Sydney", "Australia"},
		{"Sao Paulo, BR", "Sao Paulo", "Brazil"},
	}...)
)

var nodeSets = map[string][]node{
	"fast":    fastSet,
	"default": defaultSet,
	"full":    fullSet,
}

// nodeTimeout — потолок времени на одну точку, включая перебор запасных
// серверов. Произведение этого значения на число точек не должно превышать
// -test-timeout, иначе тест оборвётся на середине.
const nodeTimeout = 90 * time.Second

// Speedtest измеряет отдачу, приём и задержку по набору точек.
//
// onResult вызывается после каждой точки — благодаря этому строки таблицы
// появляются на экране по мере измерения, а не спустя минуты молчания.
// Если время вышло, возвращается уже измеренное: частичная таблица полезнее
// пустой.
func Speedtest(ctx context.Context, set string, onResult func(report.SpeedNode), status func(string, ...any)) (*report.Speedtest, error) {
	nodes, err := resolveSet(set)
	if err != nil {
		return nil, err
	}

	status("speedtest: locating the nearest server")
	base := speedtest.New()
	// Сведения о пользователе нужны только для расстояния. speedtest.net
	// нередко ограничивает этот запрос по частоте, но список серверов при этом
	// продолжает работать, поэтому ошибка не фатальна.
	_, _ = base.FetchUserInfoContext(ctx)

	out := &report.Speedtest{}
	for _, n := range nodes {
		if ctx.Err() != nil {
			// Время вышло: отдаём уже измеренные строки, а не теряем весь тест.
			return out, nil
		}
		status("speedtest: %s", n.Label)
		out.Nodes = append(out.Nodes, measureNode(ctx, base, n))
		if onResult != nil {
			onResult(out.Nodes[len(out.Nodes)-1])
		}
	}
	if len(out.Nodes) == 0 {
		return nil, errors.New("no speedtest nodes were measured")
	}
	return out, nil
}

// measureNode измеряет одну точку: задержка, отдача, приём — в этом порядке.
// Задержка первой: она дешёвая и сразу отсеивает нерабочий сервер.
func measureNode(ctx context.Context, base *speedtest.Speedtest, n node) report.SpeedNode {
	row := report.SpeedNode{Name: n.Label}
	ctx, cancel := context.WithTimeout(ctx, nodeTimeout)
	defer cancel()

	client, candidates, err := pickServers(ctx, base, n)
	if err != nil {
		row.Failed, row.Err = true, report.Truncate(err.Error(), 60)
		return row
	}
	defer client.Manager.Reset()

	// Перебираем кандидатов: если сервер не отвечает или отдаёт мусор, пробуем
	// следующий в том же городе, и только исчерпав всех, помечаем точку как
	// неудачную.
	var lastErr error
	for _, srv := range candidates {
		if ctx.Err() != nil {
			break
		}
		if err := srv.PingTestContext(ctx, nil); err != nil {
			lastErr = err
			continue
		}
		res := report.SpeedNode{Name: n.Label, Sponsor: srv.Sponsor, ID: srv.ID}
		if n.Search == "" {
			res.Name = report.Truncate(report.JoinNonEmpty(" · ", n.Label, srv.Name), 18)
		}
		res.LatencyMs = float64(srv.Latency.Microseconds()) / 1000

		if err := srv.UploadTestContext(ctx); err != nil {
			lastErr = err
			client.Manager.Reset()
			continue
		}
		res.UploadMbps = srv.ULSpeed.Mbps()

		if err := srv.DownloadTestContext(ctx); err != nil {
			lastErr = err
			client.Manager.Reset()
			continue
		}
		res.DownMbps = srv.DLSpeed.Mbps()

		// Сервер ответил, но не передал ничего — это поломка, а не медленный
		// канал; такой результат в отчёт пускать нельзя.
		if res.UploadMbps <= 0 || res.DownMbps <= 0 {
			lastErr = errors.New("server reported zero throughput")
			client.Manager.Reset()
			continue
		}
		return res
	}

	row.Failed = true
	if lastErr != nil {
		row.Err = report.Truncate(lastErr.Error(), 60)
	} else {
		row.Err = "no usable server"
	}
	return row
}

// pickServers подбирает до трёх кандидатов для точки: ближайший сервер,
// совпадение по названию города или конкретный ID, если он задан явно.
func pickServers(ctx context.Context, base *speedtest.Speedtest, n node) (*speedtest.Speedtest, []*speedtest.Server, error) {
	if n.Search == "" {
		servers, err := base.FetchServerListContext(ctx)
		if err != nil {
			return nil, nil, err
		}
		targets, err := servers.FindServer(nil)
		if err != nil || len(targets) == 0 {
			return nil, nil, errors.New("no nearby server")
		}
		alive := reachable(ctx, limit(targets, 6), 2)
		if len(alive) == 0 {
			return nil, nil, errors.New("no reachable nearby server")
		}
		return base, alive, nil
	}
	if isServerID(n.Search) {
		srv, err := base.FetchServerByIDContext(ctx, n.Search)
		if err != nil {
			return nil, nil, fmt.Errorf("server %s unavailable", n.Search)
		}
		return base, []*speedtest.Server{srv}, nil
	}

	client := speedtest.New()
	client.NewUserConfig(&speedtest.UserConfig{Keyword: n.Search})
	servers, err := client.FetchServerListContext(ctx)
	if err != nil {
		return nil, nil, err
	}
	matched := reachable(ctx, matchServers(servers, n), 3)
	if len(matched) == 0 {
		return nil, nil, fmt.Errorf("no reachable server near %s", n.Label)
	}
	for _, s := range matched {
		s.Context = client
	}
	return client, matched, nil
}

// matchServers ранжирует найденное: сначала серверы в нужном городе, затем в
// нужной стране, затем всё остальное, что вернул поиск.
func matchServers(servers speedtest.Servers, n node) []*speedtest.Server {
	city := strings.ToLower(n.Search)
	country := strings.ToLower(n.Country)
	var inCity, inCountry, others []*speedtest.Server
	for _, s := range servers {
		sc := strings.ToLower(s.Country)
		switch {
		case country != "" && !strings.Contains(sc, country):
			others = append(others, s)
		case strings.Contains(strings.ToLower(s.Name), city):
			inCity = append(inCity, s)
		default:
			inCountry = append(inCountry, s)
		}
	}
	return limit(append(append(inCity, inCountry...), others...), 8)
}

// reachable оставляет первые want серверов, чей HTTP-эндпоинт отвечает.
//
// Проверка именно HTTP, а не TCP: у мёртвых спонсоров порт нередко открыт
// (соединение устанавливается), но приложение молчит — такой сервер съедал бы
// всё время, отведённое на точку. Любой код ответа считается признаком жизни,
// включая 404 и 500: у разных сборок Ookla разное поведение на GET.
func reachable(ctx context.Context, candidates []*speedtest.Server, want int) []*speedtest.Server {
	type probe struct {
		idx int
		ok  bool
	}
	results := make(chan probe, len(candidates))
	for i, s := range candidates {
		go func(i int, host string) {
			client := netutil.Client(netutil.Any, 5*time.Second)
			defer client.CloseIdleConnections()
			// Любой ответ означает, что демон speedtest жив.
			_, err := netutil.Get(ctx, client, "http://"+host+"/speedtest/upload.php", 4<<10, nil)
			results <- probe{i, err == nil}
		}(i, s.Host)
	}
	alive := make([]bool, len(candidates))
	for range candidates {
		p := <-results
		alive[p.idx] = p.ok
	}
	var out []*speedtest.Server
	for i, s := range candidates {
		if alive[i] {
			out = append(out, s)
		}
		if len(out) == want {
			break
		}
	}
	return out
}

// limit обрезает список кандидатов.
func limit(in []*speedtest.Server, n int) []*speedtest.Server {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// isServerID отличает числовой идентификатор сервера от названия города.
func isServerID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// resolveSet превращает значение флага -nodes в список точек: это либо имя
// готового набора (fast/default/full), либо перечисленные через запятую ID
// серверов speedtest.net.
func resolveSet(set string) ([]node, error) {
	set = strings.TrimSpace(set)
	if set == "" {
		set = "default"
	}
	if nodes, ok := nodeSets[strings.ToLower(set)]; ok {
		return nodes, nil
	}
	var out []node
	for _, id := range strings.Split(set, ",") {
		if id = strings.TrimSpace(id); id != "" {
			out = append(out, node{Label: "Server " + id, Search: id})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("unknown speedtest node set %q", set)
	}
	return out, nil
}
