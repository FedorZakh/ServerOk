// Пакет runner — ядро программы: реестр тестов и их выполнение.
//
// Идея, на которой держится весь проект: тесты объявляются один раз в
// cmd/serverok/tests.go как значения runner.Test. Из этого списка
// автоматически получаются меню, разбор флага -test, вывод -list и порядок
// секций в отчёте. Добавить новый тест = дописать одну запись в реестр;
// править меню или парсер флагов при этом не нужно.
//
// Второй принцип: тесты не печатают сами, а заполняют структуру отчёта
// (пакет report). Печать делает хук Print уже после успешного выполнения.
// Исключение — speedtest: он отдаёт строки по мере измерения через колбэк,
// поэтому печатает себя сам, и его Print равен nil.
package runner

import (
	"context"
	"errors"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/FedorZakh/ServerOk/internal/report"
	"github.com/FedorZakh/ServerOk/internal/ui"
)

// Options — настройки, заданные пользователем через флаги; передаются каждому
// тесту как есть.
type Options struct {
	DiskSize  uint64        // размер файла для теста диска
	DiskPath  string        // каталог для теста диска (пусто — текущий)
	Nodes     string        // набор узлов speedtest: fast | default | full | список ID
	Timeout   time.Duration // лимит на ОДИН тест (флаг -test-timeout)
	Quiet     bool          // не печатать ничего в stdout (режим -quiet для JSON/cron)
	SkipIPv6  bool          // не трогать IPv6 (флаг -no-ipv6)
	CPUSecs   float64       // секунд на одну нагрузку CPU в каждом режиме
	TraceHops int           // максимум хопов traceroute
}

// Context — то, что получает реализация теста. Встраивает context.Context,
// поэтому его можно передавать напрямую в любые функции, ожидающие контекст
// (именно так тесты и вызывают ipinfo/netcheck).
type Context struct {
	context.Context
	Rep  *report.Report // общий отчёт, куда тест кладёт результат
	Opts Options
	Root bool // запущены ли мы с правами суперпользователя
}

// Status печатает временную строку прогресса. В режиме -quiet — тишина.
func (c *Context) Status(format string, a ...any) {
	if c.Opts.Quiet {
		return
	}
	ui.Statusf(format, a...)
}

// ClearStatus стирает строку прогресса перед печатью результата.
func (c *Context) ClearStatus() {
	if c.Opts.Quiet {
		return
	}
	ui.ClearStatus()
}

// Test описывает один запускаемый тест.
type Test struct {
	ID       string // идентификатор для флага -test и меню (например, "disk")
	Title    string // заголовок секции отчёта
	Order    int    // порядок в отчёте и в меню; шаг 10, чтобы было куда вставлять
	NeedRoot bool   // без root тест деградирует (сейчас только сетевая диагностика)
	Run      func(*Context) error
	// Print печатает результат из отчёта. Если nil — предполагается, что Run
	// напечатал себя сам (так сделан speedtest с живым выводом строк).
	Print func(*report.Report)
}

// Registry — упорядоченный набор тестов.
type Registry struct {
	tests []Test
}

// New собирает реестр, сортируя тесты по Order.
// Сортировка стабильная: тесты с одинаковым Order сохранят порядок объявления.
func New(tests ...Test) *Registry {
	sort.SliceStable(tests, func(i, j int) bool { return tests[i].Order < tests[j].Order })
	return &Registry{tests: tests}
}

// All возвращает все тесты в порядке отчёта.
func (r *Registry) All() []Test { return r.tests }

// IDs возвращает идентификаторы всех тестов.
func (r *Registry) IDs() []string {
	out := make([]string, 0, len(r.tests))
	for _, t := range r.tests {
		out = append(out, t.ID)
	}
	return out
}

// Select разрешает список идентификаторов или номеров пунктов меню в тесты.
//
// Важное свойство: результат всегда в порядке отчёта, а не в порядке ввода —
// «-test disk,cpu» выполнит сначала cpu, потом disk, чтобы секции отчёта не
// зависели от того, как пользователь перечислил тесты. Неизвестный
// идентификатор — ошибка, а не молчаливый пропуск.
func (r *Registry) Select(ids []string) ([]Test, error) {
	want := map[string]bool{}
	for _, id := range ids {
		found := false
		for i, t := range r.tests {
			// Совпадение либо по ID ("cpu"), либо по номеру пункта меню ("2").
			if t.ID == id || strconv.Itoa(i+1) == id {
				want[t.ID] = true
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("unknown test: " + id)
		}
	}
	var out []Test
	for _, t := range r.tests {
		if want[t.ID] {
			out = append(out, t)
		}
	}
	return out, nil
}

// IsRoot сообщает, есть ли у процесса права суперпользователя.
// От этого зависят ICMP-пинг через raw-сокет и нативный traceroute.
func IsRoot() bool { return os.Geteuid() == 0 }

// withTimeout строит контекст для одного теста. Если лимит не задан, тот же
// контекст используется дальше, а cancel — пустышка.
func (c *Context) withTimeout(ctx context.Context, opts Options) (*Context, context.CancelFunc) {
	if opts.Timeout <= 0 {
		return c, func() {}
	}
	sub, cancel := context.WithTimeout(ctx, opts.Timeout)
	return &Context{Context: sub, Rep: c.Rep, Opts: opts, Root: c.Root}, cancel
}

// humanError переводит служебные ошибки контекста в понятную формулировку.
// Отличить отмену от таймаута важно: «interrupted» — это Ctrl+C пользователя,
// а «timed out» — подсказка поднять -test-timeout.
func humanError(err error, parent context.Context) string {
	switch {
	case errors.Is(err, context.Canceled):
		// Если отменён родительский контекст — это сигнал (Ctrl+C/SIGTERM).
		if parent.Err() != nil {
			return "interrupted"
		}
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out (raise -test-timeout to allow more time)"
	}
	return err.Error()
}

// Run выполняет выбранные тесты по очереди, заполняя отчёт и печатая
// результаты по мере готовности.
//
// Тесты идут последовательно намеренно: параллельный запуск исказил бы и
// бенчмарки (борьба за CPU и диск), и измерения сети. Параллелизм есть только
// внутри отдельных тестов (DNSBL-зоны, порты, якоря задержек, сервисы).
func Run(ctx context.Context, tests []Test, rep *report.Report, opts Options) {
	c := &Context{Context: ctx, Rep: rep, Opts: opts, Root: IsRoot()}
	for _, t := range tests {
		// Ctrl+C между тестами: отмечаем прерывание и отдаём частичный отчёт.
		if ctx.Err() != nil {
			rep.AddFailure(t.Title, "interrupted")
			return
		}
		rep.Tests = append(rep.Tests, t.ID)
		if !opts.Quiet {
			ui.Blank()
			ui.Header(t.Title)
		}
		if t.NeedRoot && !c.Root && !opts.Quiet {
			ui.Note("running without root: some checks fall back to unprivileged probes")
		}

		tctx, cancel := c.withTimeout(ctx, opts)
		err := t.Run(tctx)
		cancel() // освобождаем таймер сразу, а не в конце всей функции
		c.ClearStatus()

		if err != nil {
			// Ошибка одного теста не останавливает остальные: отчёт остаётся
			// полезным, а причина попадает и в секцию Notes, и в JSON.
			reason := humanError(err, ctx)
			rep.AddFailure(t.Title, reason)
			if !opts.Quiet {
				ui.Warn(reason)
			}
			continue
		}
		if t.Print != nil && !opts.Quiet {
			t.Print(rep)
		}
	}
}
