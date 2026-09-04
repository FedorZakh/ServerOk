// Программа serverok — бенчмарк и сетевая диагностика сервера: шапка с
// характеристиками железа и ОС, тесты процессора, памяти и диска, замер
// скорости канала, геолокация адреса вместе с регистрационной записью RDAP,
// репутация в чёрных списках, проверка доступности сервисов и диагностика
// маршрутизации.
//
// Этот файл отвечает за запуск: разбор флагов, выбор тестов (через меню или
// флагом), обработка сигналов и сохранение отчёта. Сами тесты объявлены в
// tests.go, их выполнение — в пакете runner.
//
// Порядок работы:
//  1. разбираем флаги, настраиваем цвет и подавляем лишние логи;
//  2. строим реестр тестов;
//  3. если тесты заданы флагом (-test, -all) или терминала нет — один прогон
//     и выход;
//  4. иначе крутим меню: прогон, снова меню, и так пока пользователь не
//     выберет 0 или не нажмёт Ctrl+C;
//  5. сохраняем JSON/Markdown, если их запросили флагами.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/FedorZakh/ServerOk/internal/netcheck"
	"github.com/FedorZakh/ServerOk/internal/report"
	"github.com/FedorZakh/ServerOk/internal/runner"
	"github.com/FedorZakh/ServerOk/internal/ui"
)

// version подставляется при сборке через -ldflags "-X main.version=..."
// (см. Makefile). В обычной сборке остаётся "dev".
var version = "dev"

// usageHint печатается в шапке отчёта — так по скопированному на форум
// выводу видно, чем он получен.
const usageHint = "bash <(curl -sL https://raw.githubusercontent.com/FedorZakh/ServerOk/main/scripts/install.sh)"

// runConfig — всё, что нужно одному прогону, кроме списка тестов. Собирается
// один раз из флагов и переиспользуется на каждой итерации меню.
type runConfig struct {
	opts     runner.Options
	timeout  time.Duration
	jsonPath string
	mdPath   string
	quiet    bool
}

func main() {
	var (
		all       = flag.Bool("all", false, "run every test without showing the menu")
		testList  = flag.String("test", "", "comma-separated tests to run (see -list)")
		nodes     = flag.String("nodes", "default", "speedtest node sets: fast, default, full, us, eu, asia (combinable: -nodes eu,asia) or server IDs")
		speedWith = flag.String("speed-method", "ookla", "how to measure speed: ookla (speedtest.net servers) or cloudflare (nearest edge)")
		diskSize  = flag.String("disk-size", "1G", "disk test size, e.g. 512M or 2G")
		diskPath  = flag.String("disk-path", "", "directory for the disk test (default: working directory)")
		cpuTime   = flag.Float64("cpu-time", 2.5, "seconds spent per CPU workload and mode")
		jsonOut   = flag.String("json", "", "write the report as JSON to this file")
		mdOut     = flag.String("md", "", "write the report as Markdown to this file")
		noColor   = flag.Bool("no-color", false, "disable ANSI colors")
		noIPv6    = flag.Bool("no-ipv6", false, "skip all IPv6 lookups")
		quiet     = flag.Bool("quiet", false, "suppress terminal output (use with -json/-md)")
		timeout   = flag.Duration("timeout", 30*time.Minute, "overall time budget per run")
		testTmo   = flag.Duration("test-timeout", 20*time.Minute, "per-test time limit")
		traceHops = flag.Int("trace-hops", 15, "maximum traceroute hops")
		listTests = flag.Bool("list", false, "list available tests and exit")
		showVer   = flag.Bool("version", false, "print the version and exit")
	)
	flag.Usage = printUsage
	flag.Parse()
	// Дальше порядок важен: -version и -list завершают работу до того, как
	// программа успеет что-либо измерить или запросить.

	if *showVer {
		fmt.Println("serverok " + version)
		return
	}

	// net/http и некоторые зависимости пишут о сетевых неурядицах в
	// стандартный логгер. Эти строки ломали бы рамку отчёта, поэтому логгер
	// глушится: свои сообщения программа печатает сама, через пакет ui.
	log.SetOutput(io.Discard)

	ui.AutoDetectColor()
	if *noColor {
		ui.SetColor(false)
	}

	registry := buildRegistry()
	if *listTests {
		for i, t := range registry.All() {
			fmt.Printf("%d) %-12s %s\n", i+1, t.ID, t.Title)
		}
		return
	}

	size, err := parseSize(*diskSize)
	if err != nil {
		fail(err)
	}
	// Настройки speedtest проверяются здесь, а не в тесте: узнать об опечатке
	// в -nodes через двадцать минут прогона — обиднее всего.
	method := netcheck.NormalizeMethod(*speedWith)
	if method == "" {
		fail(fmt.Errorf("unknown speed method %q (want one of %s)", *speedWith, strings.Join(netcheck.Methods(), ", ")))
	}
	if err := netcheck.ValidateSet(*nodes); err != nil {
		fail(err)
	}

	cfg := runConfig{
		opts: runner.Options{
			DiskSize:    size,
			DiskPath:    *diskPath,
			SpeedMethod: method,
			Nodes:       *nodes,
			Timeout:     *testTmo,
			Quiet:       *quiet,
			SkipIPv6:    *noIPv6,
			CPUSecs:     *cpuTime,
			TraceHops:   *traceHops,
		},
		timeout:  *timeout,
		jsonPath: *jsonOut,
		mdPath:   *mdOut,
		quiet:    *quiet,
	}

	// flag.Visit обходит только те флаги, что пользователь действительно
	// написал в командной строке, — значения по умолчанию сюда не попадают.
	speedFlagsSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "nodes" || f.Name == "speed-method" {
			speedFlagsSet = true
		}
	})

	// Меню показывается, только когда набор тестов не задан флагами и есть
	// терминал. Всё остальное (-test, -all, запуск из cron или curl | bash) —
	// один прогон без вопросов.
	in, interactive := ui.Input()
	if *testList != "" || *all || !interactive {
		runTests(selectByFlags(registry, *testList), cfg)
		return
	}

	items := make([]ui.MenuItem, 0, len(registry.All()))
	for _, t := range registry.All() {
		items = append(items, ui.MenuItem{ID: t.ID, Title: t.Title})
	}
	if !*quiet {
		report.Banner(version, usageHint)
	}
	// Программа живёт, пока её не остановит сам пользователь: после каждого
	// прогона возвращаемся в меню, а выходим только по пункту 0 (или Ctrl+C).
	for {
		ids, ok := ui.Menu(items, in)
		if !ok {
			return
		}
		sel, err := registry.Select(ids)
		if err != nil {
			// Опечатка в выборе не повод завершать работу — спрашиваем снова.
			ui.Warn(err.Error())
			continue
		}
		run := cfg
		// Способ замера и регион спрашиваются, только если пользователь не
		// задал их флагами: явный флаг всегда сильнее подменю. Вопрос задаётся
		// на каждой итерации меню — один и тот же сервер часто хочется
		// померить сначала до Европы, потом до Азии.
		if includes(sel, "speedtest") && !speedFlagsSet {
			run.opts.SpeedMethod, run.opts.Nodes = askSpeedProfile(in)
		}
		if !runTests(sel, run) {
			// Прогон прервали сигналом: это и есть запрошенный выход.
			return
		}
	}
}

// speedProfiles — варианты подменю «чем и куда мерить скорость». Порядок
// сверху вниз: сначала то, что выбирают чаще всего.
//
// Регион здесь нужен ровно затем, чтобы не гонять девять точек по всему миру,
// когда интересно только одно направление; Cloudflare стоит последним, потому
// что это другой способ измерения, а не другой регион (см. netcheck/speedcf.go).
var speedProfiles = []struct {
	choice ui.Choice
	method string
	nodes  string
}{
	{ui.Choice{Label: "Ookla · worldwide", Note: "9 nodes, as in bench.sh"}, netcheck.MethodOokla, "default"},
	{ui.Choice{Label: "Ookla · quick", Note: "3 nodes, ~1 min"}, netcheck.MethodOokla, "fast"},
	{ui.Choice{Label: "Ookla · Europe", Note: "London … Stockholm"}, netcheck.MethodOokla, "eu"},
	{ui.Choice{Label: "Ookla · North America", Note: "Los Angeles … New York"}, netcheck.MethodOokla, "us"},
	{ui.Choice{Label: "Ookla · Asia", Note: "Hong Kong … Mumbai"}, netcheck.MethodOokla, "asia"},
	{ui.Choice{Label: "Ookla · full", Note: "16 nodes, slow"}, netcheck.MethodOokla, "full"},
	{ui.Choice{Label: "Cloudflare · nearest edge", Note: "one node, ~20 s"}, netcheck.MethodCloudflare, ""},
}

// askSpeedProfile спрашивает способ замера перед прогоном speedtest.
// При закрытом вводе возвращает вариант по умолчанию: подменю уточняет
// настройку, а не решает, запускать ли тест.
func askSpeedProfile(in io.Reader) (method, nodes string) {
	items := make([]ui.Choice, 0, len(speedProfiles))
	for _, p := range speedProfiles {
		items = append(items, p.choice)
	}
	idx, _ := ui.Choose("Speedtest: how and where to measure", items, 0, in)
	return speedProfiles[idx].method, speedProfiles[idx].nodes
}

// includes сообщает, попал ли тест с таким ID в выбранный набор.
func includes(sel []runner.Test, id string) bool {
	for _, t := range sel {
		if t.ID == id {
			return true
		}
	}
	return false
}

// selectByFlags выбирает тесты, когда меню не показывается: явный -test имеет
// приоритет, иначе (-all или отсутствие терминала) выполняются все тесты.
func selectByFlags(reg *runner.Registry, testList string) []runner.Test {
	if testList == "" {
		return reg.All()
	}
	sel, err := reg.Select(splitList(testList))
	if err != nil {
		fail(err)
	}
	return sel
}

// runTests выполняет один прогон: печатает шапку, заполняет отчёт, показывает
// итог и сохраняет файлы, если их запросили флагами.
//
// Возвращает false, если прогон прервали сигналом. В режиме меню это значит
// «выходим из программы», а не «возвращаемся к выбору тестов».
//
// Обработчик сигналов ставится только на время прогона: пока программа ждёт
// ввод в меню, Ctrl+C должен завершать процесс штатным образом.
func runTests(sel []runner.Test, c runConfig) bool {
	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// После первого сигнала возвращаем обработчик по умолчанию: второй Ctrl+C
	// должен убивать процесс сразу, даже если тест завис в системном вызове
	// (например, в системном traceroute с собственным таймаутом).
	go func() {
		<-sigCtx.Done()
		stop()
	}()
	ctx := sigCtx
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(sigCtx, c.timeout)
		defer cancel()
	}

	// С этого момента начинается собственно прогон.
	rep := &report.Report{Version: version, Generated: time.Now()}
	start := time.Now()
	if !c.quiet {
		report.Banner(version, usageHint)
	}
	runner.Run(ctx, sel, rep, c.opts)
	rep.Duration = time.Since(start).Round(time.Second).String()

	if !c.quiet {
		report.PrintFailures(rep)
		ui.Blank()
		ui.Divider()
		ui.KV("Finished in", rep.Duration)
		if ctx.Err() != nil {
			ui.Warn("run interrupted — the report above is partial")
		}
	}
	saveOutputs(rep, c.jsonPath, c.mdPath, c.quiet)
	return sigCtx.Err() == nil
}

// saveOutputs сохраняет отчёт в форматы, запрошенные флагами -json и -md.
// Без этих флагов ничего не пишется: отчёт рассчитан на чтение в терминале.
//
// В режиме -quiet в stdout не уходит ничего: этот режим существует ради
// машинного использования (cron, мониторинг), и любая лишняя строка ломала бы
// разбор. Ошибки записи при этом всё равно сообщаются — в stderr.
func saveOutputs(rep *report.Report, jsonPath, mdPath string, quiet bool) {
	// Общая обёртка для обоих форматов: пишем файл и сообщаем о результате.
	write := func(kind, path string, save func(*report.Report, string) error) {
		if path == "" {
			return
		}
		if err := save(rep, path); err != nil {
			// Об ошибке сообщаем всегда, даже в quiet, — но в stderr.
			fmt.Fprintf(os.Stderr, "serverok: cannot write %s: %v\n", kind, err)
			return
		}
		if !quiet {
			ui.KV(kind+" report", path)
		}
	}
	write("JSON", jsonPath, report.WriteJSON)
	write("Markdown", mdPath, report.WriteMarkdown)
}

// splitList разбирает список, разделённый запятыми или пробелами.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseSize понимает и голое число байт, и суффиксы K/M/G (в том числе KB,
// MB, GB). Суффикс отрезается именно как суффикс, а не как набор символов.
func parseSize(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, nil
	}
	mult := uint64(1)
	for _, u := range []struct {
		suffix string
		factor uint64
	}{{"KB", 1 << 10}, {"K", 1 << 10}, {"MB", 1 << 20}, {"M", 1 << 20}, {"GB", 1 << 30}, {"G", 1 << 30}} {
		if trimmed, ok := strings.CutSuffix(s, u.suffix); ok {
			mult, s = u.factor, trimmed
			break
		}
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return uint64(v * float64(mult)), nil
}

// printUsage печатает справку: примеры запуска и список флагов.
func printUsage() {
	fmt.Fprintf(os.Stderr, `serverok %s — VPS benchmark and network diagnostics

Usage:
  serverok [flags]

  With no flags and a terminal attached it shows the test menu and keeps
  returning to it after every run; it exits when you pick 0 or press Ctrl+C.
  Without a terminal (curl | bash, cron) it runs every test once.

  Picking the speedtest from the menu asks how and where to measure —
  worldwide, one region (Europe / North America / Asia), or Cloudflare's
  nearest edge. Passing -nodes or -speed-method skips that question.

Examples:
  serverok                        # interactive menu
  serverok -all                   # run everything
  serverok -test cpu,disk,ip      # pick tests
  serverok -all -nodes fast       # quick speedtest set
  serverok -test speedtest -nodes eu          # Europe only (also: us, asia)
  serverok -test speedtest -nodes us,asia     # two regions in one run
  serverok -test speedtest -speed-method cloudflare
  serverok -all -quiet -json r.json

Flags:
`, version)
	flag.PrintDefaults()
}

// fail печатает ошибку разбора аргументов и завершает программу с кодом 2 —
// как принято для неверного использования утилиты.
func fail(err error) {
	fmt.Fprintln(os.Stderr, "serverok: "+err.Error())
	os.Exit(2)
}
