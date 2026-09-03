// Программа servertester — бенчмарк и сетевая диагностика сервера: шапка с
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
//  2. строим реестр тестов и выбираем нужные (флаг -test, -all или меню);
//  3. создаём контекст с обработкой Ctrl+C и общим лимитом времени;
//  4. запускаем runner.Run, который заполняет отчёт и печатает секции;
//  5. сохраняем JSON/Markdown, если попросили.
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

func main() {
	var (
		all        = flag.Bool("all", false, "run every test without showing the menu")
		testList   = flag.String("test", "", "comma-separated tests to run (see -list)")
		nodes      = flag.String("nodes", "default", "speedtest node set: fast, default, full, or comma-separated server IDs")
		diskSize   = flag.String("disk-size", "1G", "disk test size, e.g. 512M or 2G")
		diskPath   = flag.String("disk-path", "", "directory for the disk test (default: working directory)")
		cpuTime    = flag.Float64("cpu-time", 2.5, "seconds spent per CPU workload and mode")
		jsonOut    = flag.String("json", "", "write the report as JSON to this file")
		mdOut      = flag.String("md", "", "write the report as Markdown to this file")
		noColor    = flag.Bool("no-color", false, "disable ANSI colors")
		noIPv6     = flag.Bool("no-ipv6", false, "skip all IPv6 lookups")
		quiet      = flag.Bool("quiet", false, "suppress terminal output (use with -json/-md)")
		timeout    = flag.Duration("timeout", 30*time.Minute, "overall time budget")
		testTmo    = flag.Duration("test-timeout", 20*time.Minute, "per-test time limit")
		traceHops  = flag.Int("trace-hops", 15, "maximum traceroute hops")
		listTests  = flag.Bool("list", false, "list available tests and exit")
		showVer    = flag.Bool("version", false, "print the version and exit")
		yesConfirm = flag.Bool("yes", false, "answer yes to prompts (e.g. saving the report)")
	)
	flag.Usage = printUsage
	flag.Parse()
	// Дальше порядок важен: -version и -list завершают работу до того, как
	// программа успеет что-либо измерить или запросить.

	if *showVer {
		fmt.Println("servertester " + version)
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

	in, interactive := ui.Input()
	selected, ok := chooseTests(registry, *testList, *all, interactive, in)
	if !ok {
		return
	}

	rep := &report.Report{Version: version, Generated: time.Now()}
	opts := runner.Options{
		DiskSize:  size,
		DiskPath:  *diskPath,
		Nodes:     *nodes,
		Timeout:   *testTmo,
		Quiet:     *quiet,
		SkipIPv6:  *noIPv6,
		CPUSecs:   *cpuTime,
		TraceHops: *traceHops,
	}

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
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(sigCtx, *timeout)
		defer cancel()
	}

	// С этого момента начинается собственно прогон.
	start := time.Now()
	if !*quiet {
		report.Banner(version, usageHint)
	}
	runner.Run(ctx, selected, rep, opts)
	rep.Duration = time.Since(start).Round(time.Second).String()

	if !*quiet {
		report.PrintFailures(rep)
		ui.Blank()
		ui.Divider()
		ui.KV("Finished in", rep.Duration)
		if ctx.Err() != nil {
			ui.Warn("run interrupted — the report above is partial")
		}
	}
	saveOutputs(rep, *jsonOut, *mdOut, interactive && !*quiet, *yesConfirm, *quiet, in)
}

// chooseTests решает, какие тесты запускать.
//
// Приоритет: явный -test, затем -all. Если ничего не задано и терминал есть —
// показываем меню; если терминала нет (curl | bash, cron, CI) — молча
// выполняем все тесты, потому что спрашивать некого.
func chooseTests(reg *runner.Registry, testList string, all, interactive bool, in io.Reader) ([]runner.Test, bool) {
	switch {
	case testList != "":
		sel, err := reg.Select(splitList(testList))
		if err != nil {
			fail(err)
		}
		return sel, true
	case all, !interactive:
		// Неинтерактивный запуск (curl | bash, cron) выполняет все тесты.
		return reg.All(), true
	}

	report.Banner(version, usageHint)
	items := make([]ui.MenuItem, 0, len(reg.All()))
	for _, t := range reg.All() {
		items = append(items, ui.MenuItem{ID: t.ID, Title: t.Title})
	}
	ids, ok := ui.Menu(items, in)
	if !ok {
		return nil, false
	}
	sel, err := reg.Select(ids)
	if err != nil {
		fail(err)
	}
	return sel, true
}

// saveOutputs сохраняет отчёт в запрошенные форматы.
//
// Если прогон был интерактивным и форматы не указаны, предлагаем сохранить —
// иначе результат живёт только в скроллбэке терминала.
//
// В режиме -quiet в stdout не уходит ничего: этот режим существует ради
// машинного использования (cron, мониторинг), и любая лишняя строка ломала бы
// разбор. Ошибки записи при этом всё равно сообщаются — в stderr.
func saveOutputs(rep *report.Report, jsonPath, mdPath string, offer, assumeYes, quiet bool, in io.Reader) {
	if jsonPath == "" && mdPath == "" && offer {
		if assumeYes || ui.Confirm("Save the report to servertester-report.json/.md?", in) {
			jsonPath, mdPath = "servertester-report.json", "servertester-report.md"
		}
	}
	// Общая обёртка для обоих форматов: пишем файл и сообщаем о результате.
	write := func(kind, path string, save func(*report.Report, string) error) {
		if path == "" {
			return
		}
		if err := save(rep, path); err != nil {
			// Об ошибке сообщаем всегда, даже в quiet, — но в stderr.
			fmt.Fprintf(os.Stderr, "servertester: cannot write %s: %v\n", kind, err)
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
	fmt.Fprintf(os.Stderr, `servertester %s — VPS benchmark and network diagnostics

Usage:
  servertester [flags]

  With no flags and a terminal attached it shows the test menu.
  Without a terminal (curl | bash, cron) it runs every test.

Examples:
  servertester                        # interactive menu
  servertester -all                   # run everything
  servertester -test cpu,disk,ip      # pick tests
  servertester -all -nodes fast       # quick speedtest set
  servertester -all -quiet -json r.json

Flags:
`, version)
	flag.PrintDefaults()
}

// fail печатает ошибку разбора аргументов и завершает программу с кодом 2 —
// как принято для неверного использования утилиты.
func fail(err error) {
	fmt.Fprintln(os.Stderr, "servertester: "+err.Error())
	os.Exit(2)
}
