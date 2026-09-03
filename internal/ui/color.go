// Пакет ui отвечает за весь вывод в терминал: цвета, рамку отчёта, таблицы,
// строку прогресса и интерактивное меню выбора тестов.
//
// Файлы пакета:
//   - color.go    — ANSI-цвета, определение TTY, измерение видимой ширины;
//   - box.go      — примитивы рамки: заголовки, разделители, строки «ключ: значение», таблицы;
//   - progress.go — временная строка прогресса, которую затирает следующий вывод;
//   - menu.go     — нумерованное меню и вопрос «да/нет».
//
// Никакой бизнес-логики здесь нет: тесты не печатают сами, они заполняют
// структуру отчёта (пакет report), а рендерит её report/text.go через эти
// примитивы.
package ui

import (
	"os"
	"strings"

	"golang.org/x/term"
)

// Width — полная ширина рамки отчёта. 70 колонок выбраны, чтобы вывод выглядел
// как у классического bench.sh и влезал в стандартный терминал 80x24.
const Width = 70

// keyWidth — ширина колонки ключа в строке «Ключ                : значение».
// Именно из неё берётся выравнивание всей шапки отчёта.
const keyWidth = 19

var (
	// colorEnabled — печатать ли ANSI-последовательности.
	colorEnabled = true
	// stdoutTTY хранится отдельно от цвета намеренно: флаг -no-color не должен
	// выключать строку прогресса, а перенаправление вывода в файл должно
	// выключать и цвет, и прогресс. Раньше это была одна переменная, из-за чего
	// -no-color в терминале молча убивал индикацию.
	stdoutTTY bool
)

// AutoDetectColor определяет режим вывода: цвет включается только если stdout —
// терминал и не выставлены NO_COLOR / TERM=dumb.
func AutoDetectColor() {
	stdoutTTY = term.IsTerminal(int(os.Stdout.Fd()))
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		colorEnabled = false
		return
	}
	colorEnabled = stdoutTTY
}

// SetColor принудительно включает или выключает цвет (флаг -no-color).
// На stdoutTTY не влияет — прогресс продолжит работать.
func SetColor(on bool) { colorEnabled = on }

// ColorEnabled сообщает, включён ли цветной вывод.
func ColorEnabled() bool { return colorEnabled }

// IsTTY сообщает, является ли stdin интерактивным терминалом.
// По этому признаку main решает, показывать меню или запускать все тесты.
func IsTTY() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// Коды ANSI. Палитра намеренно ограничена 8 базовыми цветами — они одинаково
// выглядят в любом SSH-клиенте, включая консоли хостеров.
const (
	reset   = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[34m"
	cPurple = "\033[35m"
	cCyan   = "\033[36m"
	cWhite  = "\033[37m"
)

// paint оборачивает строку в ANSI-код, если цвет включён.
func paint(code, s string) string {
	if !colorEnabled || s == "" {
		return s
	}
	return code + s + reset
}

// Раскраска по ролям: ключи — жёлтые, значения — голубые, «да/нет» — зелёный и
// красный, служебные пометки — Dim.
func Bold(s string) string   { return paint(cBold, s) }
func Dim(s string) string    { return paint(cDim, s) }
func Red(s string) string    { return paint(cRed, s) }
func Green(s string) string  { return paint(cGreen, s) }
func Yellow(s string) string { return paint(cYellow, s) }
func Blue(s string) string   { return paint(cBlue, s) }
func Purple(s string) string { return paint(cPurple, s) }
func Cyan(s string) string   { return paint(cCyan, s) }
func White(s string) string  { return paint(cWhite, s) }

// Strip убирает ANSI-последовательности. Нужен для измерения ширины: в
// раскрашенной строке len() считает и невидимые байты, из-за чего колонки
// таблиц разъезжаются.
func Strip(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b { // ESC — начало последовательности
			// Пропускаем всё до завершающей 'm' включительно.
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// visibleLen — число видимых символов (рун) без учёта ANSI-кодов.
// Именно им выравнивает колонки Row в box.go.
func visibleLen(s string) int { return len([]rune(Strip(s))) }
