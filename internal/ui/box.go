package ui

// box.go — примитивы рамки отчёта. Всё, что печатает программа, проходит
// через write() из этого файла: так вывод остаётся выровненным и его можно
// целиком перенаправить в буфер в тестах.

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Out — приёмник всего вывода. По умолчанию stdout; тесты подменяют его на
// буфер, чтобы проверять готовые строки.
var Out io.Writer = os.Stdout

// writeMu сериализует запись. Это не перестраховка: строки прогресса
// приходят из рабочих горутин параллельных проверок (DNSBL, порты, задержки,
// разблокировка), и без мьютекса вывод может перемешаться.
var writeMu sync.Mutex

// write — единственная точка записи в Out.
func write(s string) {
	writeMu.Lock()
	defer writeMu.Unlock()
	fmt.Fprint(Out, s)
}

// Line печатает строку целиком.
func Line(s string) { write(s + "\n") }

// Blank печатает пустую строку-отбивку между секциями.
func Blank() { write("\n") }

// Divider печатает горизонтальную линию во всю ширину рамки.
func Divider() { Line(Yellow(strings.Repeat("-", Width))) }

// Header печатает разделитель с заголовком по центру:
// "-------------------- System Information --------------------".
// Так начинается каждая секция отчёта; заголовок берётся из Title теста.
func Header(title string) {
	t := " " + title + " "
	dashes := Width - len([]rune(t))
	if dashes < 4 {
		dashes = 4 // очень длинный заголовок: оставляем хотя бы по два тире
	}
	left := dashes / 2
	right := dashes - left
	Line(Yellow(strings.Repeat("-", left)) + Bold(White(t)) + Yellow(strings.Repeat("-", right)))
}

// KV печатает выровненную строку «Ключ                : значение».
// Значение раскрашивается голубым — это основной формат шапки отчёта.
func KV(key, value string) {
	pad := keyWidth - len([]rune(key))
	if pad < 0 {
		pad = 0
	}
	Line(Yellow(key) + strings.Repeat(" ", pad) + Yellow(":") + " " + Cyan(value))
}

// KVRaw — то же самое, но значение не перекрашивается: вызывающий уже
// раскрасил его сам (например, зелёное «✓ Enabled» или красное «✗ Offline»).
func KVRaw(key, value string) {
	pad := keyWidth - len([]rune(key))
	if pad < 0 {
		pad = 0
	}
	Line(Yellow(key) + strings.Repeat(" ", pad) + Yellow(":") + " " + value)
}

// Note печатает приглушённую пометку с отступом (например, «тест пропущен,
// нужен root»).
func Note(s string) { Line(Dim(" " + s)) }

// Warn печатает предупреждение — им отмечаются неудавшиеся тесты.
func Warn(s string) { Line(Red(" ! " + s)) }

// Yes и No — маркеры ✓/✗ для булевых полей шапки (AES-NI, IPv6, BBR).
func Yes(s string) string { return Green("✓ " + s) }
func No(s string) string  { return Red("✗ " + s) }

// Row печатает строку таблицы: ячейки дополняются пробелами до заданных
// ширин. Ширина считается по visibleLen, то есть без ANSI-кодов — иначе
// раскрашенные ячейки съезжают. Сами цвета Row не назначает, это делает
// вызывающий (report/text.go).
func Row(widths []int, cells ...string) {
	var b strings.Builder
	for i, c := range cells {
		b.WriteString(c)
		if i < len(cells)-1 { // после последней ячейки добивка не нужна
			pad := widths[i] - visibleLen(c)
			if pad < 1 {
				pad = 1 // ячейка шире колонки: хотя бы один пробел-разделитель
			}
			b.WriteString(strings.Repeat(" ", pad))
		}
	}
	Line(strings.TrimRight(b.String(), " "))
}
