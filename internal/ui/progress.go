package ui

// progress.go — временная строка состояния («speedtest: Tokyo, JP»,
// «blacklist: 7/14 zones queried»). Она печатается с возвратом каретки и
// затирается следующим выводом, поэтому в итоговом отчёте её не остаётся.

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// statusActive помнит, висит ли сейчас на экране непогашенная строка статуса.
// Тип атомарный, потому что Statusf вызывается из рабочих горутин
// параллельных проверок, а ClearStatus — из главной.
var statusActive atomic.Bool

// Statusf печатает однострочный статус, который затрёт следующий вывод.
//
// Условие — именно stdoutTTY, а не наличие цвета: при -no-color в терминале
// прогресс должен остаться, а при перенаправлении вывода в файл строки с
// «\r» только замусорили бы отчёт.
func Statusf(format string, a ...any) {
	if !stdoutTTY {
		return
	}
	s := fmt.Sprintf(format, a...)
	if len([]rune(s)) > Width-2 {
		s = string([]rune(s)[:Width-2]) // не переносим строку на вторую
	}
	// Возврат каретки + текст + добивка пробелами до ширины рамки: пробелы
	// стирают хвост предыдущего, более длинного статуса.
	write("\r" + Dim(" "+s) + strings.Repeat(" ", max(0, Width-len([]rune(s))-1)))
	statusActive.Store(true)
}

// ClearStatus стирает строку статуса перед печатью результата.
// Swap возвращает предыдущее значение: если статуса не было, ничего не делаем.
func ClearStatus() {
	if !statusActive.Swap(false) {
		return
	}
	write("\r" + strings.Repeat(" ", Width) + "\r")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
