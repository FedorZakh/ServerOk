package ui

// menu.go — интерактивный выбор тестов и подтверждение «да/нет».
//
// Ключевая особенность: ввод читается не обязательно из stdin. Основной способ
// запуска — `curl … | bash`, где stdin занят пайпом от curl; в этом случае
// Input() открывает /dev/tty, и меню продолжает работать. Если терминала нет
// вообще (cron, CI), main просто прогоняет все тесты без меню.

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// MenuItem — один пункт меню. Список строится из реестра тестов
// (cmd/serverok/tests.go), поэтому меню всегда соответствует набору тестов.
type MenuItem struct {
	ID    string // идентификатор теста, он же значение флага -test
	Title string // человекочитаемое имя, как в заголовке секции отчёта
	Note  string // зарезервировано под пояснение к пункту
}

// Input возвращает дескриптор для чтения ввода и признак интерактивности.
// Порядок: сначала stdin (обычный запуск из терминала), затем /dev/tty
// (запуск через пайп), иначе — интерактивности нет.
func Input() (*os.File, bool) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return os.Stdin, true
	}
	if tty, err := os.Open("/dev/tty"); err == nil {
		return tty, true
	}
	return nil, false
}

// Menu печатает нумерованный список тестов и возвращает выбранные ID.
// Второе значение — false, если пользователь отказался от запуска (q или
// пустой/некорректный выбор).
//
// Принимается io.Reader, а не *os.File, чтобы меню можно было прогонять в
// тестах через strings.Reader (см. menu_test.go).
func Menu(items []MenuItem, in io.Reader) ([]string, bool) {
	if in == nil {
		return nil, false
	}
	Blank()
	Header("Select tests to run")

	// Пункты печатаются в две колонки: первая половина слева, вторая справа.
	half := (len(items) + 1) / 2
	for i := 0; i < half; i++ {
		left := fmt.Sprintf(" %s) %s", Green(itoa(i+1)), items[i].Title)
		right := ""
		if j := i + half; j < len(items) {
			right = fmt.Sprintf(" %s) %s", Green(itoa(j+1)), items[j].Title)
		}
		// Ширина считается по видимым символам: в left есть ANSI-коды.
		pad := 36 - visibleLen(left)
		if pad < 1 {
			pad = 1
		}
		Line(left + strings.Repeat(" ", pad) + right)
	}
	Line(" " + Green("a") + ") Run all tests" + strings.Repeat(" ", 21) + Green("q") + ") Quit")
	Divider()
	write(Yellow(" Select (e.g. 1,3,5 or a): "))

	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	// Пустой ввод с ошибкой (закрытый tty, EOF) — выходим, не запуская ничего.
	if err != nil && line == "" {
		return nil, false
	}
	choice := strings.TrimSpace(strings.ToLower(line))
	switch choice {
	case "q", "quit", "exit":
		return nil, false
	case "", "a", "all":
		// Enter без ввода трактуется как «запустить всё» — самый частый сценарий.
		ids := make([]string, 0, len(items))
		for _, it := range items {
			ids = append(ids, it.ID)
		}
		return ids, true
	}

	// Разбор «1,3,5», «1 3 5» и «cpu,disk» — номера и ID можно смешивать.
	var ids []string
	for _, part := range strings.FieldsFunc(choice, func(r rune) bool { return r == ',' || r == ' ' }) {
		n := atoi(part)
		switch {
		case n >= 1 && n <= len(items):
			ids = append(ids, items[n-1].ID)
		default:
			// Не число (или число вне диапазона) — пробуем как идентификатор теста.
			for _, it := range items {
				if it.ID == part {
					ids = append(ids, it.ID)
				}
			}
		}
	}
	if len(ids) == 0 {
		Warn("nothing selected")
		return nil, false
	}
	return ids, true
}

// Confirm задаёт вопрос «да/нет»; по умолчанию (пустой ввод) — «нет».
// Используется для предложения сохранить отчёт после интерактивного прогона.
func Confirm(question string, in io.Reader) bool {
	if in == nil {
		return false
	}
	write(Yellow(" " + question + " [y/N]: "))
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.TrimSpace(strings.ToLower(line))
	return answer == "y" || answer == "yes"
}

// itoa — перевод номера пункта в строку без импорта strconv.
// Меню заведомо короче 100 пунктов, поэтому двух разрядов достаточно.
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// atoi разбирает номер пункта и возвращает -1 для всего, что не является
// целым числом (тогда ввод трактуется как ID теста).
func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	if s == "" {
		return -1
	}
	return n
}
