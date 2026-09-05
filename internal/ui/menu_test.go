package ui

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// menu_test.go — разбор пользовательского ввода в меню и корректность
// выравнивания раскрашенных строк.

func testItems() []MenuItem {
	return []MenuItem{
		{ID: "system", Title: "System Information"},
		{ID: "cpu", Title: "CPU Benchmark"},
		{ID: "disk", Title: "Disk I/O Speed"},
	}
}

// Проверяем все формы ввода: номера, ID, «всё», пустой ввод (= всё), выход
// (0) и заведомо неверный номер.
func TestMenuSelection(t *testing.T) {
	Out = io.Discard
	defer func() { Out = nil }()

	cases := []struct {
		input string
		want  []string
		ok    bool
	}{
		{"1,3\n", []string{"system", "disk"}, true},
		{"2\n", []string{"cpu"}, true},
		{"a\n", []string{"system", "cpu", "disk"}, true},
		{"\n", []string{"system", "cpu", "disk"}, true},
		{"cpu, disk\n", []string{"cpu", "disk"}, true},
		{"0\n", nil, false},
		{"q\n", nil, false},
		// Неверный номер не завершает меню: оно спрашивает снова и получает
		// EOF из тестового читателя.
		{"99\n", nil, false},
		{"99\n2\n", []string{"cpu"}, true},
	}
	for _, c := range cases {
		got, ok := Menu(testItems(), strings.NewReader(c.input))
		if ok != c.ok {
			t.Errorf("Menu(%q) ok = %v, want %v", c.input, ok, c.ok)
			continue
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("Menu(%q) = %v, want %v", c.input, got, c.want)
		}
	}
}

// Ширина раскрашенной строки должна считаться по видимым символам — от этого
// зависит выравнивание всех таблиц отчёта.
func TestStripANSI(t *testing.T) {
	SetColor(true)
	colored := Green("ok") + Yellow("!")
	if Strip(colored) != "ok!" {
		t.Errorf("Strip(%q) = %q", colored, Strip(colored))
	}
	if visibleLen(colored) != 3 {
		t.Errorf("visibleLen = %d, want 3", visibleLen(colored))
	}
}

// Тот же инвариант, но уже на уровне Row: цветная ячейка не должна сдвигать
// колонку.
func TestRowAlignsOnVisibleWidth(t *testing.T) {
	var buf bytes.Buffer
	Out = &buf
	defer func() { Out = nil }()
	SetColor(true)
	Row([]int{10, 10}, Green("ab"), "cd")
	line := Strip(buf.String())
	if line != "ab        cd\n" {
		t.Errorf("Row produced %q", line)
	}
}

// Подменю выбора: Enter означает вариант по умолчанию, номер — свой вариант,
// а закрытый ввод не должен выглядеть как осознанный выбор.
func TestChoose(t *testing.T) {
	var buf bytes.Buffer
	Out = &buf
	defer func() { Out = nil }()
	items := []Choice{{Label: "first"}, {Label: "second"}, {Label: "third"}}

	if got, ok := Choose("pick", items, 1, strings.NewReader("\n")); got != 1 || !ok {
		t.Errorf("empty input = (%d, %v), want (1, true)", got, ok)
	}
	if got, ok := Choose("pick", items, 0, strings.NewReader("3\n")); got != 2 || !ok {
		t.Errorf("\"3\" = (%d, %v), want (2, true)", got, ok)
	}
	// Мусор не выбрасывает из подменю — спрашиваем снова.
	if got, ok := Choose("pick", items, 0, strings.NewReader("9\nzz\n2\n")); got != 1 || !ok {
		t.Errorf("retry = (%d, %v), want (1, true)", got, ok)
	}
	if got, ok := Choose("pick", items, 2, strings.NewReader("")); got != 2 || ok {
		t.Errorf("closed input = (%d, %v), want (2, false)", got, ok)
	}
}

// Ask должен переспрашивать после неверного ответа, не теряя остаток ввода:
// именно на этом ломался бы новый bufio.Reader на каждой попытке.
func TestAsk(t *testing.T) {
	Out = io.Discard
	defer func() { Out = nil }()

	// Валидатор: принимает только строки с точкой (упрощённый «домен»).
	validate := func(s string) (string, error) {
		if !strings.Contains(s, ".") {
			return "", errors.New("not a domain")
		}
		return strings.ToLower(s), nil
	}
	cases := []struct {
		input string
		want  string
	}{
		{"Example.COM\n", "example.com"},
		{"nonsense\nexample.net\n", "example.net"}, // первая попытка отвергнута
		{"\n", ""}, // Enter — отказ отвечать
		{"", ""},   // закрытый ввод
	}
	for _, c := range cases {
		if got := Ask("Title", "Domain", validate, strings.NewReader(c.input)); got != c.want {
			t.Errorf("Ask(%q) = %q, want %q", c.input, got, c.want)
		}
	}
	if got := Ask("Title", "Domain", validate, nil); got != "" {
		t.Errorf("Ask(nil) = %q", got)
	}
}

// KVList печатает первое значение в строке с ключом, остальные — под ним,
// с отступом ровно под значение.
func TestKVList(t *testing.T) {
	var buf bytes.Buffer
	Out = &buf
	SetColor(false)
	// Цвет возвращается на место: тесты пакета идут по очереди, и выключенный
	// цвет сбил бы проверки выравнивания раскрашенных строк.
	defer func() { Out = nil; SetColor(true) }()

	KVList("Name Servers", []string{"ns1.example.net", "ns2.example.net"})
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines: %q", len(lines), buf.String())
	}
	if strings.Index(lines[0], "ns1.example.net") != strings.Index(lines[1], "ns2.example.net") {
		t.Errorf("values are not aligned:\n%s", buf.String())
	}
	buf.Reset()
	KVList("Empty", nil)
	if buf.Len() != 0 {
		t.Errorf("an empty list must print nothing, got %q", buf.String())
	}
}
