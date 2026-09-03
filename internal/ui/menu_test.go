package ui

import (
	"bytes"
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

// Проверяем все формы ввода: номера, ID, «всё», пустой ввод (= всё), выход и
// заведомо неверный номер.
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
		{"q\n", nil, false},
		{"99\n", nil, false},
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

// По умолчанию (пустой ввод) вопрос должен трактоваться как «нет»:
// сохранение файлов не должно происходить случайно.
func TestConfirm(t *testing.T) {
	Out = io.Discard
	defer func() { Out = nil }()

	if !Confirm("save?", strings.NewReader("y\n")) {
		t.Error("y must confirm")
	}
	if Confirm("save?", strings.NewReader("\n")) {
		t.Error("empty answer must default to no")
	}
	if Confirm("save?", nil) {
		t.Error("nil input must not confirm")
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
