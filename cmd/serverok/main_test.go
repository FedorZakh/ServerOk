package main

// main_test.go — тесты разбора аргументов и реестра тестов.

import (
	"strings"
	"testing"

	"github.com/FedorZakh/ServerOk/internal/netcheck"
)

// Проверяем разбор размера с суффиксами. Кейс "1.5G" важен: дробные размеры
// используются, чтобы уместить тест на почти полном диске.
func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"1G", 1 << 30},
		{"512M", 512 << 20},
		{"2048K", 2048 << 10},
		{"1024", 1024},
		{"1.5G", 1610612736},
	}
	for _, c := range cases {
		got, err := parseSize(c.in)
		if err != nil {
			t.Fatalf("parseSize(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("parseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	if _, err := parseSize("huge"); err == nil {
		t.Error("expected an error for an unparsable size")
	}
}

// Реестр обязан возвращать тесты в порядке отчёта, а не в порядке, в котором
// их перечислил пользователь, и распознавать как ID, так и номера пунктов меню.
func TestRegistrySelect(t *testing.T) {
	reg := buildRegistry()
	sel, err := reg.Select([]string{"disk", "cpu"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 2 || sel[0].ID != "cpu" || sel[1].ID != "disk" {
		t.Errorf("Select must return tests in report order, got %+v", sel)
	}
	if _, err := reg.Select([]string{"nope"}); err == nil {
		t.Error("expected an error for an unknown test id")
	}
	// Номера пунктов меню тоже должны разрешаться.
	if sel, err := reg.Select([]string{"1"}); err != nil || sel[0].ID != "system" {
		t.Errorf("index selection failed: %+v %v", sel, err)
	}
}

// Подменю speedtest должно давать флагам ровно те же значения, что и
// командная строка: каждый вариант обязан быть разрешимым набором точек.
func TestSpeedProfiles(t *testing.T) {
	for _, p := range speedProfiles {
		if netcheck.NormalizeMethod(p.method) == "" {
			t.Errorf("%q: unknown method %q", p.choice.Label, p.method)
		}
		if p.method == netcheck.MethodOokla {
			if err := netcheck.ValidateSet(p.nodes); err != nil {
				t.Errorf("%q: %v", p.choice.Label, err)
			}
		}
	}
}

// Ответ пользователя должен попадать в настройки прогона, а закрытый ввод —
// давать первый (он же рекомендованный) вариант.
func TestAskSpeedProfile(t *testing.T) {
	method, nodes := askSpeedProfile(strings.NewReader("3\n"))
	if method != netcheck.MethodOokla || nodes != "eu" {
		t.Errorf("third option = (%q, %q), want ookla/eu", method, nodes)
	}
	method, nodes = askSpeedProfile(strings.NewReader(""))
	if method != speedProfiles[0].method || nodes != speedProfiles[0].nodes {
		t.Errorf("closed input = (%q, %q), want the default profile", method, nodes)
	}
}

// includes отвечает на вопрос «просили ли speedtest» — от него зависит, будет
// ли задан вопрос о способе замера.
func TestIncludes(t *testing.T) {
	sel, err := buildRegistry().Select([]string{"cpu", "speedtest"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if !includes(sel, "speedtest") || includes(sel, "disk") {
		t.Errorf("includes misreports the selection: %v", sel)
	}
}
