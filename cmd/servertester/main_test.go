package main

// main_test.go — тесты разбора аргументов и реестра тестов.

import "testing"

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
