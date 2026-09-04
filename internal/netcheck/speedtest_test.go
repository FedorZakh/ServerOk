package netcheck

// speedtest_test.go — разбор значения флага -nodes и имени способа замера.
// Проверяется именно то, что видит пользователь: смешивание наборов,
// повторы и опечатки. Сами измерения тестами не покрываются — они ходят в
// сеть.

import (
	"strings"
	"testing"

	"github.com/FedorZakh/ServerOk/internal/report"
)

func TestResolveSet(t *testing.T) {
	cases := []struct {
		in    string
		first string
		count int
	}{
		{"", "Speedtest.net", len(defaultSet)},
		{"fast", "Speedtest.net", len(fastSet)},
		{"eu", "London, UK", len(euSet)},
		{"EUROPE", "London, UK", len(euSet)},
		{"us", "Los Angeles, US", len(usSet)},
		{"asia", "Hong Kong", len(asiaSet)},
	}
	for _, c := range cases {
		nodes, err := resolveSet(c.in)
		if err != nil {
			t.Fatalf("resolveSet(%q): %v", c.in, err)
		}
		if len(nodes) != c.count || nodes[0].Label != c.first {
			t.Errorf("resolveSet(%q) = %d nodes starting with %q, want %d starting with %q",
				c.in, len(nodes), nodes[0].Label, c.count, c.first)
		}
	}
}

func TestResolveSetCombines(t *testing.T) {
	nodes, err := resolveSet("eu, asia, 12345")
	if err != nil {
		t.Fatalf("resolveSet: %v", err)
	}
	if want := len(euSet) + len(asiaSet) + 1; len(nodes) != want {
		t.Fatalf("got %d nodes, want %d", len(nodes), want)
	}
	last := nodes[len(nodes)-1]
	if last.Search != "12345" || last.Label != "Server 12345" {
		t.Errorf("numeric ID should become a node of its own: %+v", last)
	}
}

func TestResolveSetDeduplicates(t *testing.T) {
	// Наборы пересекаются (Токио есть и в default, и в asia) — город не
	// должен меряться дважды.
	nodes, err := resolveSet("default,asia,europe,eu")
	if err != nil {
		t.Fatalf("resolveSet: %v", err)
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		if seen[n.Label] {
			t.Errorf("node %q appears twice", n.Label)
		}
		seen[n.Label] = true
	}
}

func TestResolveSetRejectsUnknown(t *testing.T) {
	if _, err := resolveSet("eu,mars"); err == nil {
		t.Fatal("unknown set name should be an error, not a silent skip")
	} else if !strings.Contains(err.Error(), "mars") {
		t.Errorf("error should name the offending part: %v", err)
	}
}

func TestValidateSet(t *testing.T) {
	if err := ValidateSet("us,eu"); err != nil {
		t.Errorf("us,eu should be valid: %v", err)
	}
	if err := ValidateSet("nowhere"); err == nil {
		t.Error("nowhere should be rejected")
	}
}

func TestNormalizeMethod(t *testing.T) {
	cases := map[string]string{
		"":              report.MethodOokla,
		"ookla":         report.MethodOokla,
		"Speedtest.net": report.MethodOokla,
		" Cloudflare  ": report.MethodCloudflare,
		"cf":            report.MethodCloudflare,
		"fast.com":      "",
	}
	for in, want := range cases {
		if got := NormalizeMethod(in); got != want {
			t.Errorf("NormalizeMethod(%q) = %q, want %q", in, got, want)
		}
	}
}
