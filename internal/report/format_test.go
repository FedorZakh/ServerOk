package report

// format_test.go — форматирование величин отчёта. Значения сверены с выводом
// оригинального bench.sh, поэтому тесты фиксируют именно его формат.

import "testing"

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0 KB"},
		{512 << 10, "512.0 KB"},
		{2 << 20, "2.0 MB"},
		{32105906176, "29.9 GB"},
	}
	for _, c := range cases {
		if got := HumanBytes(c.in); got != c.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestUptime(t *testing.T) {
	if got := Uptime(300); got != "0 days, 0 hour 5 min" {
		t.Errorf("Uptime(300) = %q", got)
	}
	if got := Uptime(3*86400 + 4*3600 + 12*60); got != "3 days, 4 hour 12 min" {
		t.Errorf("Uptime = %q", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("abcdefgh", 4); got != "abc…" {
		t.Errorf("Truncate = %q", got)
	}
	if got := Truncate("abc", 10); got != "abc" {
		t.Errorf("Truncate = %q", got)
	}
}

func TestJoinNonEmpty(t *testing.T) {
	if got := JoinNonEmpty(", ", "Berlin", "", "DE"); got != "Berlin, DE" {
		t.Errorf("JoinNonEmpty = %q", got)
	}
}

func TestSpeedMethodLabel(t *testing.T) {
	if got := SpeedMethodLabel(MethodOokla, "eu"); got != "Ookla (speedtest.net) · nodes: eu" {
		t.Errorf("ookla label = %q", got)
	}
	// Пустой способ — это способ по умолчанию, а не «неизвестно».
	if got := SpeedMethodLabel("", ""); got != "Ookla (speedtest.net) · nodes: default" {
		t.Errorf("default label = %q", got)
	}
	// У Cloudflare узел всегда один, набор точек к нему неприменим.
	if got := SpeedMethodLabel(MethodCloudflare, "eu"); got != "Cloudflare (nearest edge)" {
		t.Errorf("cloudflare label = %q", got)
	}
}
