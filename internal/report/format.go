package report

// format.go — форматирование величин для отчёта. Вынесено отдельно, потому
// что одни и те же функции используют все три рендера (текст, Markdown) и
// тесты: если поменять здесь формат, он поменяется везде согласованно.

import (
	"fmt"
	"strings"
)

// HumanBytes печатает размер так же, как bench.sh: "29.9 GB", "512.0 MB".
// Единицы двоичные (1 KB = 1024 байта) — так их показывают free/df, с
// которыми пользователь будет сверять шапку отчёта.
func HumanBytes(b uint64) string {
	const unit = 1024.0
	f := float64(b)
	switch {
	case b == 0:
		return "0 KB" // именно "0 KB", а не "0 B" — как в оригинальном bench.sh
	case f < unit*unit:
		return fmt.Sprintf("%.1f KB", f/unit)
	case f < unit*unit*unit:
		return fmt.Sprintf("%.1f MB", f/(unit*unit))
	case f < unit*unit*unit*unit:
		return fmt.Sprintf("%.1f GB", f/(unit*unit*unit))
	default:
		return fmt.Sprintf("%.1f TB", f/(unit*unit*unit*unit))
	}
}

// UsedOf печатает «всего (занято)»: "29.9 GB (2.9 GB Used)".
func UsedOf(total, used uint64) string {
	return fmt.Sprintf("%s (%s Used)", HumanBytes(total), HumanBytes(used))
}

// Uptime печатает время работы в формате bench.sh: "3 days, 4 hour 12 min".
// Грамматика намеренно не согласуется по числу — так в оригинале.
func Uptime(sec uint64) string {
	days := sec / 86400
	hours := (sec % 86400) / 3600
	mins := (sec % 3600) / 60
	return fmt.Sprintf("%d days, %d hour %d min", days, hours, mins)
}

// Speed печатает скорость канала в Мбит/с.
func Speed(mbps float64) string {
	if mbps <= 0 {
		return "0.00 Mbps"
	}
	return fmt.Sprintf("%.2f Mbps", mbps)
}

// MBs печатает скорость диска в МБ/с.
func MBs(v float64) string { return fmt.Sprintf("%.1f MB/s", v) }

// Latency печатает время отклика; прочерк означает «не измерено».
func Latency(ms float64) string {
	if ms <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.2f ms", ms)
}

// Truncate обрезает строку до n символов (не байт — рун, поэтому кириллица и
// имена сетей не рвутся посередине), добавляя многоточие.
// Используется, чтобы длинные значения не ломали ширину колонок.
func Truncate(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// JoinNonEmpty склеивает только непустые части. Нужен постоянно: у половины
// внешних API часть полей приходит пустыми, и без этого в отчёте появлялись
// бы висящие запятые вида "Frankfurt, , DE".
func JoinNonEmpty(sep string, parts ...string) string {
	out := parts[:0:0] // новый слайс, не переиспользуя массив аргументов
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return strings.Join(out, sep)
}
