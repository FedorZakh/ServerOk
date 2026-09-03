//go:build !linux

package sysinfo

// features_other.go — заглушки для платформ без /proc и /sys (macOS, FreeBSD,
// Windows). Тест «System Information» там остаётся рабочим, просто часть
// полей пустует и рендер их пропускает. Основная цель проекта — Linux-VPS,
// остальные платформы поддерживаются для локальной разработки.

import (
	"context"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/v4/cpu"
)

// cpuFeatures опирается на флаги, которые отдаёт gopsutil.
// Для arm64 ответ зашит: в ARMv8 криптографические инструкции и расширения
// виртуализации обязательны для серверных и десктопных чипов, а флагов в
// духе x86 система не публикует.
func cpuFeatures() (aes, virt bool) {
	if runtime.GOARCH == "arm64" {
		return true, true
	}
	infos, err := cpu.InfoWithContext(context.Background())
	if err != nil || len(infos) == 0 {
		return false, false
	}
	for _, f := range infos[0].Flags {
		switch strings.ToLower(f) {
		case "aes", "aes-ni":
			aes = true
		case "vmx", "svm":
			virt = true
		}
	}
	return aes, virt
}

// Ниже — пустые реализации: соответствующие данные на этих платформах либо
// недоступны, либо требуют разбора вывода sysctl, что для целей отчёта
// избыточно.
func cpuCache() string      { return "" }
func cpuFreq() float64      { return 0 }
func tcpCongestion() string { return "" }
func prettyOS() string      { return "" }
func detectVirt() string    { return "" }
