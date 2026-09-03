package sysinfo

// features_linux.go — факты, которые есть только в Linux: флаги процессора,
// размер кэша, текущая частота, алгоритм управления перегрузкой TCP, красивое
// имя дистрибутива и признаки виртуализации.
//
// Файл собирается только под Linux (по суффиксу имени). Аналог для остальных
// платформ — features_other.go с заглушками. Всё, что читает /proc или /sys,
// должно попадать сюда, иначе сборка под macOS/FreeBSD сломается.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// cpuFeatures определяет по /proc/cpuinfo аппаратное ускорение AES и наличие
// расширений виртуализации. Обрабатываются оба формата: x86 пишет их в
// строку "flags", ARM — в "Features".
//
// Практический смысл: без AES-NI шифрование (TLS, VPN, дисковое) на таком
// сервере будет заметно медленнее, а без vmx/svm на нём нельзя поднять
// вложенную виртуализацию.
func cpuFeatures() (aes, virt bool) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(strings.ToLower(key)) {
		case "flags", "features":
			for _, f := range strings.Fields(strings.ToLower(val)) {
				switch f {
				case "aes", "aes_ni":
					aes = true
				case "vmx", "svm", "el2":
					virt = true
				}
			}
		}
		if aes && virt {
			break
		}
	}
	return aes, virt
}

// cpuCache возвращает самый большой уровень кэша по данным sysfs.
// Берётся максимум по всем index* — это, как правило, L3 (или L2 на простых
// процессорах), то же число, что показывает "cache size" в /proc/cpuinfo.
func cpuCache() string {
	matches, _ := filepath.Glob("/sys/devices/system/cpu/cpu0/cache/index*/size")
	best := 0
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		mult := 1
		switch {
		case strings.HasSuffix(s, "K"):
			s = strings.TrimSuffix(s, "K")
		case strings.HasSuffix(s, "M"):
			s, mult = strings.TrimSuffix(s, "M"), 1024
		}
		if v, err := strconv.Atoi(s); err == nil && v*mult > best {
			best = v * mult
		}
	}
	if best > 0 {
		return strconv.Itoa(best) + " KB"
	}
	return ""
}

// cpuFreq возвращает текущую частоту первого ядра в МГц.
// Это мгновенное значение: под нагрузкой и в простое оно разное.
func cpuFreq() float64 {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(strings.ToLower(key)) == "cpu mhz" {
			if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil {
				return f
			}
		}
	}
	return 0
}

// tcpCongestion возвращает активный алгоритм управления перегрузкой TCP
// (cubic, bbr, …). Для VPS это важный признак: bbr заметно меняет поведение
// канала на дальних маршрутах.
func tcpCongestion() string {
	b, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// prettyOS достаёт PRETTY_NAME из os-release, например "Ubuntu 24.04.4 LTS".
// Проверяются оба стандартных пути: /etc и /usr/lib.
func prettyOS() string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	return ""
}

// detectVirt уточняет тип виртуализации по данным DMI и служебным файлам.
// Порядок проверок: имя продукта в DMI (KVM, VMware, Hyper-V, облачные
// платформы), затем контейнер OpenVZ, затем тип гипервизора Xen.
// Пустая строка означает «уточнить не удалось» — тогда остаётся ответ
// gopsutil, а если и его нет, в отчёте будет "Dedicated".
func detectVirt() string {
	if b, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		switch name := strings.TrimSpace(string(b)); {
		case strings.Contains(name, "KVM"):
			return "KVM"
		case strings.Contains(name, "VMware"):
			return "VMware"
		case strings.Contains(name, "VirtualBox"):
			return "VirtualBox"
		case strings.Contains(name, "Virtual Machine"):
			return "Hyper-V"
		case strings.Contains(name, "Droplet"), strings.Contains(name, "OpenStack"):
			return "KVM"
		}
	}
	if _, err := os.Stat("/proc/vz"); err == nil {
		return "OpenVZ"
	}
	if b, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		if strings.Contains(strings.ToLower(string(b)), "xen") {
			return "Xen"
		}
	}
	return ""
}
