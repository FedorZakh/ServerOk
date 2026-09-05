// Пакет sysinfo собирает всё, что показывается в шапке отчёта: процессор,
// память, диски, ОС, гипервизор и сетевую «личность» машины.
//
// Источники данных, по убыванию точности:
//  1. gopsutil — кроссплатформенные факты (модель CPU, память, разделы, uptime);
//  2. /proc и /sys — то, что gopsutil не отдаёт или отдаёт хуже: флаги CPU,
//     размер кэша, congestion control, признаки виртуализации (features_linux.go);
//  3. внешние сервисы — ASN и локация публичного адреса (через пакет ipinfo).
//
// Разделение по платформам сделано тегами сборки: features_linux.go читает
// /proc и /sys, features_other.go возвращает заглушки. Всё, что читает /proc,
// должно жить в первом файле.
package sysinfo

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/Zagorsky17/ServerOk/internal/ipinfo"
	"github.com/Zagorsky17/ServerOk/internal/netutil"
	"github.com/Zagorsky17/ServerOk/internal/report"
)

// Collect собирает данные для шапки отчёта.
//
// Функция намеренно не возвращает ошибку при частичных неудачах: если не
// удалось прочитать swap или узнать ASN, соответствующие поля просто остаются
// пустыми, а рендер их пропускает. Тест «System Information» должен давать
// результат даже на урезанном контейнере без сети.
func Collect(ctx context.Context, skipIPv6 bool) (*report.System, error) {
	s := &report.System{
		Arch:     runtime.GOARCH,
		ArchBits: archBits(),
	}

	// --- процессор ---
	if infos, err := cpu.InfoWithContext(ctx); err == nil && len(infos) > 0 {
		s.CPUModel = strings.TrimSpace(infos[0].ModelName)
		s.CPUFreqMHz = infos[0].Mhz
		if infos[0].CacheSize > 0 {
			s.CPUCache = fmt.Sprintf("%d KB", infos[0].CacheSize)
		}
	}
	if s.CPUModel == "" {
		s.CPUModel = "unknown"
	}
	// Считаем логические ядра: именно их «продаёт» хостер и видит планировщик.
	if n, err := cpu.CountsWithContext(ctx, true); err == nil && n > 0 {
		s.CPUCores = n
	} else {
		s.CPUCores = runtime.NumCPU()
	}
	// На Linux данные из sysfs точнее, чем то, что вернул gopsutil, — если они
	// есть, перекрывают предыдущие значения.
	if c := cpuCache(); c != "" {
		s.CPUCache = c
	}
	if f := cpuFreq(); f > 0 {
		s.CPUFreqMHz = f
	}
	s.AESNI, s.VirtExt = cpuFeatures()

	// --- память и диски ---
	if vm, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		s.RAMTotal = vm.Total
		s.RAMUsed = vm.Used
	}
	if sw, err := mem.SwapMemoryWithContext(ctx); err == nil {
		s.SwapTotal = sw.Total
		s.SwapUsed = sw.Used
	}
	s.DiskTotal, s.DiskUsed = diskTotals(ctx)

	// --- ОС, аптайм, гипервизор ---
	if h, err := host.InfoWithContext(ctx); err == nil {
		s.UptimeSec = h.Uptime
		s.Kernel = report.JoinNonEmpty(" ", h.KernelVersion, h.KernelArch)
		s.OS = report.JoinNonEmpty(" ", capitalize(h.Platform), h.PlatformVersion)
		s.Virtualization = prettyVirt(h.VirtualizationSystem, h.VirtualizationRole)
	}
	// PRETTY_NAME из os-release читается человеком лучше, чем сборка из
	// platform+version ("Ubuntu 24.04.4 LTS" против "Ubuntu 24.04").
	if pretty := prettyOS(); pretty != "" {
		s.OS = pretty
	}
	if s.OS == "" {
		s.OS = runtime.GOOS
	}
	if avg, err := load.AvgWithContext(ctx); err == nil {
		s.LoadAvg = [3]float64{avg.Load1, avg.Load5, avg.Load15}
	}
	s.TCPCongestion = tcpCongestion()
	// DMI/sysfs дают более конкретный ответ, чем эвристика gopsutil
	// (например, отличают KVM от «просто виртуалки»).
	if v := detectVirt(); v != "" {
		s.Virtualization = v
	}
	if s.Virtualization == "" {
		s.Virtualization = "Dedicated"
	}

	// --- связность и «личность» адреса ---
	// Проверяем именно TCP-соединение с публичным адресом: ICMP на многих
	// хостингах закрыт, а факт «интернет есть» нужен достоверный.
	s.IPv4Online = netutil.TCPReachable(ctx, netutil.IPv4, "1.1.1.1:443", 3*time.Second)
	if !skipIPv6 {
		s.IPv6Online = netutil.TCPReachable(ctx, netutil.IPv6, "[2606:4700:4700::1111]:443", 3*time.Second)
	}
	if s.IPv4Online {
		// Результат запоминается внутри ipinfo, поэтому тест «IP Location»
		// потом переиспользует его без второго запроса к API.
		if g, err := ipinfo.LookupGeo(ctx, netutil.IPv4); err == nil {
			s.Org, s.Location, s.Region = ipinfo.SummaryFields(g)
		}
	}
	return s, nil
}

// capitalize делает первую букву заглавной: "ubuntu" -> "Ubuntu".
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// archBits возвращает разрядность для строки Arch отчёта.
func archBits() string {
	switch runtime.GOARCH {
	case "amd64", "arm64", "ppc64", "ppc64le", "s390x", "riscv64", "mips64", "mips64le", "loong64":
		return "(64 Bit)"
	default:
		return "(32 Bit)"
	}
}

// diskTotals суммирует реальные примонтированные файловые системы.
//
// Виртуальные ФС (tmpfs, overlay и прочие) исключаются, а устройства
// учитываются по одному разу: иначе bind-монтирования и подтома удваивают
// объём. Если ничего не нашлось — откат на корневой раздел, чтобы поле не
// осталось нулевым.
func diskTotals(ctx context.Context) (total, used uint64) {
	parts, err := disk.PartitionsWithContext(ctx, false)
	if err != nil || len(parts) == 0 {
		if u, err := disk.UsageWithContext(ctx, "/"); err == nil {
			return u.Total, u.Used
		}
		return 0, 0
	}
	seen := map[string]bool{}
	for _, p := range parts {
		if isVirtualFS(p.Fstype) || seen[p.Device] {
			continue
		}
		u, err := disk.UsageWithContext(ctx, p.Mountpoint)
		if err != nil || u.Total == 0 {
			continue
		}
		seen[p.Device] = true
		total += u.Total
		used += u.Used
	}
	if total == 0 {
		if u, err := disk.UsageWithContext(ctx, "/"); err == nil {
			return u.Total, u.Used
		}
	}
	return total, used
}

// isVirtualFS отсеивает псевдо-файловые системы, которые не являются диском.
func isVirtualFS(fstype string) bool {
	switch strings.ToLower(fstype) {
	case "tmpfs", "devtmpfs", "squashfs", "overlay", "ramfs", "proc", "sysfs", "cgroup", "cgroup2",
		"devfs", "autofs", "fuse.snapfuse", "fuse.gvfsd-fuse", "iso9660", "efivarfs":
		return true
	}
	return false
}

// prettyVirt приводит название гипервизора к привычному виду ("kvm" -> "KVM").
// Неизвестные значения оставляются как есть — лучше показать сырое имя, чем
// потерять информацию.
func prettyVirt(system, role string) string {
	if system == "" {
		return ""
	}
	name := map[string]string{
		"kvm": "KVM", "qemu": "QEMU", "xen": "Xen", "vmware": "VMware",
		"microsoft": "Hyper-V", "hyperv": "Hyper-V", "openvz": "OpenVZ",
		"lxc": "LXC", "docker": "Docker", "podman": "Podman", "bhyve": "bhyve",
		"virtualbox": "VirtualBox", "vbox": "VirtualBox", "parallels": "Parallels",
	}[strings.ToLower(system)]
	if name == "" {
		name = system
	}
	// role == "host" означает, что мы сами гипервизор, а не гость.
	if role == "host" {
		return name + " host"
	}
	return name
}
