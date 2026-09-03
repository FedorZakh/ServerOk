// Пакет bench — локальные бенчмарки: процессор (cpu.go), память (mem.go) и
// диск (disk.go). Общее правило пакета: измерять устройство, а не обвязку —
// всё, что можно подготовить заранее (буферы, случайные смещения), готовится
// до старта секундомера.
package bench

// disk.go — замер дисковой подсистемы.
//
// Последовательная запись повторяет методику bench.sh (`dd bs=512k
// conv=fdatasync`): пишем файл блоками по 512 КиБ и один раз сбрасываем на
// устройство. Три прогона и среднее — чтобы сгладить попадание в кэш
// хостовой машины. Дополнительно меряются 4K IOPS случайной записи.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/shirou/gopsutil/v4/disk"

	"github.com/FedorZakh/ServerOk/internal/report"
)

const (
	defaultBlock    = 512 << 10 // размер блока записи, как у dd в bench.sh
	defaultTestSize = 1 << 30   // 1 ГиБ — объём одного прогона по умолчанию
	reducedSize     = 256 << 20 // запасной объём, когда места мало
	minFreeSpace    = 512 << 20 // меньше этого — тест не запускаем вовсе
	randomFileSize  = 64 << 20  // область, по которой бьёт случайная запись
	randomBlock     = 4096      // размер блока случайной записи
	randomWrites    = 1500      // сколько таких записей выполняем
)

// Disk измеряет скорость последовательной записи (runs прогонов) и, если
// получится, 4K IOPS случайной записи.
//
// Файлы создаются в path (по умолчанию — текущий каталог, как в bench.sh) и
// удаляются в любом случае, включая Ctrl+C. Если свободного места меньше
// полутора объёмов теста, объём уменьшается, и об этом сообщается в отчёте —
// иначе цифры несопоставимы с чужими прогонами.
func Disk(ctx context.Context, path string, size uint64, runs int, status func(string, ...any)) (*report.DiskIO, error) {
	if path == "" {
		path = defaultDiskPath()
	}
	if runs <= 0 {
		runs = 3
	}
	if size == 0 {
		size = defaultTestSize
	}

	res := &report.DiskIO{Path: path, BlockSize: defaultBlock, TestSize: size}
	// Проверка свободного места: тест не должен доводить раздел до нуля.
	if u, err := disk.UsageWithContext(ctx, path); err == nil {
		if u.Free < minFreeSpace {
			return nil, fmt.Errorf("not enough free space on %s (%s available)", path, report.HumanBytes(u.Free))
		}
		if u.Free < size*3/2 {
			res.TestSize = reducedSize
			res.ReducedSize = true
		}
	}

	// Буфер заполняется ненулевыми данными: файловые системы со сжатием или
	// поддержкой разрежённых файлов могут «схлопнуть» запись нулей и выдать
	// фантастическую скорость.
	buf := make([]byte, defaultBlock)
	for i := range buf {
		buf[i] = byte(i)
	}

	for i := 0; i < runs; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		status("disk: sequential write run %d/%d (%s)", i+1, runs, report.HumanBytes(res.TestSize))
		mbs, err := sequentialWrite(ctx, path, buf, res.TestSize)
		if err != nil {
			return nil, err
		}
		res.Runs = append(res.Runs, mbs)
		res.Average += mbs
	}
	if len(res.Runs) > 0 {
		res.Average /= float64(len(res.Runs))
	}

	status("disk: 4K random write")
	iops, err := randomWrite(ctx, path)
	switch {
	case err == nil:
		res.RandWrIOPS = iops
	case ctx.Err() != nil:
		// Прерывание пользователем: отдаём ошибку, чтобы runner отметил тест
		// как незавершённый, а не сделал вид, что IOPS просто не измерились.
		return nil, ctx.Err()
	}
	return res, nil
}

// sequentialWrite пишет total байт блоками и один раз делает Sync.
//
// Sync обязателен: без него измерялась бы скорость страничного кэша, а не
// диска. На macOS File.Sync выполняет F_FULLFSYNC, на Linux — fsync, то есть
// поведение соответствует `dd conv=fdatasync`.
func sequentialWrite(ctx context.Context, dir string, block []byte, total uint64) (float64, error) {
	f, err := os.CreateTemp(dir, ".servertester-io-*")
	if err != nil {
		return 0, fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	name := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(name)
	}()

	start := time.Now()
	var written uint64
	for written < total {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, err := f.Write(block)
		if err != nil {
			return 0, err
		}
		written += uint64(n)
	}
	if err := f.Sync(); err != nil {
		return 0, err
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0, fmt.Errorf("timer resolution too low")
	}
	return float64(written) / (1024 * 1024) / elapsed, nil
}

// randomWrite измеряет IOPS случайной записи блоками по 4 КиБ.
//
// Два принципиальных момента (оба были найдены на ревью):
//  1. Смещения генерируются ДО запуска секундомера — иначе в измерение
//     попадает работа генератора случайных чисел.
//  2. Смещения выровнены по размеру блока: невыровненная запись заставляет
//     устройство делать read-modify-write, и это уже не «4K запись».
//
// Sync делается не после каждой записи, а раз в 32: посинхронная запись
// меряла бы задержку сброса кэша, а не пропускную способность.
func randomWrite(ctx context.Context, dir string) (float64, error) {
	f, err := os.CreateTemp(dir, ".servertester-rnd-*")
	if err != nil {
		return 0, err
	}
	name := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(name)
	}()

	if err := f.Truncate(randomFileSize); err != nil {
		return 0, err
	}
	block := make([]byte, randomBlock)
	for i := range block {
		block[i] = byte(i)
	}

	slots := randomFileSize / randomBlock
	offsets := make([]int64, randomWrites)
	for i := range offsets {
		offsets[i] = int64(rand.IntN(slots)) * randomBlock
	}

	start := time.Now()
	for i, off := range offsets {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if _, err := f.WriteAt(block, off); err != nil {
			return 0, err
		}
		// Sync раз в 32 записи: синхронизация после каждой превратила бы тест
		// в замер задержки сброса кэша, а не пропускной способности.
		if i%32 == 31 {
			if err := f.Sync(); err != nil {
				return 0, err
			}
		}
	}
	if err := f.Sync(); err != nil {
		return 0, err
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0, fmt.Errorf("timer resolution too low")
	}
	return float64(randomWrites) / elapsed, nil
}

// defaultDiskPath выбирает каталог для теста: текущий, если в него можно
// писать (это ожидаемое поведение — тест меряет тот раздел, где работает
// пользователь), иначе — системный временный каталог. Проверка делается
// созданием и удалением пробного файла.
func defaultDiskPath() string {
	wd, err := os.Getwd()
	if err != nil {
		return os.TempDir()
	}
	probe, err := os.CreateTemp(wd, ".servertester-probe-*")
	if err != nil {
		return os.TempDir()
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())
	return filepath.Clean(wd)
}
