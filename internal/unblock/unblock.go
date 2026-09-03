// Пакет unblock проверяет, доступны ли с этого сервера популярные сервисы
// (стриминг, ИИ-сервисы, магазины) и какой регион они присваивают адресу.
//
// Зачем это в бенчмарке VPS: адреса дата-центров часто лежат в чёрных списках
// стриминговых сервисов, а часть провайдеров вообще недоступна из некоторых
// стран. Для покупателя VPS это такой же важный параметр, как скорость диска.
//
// Устройство: unblock.go — общий каркас (параллельный запуск, таймауты,
// изоляция паник), checks.go — сами проверки, по одной функции на сервис.
//
// Все проверяемые эндпоинты — чужие и со временем меняются. Поэтому каждая
// проверка изолирована: устаревшая деградирует до «Failed», но не ломает
// прогон. По той же причине проверка, которая не смогла подтвердить регион,
// возвращает «unknown», а не «доступно».
package unblock

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/FedorZakh/ServerOk/internal/netutil"
	"github.com/FedorZakh/ServerOk/internal/report"
)

const checkTimeout = 12 * time.Second

// Check — одна проверка сервиса.
type Check struct {
	Name string
	Run  func(ctx context.Context, c *http.Client) report.UnblockItem
}

// Run выполняет все проверки параллельно (не более пяти одновременно) и
// возвращает результаты в порядке объявления — так таблица в отчёте не
// перемешивается от запуска к запуску.
func Run(ctx context.Context, status func(string, ...any)) *report.Unblock {
	checks := AllChecks()
	items := make([]report.UnblockItem, len(checks))

	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0

	for i, chk := range checks {
		wg.Add(1)
		go func(i int, chk Check) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			items[i] = runOne(ctx, chk)

			mu.Lock()
			done++
			status("unblock: %d/%d services checked", done, len(checks))
			mu.Unlock()
		}(i, chk)
	}
	wg.Wait()
	return &report.Unblock{Items: items}
}

// runOne изолирует одну проверку: собственный таймаут, свой HTTP-клиент и
// перехват паники. Паника в разборе чужого HTML не должна ронять весь прогон.
//
// Клиент создаётся отдельно на каждую проверку намеренно: сервисы выдают
// cookies и следят за редиректами, и общий клиент склеивал бы их состояния.
func runOne(ctx context.Context, chk Check) (item report.UnblockItem) {
	item = report.UnblockItem{Service: chk.Name, Status: statusFailed}
	defer func() {
		if r := recover(); r != nil {
			item = report.UnblockItem{Service: chk.Name, Status: statusFailed, Detail: "internal error"}
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	client := netutil.Client(netutil.IPv4, checkTimeout)
	defer client.CloseIdleConnections()
	// Стриминговые сервисы активно используют редиректы (локаль, выбор рынка),
	// поэтому переходы разрешены, но не больше пяти — от циклов.
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	}
	out := chk.Run(cctx, client)
	if out.Service == "" {
		out.Service = chk.Name
	}
	if out.Status == "" {
		out.Status = statusFailed
	}
	return out
}
