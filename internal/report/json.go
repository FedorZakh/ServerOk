package report

// json.go — экспорт отчёта в JSON (флаг -json). Формат задан тегами в
// model.go; пустые секции не попадают в файл благодаря omitempty.

import (
	"encoding/json"
	"os"
)

// WriteJSON сохраняет отчёт в JSON с отступами.
// Права 0644: в отчёте нет секретов, только публичный IP и характеристики
// машины, зато файл удобно забрать мониторингом.
func WriteJSON(r *Report, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}
