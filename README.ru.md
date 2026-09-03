# ServerOk

Бенчмарк и диагностика VPS одним бинарником — в духе `bench.sh`, но на Go, с
интерактивным меню выбора тестов и заметно более широким набором проверок:
геолокация IP, **данные RDAP о том, на кого зарегистрирован IP**, репутация IP
по DNSBL, проверка разблокировки стриминга и AI-сервисов, диагностика
маршрутизации.

На сервере ничего не нужно: один статический бинарник, без Python,
`speedtest-cli` и `whois`.

## Быстрый старт

Запуск прямо с GitHub — скрипт скачает бинарник под вашу платформу, проверит
SHA-256 и откроет меню:

```bash
bash <(curl -sL https://raw.githubusercontent.com/FedorZakh/ServerOk/main/scripts/install.sh)
```

Прогнать все тесты без меню (так же происходит автоматически, если терминала
нет — например, в cron):

```bash
curl -sL https://raw.githubusercontent.com/FedorZakh/ServerOk/main/scripts/install.sh | bash -s -- -all
```

Установить в систему:

```bash
bash <(curl -sL https://raw.githubusercontent.com/FedorZakh/ServerOk/main/scripts/install.sh) --install
serverok
```

Скрипт откажется запускать бинарник, который не удалось сверить с
`checksums.txt`; отменяет это `--no-verify`, а каталог задаётся `--install=<dir>`.

Собрать самому:

```bash
go install github.com/FedorZakh/ServerOk/cmd/serverok@latest
# или
git clone https://github.com/FedorZakh/ServerOk && cd serverok && make build
```

### Запуск после установки

`--install` кладёт бинарник в `PATH` (по умолчанию `/usr/local/bin/serverok`),
дальше достаточно:

```bash
serverok                 # интерактивное меню
serverok -all             # все тесты без меню
serverok -test cpu,disk   # только нужные тесты (список — -list)
serverok -h                # все флаги
```

Если собирали через `go install`, бинарник окажется в
`$(go env GOPATH)/bin/serverok` — убедитесь, что этот каталог есть в `PATH`.

### Удаление

`serverok` — один статический бинарник без конфигов, сервисов и фоновых
процессов, поэтому удаление — это просто удалить файл:

```bash
sudo rm /usr/local/bin/serverok          # или другой каталог из --install=<dir>
# собирали через `go install`?
rm "$(go env GOPATH)/bin/serverok"
```

## Меню

```
 1) System Information               6) IP Location & Registration
 2) CPU Benchmark                    7) IP Reputation (DNSBL)
 3) Memory Benchmark                 8) Streaming & AI Service Unblock
 4) Disk I/O Speed                   9) Routing, Latency & Ports
 5) Network Speedtest
 a) Run all tests                    q) Quit
 Select (e.g. 1,3,5 or a):
```

Отчёт печатается на английском — так им удобнее делиться на форумах
(LowEndTalk, NodeSeek и т. п.).

## Тесты

| Тест | Что измеряет |
|---|---|
| **System Information** | Модель CPU, ядра, кэш, AES-NI и аппаратная виртуализация, диск, RAM, swap, uptime, load, ОС, ядро, TCP congestion control, гипервизор, доступность IPv4/IPv6, ASN, локация |
| **CPU Benchmark** | AES-256-GCM, SHA-256, gzip и решето Эратосфена — в один поток и во все ядра, плюс нормированный балл (≈1000 ≙ одно современное серверное ядро) и коэффициент масштабирования |
| **Memory Benchmark** | Скорость последовательной записи/чтения/копирования и задержка случайного доступа (pointer chase) |
| **Disk I/O Speed** | Три последовательные записи по 1 ГиБ с `fsync` (аналог `dd conv=fdatasync`), среднее значение и 4K random write IOPS |
| **Network Speedtest** | Upload, download и задержка до узлов speedtest.net по всему миру; серверы ищутся по названию города, нерабочие спонсоры пропускаются автоматически |
| **IP Location & Registration** | Геолокация IPv4/IPv6 (ASN, ISP, город, признаки hosting/proxy) **и запись RDAP: имя сети, CIDR, тип выделения, реестр, организация-владелец, даты регистрации и abuse-контакт** |
| **IP Reputation (DNSBL)** | 14 чёрных списков (Spamhaus, Barracuda, SpamCop, SORBS, UCEPROTECT и др.). Зоны, отказывающие публичным резолверам, помечаются как неопределённые, а не как «в списке» |
| **Streaming & AI Service Unblock** | Netflix (полный каталог / только оригиналы / блок), YouTube Premium, Disney+, Prime Video, Spotify, ChatGPT, Claude, TikTok, Steam — с регионом, который видит каждый сервис. Если сервис отвечает, но регион подтвердить нечем, пишется `Unknown`, а не уверенное `Yes` |
| **Routing, Latency & Ports** | RTT до 11 мировых точек (ICMP с откатом на TCP/443), доступность исходящих портов (25, 465, 587 — не режет ли провайдер SMTP), IPv4/IPv6, MTU, congestion control и наличие BBR, публичный DNS-резолвер, трассировки до четырёх ключевых сетей с определением AS каждого хопа |

## Флаги

```
  -all                 прогнать все тесты без меню
  -test cpu,disk,ip    выбрать конкретные тесты (список: -list)
  -list                показать доступные тесты
  -nodes fast|default|full|<ids>
                       набор узлов speedtest (по умолчанию 9 узлов)
  -disk-size 1G        размер файла для теста диска
  -disk-path DIR       где выполнять тест диска (по умолчанию — текущий каталог)
  -cpu-time 2.5        секунд на каждую нагрузку CPU в каждом режиме
  -json report.json    сохранить отчёт в JSON
  -md report.md        сохранить отчёт в Markdown (для форумов)
  -no-color            без ANSI-цветов
  -no-ipv6             пропустить все проверки IPv6
  -quiet               без вывода в терминал (вместе с -json/-md)
  -timeout 30m         общий лимит времени
  -test-timeout 20m    лимит на один тест
  -trace-hops 15       максимум хопов traceroute
  -yes                 отвечать «да» на вопросы
  -version
```

Примеры:

```bash
serverok -all -nodes fast              # всё, но быстрый speedtest
serverok -test ip,blacklist            # чей это IP и чист ли он
serverok -all -quiet -json report.json # для cron и дашбордов
```

## Важные детали

* **root не нужен.** Он полезен только для traceroute: без root используется
  системный `traceroute`, а если его нет — тест пропускается с пометкой.
  Замер задержек сам переключается с ICMP на TCP-хендшейк.
* **Тест диска пишет в текущий каталог** (меняется флагом `-disk-path`). Нужно
  ~1,5 ГиБ свободного места, иначе размер файла уменьшается до 256 МиБ с
  пометкой в отчёте. Временный файл удаляется всегда, в том числе по Ctrl+C.
* **Проверки сервисов — best effort.** Они обращаются к сторонним эндпоинтам,
  которые меняются со временем; капча Cloudflare показывается как `Failed`, а
  не как гео-блокировка, а доступность без подтверждённого региона — как
  `Unknown`, а не `Yes` (тот же disneyplus.com отвечает 200 из любой страны).
  Все проверки лежат в `internal/unblock/checks.go` — по одной функции на сервис.
* **Задержки меряются по ICMP с откатом на TCP-хендшейк**, и в строке указан
  фактический метод. Ответ сопоставляется с запросом (адрес, sequence, а на
  raw-сокете ещё и id), поэтому параллельные якоря не забирают чужие тайминги.
* **Адреса, полученные от гео-API, валидируются** перед подстановкой в URL
  RDAP, в запрос DNSBL и в аргумент `whois`: ip-api.com на бесплатном тарифе
  работает по HTTP, поэтому его ответ считается недоверенным вводом.
* **Spamhaus и часть других DNSBL не отвечают публичным резолверам**
  (1.1.1.1, 8.8.8.8) и возвращают `127.255.255.x`. Это показывается как
  `unavailable`, а не как попадание в список.
* Балл CPU — относительный индекс, а не Geekbench: среднее геометрическое
  четырёх нагрузок относительно фиксированной базовой линии.

## Разработка

```bash
make lint     # gofmt + go vet + go test
make build    # ./serverok
make build-all VERSION=v1.0.0   # архивы релиза под 7 платформ в dist/
```

Релиз выпускается пушем тега:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

`.github/workflows/release.yml` соберёт linux (amd64/arm64/386/arm),
darwin (amd64/arm64) и freebsd (amd64), сгенерирует `checksums.txt` и
опубликует их в GitHub Releases — именно это скачивает `scripts/install.sh`.

## Архитектура

```
cmd/serverok/          флаги, меню, реестр тестов
internal/ui/          ANSI-цвета, рамка, таблицы, меню
internal/runner/      реестр и запуск тестов (таймауты, Ctrl+C)
internal/sysinfo/     железо и ОС (/proc, sysfs, gopsutil)
internal/bench/       бенчмарки CPU, памяти и диска
internal/netcheck/    speedtest, задержки, traceroute, порты, стек
internal/ipinfo/      геолокация, RDAP, DNSBL
internal/unblock/     проверки стриминга и AI-сервисов
internal/report/      модель данных + рендеры text/JSON/Markdown
```

Добавить тест = дописать один `runner.Test` в `cmd/serverok/tests.go`:
меню, флаг `-test` и порядок в отчёте берутся из этого реестра.

## Технологии

* **[Go](https://go.dev/)** (1.26) — весь инструмент собирается в один
  статический бинарник без зависимостей: на сервере не нужен ни рантайм, ни
  интерпретатор.
* **[gopsutil](https://github.com/shirou/gopsutil)** — кроссплатформенные
  данные о хосте, CPU, памяти и диске для System Information.
* **[speedtest-go](https://github.com/showwin/speedtest-go)** — клиент
  speedtest.net для теста Network Speedtest.
* **[golang.org/x/net](https://pkg.go.dev/golang.org/x/net)** — raw ICMP-сокеты
  для замера задержек.
* **[golang.org/x/term](https://pkg.go.dev/golang.org/x/term)** — определение
  TTY, чтобы выбрать интерактивное меню или неинтерактивный режим (`-all`/cron).
* Всё остальное (RDAP, DNSBL, геолокация, проверки разблокировки, traceroute)
  сделано на голых `net`/`net/http` к публичным API и системным утилитам —
  других сторонних зависимостей нет.

## Лицензия

MIT — см. [LICENSE](LICENSE).
