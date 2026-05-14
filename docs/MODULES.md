# Добавление модуля (фазы) сканера

Цель: новая проверка живёт в `internal/modules/`, оркестрация — в одном месте, без размазывания по `main` и TUI.

## Где что лежит

| Что | Где |
|-----|-----|
| Реализация HTTP/CLI/TUI вывода фазы | `internal/modules/<имя>.go` |
| Порядок фаз pentest 1–12, skip, тайминги | `internal/modules/pentest_pipeline.go` |
| Маркеры `[PHASE …]` для парсинга логов дашборда | `internal/phasemarkers/markers.go` |
| Флаги pentest | `cmd/pentest/main1.go` |
| Флаги crawl + передача в дочерний pentest | `main.go` |
| Фазы 0 / 0.1 (subdomain, httpx) | `main.go` и модули `subdomain.go`, `https.go` |

Пакет `internal/phasemarkers` не импортирует `internal/ui` и `internal/modules` — так нет циклических импортов. Любой новый маркер фазы в логе добавляйте туда же.

## Контракт модуля pentest (фазы 1–12)

1. **Поток вывода**  
   Пишите заголовок фазы в `w` (`io.Writer`), как сейчас: строка с подстрокой вида `[PHASE N] …` (совпадает с одним из маркеров в `phasemarkers.PentestLogPhaseMarkers()`). Для веток без работы тоже логируйте `[PHASE N]`, иначе TUI не увидит смену фазы по файлу лога.

2. **Прогресс и события**  
   Используйте `sb *ui.StatusBar`: `SetPhase("ИМЯ", total)`, `Log(...)`. Статусбар публикует `internal/events` для живого TUI.

3. **Находки**  
   Через `rc *ui.ReportCollector`: те же методы, что в существующих модулях (sitemap, findings, уровни).

4. **Лимит скорости**  
   Для исходящих HTTP-запросов из Go ждите `<-limiter` (`<-chan time.Time`), как в текущих фазах.

5. **Заголовки**  
   Глобальные кастомные заголовки задаются через `modules.SetCustomHeaders` в `main` / pentest `main`; внутри модуля обычно достаточно общего HTTP-клиента проекта.

6. **Skip**  
   В `pentest_pipeline.go` фаза участвует через `IsPhaseSkipped("<id>", skipPhases)`. ID — строка, как в `-skip-phase` (например `"4"` для GraphQL).

## Что сделать при добавлении новой фазы

1. **Новый файл** в `internal/modules/` с функцией вроде `YourScan(urls []string, w io.Writer, …, sb *ui.StatusBar, rc *ui.ReportCollector)` (сигнатура по аналогии с соседними фазами).

2. **`pentest_pipeline.go`**  
   - Расширьте `PentestRunInput`, если нужны новые данные (токены, пути, флаги).  
   - Вставьте вызов в нужное место цепочки (или замените существующий блок, если фаза встраивается между другими).  
   - Добавьте ветки skip / «ничего не делать» с тем же стилем логов, что у соседних фаз.

3. **`internal/phasemarkers/markers.go`**  
   Добавьте новый `[PHASE …]` в слайс **в правильном порядке** (более длинные маркеры раньше коротких).

4. **`cmd/pentest/main1.go`**  
   Новые флаги: `flag.*`, проброс в `PentestRunInput`, строка help в `Usage` / текст про фазы.

5. **`main.go`**  
   Только если фаза нужна при `luska -ps` и требует новых флагов на стороне crawl — добавьте флаг и передайте в аргументы `./pentest`.

6. **Документация**  
   Обновите таблицу фаз в `README.md` (номер, `-skip-phase`, описание).

## Запуск и отладка

- Только pentest по crawl-файлу:  
  `go build -o pentest ./cmd/pentest/main1.go`  
  `./pentest -f 'output/host|timestamp.txt' -host host …`
- Полный поток:  
  `go build -o luska ./main.go`  
  `./luska -u https://target -ps`
- Пропуск фазы: `-skip-phase 3` или список `2,4,7`.

## UI

- **CLI**: всё идёт в `w` (мультирайтер со статусом и отчётом).  
- **TUI pentest**: события из `StatusBar` + парсинг `[PHASE …]` из лога для фоновых сканов. Менять `internal/ui/tui` нужно только если меняется **семантика** UI, а не список фаз.

## Итог

Новый модуль = **один файл реализации** + **один блок в `pentest_pipeline.go`** + при необходимости **флаги** и **`phasemarkers`**. Файл `cmd/pentest/main1.go` больше не должен разрастаться за счёт очередного `if phase`.
