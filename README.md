# Trawler

Встраиваемое Erlang/OTP-приложение для поиска доступных TCP-портов по IPv4-адресам,
спискам адресов, диапазонам и CIDR. Отдельный CLI использует то же ядро.

Сейчас готов каркас: OTP-приложение запускается, CLI показывает справку и версию.
Сканирование описано в OpenSpec-изменении `add-tcp-ipv4-scanner` и ещё не реализовано.

## Окружение

| Инструмент | Версия |
| --- | --- |
| Erlang/OTP | 27.3.4.18 |
| rebar3 | 3.27.3 |
| Node.js | 24.15.0 |
| OpenSpec | 1.14.1, глобальная установка |

На текущей машине OTP установлен через Kerl в `$HOME/erlang/27.3.4.18`.
Обёртки в `scripts/` подключают его автоматически. Для другого пути задайте
`TRAWLER_OTP_ROOT`; при отсутствии Kerl-активации используется OTP 27 из `PATH`.
Версии также закреплены в `.tool-versions` и `.nvmrc`.

OpenSpec устанавливается глобально в выбранную версию Node:

```bash
source "$HOME/.nvm/nvm.sh"
nvm use 24.15.0
npm install -g @fission-ai/openspec@1.14.1
./scripts/openspec --version
```

Смена версии Node через NVM меняет доступные глобальные пакеты. Для команд OpenSpec
используйте обёртку проекта. Сборке и работе Erlang-библиотеки Node не требуется.

## Сборка и проверки

```bash
make build
make cli
make check
source scripts/env.sh otp
_build/default/bin/trawler --help
_build/default/bin/trawler --version
```

`make check` включает EUnit, Common Test, Xref, Dialyzer, строгую проверку OpenSpec
и сборку отдельного временного Erlang-приложения с зависимостью на Trawler.
При первом запуске Dialyzer строит PLT; это занимает больше времени.
`make docs` создаёт EDoc, `make shell` запускает оболочку с приложением.

## Подключение к другому Erlang-приложению

После публикации изменений в Git добавьте зависимость в `rebar.config`, заменив
`<commit>` на реальный SHA опубликованной версии:

```erlang
{deps, [{trawler, {git, "https://github.com/snakeduse/trawler.git",
                  {ref, "<commit>"}}}]}.
```

Укажите `trawler` в `applications` файла `.app.src` приложения-потребителя.
Для ручного запуска:

```erlang
{ok, _} = application:ensure_all_started(trawler).
ok = application:stop(trawler).
```

Будущие функции `trawler:scan/3`, `start_scan/3`, `status/1`, `cancel/1` описаны в
design и delta-спецификациях первой задачи. Сейчас эти функции ещё не экспортируются.
CLI-параметры сканирования также появятся при реализации этой задачи.

## Hermes: Pro планирует, Flash реализует

```bash
./scripts/hermes --version
./scripts/hermes doctor
./scripts/hermes skills list
./scripts/hermes chat
```

Конфигурация проекта — `.hermes/config.yaml`; локальное состояние находится в
игнорируемой `.hermes/runtime/`. Запуск не меняет основной профиль Hermes.
Деревья установленных инструментов и зависимостей Hermes используются совместно
через ссылки `runtime/tools` и `runtime/installs`; сессии и настройки изолированы.
Ключ берётся из `DEEPSEEK_API_KEY` в окружении, затем из `.hermes/runtime/.env`,
затем из существующего `$HOME/.hermes/.env`. Используется только ключ DeepSeek;
его значение не выводится и не копируется в репозиторий.

Основной агент использует `deepseek-v4-pro`. Он подготавливает и валидирует OpenSpec,
автоматически поручает реализацию `deepseek-flash`, проверяет результат и тесты,
затем завершает изменение. Отдельная команда для Flash не нужна. Запрос только
на планирование или подготовку проекта оставляет задачи реализации невыполненными.
Для автоматического цикла Pro создаёт артефакты через OpenSpec CLI и продолжает
реализацию в рамках исходной задачи. Отдельный вызов `/openspec-propose` служит
только подготовке спецификаций; это правило не добавляет паузу в автоматический цикл.

В сессии доступны навыки `/openspec-propose`, `/openspec-apply-change`,
`/openspec-update-change`, `/openspec-sync-specs`, `/openspec-explore`,
`/openspec-archive-change`. Инструкции и критерии работы находятся в `AGENTS.md`.

```bash
./scripts/openspec list
./scripts/openspec status --change add-tcp-ipv4-scanner
make specs
```

Первая версия ограничена TCP и IPv4. IPv6, UDP, ICMP/ARP, определение ОС и
веб-интерфейс оставлены последующим версиям. TCP-таймаут не означает отсутствия хоста.

Лицензия: Apache-2.0.
