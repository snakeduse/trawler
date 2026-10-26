# Проверка add-host-inventory

## Архивирование

Изменение завершено: 9/9 проверенных задач. Штатная команда `./scripts/openspec archive add-host-inventory --yes` перенесла его в `openspec/changes/archive/2026-10-26-add-host-inventory/` и обновила основные спецификации `discovery-api`, `discovery-cli`, `host-discovery`, `host-inspection`.

После архива строгая валидация дала 9 успешных спецификаций без ошибок; активных изменений нет. Программно проверены точное соответствие изменённых requirement-блоков архивным delta, сохранность незатронутых требований и прежних Purpose, правильный новый Purpose и отсутствие delta-заголовков в основных спецификациях. CLI выдал только неблокирующий совет разбивать большие изменения; незавершённых задач или ошибок валидации нет.

## Итоговые проверки координатора

Реализация проверена независимо от самоотчётов Flash. После review исправлены валидация SSH identification, проверка срока непосредственно перед connect и сохранение обязательных полей при постоянном исключении инспектора. Проверки ошибок ограничены loopback; внутренний `probe_ports` не входит в публичный тип опций.

- `make check` — успешно: сборка, 303 EUnit-теста, 79 Common Test, Xref, Dialyzer, строгая проверка OpenSpec и отдельное OTP-приложение-потребитель.
- `make docs` — EDoc без ошибок.
- `git diff --check` — без замечаний.
- Дополнительный запуск настоящего escript через `verify-host-inventory.py` на локальных тестовых сервисах — успешно: фрагментированные Linux/Windows SSH-баннеры, конфликт, закрытые порты без фильтрации IP и молчащий сервис.
- Текстовый CLI дополнительно вызван через `trawler_discovery_cli:run/1` в отдельной Erlang VM: столбцы IP/метод/MAC/ОС/открытые порты, `linux (medium, предположение)`, открытый 22 и закрытый 445; код 0, найден один адрес.
- Синхронный и асинхронный README-примеры исполнены в одной VM. В асинхронной части документационный диапазон `192.0.2.0/30` заменён на `127.0.0.1-2`, чтобы не отправлять пробы во внешнюю сеть. Получены два результата `up`, итог completed=2, сохранённый статус completed, отмена завершённого задания вернула `{error, already_finished}`.
- Отдельная реальная TCP-проба с закрытым первым и открытым вторым loopback-портом подтвердила остановку обнаружения на первом ответе `tcp_refused`; второй слушатель не получил соединения. Проба не запускала дополнительную фазу проверки портов.

Новая конфигурация возможностей отражена в текстовом `context` OpenSpec; настройки моделей и секреты в Git не менялись. Коммиты и push не выполнялись.

## Реальные локальные результаты CLI/API

На loopback `127.0.0.1` запрос с `ports => [22,445]` и `os_detection => true` вернул:

```text
port_results: 22/open, 445/closed
os: family=linux, confidence=medium, evidence=[ssh_banner:linux]
```

Это фактический результат этой машины, не эталон для всех Linux/Windows-устройств. Тестовый Windows-баннер на дополнительном порту одновременно с реальным Debian SSH на 22 дал `unknown/none` с двумя основаниями `ssh_banner:linux` и `ssh_banner:windows`; конфликт не скрывается произвольным выбором семьи. При всех закрытых выбранных портах адрес сохранился как `up`, `open_ports=[]`. Молчащий тестовый сервис завершился за 0.391 с вместе с запуском отдельной Erlang VM.

## Реальный локальный замер

В отдельной Erlang VM выполнен синхронный `trawler:discover/2` с параметрами:

- цели `127.1.0.1-127.1.39.16` — 10000 уникальных loopback-адресов;
- `method => tcp`, один явно выбранный временный закрытый порт;
- `concurrency => 64`, `timeout_ms => 1000`, `retries => 0`;
- определение ОС выключено; явный порт проверяется также в дополнительной фазе у найденного адреса.

Фактический вывод:

```text
Wall: 1.632 seconds
Summary: #{counters => #{error => 0,up => 10000,no_response => 0},
           total => 10000,completed => 10000,warnings => [],
           elapsed_ms => 1614}
Unique results: 10000
Scheduler in_flight after completion: 0
```

Проверено программно: ровно 10000 результатов, 10000 уникальных IP, total/completed равны 10000, на каждый `up` есть один `port_results`, ёмкость после завершения освобождена.

Это один компьютер с loopback-адресами, не 10000 разных машин. Замер проверяет масштабирование локального выполнения и не обещает такое время в сети предприятия. Потери, firewall, маршрутизация, ожидание молчащих адресов и определение ОС в этот замер не входят. ARP в реальном Ethernet-сегменте и сеть предприятия не проверялись.

## Соответствие сценариев тестам

Для каждой строки перечислены реальные функции EUnit/CT. Сверка имён сценариев и существования функций выполнена программно: 29 сценариев, 75 ссылок на тестовые функции, пропусков и лишних сценариев нет. Содержимое проверено при review. Сетевые взаимодействия — loopback, выбор raw-методов дополнительно проверяется чистыми fixture-тестами.

| Возможность | Сценарий | Проверки |
| --- | --- | --- |
| discovery-api | Проверка входа | trawler_discovery_tests:validation_no_network; trawler_discovery_tests:ports_validation_all_methods |
| discovery-api | Приложение остановлено | trawler_discovery_tests:not_started |
| discovery-api | Порты при автоматическом методе | trawler_discovery_cli_SUITE:discover_json_real_os; trawler_discovery_tests:auto_ports_closed_up_no_filter |
| discovery-api | Синхронный и потоковый сбор | trawler_discovery_tests:inspection_sync_async_equivalent; trawler_discovery_tests:one_result_per_ip; trawler_discovery_tests:async_terminal_once_with_warnings |
| discovery-api | Прежний запрос | trawler_discovery_tests:default_request_no_extra_fields |
| discovery-cli | Loopback и проверка опций | trawler_discovery_cli_SUITE:discover_text; trawler_discovery_cli_SUITE:discover_invalid; trawler_discovery_cli_SUITE:discover_duplicate_flags |
| discovery-cli | Необязательные ОС и порты | trawler_discovery_cli_SUITE:discover_auto_ports_closed; trawler_discovery_cli_SUITE:discover_json_real_os |
| discovery-cli | Потоковый вывод | trawler_discovery_cli_SUITE:discover_stream_pre_finish; trawler_discovery_cli_SUITE:discover_heartbeat; trawler_discovery_cli_SUITE:discover_stream_status_lost |
| discovery-cli | Терминал и перенаправление | trawler_discovery_cli_SUITE:discover_tty_line; trawler_discovery_cli_SUITE:discover_text; trawler_discovery_cli_SUITE:discover_status_ahead; trawler_discovery_cli_SUITE:discover_status_ahead_tick |
| discovery-cli | Все порты закрыты | trawler_discovery_cli_SUITE:discover_ports_columns; trawler_discovery_cli_SUITE:discover_os_unknown; trawler_discovery_tests:auto_ports_closed_up_no_filter |
| discovery-cli | Машинный вывод и fallback | trawler_discovery_cli_SUITE:discover_json_sync_warning; trawler_discovery_cli_SUITE:discover_json_auto; trawler_discovery_cli_SUITE:discover_warning_no_progress |
| discovery-cli | Недоступный явный метод | trawler_discovery_cli_SUITE:discover_raw_unavailable |
| discovery-cli | Дополнительные данные в JSON | trawler_discovery_cli_SUITE:discover_json_full; trawler_discovery_cli_SUITE:discover_json_os_only; trawler_discovery_cli_SUITE:discover_json_real_os |
| discovery-cli | Справка | trawler_discovery_cli_SUITE:discover_help |
| host-discovery | Полный набор удалённых проб | trawler_discovery_probe_tests:auto_gateway_excludes_arp_test; trawler_discovery_probe_tests:plan_covers_all_kinds_in_tiny_budget_test; trawler_discovery_probe_tests:run_tcp_refused_loopback_test |
| host-discovery | TCP без привилегий | trawler_discovery_SUITE:loopback_open_sync; trawler_discovery_SUITE:loopback_refused_sync |
| host-discovery | Большой явный TCP-набор | trawler_discovery_tests:explicit_many_ports_accepted; trawler_discovery_probe_tests:normalize_ports_accepts_many_test |
| host-discovery | Потери и предел ожидания | trawler_discovery_probe_tests:schedule_send_numbers_test; trawler_discovery_probe_tests:tcp_connect_budget_deadline_test; trawler_discovery_tests:address_budget_bounded |
| host-discovery | Совместная нагрузка | trawler_discovery_SUITE:shared_capacity_with_scan; trawler_discovery_tests:cancel_during_banner_read |
| host-discovery | Дополнительные проверки после подтверждения | trawler_discovery_tests:budget_exhausted_up_preserved; trawler_discovery_tests:inspection_exception_keeps_requested_fields |
| host-inspection | Открытый и закрытый порт | trawler_host_inspection_tests:inspect_open_closed_test |
| host-inspection | Бюджет исчерпан | trawler_host_inspection_tests:inspect_expired_deadline_no_connect_test; trawler_host_inspection_tests:inspect_many_ports_expired_are_all_skipped_test; trawler_discovery_tests:budget_exhausted_up_preserved |
| host-inspection | Нет открытых портов | trawler_discovery_tests:auto_ports_closed_up_no_filter; trawler_discovery_cli_SUITE:discover_ports_columns |
| host-inspection | Адрес не подтверждён | trawler_discovery_tests:no_response_skips_inspector; trawler_discovery_tests:error_skips_inspector |
| host-inspection | Явный SSH-признак | trawler_host_inspection_tests:classify_linux_ssh_banner_test; trawler_host_inspection_tests:classify_windows_ssh_banner_test; trawler_host_inspection_tests:inspect_fragmented_linux_banner_test; trawler_host_inspection_tests:inspect_fragmented_windows_banner_test |
| host-inspection | Слабые и противоречивые признаки | trawler_host_inspection_tests:classify_generic_openssh_is_weak_test; trawler_host_inspection_tests:classify_windows_ports_low_test; trawler_host_inspection_tests:classify_both_weak_families_unknown_test; trawler_host_inspection_tests:classify_conflicting_banners_test |
| host-inspection | Нет признаков и отключение | trawler_host_inspection_tests:classify_no_signals_test; trawler_host_inspection_tests:inspect_no_options_does_no_network_test; trawler_host_inspection_tests:inspect_os_false_does_not_read_test; trawler_discovery_tests:default_request_no_extra_fields |
| host-inspection | Молчащий сервис и отмена | trawler_discovery_tests:cancel_during_banner_read; trawler_discovery_tests:deadline_during_banner_read; trawler_discovery_tests:owner_down_during_banner_read; trawler_discovery_tests:recipient_down_during_banner_read; trawler_discovery_tests:app_stop_during_banner_read |
| host-inspection | Повреждённый баннер | trawler_host_inspection_tests:classify_control_bytes_banner_test; trawler_host_inspection_tests:classify_oversized_identification_test; trawler_host_inspection_tests:inspect_oversize_malformed_bounded_test; trawler_host_inspection_tests:inspect_invalid_banner_then_valid_test |
