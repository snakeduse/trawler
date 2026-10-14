# Проверка сценариев

Сопоставление относится к каждой клаузе WHEN/THEN/AND delta-спецификаций. Сетевые автоматические проверки ограничены loopback; fixtures проверяют политику и пакеты, но не заменяют end-to-end Ethernet ARP.

## host-discovery

| Сценарий | Свидетельство |
| --- | --- |
| Полный набор удалённых проб | `prepare_auto_uses_raw_test`, `auto_gateway_excludes_arp_test`, `plan_splits_budget_test`; ревью `trawler_discovery_probe:execute` подтверждает выход сразу при `{ok, Method, Extra}`. Настоящие ICMP echo/timestamp и raw SYN 443/ACK 80 отдельно выполнены opt-in runner на loopback. |
| TCP без привилегий | `run_tcp_open_loopback_test`, `run_tcp_refused_loopback_test`; CT `loopback_open_sync`, `loopback_refused_sync`. |
| Локальный сегмент | `auto_onlink_ether_arp_only_test`, `auto_gateway_excludes_arp_test`; `arp_reply_accepts_matching_test`, `arp_reply_accepts_same_mac_test` и отрицательные ARP fixtures. Политика только `[arp]` исключает TCP после молчания. Native AF_PACKET bind/recv проверены runner; настоящее обнаружение в Ethernet-сегменте не выполнялось. |
| VPN и шлюз | `route_gateway_test`, `route_vpn_not_ethernet_test`, `auto_gateway_excludes_arp_test`, `arp_gateway_rejected_test`, `arp_ethernet_required_test`. |
| Нет raw-привилегий | `prepare_auto_falls_back_to_tcp_test`, `prepare_explicit_icmp_unavailable_test`, `prepare_explicit_arp_unavailable_test`, `prepare_explicit_raw_tcp_unavailable_test`, `async_terminal_once_with_warnings`; CLI `discover_raw_unavailable`, `discover_warning_no_progress`. |
| Подмена и повреждение | `trawler_discovery_packet_tests`: усечение, checksum, IHL/length/fragments, чужие адреса/id/sequence/payload/порты и недопустимые TCP flags. |
| Ошибка маршрутизатора | `icmp_reply_rejects_unreachable_test`, `tcp_reply_rejects_icmp_unreachable_test`. |
| Потери и предел ожидания | `plan_never_exceeds_budget_test`, `schedule_send_numbers_test`, `confirmation_extra_karn_test`, `tcp_connect_budget_deadline_test`, `address_budget_bounded`, `route_lookup_honours_timeout`, timing EUnit. Ревью recv-путей: остаток берётся от абсолютного монотонного deadline; чужой пакет не сбрасывает срок. |
| Совместная нагрузка | CT `shared_capacity_with_scan`, EUnit существующего глобального scheduler; coordinator использует индивидуальный лимит и единственный pending grant. |
| Молчание и ошибки | `stale_worker_exit_ignored` и `address_budget_bounded` дают `no_response`, `worker_crash` даёт `error` с причиной; CLI `discover_no_found_hidden`, `discover_no_found_verbose`. |

## discovery-api

| Сценарий | Свидетельство |
| --- | --- |
| Проверка входа | `validation_no_network`, `ports_only_tcp`, существующие target/port parser EUnit. Дополнительный реальный API-вызов с `max_hosts=1` и двумя loopback-адресами вернул `{error,too_many_hosts}`. |
| Приложение остановлено | `not_started` проверяет sync и async. |
| Оба режима | CT `sync_async_equivalent`; `sync_results_sorted`, `sync_preserves_foreign_messages`, `async_terminal_once_with_warnings`, `one_result_per_ip`, `ensure_no_more`. Дополнительная runtime-проверка sync deadline с насыщенным scheduler вернула `{error,deadline_exceeded}` без частичного успеха, сохранила чужое сообщение и освободила ёмкость. |
| Отмена и deadline | `cancel_queued_saturated`, `deadline_queued_saturated`, `cancel_running_releases_before_event`, `deadline_running_releases_before_event`: отмена идемпотентна, воркер мёртв и слот свободен до чтения terminal event, поздних событий нет. |
| Выход владельца и остановка | `owner_down`, `recipient_down`, `app_stop_cleanup`; проверены смерть воркера и возврат ёмкости. `cancel_status_kept_after_owner_exit` и `cancel_status_kept_after_recipient_exit` сохраняют уже терминальный статус. |
| Статус и неизвестная ссылка | `status_cancel_unknown`, проверки счётчиков и состояний в sync/cancel/deadline тестах. Runtime TTL: completed-статус присутствует через 59 секунд, отсутствует через 61 секунду (ожидание 61003 мс); полного поля `results` нет, отмена completed возвращает `{error,already_finished}`. |

## discovery-cli

| Сценарий | Свидетельство |
| --- | --- |
| Loopback и проверка опций | `discover_text`, `discover_no_progress`, `discover_invalid`, `discover_duplicate_flags`, старый `trawler_cli_SUITE` и `trawler_scan_SUITE`. |
| Потоковый вывод | `discover_stream_pre_finish`, `discover_heartbeat`, `discover_stream_status_lost`, `discover_stream_status_lost_no_progress`; абсолютный tick работает при непрерывной очереди результатов. Регрессии `discover_status_ahead` (PTY) и `discover_status_ahead_tick` подтверждают отсутствие повторного учёта status/event, монотонность счётчиков и последовательность 0→1→2 без превышения 100%. `discover_status_exception` подтверждает код 1 и отмену собственного задания при throw/exit/неожиданном ответе status. |
| Терминал и перенаправление | `discover_tty_line` (настоящий PTY через `script`), `discover_text` (раздельные stdout/stderr, отсутствие ANSI/CR), `discover_no_progress`; итог берётся из summary. |
| Машинный вывод и fallback | `discover_json`, `discover_json_auto`, `discover_json_sync_warning`: полный сортированный JSON, предупреждение в stderr, отсутствие heartbeat, код 0. |
| Недоступный явный метод | `discover_raw_unavailable` использует реальные capabilities процесса. |
| Справка | `discover_help`, обновлённая общая справка, README и `openspec/config.yaml`; методы/права/Linux/fallback/таймаут адреса/разница scan-discover и ограничения обнаружения описаны. README sync/async discover и синхронный scan выполнены координатором через `erl -noshell`: выражения shell соединены запятыми, асинхронная документальная выборка заменена на loopback `127.0.0.1-4`. |

## Подтверждённая база проверок

Независимый итоговый запуск координатора `make check docs`: 256 EUnit, 70 Common Test; compile/xref/dialyzer/strict specs/внешнее OTP-приложение/EDoc прошли. `scripts/check-discovery-raw` подтвердил настоящие ICMP echo/timestamp, raw SYN/ACK и TCP open/refused; ARP codec, native bind и AF_PACKET recv/ifindex также прошли. Реальный свежий escript `_build/default/bin/trawler` проверен в текстовом `tcp --no-progress` и JSON `auto` режимах на loopback: один результат и корректные счётчики, явное fallback-предупреждение.

## Ограничения

- End-to-end ARP в реальном Ethernet-сегменте пока не проверен; пакетные fixtures и AF_PACKET loopback не доказывают полноту поиска устройств LAN.
- Нет гарантии одинакового списка с Nmap; молчание, поздние ответы и proxy ARP описаны в README/design.
- AGENTS.md оставлен без изменений: среда запретила запись, пользователь не дал разрешения. Актуальное описание состояния записано в README, контексте OpenSpec и текущих спецификациях после архивации.
- Все задачи реализации проверены; архивация и строгая валидация основных спецификаций выполняются средствами OpenSpec после приёмки.
