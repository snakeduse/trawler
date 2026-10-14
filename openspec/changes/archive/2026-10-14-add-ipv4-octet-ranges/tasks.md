# Tasks

## 1. Чистый парсер и библиотечный контракт

- [x] 1.1 Реализовать разделение целей и пооктетную грамматику без изменения публичных типов и формата диапазонов; подтвердить EUnit точные выборки, все четыре октета, открытые границы, ошибки, старые формы и Erlang-списки.
- [x] 1.2 Ограничить разворачивание по размеру нормализованного произведения, объединять цели без повторов; подтвердить EUnit огромную выборку, пересечения у лимита и превышение общего объединения.
- [x] 1.3 Обновить EDoc парсера и README с грамматикой и ограничениями; проверить примеры через парсер, выполнить make docs.

## 2. CLI общего ядра

- [x] 2.1 Обновить справку и примеры CLI; добавить Common Test для смешанной loopback-выборки, ошибок и справки; проверить make cli и make test.

## 3. Интеграционная приёмка

- [x] 3.1 Сопоставить каждый сценарий и AND delta-спецификаций с тестами, проверить diff и выполнить make check (EUnit, Common Test, Xref, Dialyzer, OpenSpec, consumer) и make docs.

Проверено координатором: `make check` (81 EUnit, 25 CT, Xref, Dialyzer, строгий OpenSpec, внешний OTP consumer), `make docs`, `git diff --check`.

Соответствие сценариев тестам:

- Смешанные пересекающиеся адреса — `mixed_list_test`, `merge_overlap_test`, `octet_merges_with_legacy_targets_test`; уникальность подтверждается точным сравнением диапазонов.
- Границы CIDR и `/32` — `cidr_normalisation_test`, `cidr_slash_32_test`.
- Пооктетное выражение в Erlang-списке — `octet_in_erlang_list_test`.
- Диапазоны в любом октете — `octet_ranges_in_all_four_octets_test`, независимое точное произведение.
- Смесь списков и диапазонов — `octet_lists_and_ranges_test`.
- Открытые границы и `-1` — `octet_open_bounds_test`, `octet_open_bounds_in_each_octet_test`.
- Повторы в октетах — `octet_repeated_values_test`.
- Неверное выражение — `invalid_octet_target_test`, `leading_zero_octet_test`, `reversed_range_test`, `empty_targets_test`.
- Старый список — `legacy_spaced_list_test`.
- Новая смешанная выборка, включая табуляцию, LF и CRLF — `mixed_fragments_test`.
- Некорректное разделение — `empty_targets_test`, `trim_whitespace_test`, `invalid_octet_target_test`.
- Огромное произведение — `octet_huge_product_test`; проверка лимита до вызова построения интервалов также подтверждена ревью.
- Пересечения у лимита и добавление пятого адреса — `octet_intersections_at_limit_test`.
- Смешанная loopback-выборка CLI, уникальные результаты и код 0 — `scan_mixed_targets`.
- Ошибка новой цели CLI, код 2 и stderr при пустом stdout — `scan_invalid_streams`.
- Справка новых форматов — `help`.
- Дополнительная регрессия производительности — `big_sparse_product_65536`, точные 65536 адресов и бюджет reductions; мостящие пересечения — `octet_sparse_overlap_bridging_test`.

## Workflow follow-up

- После успешных проверок архивировать add-ipv4-octet-ranges средствами OpenSpec с обновлением основных спецификаций.
- Проверить обновлённые спецификации и выполнить строгую валидацию всех спецификаций и изменений.
