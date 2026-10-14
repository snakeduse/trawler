# Tasks

## 1. Пакеты и маршруты Linux

- [x] 1.1 Реализовать чистый codec ARP, ICMP echo/timestamp и TCP SYN/ACK с checksum/correlation; EUnit подтверждает корректные ответы и отвергает повреждённые, чужие и ICMP unreachable; compile/xref/dialyzer проходят.
- [x] 1.2 Реализовать kernel route lookup через netlink и интерфейсы OTP без внешних команд; fixture-тесты покрывают gateway/onlink/local/VPN и ошибки, реальный loopback lookup работает; native AF_PACKET bind проверен.

## 2. Транспорт и адресная политика

- [x] 2.1 Реализовать capabilities, явные ошибки и auto fallback, ARP/ICMP/raw TCP/TCP connect, закрытие всех сокетов через after; EUnit и реальные TCP loopback open/refused подтверждают transport.
- [x] 2.2 Реализовать конечный budget адреса, повторы и RTT-адаптацию; deterministic-тесты подтверждают границы, число отправок и отсутствие продления чужими пакетами; EDoc описывает trade-offs.
- [x] 2.3 Добавить opt-in raw loopback runner и выполнить настоящие ICMP echo и TCP SYN/ACK с привилегиями, а ARP codec/native bind проверить без сканирования внешней сети; результаты не подменять fixtures.

## 3. API и процессы

- [x] 3.1 Добавить discover/start_discovery/discovery_status/cancel_discovery, валидацию и синхронный сбор; EUnit проверяет неверные опции до сети, сортировку, события, предупреждения, чужой mailbox и not_started.
- [x] 3.2 Добавить supervision, реестр, статус TTL и совместное использование scheduler со scan; EUnit проверяет worker crash, отмену/deadline, owner/recipient exit, остановку приложения, отсутствие утечек слотов и одно terminal event.
- [x] 3.3 Добавить EDoc публичного API; make docs проходит и примеры выполняются на loopback.

## 4. CLI и руководство

- [x] 4.1 Добавить discover с методами/параметрами и кодами ошибок без изменения scan; CT запускает свежий escript и проверяет аргументы, явную недоступность raw и старые команды.
- [x] 4.2 Добавить потоковые находки, адресный прогресс, verbose/no-progress и полный JSON; CT/PTY проверяют stdout/stderr до завершения, heartbeat без находок и при потоке, JSON и fallback warning.
- [x] 4.3 Обновить справку, README и устаревшее описание состояния проекта; проверить реальные команды и описать Linux/root, отсутствие гарантии Nmap, proxy ARP и ограничения поздних ответов.

## 5. Итоговая интеграция

- [x] 5.1 Сверить каждый сценарий delta-спецификаций с тестом или явной runtime-проверкой, проверить diff, make check и make docs; все обязательные проверки проходят.

## Workflow follow-up

- После проверок архивировать add-ipv4-host-discovery через OpenSpec CLI.
- Проверить новые основные спецификации и строгую валидацию после архива.
