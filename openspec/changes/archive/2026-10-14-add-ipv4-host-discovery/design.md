# Design

## Context

Мотивация — proposal.md. Действующий scan использует trawler_scheduler, trawler_scan_registry и динамический trawler_scan_sup, 64 индивидуальных и 256 глобальных слотов. CLI имеет потоковый текст и отдельный JSON. Сохранить эти пути.

Проверка установленного Linux OTP 27: socket:open(inet, raw, icmp/tcp) работает с root; символ packet не принимается при open, но числовой AF_PACKET=17 работает. sockaddr_ll необходимо передавать через sockaddr_native: family=17, addr — поля после sa_family (protocol big-endian, ifindex/hatype native-endian, pkttype, halen, 8 байт MAC). Привязка успешно проверена. Native-числа инкапсулировать в Linux transport.

## Goals / Non-Goals

Goals: полностью собственный Linux IPv4 discovery на Erlang, не ломая библиотечный TCP scan; адресный API, строгая корреляция, конечная работа и реальные loopback-проверки.
Non-Goals: одинаковые результаты с Nmap в произвольной сети, IPv6, изменение privileges/firewall, внешний ip/ping/nmap как backend, нативный helper, NIF, vendor/DNS lookup. Тестовая сеть ограничена loopback; локальный сегмент пользователя можно использовать только для явно запрошенной ручной проверки.

## Decisions

### 1. Контракты API

Публичные функции trawler:start_discovery(Targets, Options) -> {ok, reference()} | {error, term()}; trawler:discover/2 -> {ok, Results, Summary} | {error, term()}; discovery_status/1 и cancel_discovery/1 аналогичны scan, но принимают только discovery-ссылки. Отдельный фасад trawler_discovery экспортирует start/2, run/2, status/1, cancel/1. Не создавать атомы из ввода.

Options: method=auto|arp|icmp|tcp|raw_tcp (auto); ports=[80,443] или существующий ввод выборки портов (только tcp); timeout_ms=1000 (конечный бюджет одного адреса, не отдельного пакета); concurrency=64; retries=2 (0..5); deadline_ms=infinity; recipient=self() для async. Только известные ключи. Порты вне tcp отклонять, чтобы не игнорировать намерение пользователя. Порты проверять существующим parser, ограничить выборку discovery TCP 16 портами, иначе invalid_options. Все цели/опции до route/socket/send. Linux/raw capability check до запуска координатора, не отправляя пакеты.

Result: #{ip=>ip4(),state=>up|no_response|error,elapsed_ms=>non_neg_integer(),method=>local|arp|icmp_echo|icmp_timestamp|tcp_syn|tcp_ack|tcp_open|tcp_refused,mac=>binary(),port=>integer(),reason=>term()}; дополнительные ключи только когда применимы, MAC 6 сырых байт. Summary: #{total,completed,counters=>#{up,no_response,error},elapsed_ms,warnings=>[tcp_fallback]}. Status: #{state=>queued|running|completed|cancelled|failed,total,completed,counters,warnings}. Events: {result, Result}, {warning, tcp_fallback}, {done,Summary}, {cancelled,Summary}, {error,Reason,Summary} внутри {trawler_discovery,Ref,Event}. В результатах один IP ровно раз; async хранит счётчики, не полный список. Sync собирает отдельно, сортирует IP, не съедает чужие сообщения.

### 2. Wire и маршруты

trawler_discovery_packet — чистый модуль. checksum(binary())->0..65535; arp_request(SourceMac,SourceIP,TargetIP)->binary(); arp_reply(Frame,TargetIP,SourceIP,SourceMac)->{ok,Mac}|ignore; icmp_request(echo|timestamp,Id,Seq,Payload)->binary(); icmp_reply(Packet,TargetIP,SourceIP,Id,Seq,Payload)->{ok,icmp_echo|icmp_timestamp}|ignore; tcp_request(syn|ack,SourceIP,TargetIP,SourcePort,TargetPort,Seq,Ack)->binary() (TCP header с pseudo-header checksum, без IPv4); tcp_reply(Packet,TargetIP,SourceIP,SourcePort,TargetPort,Seq,Ack,Kind)->{ok,tcp_syn|tcp_ack}|ignore; native_packet_address(Ifindex,Protocol,Mac)->socket:sockaddr_native(). Пакеты IPv4 проверяют IHL/total length/fragmentation/checksum, source/dest, checksum payload, TCP offset/flags и sequence correlation; ICMP timestamp проверяет originate timestamp. ARP принимает только reply Ether/IPv4 для правильного sender/target и target MAC, отвергает нулевой/групповой sender MAC. SYN: SYN+ACK ack=Seq+1 либо RST+ACK ack=Seq+1; ACK: RST seq=Ack (по RFC), не любой RST. Игнорировать чужие запросы и ICMP ошибки.

trawler_discovery_route:lookup(IP)->{ok,Route}|{error,term()}, interfaces()->{ok,[map()]}|{error,term()}. Route #{source=>ip4(),ifindex=>integer(),interface=>string(),local=>boolean(),ethernet=>boolean(),on_link=>boolean(),mac=>binary(),gateway=>ip4()} (mac/gateway необязательны). Маршрут спрашивать у ядра Linux RTM_GETROUTE через NETLINK_ROUTE (AF_NETLINK=16, raw, protocol=0) с destination /32, учитывать seq и NLMSG_ERROR, RTA_OIF/GATEWAY/PREFSRC и RTN_LOCAL. Интерфейсы брать net:getifaddrs(), соединять ifindex/source/MAC по имени. Если source не дан в маршруте, определить через UDP connect+sockname без отправки данных. Не выводить on_link только из private CIDR или интерфейсной маски: это ломает более специфичные маршруты/VPN. Netlink имеет собственный конечный timeout, закрывается через after; неизвестный маршрут — error, не подтверждение.

### 3. Transport и политика ожидания

trawler_discovery_probe:capabilities()->#{arp=>boolean(),icmp=>boolean(),raw_tcp=>boolean(),reason=>term()} проверяет open/close без send; prepare(Method,Caps)->{ok,Effective,Warnings}|{error,term()}; run(IP,Route,Options)->Result. Отдельный модуль политики trawler_discovery_timing экспортирует initial/1, observe/2, rto/1; EWMA SRTT/RTTVAR, clamp между 50 мс и timeout_ms, начальное ожидание ограничено бюджетом. Настроенный timeout — жёсткий общий адресный бюджет; retries — максимум дополнительных отправок каждого вида. RTT не учитывать после повторов (Karn). Координатор обновляет оценку на подтверждённых RTT и передаёт следующим заданиям, не сокращая жёсткий budget.

Для простоты и строгого лимита один адресный worker занимает один глобальный слот и держит не более одного сетевого сокета/пробы одновременно. Не ждёт весь budget только ICMP: проходит методы циклически короткими долями общего бюджета; каждый вид отправляется в первой серии, если предыдущий не подтвердил хост. В каждой серии budget делится между оставшимися методами и повторами, интервалы ограничены rto и остатком deadline. Не обещать параллельную отправку всех четырёх видов. При закрытии сокета поздний ответ может быть потерян — это явный trade-off первой версии, тестировать конечность и повторы; не выдавать за полную реализацию эвристик Nmap. ARP один метод; tcp connect выбранные порты по очереди; ICMP два вида; raw_tcp два вида; raw auto четыре вида. Успех немедленно завершает IP.

Raw TCP source port резервировать открытым TCP-сокетом bind на source/port=0 без listen/connect, чтобы разные probes не совпадали; резервирование считается служебным сокетом, не активным сетевым соединением. ID/seq/token генерировать из unique_integer и монотонного времени, хранить в worker; не переиспользовать одни значения между адресами. Raw inet socket отправляет TCP segment, ядро строит IPv4 header; socket bind выбирает source, при необходимости bindtodevice по интерфейсу ядра. Не менять firewall ради системных RST; это ограничение документировать. Каждая open/send/recv ветка обрабатывает ошибки и закрывает сокеты through after, recv с абсолютным deadline не продлевается чужими пакетами.

### 4. Coordinator и ресурсы

trawler_discovery_scan — gen_server под новым trawler_discovery_sup (dynamic supervisor); ссылки в отдельном trawler_discovery_registry или безопасно типизированном существующем registry. Переиспользовать глобальный scheduler без изменения поведения scan. Координатор выдаёт один worker на адрес, не более concurrency и одного pending grant. Addr vector/tuple и cursor, никаких lists:nth в больших горячих путях.

grant: сброс pending; если active и есть ёмкость, spawn_monitor worker, сохранить IP/start вместе с monitor; если нет — release. worker присылает результат перед DOWN; completed увеличивается ровно раз, на DOWN slot release и следующий request. DOWN без результата: синтезировать error(worker_failed), иначе не терять IP. Workers linked/monitored так, чтобы shutdown координатора убивал их (trap_exit coordinator или явная terminate cleanup).

cancel/deadline/owner-exit/recipient-exit/terminate: retract ожидающего grant, остановить workers, дождаться DOWN/close, освободить каждый slot ровно раз; drain уже выданный grant через упорядоченный барьер scheduler, а не произвольную бесконечную паузу. После cleanup terminal event один раз, никакой выдачи/результатов. Для owner/recipient exit event не нужен, процесс остановить. Terminal state сохранять 60 сек с timer; cancel cancelled -> ok; completed/failed -> already_finished. terminate выполняет такую же очистку при OTP shutdown. Глобальная ёмкость не должна утекать ни при аварии worker, ни при shutdown supervisor.

### 5. CLI

Основной main добавляет discover, реализация печати в trawler_discovery_cli:run(Args)->0|1|2; VM halt остаётся в trawler_cli. Существующий scan не рефакторить. Статические имена методов, строгие повторы и positive ints/retries. Строки результата IP METHOD MAC (и state для verbose), подтверждённые IP сразу. Summary количества адресов up/no_response/error. Progress stdout не касается; stderr tty clear/redraw before finding и heartbeat по абсолютному next_update, plain раз в 2 секунды; no-progress отключает только heartbeat, не warnings. JSON использует sync API и json OTP27; results полные sorted, warnings в summary и человекочитаемое предупреждение stderr, не progress. Коды: invalid input 2; недоступный метод/start/runtime 1; закончившийся поиск 0 даже при error отдельных адресов, счётчики явно показывают ошибки.

### 6. Проверки

Wire fixtures с независимыми checksum, truncation/fragment/foreign replies, TCP correlation и ARP адресами; route decoder fixtures gateway/onlink/local/VPN/native endian. Timing deterministic EWMA/retry budget. Lifecycle EUnit/CT реальные loopback tcp open/refused, invalid input до socket, sync mailbox, cancellation/deadline, worker crash, owner/recipient exit и stop приложения плюс совместная ёмкость со scan. Для raw integration отдельный opt-in тест runner на loopback с root, без privileged test в make check; echo и raw SYN/ACK действительно отправить/получить. ARP wire и socket native bind проверяются отдельно; не объявлять end-to-end ARP доказанным без реальной Ethernet-пробы. CLI раздельные потоки и PTY, JSON/warnings/errors, старые CT без изменений.

## Risks / Trade-offs

- Привилегии всей BEAM при sudo → не присваивать capability глобальному erl; явно показать требование, auto fallback.
- Linux sockaddr/netlink ABI → инкапсулировать числа/endian, fixture тесты и runtime probe на установленном OTP.
- Proxy ARP отвечает за другие IP → ARP доказывает ответ за адрес, не отдельное физическое устройство; одинаковые MAC не запрещать, ограничение документировать.
- Потери/фильтрация/поздние ответы → no_response не down, ограниченные повторы и настройка budget; нет гарантии равенства Nmap.
- Много raw sockets → один активный probe на worker, глобальная ёмкость, закрытие при отмене; оптимизация общих receive sockets вне этой версии.

## Migration Plan

Добавить модули/API и CLI без изменения существующих scan-вызовов. Проверить make check и make docs, затем raw loopback. Архивировать только после проверки всех tasks. Откат — удалить новые экспорты/команду и новые supervisor children; формат scan не меняется.
