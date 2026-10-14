%%%-------------------------------------------------------------------
%%% @doc Транспорт IPv4-обнаружения: capabilities, выбор метода, пробы.
%%%
%%% Модуль отвечает за отправку и приём сетевых проб одного адреса и
%%% возвращает {@link result/0}. Он не управляет процессами и не
%%% подменяет вывод: подтверждением (`up') считается только ответ,
%%% прошедший строгую проверку {@link trawler_discovery_packet}. Ошибка
%%% сокета или отправки даёт `error', а чистое истечение срока —
%%% `no_response'; эти исходы не смешиваются.
%%%
%%% Правила первой версии:
%%% <ul>
%%%   <li>capabilities/0 проверяет только `open'/'close' без отправки
%%%       пакетов и ничего не настраивает в системе: привилегии не
%%%       запрашиваются и firewall не меняется;</li>
%%%   <li>один worker адреса держит не более одного активного сетевого
%%%       сокета одновременно; методы проходят циклически;</li>
%%%   <li>бюджет адреса `timeout_ms' — жёсткий предел; дедлайн
%%%       монотонный и абсолютный, чужие пакеты его не продлевают;</li>
%%%   <li>размер ожидания берётся из {@link trawler_discovery_timing},
%%%       в каждой серии бюджет делится между оставшимися отправками;</li>
%%%   <li>повтор — это новая отправка с новыми идентификаторами и
%%%       сокетом: поздний ответ на прежнюю отправку после закрытия её
%%%       сокета теряется, а не приписывается повтору (см.
%%%       {@link schedule/4}); RTT учитывается только по первой отправке
%%%       вида (правило Карна, {@link confirmation_extra/2}).</li>
%%% </ul>
%%%
%%% Методы: `auto' выбирает ARP для непосредственно подключённого
%%% Ethernet-сегмента и ICMP/raw TCP для остальных адресов (собственный
%%% адрес подтверждается как `local'); `tcp' использует connect к 80/443
%%% или выбранным портам и доступен без raw-привилегий; `icmp' — echo и
%%% timestamp; `raw_tcp' — SYN 443 и ACK 80. Ответ на любую пробу
%%% немедленно завершает адрес.
%%%
%%% Внутренние опции (не входят в публичный CLI, координатор может их
%%% передавать): `caps' — заранее полученный результат capabilities/0,
%%% чтобы не открывать raw-сокеты на каждый адрес; `timing' — состояние
%%% {@link trawler_discovery_timing}, чтобы переносить оценку RTT между
%%% адресами; `rto_ms' — начальный RTO для этой пробы. Настраиваемый
%%% `timeout_ms' остаётся жёстким бюджетом независимо от этих опций.
%%%
%%% Ограничения: raw-методы доступны только на Linux и требуют сетевых
%%% привилегий; клиент после raw SYN/ACK может ответить RST, что
%%% нормально для подтверждения ответа; proxy ARP отвечает за адрес, а
%%% не за отдельное устройство.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_probe).

%% Публичный контракт.
-export([capabilities/0, prepare/2, run/3]).

%% Чистые части, вынесенные для детерминированных тестов и runner'а:
%% `normalize_ports/1', `schedule/4', `confirmation_extra/2',
%% `candidate_kinds/3' и `packet_ifindex/1' не работают с сетью.
%% `run_kind/4' — внутренняя точка входа для opt-in runner'а: выполняет
%% ровно один вид пробы, не сокращая loopback до `local' и не подменяя
%% исход. `plan/4' сохранён как совместимая форма `schedule/4'.
-export([normalize_ports/1, plan/4, schedule/4, confirmation_extra/2,
         candidate_kinds/3, packet_ifindex/1, run_kind/4]).

-export_type([ip4/0, mac/0, method/0, effective/0, caps/0, options/0, result/0]).

%% IPv4-адрес в форме кортежа октетов.
-type ip4() :: {0..255, 0..255, 0..255, 0..255}.
%% MAC-адрес Ethernet: 6 сырых байт.
-type mac() :: <<_:48>>.
%% Запрошенный метод обнаружения.
-type method() :: auto | arp | icmp | tcp | raw_tcp.
%% Способ, которым адрес подтверждён.
-type effective() :: local | arp | icmp_echo | icmp_timestamp
                   | tcp_syn | tcp_ack | tcp_open | tcp_refused.
%% Доступность raw-методов. `reason' — первая причина недоступности
%% (например, `eperm') либо `undefined'.
-type caps() :: #{arp := boolean(),
                  icmp := boolean(),
                  raw_tcp := boolean(),
                  reason := term()}.
%% Опции пробы одного адреса.
-type options() :: #{method => method(),
                     timeout_ms => pos_integer(),
                     retries => 0..5,
                     ports => [1..65535],
                     rto_ms => pos_integer(),
                     timing => trawler_discovery_timing:state(),
                     caps => caps()}.
%% Результат адреса. `method' присутствует у подтверждённых адресов,
%% `mac' — у ARP, `port' — у TCP, `rtt_ms' — у подтверждённых проб,
%% `reason' — у ошибок.
-type result() :: #{ip := ip4(),
                    state := up | no_response | error,
                    elapsed_ms := non_neg_integer(),
                    method => effective(),
                    mac => mac(),
                    port => 1..65535,
                    rtt_ms => non_neg_integer(),
                    reason => term()}.

%% Вид отдельной отправки внутри адреса.
-type kind() :: arp | icmp_echo | icmp_timestamp | tcp_syn | tcp_ack | tcp.

%% Linux ABI и умолчания обнаружения.
-define(AF_PACKET, 17).
-define(ETH_P_ARP, 16#0806).
-define(SYN_PORT, 443).
-define(ACK_PORT, 80).
-define(DEFAULT_PORTS, [80, 443]).
-define(DEFAULT_TIMEOUT_MS, 1000).
-define(DEFAULT_RETRIES, 2).
-define(MAX_RETRIES, 5).
-define(MAX_PORTS, 16).
-define(MIN_RTO, 50).

%%% ------------------------------------------------------------------
%%% capabilities
%%% ------------------------------------------------------------------

%% @doc Проверяет доступность raw-методов открытием и закрытием сокетов.
%%
%% Пакеты не отправляются, система не настраивается, привилегии не
%% запрашиваются. `reason' — первая причина недоступности либо
%% `undefined'. На не-Linux raw-методы помечаются недоступными.
-spec capabilities() -> caps().
capabilities() ->
    case os:type() of
        {unix, linux} ->
            Results = [{arp, open_close(?AF_PACKET, raw, htons(?ETH_P_ARP))},
                       {icmp, open_close(inet, raw, icmp)},
                       {raw_tcp, open_close(inet, raw, tcp)}],
            Flags = maps:from_list([{Kind, Result =:= ok}
                                    || {Kind, Result} <- Results]),
            Flags#{reason => first_error(Results)};
        _Other ->
            #{arp => false, icmp => false, raw_tcp => false,
              reason => unsupported}
    end.

open_close(Domain, Type, Protocol) ->
    case socket:open(Domain, Type, Protocol) of
        {ok, Socket} ->
            _ = socket:close(Socket),
            ok;
        {error, Reason} ->
            {error, Reason}
    end.

first_error(Results) ->
    case [Reason || {_Kind, {error, Reason}} <- Results] of
        [] -> undefined;
        [Reason | _Rest] -> Reason
    end.

%%% ------------------------------------------------------------------
%%% prepare
%%% ------------------------------------------------------------------

%% @doc Приводит запрошенный метод к фактически исполняемому.
%%
%% Для `auto' при доступных ICMP и raw TCP возвращается `auto'; если
%% raw-привилегий нет — `tcp' с предупреждением `tcp_fallback'. Явно
%% выбранный raw-метод без привилегий возвращает ошибку до отправки
%% проб. `tcp' доступен всегда; порты вне `tcp' проверяет вызывающая
%% сторона.
-spec prepare(method(), caps()) ->
          {ok, arp | icmp | tcp | raw_tcp | auto, [tcp_fallback]} | {error, term()}.
prepare(Method, Caps) when is_atom(Method), is_map(Caps) ->
    prepare_method(Method, Caps);
prepare(Method, _Caps) ->
    {error, {invalid_method, Method}}.

prepare_method(tcp, _Caps) ->
    {ok, tcp, []};
prepare_method(auto, Caps) ->
    %% ARP нужен только для on-link Ethernet; для маршрутизируемых
    %% адресов достаточно ICMP и raw TCP, поэтому `auto' считается
    %% доступным при этих двух возможностях.
    case maps:get(icmp, Caps, false) andalso maps:get(raw_tcp, Caps, false) of
        true -> {ok, auto, []};
        false -> {ok, tcp, [tcp_fallback]}
    end;
prepare_method(Kind, Caps) when Kind =:= arp; Kind =:= icmp; Kind =:= raw_tcp ->
    require_cap(Kind, Caps);
prepare_method(Other, _Caps) ->
    {error, {invalid_method, Other}}.

require_cap(Kind, Caps) ->
    case maps:get(Kind, Caps, false) of
        true -> {ok, Kind, []};
        false -> {error, {method_unavailable, Kind}}
    end.

%%% ------------------------------------------------------------------
%%% normalize_ports
%%% ------------------------------------------------------------------

%% @doc Нормализует выбранные TCP-порты.
%%
%% Принимает непустой список целых 1..65535, убирает повторы, сортирует
%% по возрастанию и допускает не более 16 портов. Иные значения —
%% ошибка, чтобы намерение пользователя не терялось молча.
-spec normalize_ports(term()) -> {ok, [1..65535]} | {error, term()}.
normalize_ports(Ports) when is_list(Ports), Ports =/= [] ->
    case lists:all(fun valid_port/1, Ports) of
        false ->
            {error, {invalid_ports, Ports}};
        true ->
            Unique = lists:usort(Ports),
            case length(Unique) =< ?MAX_PORTS of
                true -> {ok, Unique};
                false -> {error, {too_many_ports, length(Unique)}}
            end
    end;
normalize_ports(Ports) ->
    {error, {invalid_ports, Ports}}.

valid_port(Port) ->
    is_integer(Port) andalso Port >= 1 andalso Port =< 65535.

%%% ------------------------------------------------------------------
%%% plan
%%% ------------------------------------------------------------------

%% @doc Планирует отправки адреса: серии по всем видам с повторами.
%%
%% Число отправок каждого вида равно `Retries + 1'. Ожидание каждой
%% отправки не превышает `Rto' и делится поровну между оставшимися
%% отправками, поэтому суммарное ожидание никогда не превышает бюджет,
%% а каждый вид попадает хотя бы в первую серию даже при крошечном
%% бюджете. Чистая функция: абсолютный дедлайн и сокеты — у run/3.
-spec plan([kind()], 0..5, pos_integer(), pos_integer()) ->
          [{kind(), non_neg_integer()}].
plan(Kinds, Retries, Budget, Rto) ->
    [{Kind, Wait} || {Kind, Wait, _SendNumber}
                        <- schedule(Kinds, Retries, Budget, Rto)].

%% @doc Планирует отправки, сохраняя номер отправки каждого вида.
%%
%% Каждая запись — `{Kind, Wait, SendNumber}', где `SendNumber'
%% начинается с 1 и увеличивается при повторе того же вида. Номер нужен
%% для правила Карна: RTT учитывается только по первой отправке вида,
%% потому что повторный ответ неотличим от отклика на потерянный пакет.
%% Планировщик не переиспользует ни идентификаторы, ни сокеты отправок:
%% повтор — это новая проба, а поздний ответ на прежнюю отправку после
%% закрытия её сокета теряется (явный trade-off первой версии), а не
%% молча приписывается повтору.
-spec schedule([kind()], 0..5, pos_integer(), pos_integer()) ->
          [{kind(), non_neg_integer(), pos_integer()}].
schedule(Kinds, Retries, Budget, Rto)
  when is_list(Kinds), Kinds =/= [],
       is_integer(Retries), Retries >= 0,
       is_integer(Budget), Budget > 0,
       is_integer(Rto), Rto > 0 ->
    Sequence = lists:append(lists:duplicate(Retries + 1, Kinds)),
    build_plan(Sequence, Budget, Rto, #{}, []).

build_plan([], _Remaining, _Rto, _Counts, Acc) ->
    lists:reverse(Acc);
build_plan([Kind | Rest], Remaining, Rto, Counts, Acc) ->
    SendsLeft = length(Rest) + 1,
    Share = case Remaining of
                0 -> 0;
                _ -> max(1, Remaining div SendsLeft)
            end,
    Wait = min(Rto, Share),
    SendNumber = maps:get(Kind, Counts, 0) + 1,
    build_plan(Rest, Remaining - Wait, Rto, Counts#{Kind => SendNumber},
               [{Kind, Wait, SendNumber} | Acc]).

%%% ------------------------------------------------------------------
%%% run
%%% ------------------------------------------------------------------

%% @doc Выполняет обнаружение одного адреса.
%%
%% `Route' — результат {@link trawler_discovery_route:lookup/1};
%% `Options' — {@link options/0}. Возвращается {@link result/0} ровно с
%% одним исходом. Для `auto' собственный адрес (`local') подтверждается
%% без отправки пакетов; явные `tcp', `icmp' и `raw_tcp' на loopback
%% всё равно выполняют реальную пробу.
-spec run(ip4(), map(), options()) -> result().
run(IP, Route, Options) when is_map(Route), is_map(Options) ->
    Start = erlang:monotonic_time(millisecond),
    case valid_ip(IP) of
        false -> error_result(IP, {invalid_ip, IP}, Start);
        true -> run_valid(IP, Route, Options, Start)
    end.

run_valid(IP, Route, Options, Start) ->
    Method = maps:get(method, Options, auto),
    case validate_ports(Method, Options) of
        {error, Reason} ->
            error_result(IP, Reason, Start);
        {ok, Ports} ->
            case candidate_kinds(Method, Route, Options) of
                {error, Reason} ->
                    error_result(IP, Reason, Start);
                {ok, [local]} ->
                    up_result(IP, local, Start, #{});
                {ok, Kinds} ->
                    run_kinds(IP, Route, Options, Kinds, Ports, Start)
            end
    end.

%% @doc Выполняет ровно один вид пробы (внутренний диагностический вход).
%%
%% Используется opt-in runner'ом, чтобы независимо проверить echo,
%% timestamp, raw SYN и raw ACK на loopback: обычный run/3 останавливается
%% на первом подтверждении и не обязан доходить до остальных видов.
%% Контракт исхода совпадает с run/3; `local' здесь не применяется.
-spec run_kind(kind(), ip4(), map(), options()) -> result().
run_kind(Kind, IP, Route, Options) when is_map(Route), is_map(Options) ->
    Start = erlang:monotonic_time(millisecond),
    case valid_ip(IP) andalso lists:member(Kind, [arp, icmp_echo, icmp_timestamp,
                                                  tcp_syn, tcp_ack, tcp]) of
        false ->
            error_result(IP, {invalid_probe, Kind}, Start);
        true ->
            case validate_ports(Kind, Options) of
                {error, Reason} ->
                    error_result(IP, Reason, Start);
                {ok, Ports} ->
                    run_kinds(IP, Route, Options, [Kind], Ports, Start)
            end
    end.

run_kinds(IP, Route, Options, Kinds, Ports, Start) ->
    Budget = budget(Options),
    Deadline = Start + Budget,
    Timing = timing_state(Options, Budget),
    Rto = trawler_discovery_timing:rto(Timing),
    Schedule = schedule(Kinds, retries(Options), Budget, Rto),
    execute(IP, Route, Ports, Schedule, Timing, Start, Deadline,
            #{failed => [], error => undefined}).

%% Порты допустимы только для методов, которые могут использовать TCP;
%% иначе намерение пользователя не выполнимо и должно быть отклонено.
validate_ports(Method, Options) when Method =:= tcp; Method =:= auto ->
    normalize_ports(maps:get(ports, Options, ?DEFAULT_PORTS));
validate_ports(_Method, Options) ->
    case maps:is_key(ports, Options) of
        true -> {error, {invalid_options, ports}};
        false -> {ok, []}
    end.

%% @doc Выбирает виды проб для метода и маршрута (чистая функция).
%%
%% `auto' на собственном адресе даёт `[local]' без обращения к caps;
%% на подключённом Ethernet с известным MAC и доступным ARP — только
%% `[arp]' (молчание ARP не переводится в TCP-пробы); иначе — доступные
%% ICMP/raw TCP либо TCP connect. Явный ARP требует одновременно
%% Ethernet и признака подключённого канала (`on_link'), поэтому для
%% маршрута через шлюз ARP не отправляется.
-spec candidate_kinds(method(), map(), options()) ->
          {ok, [kind() | local]} | {error, term()}.
candidate_kinds(Method, Route, Options) ->
    case Method of
        arp -> arp_kinds(Route);
        icmp -> {ok, [icmp_echo, icmp_timestamp]};
        raw_tcp -> {ok, [tcp_syn, tcp_ack]};
        tcp -> {ok, [tcp]};
        auto -> auto_kinds(Route, Options);
        Other -> {error, {invalid_method, Other}}
    end.

%% Собственный адрес подтверждается как `local' до любого обращения к
%% capabilities/0: raw-проверка при этом не нужна.
auto_kinds(Route, Options) ->
    case maps:get(local, Route, false) of
        true ->
            {ok, [local]};
        false ->
            {ok, select_auto_kinds(Route, caps(Options))}
    end.

%% ARP добавляется только для on-link Ethernet с известным MAC, и тогда
%% он единственный вид: молчание on-link сегмента не должно запускать
%% ICMP или TCP-пробы, которых не требует сценарий локальной сети.
%% Для маршрутизируемых адресов ARP исключён, а ICMP и raw TCP — по
%% доступности; без raw-возможностей остаётся только TCP connect, что
%% совпадает с prepare/2.
select_auto_kinds(Route, Caps) ->
    case on_link_arp(Route, Caps) of
        true ->
            [arp];
        false ->
            Icmp = maps:get(icmp, Caps, false),
            RawTcp = maps:get(raw_tcp, Caps, false),
            Kinds = (case Icmp of true -> [icmp_echo, icmp_timestamp]; false -> [] end)
                ++ (case RawTcp of true -> [tcp_syn, tcp_ack]; false -> [] end),
            case Kinds of
                [] -> [tcp];
                _ -> Kinds
            end
    end.

on_link_arp(Route, Caps) ->
    maps:get(ethernet, Route, false)
        andalso maps:get(on_link, Route, false)
        andalso maps:is_key(mac, Route)
        andalso maps:get(arp, Caps, false).

%% ARP подтверждает адрес только в подключённом Ethernet-сегменте:
%% маршрут через шлюз (on_link = false) до ARP не допускается, иначе
%% ARP ушёл бы не тому адресату, который выберет ядро.
arp_kinds(Route) ->
    case {maps:get(ethernet, Route, false), maps:get(on_link, Route, false)} of
        {false, _} -> {error, {method_not_applicable, not_ethernet}};
        {true, false} -> {error, {method_not_applicable, not_on_link}};
        {true, true} -> {ok, [arp]}
    end.

%% caps из опций читается лениво: при наличии ключа capabilities/0 не
%% вызывается вовсе, поэтому raw-проверка не повторяется на каждый адрес.
caps(Options) ->
    case maps:find(caps, Options) of
        {ok, Caps} -> Caps;
        error -> capabilities()
    end.

budget(Options) ->
    case maps:get(timeout_ms, Options, ?DEFAULT_TIMEOUT_MS) of
        Timeout when is_integer(Timeout), Timeout > 0 -> Timeout;
        _Other -> ?DEFAULT_TIMEOUT_MS
    end.

retries(Options) ->
    Value = maps:get(retries, Options, ?DEFAULT_RETRIES),
    case is_integer(Value) of
        true -> min(?MAX_RETRIES, max(0, Value));
        false -> ?DEFAULT_RETRIES
    end.

%% Состояние ожидания: начальное для бюджета, с необязательными
%% переносимой оценкой RTT и стартовым RTO. RTO не выходит за бюджет.
timing_state(Options, Budget) ->
    Base = case maps:get(timing, Options, undefined) of
               undefined -> trawler_discovery_timing:initial(Budget);
               State -> State
           end,
    Max = maps:get(max, Base),
    case maps:get(rto_ms, Options, undefined) of
        Rto when is_integer(Rto), Rto > 0 ->
            Base#{rto := min(max(Rto, ?MIN_RTO), Max)};
        _Other ->
            Base
    end.

%%% ------------------------------------------------------------------
%%% Исполнение плана
%%% ------------------------------------------------------------------

execute(IP, _Route, _Ports, [], _Timing, Start, _Deadline, Acc) ->
    finish(IP, Acc, Start);
execute(IP, Route, Ports, [{Kind, Wait, SendNumber} | Rest], Timing, Start, Deadline, Acc) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    Failed = maps:get(failed, Acc),
    case Remaining > 0 of
        false ->
            %% Истёк настоящий срок адреса: единственная причина
            %% прервать оставшиеся виды и повторы.
            finish(IP, Acc, Start);
        true ->
            case lists:member(Kind, Failed) of
                true ->
                    %% Вид уже дал сокетную ошибку: пропускаем только
                    %% его, продолжая остальные виды и повторы, иначе
                    %% один сбой отменял бы ещё не использованные методы.
                    execute(IP, Route, Ports, Rest, Timing, Start, Deadline, Acc);
                false ->
                    try_kind(IP, Route, Ports, Kind, Wait, SendNumber, Rest,
                             Timing, Start, Deadline, Acc)
            end
    end.

try_kind(IP, Route, Ports, Kind, Wait, SendNumber, Rest, Timing, Start,
         Deadline, Acc) ->
    case probe(Kind, IP, Route, Ports, min(Wait, Deadline - erlang:monotonic_time(millisecond)), Timing) of
        {up, Method, Extra} ->
            up_result(IP, Method, Start, confirmation_extra(Extra, SendNumber));
        timeout ->
            execute(IP, Route, Ports, Rest, Timing, Start, Deadline, Acc);
        {error, Reason} ->
            %% Ошибка сокета/отправки: вид больше не повторяем,
            %% но остальные методы продолжают попытки.
            Failed = [Kind | maps:get(failed, Acc)],
            Error = case maps:get(error, Acc) of
                        undefined -> Reason;
                        Saved -> Saved
                    end,
            execute(IP, Route, Ports, Rest, Timing, Start, Deadline,
                    Acc#{failed => Failed, error => Error})
    end.

%% @doc Применяет правило Карна к дополнительным полям подтверждения.
%%
%% `rtt_ms' сохраняется только для первой отправки вида (`SendNumber'
%% равен 1). Ответ на повтор неотличим от отклика на потерянную первую
%% отправку, поэтому его RTT не используется для адаптации ожидания.
-spec confirmation_extra(map(), pos_integer()) -> map().
confirmation_extra(Extra, SendNumber) when SendNumber > 1 ->
    maps:remove(rtt_ms, Extra);
confirmation_extra(Extra, _FirstSend) ->
    Extra.

%% Если был хоть один сокетный сбой — это `error'; чистое молчание —
%% `no_response', и оно не утверждает отсутствие устройства.
finish(IP, Acc, Start) ->
    case maps:get(error, Acc) of
        undefined -> no_response_result(IP, Start);
        Reason -> error_result(IP, Reason, Start)
    end.

probe(arp, IP, Route, _Ports, Wait, _Timing) ->
    arp_probe(IP, Route, Wait);
probe(icmp_echo, IP, Route, _Ports, Wait, _Timing) ->
    icmp_probe(echo, IP, Route, Wait);
probe(icmp_timestamp, IP, Route, _Ports, Wait, _Timing) ->
    icmp_probe(timestamp, IP, Route, Wait);
probe(tcp_syn, IP, Route, _Ports, Wait, _Timing) ->
    raw_tcp_probe(syn, IP, Route, Wait);
probe(tcp_ack, IP, Route, _Ports, Wait, _Timing) ->
    raw_tcp_probe(ack, IP, Route, Wait);
probe(tcp, IP, _Route, Ports, Wait, _Timing) ->
    tcp_connect_probe(IP, Ports, Wait).

%%% ------------------------------------------------------------------
%%% TCP connect
%%% ------------------------------------------------------------------

tcp_connect_probe(IP, Ports, Wait) ->
    Deadline = erlang:monotonic_time(millisecond) + Wait,
    connect_ports(IP, Ports, Deadline, undefined).

%% Один абсолютный срок на всю серию портов: дедлайн не продлевается
%% каждым следующим портом, а остаток делится поровну между ещё не
%% проверенными портами, поэтому суммарное ожидание не превосходит
%% бюджет адреса и не умножается на число портов.
connect_ports(_IP, [], _Deadline, Error) ->
    case Error of
        undefined -> timeout;
        Reason -> {error, Reason}
    end;
connect_ports(IP, [Port | Rest], Deadline, Error) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining > 0 of
        false ->
            connect_ports(IP, [], Deadline, Error);
        true ->
            PortsLeft = length(Rest) + 1,
            Wait = min(Remaining, max(1, Remaining div PortsLeft)),
            SendTime = erlang:monotonic_time(millisecond),
            case gen_tcp:connect(IP, Port, [inet, {active, false}], Wait) of
                {ok, Socket} ->
                    _ = gen_tcp:close(Socket),
                    {up, tcp_open, #{port => Port, rtt_ms => rtt(SendTime)}};
                {error, econnrefused} ->
                    %% Закрытый порт — действительный ответ, подтверждающий хост.
                    {up, tcp_refused, #{port => Port, rtt_ms => rtt(SendTime)}};
                {error, timeout} ->
                    connect_ports(IP, Rest, Deadline, Error);
                {error, Reason} ->
                    connect_ports(IP, Rest, Deadline, Reason)
            end
    end.

%%% ------------------------------------------------------------------
%%% ICMP echo / timestamp
%%% ------------------------------------------------------------------

icmp_probe(Kind, TargetIP, Route, Wait) ->
    SourceIP = maps:get(source, Route),
    Id = unique16(),
    Seq = unique16(),
    Payload = icmp_payload(Kind),
    case socket:open(inet, raw, icmp) of
        {ok, Socket} ->
            try
                case bind_source(Socket, SourceIP) of
                    ok ->
                        Message = trawler_discovery_packet:icmp_request(Kind, Id, Seq, Payload),
                        SendTime = erlang:monotonic_time(millisecond),
                        case socket:sendto(Socket, Message, inet_target(TargetIP)) of
                            ok ->
                                icmp_receive(Socket, TargetIP, SourceIP, Id, Seq,
                                             Payload, SendTime, Wait);
                            {error, Reason} ->
                                {error, Reason}
                        end;
                    {error, Reason} ->
                        {error, Reason}
                end
            after
                _ = socket:close(Socket)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

icmp_receive(Socket, TargetIP, SourceIP, Id, Seq, Payload, SendTime, Wait) ->
    Deadline = erlang:monotonic_time(millisecond) + Wait,
    icmp_recv_loop(Socket, TargetIP, SourceIP, Id, Seq, Payload, SendTime, Deadline).

%% Абсолютный дедлайн: чужие/неподходящие пакеты не продлевают ожидание.
icmp_recv_loop(Socket, TargetIP, SourceIP, Id, Seq, Payload, SendTime, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining > 0 of
        false ->
            timeout;
        true ->
            case socket:recvfrom(Socket, 0, Remaining) of
                {ok, {_SockAddr, Packet}} ->
                    case trawler_discovery_packet:icmp_reply(Packet, TargetIP,
                                                             SourceIP, Id, Seq,
                                                             Payload) of
                        {ok, Method} ->
                            {up, Method, #{rtt_ms => rtt(SendTime)}};
                        ignore ->
                            icmp_recv_loop(Socket, TargetIP, SourceIP, Id, Seq,
                                           Payload, SendTime, Deadline)
                    end;
                {error, timeout} ->
                    timeout;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% echo несёт корреляционный маркер, timestamp — метку отправки (4 байта).
icmp_payload(echo) ->
    <<(unique32()):32, (stamp32()):32>>;
icmp_payload(timestamp) ->
    <<(stamp32()):32>>.

%%% ------------------------------------------------------------------
%%% Raw TCP SYN / ACK
%%% ------------------------------------------------------------------

%% @doc Проба raw TCP: SYN на 443 либо ACK на 80.
%%
%% Локальный порт резервируется отдельным TCP-сокетом через bind без
%% listen и connect — это служебное резервирование, а не соединение.
%% Сегмент отправляется raw-сокетом, IPv4-заголовок строит ядро. Ответ
%% на закрытый порт (RST) считается действительным подтверждением.
raw_tcp_probe(Kind, TargetIP, Route, Wait) ->
    SourceIP = maps:get(source, Route),
    TargetPort = case Kind of
                     syn -> ?SYN_PORT;
                     ack -> ?ACK_PORT
                 end,
    case reserve_source(SourceIP) of
        {ok, Reserve, SourcePort} ->
            try
                raw_tcp_exchange(Kind, TargetIP, SourceIP, SourcePort,
                                 TargetPort, Wait)
            after
                _ = socket:close(Reserve)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

reserve_source(SourceIP) ->
    case socket:open(inet, stream, tcp) of
        {ok, Socket} ->
            case bind_source(Socket, SourceIP) of
                ok ->
                    case socket:sockname(Socket) of
                        {ok, SockAddr} ->
                            {ok, Socket, maps:get(port, SockAddr)};
                        {error, Reason} ->
                            _ = socket:close(Socket),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    _ = socket:close(Socket),
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

raw_tcp_exchange(Kind, TargetIP, SourceIP, SourcePort, TargetPort, Wait) ->
    {Seq, Ack} = case Kind of
                     syn -> {unique32(), 0};
                     ack -> {0, unique32()}
                 end,
    case socket:open(inet, raw, tcp) of
        {ok, Socket} ->
            try
                case bind_source(Socket, SourceIP) of
                    ok ->
                        Segment = trawler_discovery_packet:tcp_request(
                                    Kind, SourceIP, TargetIP, SourcePort,
                                    TargetPort, Seq, Ack),
                        SendTime = erlang:monotonic_time(millisecond),
                        case socket:sendto(Socket, Segment, inet_target(TargetIP)) of
                            ok ->
                                raw_tcp_receive(Socket, TargetIP, SourceIP,
                                                SourcePort, TargetPort, Seq, Ack,
                                                Kind, SendTime, Wait);
                            {error, Reason} ->
                                {error, Reason}
                        end;
                    {error, Reason} ->
                        {error, Reason}
                end
            after
                _ = socket:close(Socket)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

raw_tcp_receive(Socket, TargetIP, SourceIP, SourcePort, TargetPort, Seq, Ack,
                Kind, SendTime, Wait) ->
    Deadline = erlang:monotonic_time(millisecond) + Wait,
    raw_tcp_recv_loop(Socket, TargetIP, SourceIP, SourcePort, TargetPort, Seq,
                      Ack, Kind, SendTime, Deadline).

raw_tcp_recv_loop(Socket, TargetIP, SourceIP, SourcePort, TargetPort, Seq, Ack,
                  Kind, SendTime, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining > 0 of
        false ->
            timeout;
        true ->
            case socket:recvfrom(Socket, 0, Remaining) of
                {ok, {_SockAddr, Packet}} ->
                    case trawler_discovery_packet:tcp_reply(Packet, TargetIP,
                                                            SourceIP, SourcePort,
                                                            TargetPort, Seq, Ack,
                                                            Kind) of
                        {ok, Method} ->
                            {up, Method, #{port => TargetPort, rtt_ms => rtt(SendTime)}};
                        ignore ->
                            raw_tcp_recv_loop(Socket, TargetIP, SourceIP,
                                              SourcePort, TargetPort, Seq, Ack,
                                              Kind, SendTime, Deadline)
                    end;
                {error, timeout} ->
                    timeout;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%%% ------------------------------------------------------------------
%%% ARP (AF_PACKET)
%%% ------------------------------------------------------------------

arp_probe(TargetIP, Route, Wait) ->
    SourceIP = maps:get(source, Route),
    SourceMac = maps:get(mac, Route, <<>>),
    Ifindex = maps:get(ifindex, Route),
    case socket:open(?AF_PACKET, raw, htons(?ETH_P_ARP)) of
        {ok, Socket} ->
            try
                BindAddr = trawler_discovery_packet:native_packet_address(
                             Ifindex, ?ETH_P_ARP, SourceMac),
                case socket:bind(Socket, BindAddr) of
                    ok ->
                        Frame = trawler_discovery_packet:arp_request(SourceMac,
                                                                     SourceIP,
                                                                     TargetIP),
                        SendTime = erlang:monotonic_time(millisecond),
                        case socket:sendto(Socket, Frame, BindAddr) of
                            ok ->
                                arp_receive(Socket, TargetIP, SourceIP, SourceMac,
                                            Ifindex, SendTime, Wait);
                            {error, Reason} ->
                                {error, Reason}
                        end;
                    {error, Reason} ->
                        {error, Reason}
                end
            after
                _ = socket:close(Socket)
            end;
        {error, Reason} ->
            {error, Reason}
    end.

arp_receive(Socket, TargetIP, SourceIP, SourceMac, Ifindex, SendTime, Wait) ->
    Deadline = erlang:monotonic_time(millisecond) + Wait,
    arp_recv_loop(Socket, TargetIP, SourceIP, SourceMac, Ifindex, SendTime, Deadline).

arp_recv_loop(Socket, TargetIP, SourceIP, SourceMac, Ifindex, SendTime, Deadline) ->
    Remaining = Deadline - erlang:monotonic_time(millisecond),
    case Remaining > 0 of
        false ->
            timeout;
        true ->
            case socket:recvfrom(Socket, 0, Remaining) of
                {ok, {SockAddr, Frame}} ->
                    %% Кадр принимается только с привязанного интерфейса.
                    case packet_ifindex(SockAddr) of
                        Ifindex ->
                            case trawler_discovery_packet:arp_reply(Frame, TargetIP,
                                                                    SourceIP,
                                                                    SourceMac) of
                                {ok, Mac} -> {up, arp, #{mac => Mac, rtt_ms => rtt(SendTime)}};
                                ignore ->
                                    arp_recv_loop(Socket, TargetIP, SourceIP,
                                                  SourceMac, Ifindex, SendTime,
                                                  Deadline)
                            end;
                        _Other ->
                            arp_recv_loop(Socket, TargetIP, SourceIP, SourceMac,
                                          Ifindex, SendTime, Deadline)
                    end;
                {error, timeout} ->
                    timeout;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% @doc Извлекает ifindex из `socket:sockaddr()' принятого кадра.
%%
%% Декодер OTP возвращает `AF_PACKET'-адрес уже нормализованным:
%% `#{family => packet, ifindex => N, hatype => ..., pkttype => ...,
%% addr => MAC}'. Числовая native-форма (`family => 17', `addr' с
%% полями после `sa_family') поддерживается как запасная, потому что
%% именно её принимает `socket:bind/2' и она может встретиться в
%% тестовых fixture. Неизвестная форма даёт `undefined', и кадр
%% игнорируется.
-spec packet_ifindex(socket:sockaddr()) -> pos_integer() | undefined.
packet_ifindex(#{family := packet, ifindex := Ifindex}) when is_integer(Ifindex) ->
    Ifindex;
packet_ifindex(#{family := ?AF_PACKET,
                 addr := <<_:2/binary, Ifindex:32/native, _/binary>>}) ->
    Ifindex;
packet_ifindex(_SockAddr) ->
    undefined.

%%% ------------------------------------------------------------------
%%% Результаты и вспомогательные функции
%%% ------------------------------------------------------------------

up_result(IP, Method, Start, Extra) ->
    maps:merge(#{ip => IP,
                 state => up,
                 elapsed_ms => elapsed(Start),
                 method => Method}, Extra).

no_response_result(IP, Start) ->
    #{ip => IP,
      state => no_response,
      elapsed_ms => elapsed(Start)}.

error_result(IP, Reason, Start) ->
    #{ip => IP,
      state => error,
      elapsed_ms => elapsed(Start),
      reason => Reason}.

elapsed(Start) ->
    max(0, erlang:monotonic_time(millisecond) - Start).

rtt(SendTime) ->
    max(0, erlang:monotonic_time(millisecond) - SendTime).

valid_ip({A, B, C, D}) ->
    is_integer(A) andalso A >= 0 andalso A =< 255
        andalso is_integer(B) andalso B >= 0 andalso B =< 255
        andalso is_integer(C) andalso C >= 0 andalso C =< 255
        andalso is_integer(D) andalso D >= 0 andalso D =< 255;
valid_ip(_Other) ->
    false.

bind_source(Socket, SourceIP) ->
    socket:bind(Socket, #{family => inet, addr => SourceIP, port => 0}).

inet_target(IP) ->
    #{family => inet, addr => IP, port => 0}.

unique16() ->
    erlang:unique_integer([positive]) band 16#FFFF.

unique32() ->
    erlang:unique_integer([positive]) band 16#FFFFFFFF.

%% Младшие 32 бита монотонного времени в миллисекундах.
stamp32() ->
    erlang:monotonic_time(millisecond) band 16#FFFFFFFF.

%% Перевод сетевого порядка (big-endian) в native целое: на
%% little-endian машине ETH_P_ARP 16#0806 превращается в 16#0608.
htons(Value) when is_integer(Value), Value >= 0, Value =< 65535 ->
    <<Native:16/native>> = <<Value:16/big>>,
    Native.
