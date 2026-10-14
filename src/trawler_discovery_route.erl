%%%-------------------------------------------------------------------
%%% @doc Маршрут IPv4-адреса и список интерфейсов средствами OTP.
%%%
%%% Модуль отвечает на два вопроса обнаружения без внешних команд
%%% (`ip', `route', `ping'): какой маршрут выберет ядро Linux для
%%% конкретного адреса и какие интерфейсы, адреса и MAC есть у машины.
%%%
%%% Маршрут запрашивается у ядра через `NETLINK_ROUTE'
%%% (`AF_NETLINK' = 16, `SOCK_RAW', протокол 0) сообщением
%%% `RTM_GETROUTE' с destination /32. Учитываются `RTA_OIF',
%%% `RTA_GATEWAY', `RTA_PREFSRC' и `RTN_LOCAL', проверяется sequence
%%% ответа и `NLMSG_ERROR'. Собственный конечный timeout и закрытие
%%% сокета через `after' исключают зависание и утечку дескриптора.
%%% Netlink не требует привилегий root.
%%%
%%% Интерфейсы собираются из `net:getifaddrs/0' (адреса, MAC, тип
%%% оборудования, флаги), а index интерфейса — из `net:if_names/0':
%%% `net:getifaddrs/0' не сообщает ifindex для интерфейсов без
%%% link-layer адреса (например, point-to-point/VPN), и без этого
%%% такой маршрут остался бы без имени интерфейса.
%%%
%%% `on_link' выводится только из ответа ядра (маршрут без шлюза), а не
%%% из приватных диапазонов или маски интерфейса: иначе более
%%% специфичные маршруты и VPN определялись бы неверно. Неизвестный
%%% маршрут — ошибка, а не подтверждение адреса.
%%%
%%% Интерфейс привязки AF_PACKET и проверки пакетов находятся в
%%% {@link trawler_discovery_packet}.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_route).

%% Публичный контракт.
-export([lookup/1, lookup/2, interfaces/0]).

%% Экспорт для fixture-тестов: `encode_getroute/2', `decode_message/2',
%% `route_from_attrs/3' и `interfaces_from/2' — чистые части
%% netlink-разбора и соединения интерфейсов, проверяемые на
%% синтетических сообщениях без сети; `resolve_source/1' проверяется на
%% loopback. Публичный контракт — только `lookup/1' и `interfaces/0'.
-export([encode_getroute/2, decode_message/2, route_from_attrs/3,
         interfaces_from/2, resolve_source/1]).

-export_type([ip4/0, interface/0, route/0, reason/0]).

%% IPv4-адрес в форме кортежа октетов.
-type ip4() :: {0..255, 0..255, 0..255, 0..255}.

%% Интерфейс машины. `mac' присутствует только для Ethernet-каналов:
%% у loopback и point-to-point link-layer адреса нет.
-type interface() :: #{name := string(),
                       ifindex := pos_integer(),
                       addresses := [ip4()],
                       ethernet := boolean(),
                       flags := [atom()],
                       up := boolean(),
                       mac => binary()}.

%% Разобранные атрибуты маршрута ядра. Отсутствующие атрибуты равны
%% `undefined'.
-type attributes() :: #{type := non_neg_integer(),
                        table := non_neg_integer(),
                        dst := ip4() | undefined,
                        source := ip4() | undefined,
                        gateway := ip4() | undefined,
                        ifindex := pos_integer() | undefined}.

%% Готовый маршрут адреса. `mac' и `gateway' присутствуют, только когда
%% применимы.
-type route() :: #{source := ip4(),
                   ifindex := pos_integer(),
                   interface := string(),
                   local := boolean(),
                   ethernet := boolean(),
                   on_link := boolean(),
                   mac => binary(),
                   gateway => ip4()}.

%% Причина ошибки: атом errno, `timeout' либо `{netlink, Term}'.
-type reason() :: atom() | {atom(), term()}.

%% lookup/1 делегирует lookup/2 с собственным конечным сроком; анализатор
%% выводит более узкий тип возврата, чем объявляет reason(), поэтому
%% предупреждение underspecs подавлено (аналогично trawler_discovery_registry).
-dialyzer({no_underspecs, [lookup/1]}).

%% Linux ABI: AF_NETLINK и NETLINK_ROUTE из linux/netlink.h.
-define(AF_NETLINK, 16).
-define(NETLINK_ROUTE, 0).

-define(NLMSG_HEADER, 16).
-define(NLMSG_ALIGNTO, 4).
-define(NLMSG_ERROR, 2).
-define(NLM_F_REQUEST, 1).

-define(RTM_NEWROUTE, 24).
-define(RTM_GETROUTE, 26).

-define(AF_INET, 2).
-define(RTN_LOCAL, 2).

-define(RTA_DST, 1).
-define(RTA_OIF, 4).
-define(RTA_GATEWAY, 5).
-define(RTA_PREFSRC, 7).

%% Собственный конечный срок netlink-обмена, миллисекунды.
-define(NETLINK_TIMEOUT_MS, 2000).
%% Порт UDP-соединения для определения исходного адреса. Данные не
%% отправляются, порт участвует только в выборе маршрута ядром.
-define(DISCARD_PORT, 9).

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

%% @doc Возвращает маршрут ядра для IPv4-адреса.
%%
%% Поле `source' берётся из `RTA_PREFSRC'; если ядро его не сообщило,
%% исходный адрес определяется через UDP `connect' и `sockname' без
%% отправки данных. `local' истинно для `RTN_LOCAL' и для адреса,
%% принадлежащего интерфейсу маршрута. `on_link' истинно, когда маршрут
%% не содержит шлюза, то есть адрес достижим по подключённому каналу;
%% ARP возможен только при `on_link' и `ethernet' одновременно.
%% Неизвестный маршрут возвращает ошибку и не подтверждает адрес.
-spec lookup(ip4()) -> {ok, route()} | {error, reason()}.
lookup(IP) ->
    lookup(IP, ?NETLINK_TIMEOUT_MS).

%% @doc Возвращает маршрут ядра с конечным сроком netlink-обмена.
%%
%% `TimeoutMs' ограничивает ожидание ответа ядра и никогда не превышает
%% собственный предел модуля. Это позволяет воркеру вложить поиск
%% маршрута в общий бюджет адреса, а не тратить его отдельно. Ноль или
%% отрицательное значение даёт немедленный `{error, timeout}'.
-spec lookup(ip4(), integer()) -> {ok, route()} | {error, reason()}.
lookup(IP, TimeoutMs) ->
    case valid_ip(IP) of
        false ->
            {error, {invalid_ip, IP}};
        true ->
            case netlink_route(IP, next_seq(), TimeoutMs) of
                {ok, Attrs} ->
                    case interfaces() of
                        {ok, Interfaces} ->
                            case route_from_attrs(Attrs, Interfaces, IP) of
                                {error, _} = Error -> Error;
                                Route -> {ok, Route}
                            end;
                        {error, Reason} -> {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% @doc Возвращает интерфейсы машины, отсортированные по ifindex.
%%
%% Для каждого интерфейса: имя, индекс, все IPv4-адреса, флаги,
%% признак `up' и признак `ethernet' с MAC для Ethernet-каналов.
-spec interfaces() -> {ok, [interface()]} | {error, term()}.
interfaces() ->
    case net:if_names() of
        {ok, Names} ->
            case net:getifaddrs() of
                {ok, IfAddrs} -> {ok, interfaces_from(Names, IfAddrs)};
                {error, Reason} -> {error, {interfaces, Reason}}
            end;
        {error, Reason} ->
            {error, {interfaces, Reason}}
    end.

%%% ------------------------------------------------------------------
%%% Netlink-обмен
%%% ------------------------------------------------------------------

netlink_route(IP, Seq, TimeoutMs) ->
    case socket:open(?AF_NETLINK, raw, ?NETLINK_ROUTE) of
        {ok, Socket} ->
            try
                Deadline = erlang:monotonic_time(millisecond)
                           + effective_timeout(TimeoutMs),
                netlink_exchange(Socket, encode_getroute(IP, Seq), Seq, Deadline)
            after
                _ = socket:close(Socket)
            end;
        {error, Reason} ->
            {error, {netlink, Reason}}
    end.

%% Срок netlink-обмена ограничен и владельцем, и собственным пределом.
%% Неположительный срок не продлевается: ответ ядра ожидается без задержки.
effective_timeout(TimeoutMs) when is_integer(TimeoutMs), TimeoutMs > 0 ->
    min(TimeoutMs, ?NETLINK_TIMEOUT_MS);
effective_timeout(_Other) ->
    0.

netlink_exchange(Socket, Request, Seq, Deadline) ->
    case socket:send(Socket, Request) of
        ok -> netlink_receive(Socket, Seq, Deadline);
        {error, Reason} -> {error, {netlink, Reason}}
    end.

%% Ожидание ответа ограничено абсолютным сроком: чужие сообщения не
%% продлевают ожидание.
netlink_receive(Socket, Seq, Deadline) ->
    Timeout = Deadline - erlang:monotonic_time(millisecond),
    case Timeout > 0 of
        false ->
            {error, timeout};
        true ->
            case socket:recv(Socket, 0, Timeout) of
                {ok, Data} ->
                    case select_message(Data, Seq) of
                        nomatch -> netlink_receive(Socket, Seq, Deadline);
                        Result -> Result
                    end;
                {error, timeout} ->
                    {error, timeout};
                {error, Reason} ->
                    {error, {netlink, Reason}}
            end
    end.

%% В датаграмме может быть несколько сообщений; берётся первое с нашим
%% sequence.
select_message(Data, Seq) ->
    case split_messages(Data, []) of
        {ok, Messages} -> select_by_seq(Messages, Seq);
        {error, Reason} -> {error, Reason}
    end.

select_by_seq([], _Seq) ->
    nomatch;
select_by_seq([Message | Rest], Seq) ->
    case message_seq(Message) of
        Seq -> decode_message(Message, Seq);
        _Other -> select_by_seq(Rest, Seq)
    end.

message_seq(<<_:4/binary, _:2/binary, _:2/binary, Seq:32/native, _/binary>>) ->
    Seq;
message_seq(_Message) ->
    undefined.

%%% ------------------------------------------------------------------
%%% Кодирование и разбор netlink (доступно fixture-тестам)
%%% ------------------------------------------------------------------

%% @doc Кодирует запрос `RTM_GETROUTE' с destination /32.
%%
%% Заголовок netlink, `struct rtmsg' и атрибут `RTA_DST' записываются в
%% native-порядке машины, атрибут выровнен до 4 байт. Только этот
%% запрос отправляется ядру; никакие внешние команды не вызываются.
-spec encode_getroute(ip4(), integer()) -> binary().
encode_getroute(IP, Seq) when is_integer(Seq) ->
    RtMsg = <<?AF_INET:8, 32:8, 0:8, 0:8, 0:8, 0:8, 0:8, 0:8, 0:32/native>>,
    Dst = <<8:16/native, ?RTA_DST:16/native, (ip_to_bin(IP))/binary>>,
    Body = <<RtMsg/binary, Dst/binary>>,
    <<(?NLMSG_HEADER + byte_size(Body)):32/native,
      ?RTM_GETROUTE:16/native, ?NLM_F_REQUEST:16/native,
      Seq:32/native, 0:32/native, Body/binary>>.

%% @doc Разбирает одно сообщение netlink ожидаемого sequence.
%%
%% `NLMSG_ERROR' переводится в атом errno (`enetunreach',
%% `ehostunreach', `eopnotsupp', ...) или `{netlink_error, Errno}',
%% `RTM_NEWROUTE' — в карту {@link attributes()}. Чужой sequence,
%% чужие типы сообщений и усечённые данные возвращают ошибку.
-spec decode_message(binary(), integer()) -> {ok, attributes()} | {error, reason()}.
decode_message(Message, ExpectedSeq) ->
    case Message of
        <<Len:32/native, Type:16/native, _Flags:16/native, Seq:32/native,
          _Pid:32/native, Rest/binary>> when Len >= ?NLMSG_HEADER ->
            BodyLen = Len - ?NLMSG_HEADER,
            case Rest of
                <<Body:BodyLen/binary, _/binary>> ->
                    decode_body(Type, Seq, Body, ExpectedSeq);
                _ ->
                    {error, {netlink, truncated}}
            end;
        _ ->
            {error, {netlink, truncated}}
    end.

decode_body(_Type, Seq, _Body, ExpectedSeq) when Seq =/= ExpectedSeq ->
    {error, {netlink, {unexpected_seq, Seq}}};
decode_body(?NLMSG_ERROR, _Seq, Body, _ExpectedSeq) ->
    decode_error(Body);
decode_body(?RTM_NEWROUTE, _Seq, Body, _ExpectedSeq) ->
    decode_route(Body);
decode_body(Type, _Seq, _Body, _ExpectedSeq) ->
    {error, {netlink, {unexpected_message, Type}}}.

decode_error(<<Errno:32/native, _/binary>>) ->
    {error, netlink_reason(signed32(Errno))};
decode_error(_Body) ->
    {error, {netlink, truncated}}.

decode_route(<<Family:8, _DstLen:8, _SrcLen:8, _Tos:8, Table:8, _Protocol:8,
               _Scope:8, RtmType:8, _Flags:32/native, Attrs/binary>>) ->
    case Family of
        ?AF_INET ->
            decode_attributes(Attrs, #{type => RtmType,
                                       table => Table,
                                       dst => undefined,
                                       source => undefined,
                                       gateway => undefined,
                                       ifindex => undefined});
        _ ->
            {error, {netlink, {unexpected_family, Family}}}
    end;
decode_route(_Body) ->
    {error, {netlink, truncated}}.

decode_attributes(<<>>, Acc) ->
    {ok, Acc};
decode_attributes(<<RtaLen:16/native, _/binary>> = Rest, Acc) when RtaLen >= 4 ->
    AlignedLen = align4(RtaLen),
    case Rest of
        <<Attribute:AlignedLen/binary, Next/binary>> ->
            PayloadLen = RtaLen - 4,
            <<_:2/binary, RtaType:16/native, _/binary>> = Attribute,
            <<_:4/binary, Payload:PayloadLen/binary, _/binary>> = Attribute,
            decode_attributes(Next, set_attribute(RtaType, Payload, Acc));
        _ ->
            {error, {netlink, truncated}}
    end;
decode_attributes(_Rest, _Acc) ->
    {error, {netlink, truncated}}.

set_attribute(?RTA_DST, <<A, B, C, D>>, Acc) ->
    Acc#{dst => {A, B, C, D}};
set_attribute(?RTA_PREFSRC, <<A, B, C, D>>, Acc) ->
    Acc#{source => {A, B, C, D}};
set_attribute(?RTA_GATEWAY, <<A, B, C, D>>, Acc) ->
    Acc#{gateway => {A, B, C, D}};
set_attribute(?RTA_OIF, <<Index:32/native>>, Acc) ->
    Acc#{ifindex => Index};
set_attribute(_RtaType, _Payload, Acc) ->
    Acc.

%%% ------------------------------------------------------------------
%%% Маршрут из атрибутов
%%% ------------------------------------------------------------------

%% @doc Собирает маршрут из разобранных атрибутов и списка интерфейсов.
%%
%% Функция чистая, кроме случая отсутствия `source': тогда исходный
%% адрес определяется через {@link resolve_source/1} (UDP без отправки
%% данных). Интерфейс ищется по ifindex маршрута; неизвестный ifindex —
%% ошибка.
-spec route_from_attrs(attributes(), [interface()], ip4()) ->
          route() | {error, reason()}.
route_from_attrs(Attrs, Interfaces, IP) ->
    Index = maps:from_list([{maps:get(ifindex, Interface), Interface}
                            || Interface <- Interfaces]),
    case maps:get(ifindex, Attrs, undefined) of
        undefined ->
            {error, {no_route, IP}};
        Ifindex ->
            case maps:find(Ifindex, Index) of
                error -> {error, {unknown_interface, Ifindex}};
                {ok, Interface} -> build_route(Attrs, Interface, IP)
            end
    end.

build_route(Attrs, Interface, IP) ->
    case route_source(Attrs, IP) of
        {error, Reason} ->
            {error, Reason};
        {ok, Source} ->
            Gateway = maps:get(gateway, Attrs, undefined),
            Route = #{source => Source,
                      ifindex => maps:get(ifindex, Interface),
                      interface => maps:get(name, Interface),
                      local => is_local(Attrs, Interface, IP),
                      ethernet => maps:get(ethernet, Interface),
                      on_link => Gateway =:= undefined},
            with_gateway(with_mac(Route, Interface), Gateway)
    end.

with_mac(Route, Interface) ->
    case maps:find(mac, Interface) of
        {ok, Mac} -> Route#{mac => Mac};
        error -> Route
    end.

with_gateway(Route, undefined) ->
    Route;
with_gateway(Route, Gateway) ->
    Route#{gateway => Gateway}.

route_source(Attrs, IP) ->
    case maps:get(source, Attrs, undefined) of
        undefined -> resolve_source(IP);
        Source -> {ok, Source}
    end.

%% Локальный адрес: ядро пометило маршрут RTN_LOCAL либо адрес
%% принадлежит интерфейсу маршрута.
is_local(Attrs, Interface, IP) ->
    maps:get(type, Attrs, undefined) =:= ?RTN_LOCAL
        orelse lists:member(IP, maps:get(addresses, Interface, [])).

%% @doc Определяет исходный адрес через UDP `connect' и `sockname'.
%%
%% Данные не отправляются: `connect' только выбирает маршрут и
%% локальный адрес. Сокет закрывается через `after' и на успешном, и на
%% ошибочном пути, и при исключении: дескриптор не утекает.
-spec resolve_source(ip4()) -> {ok, ip4()} | {error, reason()}.
resolve_source(IP) ->
    case valid_ip(IP) of
        false ->
            {error, {invalid_ip, IP}};
        true ->
            case gen_udp:open(0, [inet, {active, false}]) of
                {ok, Socket} ->
                    try connected_source(Socket, IP)
                    after
                        _ = gen_udp:close(Socket)
                    end;
                {error, Reason} ->
                    {error, Reason}
            end
    end.

connected_source(Socket, IP) ->
    case gen_udp:connect(Socket, IP, ?DISCARD_PORT) of
        ok ->
            case inet:sockname(Socket) of
                {ok, {Source, _Port}} -> {ok, Source};
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

%%% ------------------------------------------------------------------
%%% Интерфейсы
%%% ------------------------------------------------------------------

%% @doc Собирает интерфейсы из пар «index — имя» и вывода
%% `net:getifaddrs/0'.
%%
%% Функция чистая и служит fixture-тестом соединения ifindex, адресов,
%% MAC и типа канала по имени интерфейса. Имена без известного index
%% пропускаются, поэтому результат отсортирован по ifindex.
-spec interfaces_from([{pos_integer(), string()}], [map()]) -> [interface()].
interfaces_from(Names, IfAddrs) when is_list(Names), is_list(IfAddrs) ->
    Details = ifaddr_details(IfAddrs),
    [build_interface(Index, Name, Details) || {Index, Name} <- lists:sort(Names)].

build_interface(Index, Name, Details) ->
    Detail = maps:get(Name, Details, #{}),
    Flags = maps:get(flags, Detail, []),
    Base = #{name => Name,
             ifindex => Index,
             addresses => maps:get(addresses, Detail, []),
             ethernet => maps:get(ethernet, Detail, false),
             flags => Flags,
             up => lists:member(up, Flags)},
    case maps:find(mac, Detail) of
        {ok, Mac} -> Base#{mac => Mac};
        error -> Base
    end.

ifaddr_details(IfAddrs) ->
    lists:foldl(fun ifaddr_detail/2, #{}, IfAddrs).

ifaddr_detail(#{name := Name, addr := AddrMap} = Entry, Acc) ->
    Current = maps:get(Name, Acc, #{addresses => [],
                                    ethernet => false,
                                    flags => maps:get(flags, Entry, [])}),
    Updated = case maps:get(family, AddrMap, undefined) of
                  packet -> add_link(AddrMap, Current);
                  inet -> add_address(AddrMap, Current);
                  _Other -> Current
              end,
    Acc#{Name => Updated};
ifaddr_detail(_Entry, Acc) ->
    Acc.

%% MAC сохраняется только для Ethernet-каналов: у loopback и
%% point-to-point link-layer адрес либо нулевой, либо отсутствует.
add_link(AddrMap, Current) ->
    Ethernet = maps:get(hatype, AddrMap, undefined) =:= ether,
    case Ethernet andalso is_binary(maps:get(addr, AddrMap, undefined)) of
        true -> Current#{ethernet => true, mac => maps:get(addr, AddrMap)};
        false -> Current
    end.

add_address(#{addr := {A, B, C, D}}, Current) ->
    Current#{addresses => maps:get(addresses, Current) ++ [{A, B, C, D}]};
add_address(_AddrMap, Current) ->
    Current.

%%% ------------------------------------------------------------------
%%% Вспомогательные функции
%%% ------------------------------------------------------------------

valid_ip({A, B, C, D}) ->
    is_integer(A) andalso A >= 0 andalso A =< 255
        andalso is_integer(B) andalso B >= 0 andalso B =< 255
        andalso is_integer(C) andalso C >= 0 andalso C =< 255
        andalso is_integer(D) andalso D >= 0 andalso D =< 255;
valid_ip(_Other) ->
    false.

ip_to_bin({A, B, C, D}) ->
    <<A, B, C, D>>.

next_seq() ->
    erlang:unique_integer([positive]) band 16#7FFFFFFF.

%% Содержимое сообщения netlink делится по nlmsg_len: одна датаграмма
%% может содержать несколько сообщений.
split_messages(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
split_messages(<<Len:32/native, _/binary>> = Data, Acc) when Len >= ?NLMSG_HEADER ->
    case Data of
        <<Message:Len/binary, Rest/binary>> ->
            split_messages(Rest, [Message | Acc]);
        _ ->
            {error, {netlink, truncated}}
    end;
split_messages(_Data, _Acc) ->
    {error, {netlink, truncated}}.

align4(Length) ->
    ((Length + ?NLMSG_ALIGNTO - 1) div ?NLMSG_ALIGNTO) * ?NLMSG_ALIGNTO.

signed32(Unsigned) when Unsigned >= 16#80000000 ->
    Unsigned - 16#100000000;
signed32(Unsigned) ->
    Unsigned.

%% errno из linux/errno.h, приводимые к атомам. -101 = ENETUNREACH,
%% -113 = EHOSTUNREACH, -95 = EOPNOTSUPP, -22 = EINVAL,
%% -111 = ECONNREFUSED.
netlink_reason(0) -> {netlink, unexpected_ack};
netlink_reason(-101) -> enetunreach;
netlink_reason(-113) -> ehostunreach;
netlink_reason(-95) -> eopnotsupp;
netlink_reason(-22) -> einval;
netlink_reason(-111) -> econnrefused;
netlink_reason(Errno) -> {netlink_error, Errno}.
