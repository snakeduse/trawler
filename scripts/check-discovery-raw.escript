#!/usr/bin/env escript
%%! -noshell
%%%-------------------------------------------------------------------
%%% check-discovery-raw.escript — opt-in runner raw-проб на loopback.
%%%
%%% Задача 2.3 изменения add-ipv4-host-discovery. Скрипт НЕ входит в
%%% make check и требует сетевых привилегий: он выполняет настоящие
%%% raw-пробы на loopback и печатает фактический результат, ничего не
%%% подменяя fixtures. Библиотечное ядро root не требует — привилегии
%%% нужны только этой диагностике.
%%%
%%% Что проверяется на интерфейсе lo (индекс берётся из ядра через
%%% trawler_discovery_route:interfaces/0, а не задаётся числом):
%%%   * ICMP echo — настоящий запрос и приём ответа;
%%%   * ICMP timestamp — если ядро отвечает; иначе пропуск, не провал;
%%%   * raw TCP SYN 443 и ACK 80 — настоящие SYN/RST и ACK/RST;
%%%   * AF_PACKET: native-привязка sockaddr_ll по протоколу ARP (без
%%%     сканирования внешней сети);
%%%   * ARP codec (request/reply) на синтетическом кадре;
%%%   * TCP connect: динамический открытый и закрытый локальный порт
%%%     (80/443 не занимаются, их состояние только сообщается);
%%%   * auto на loopback сокращается до `local' — отдельно от raw-проб,
%%%     которые loopback до local НЕ сокращают.
%%%
%%% Запуск с привилегиями (рекомендуется обёртка scripts/check-discovery-raw):
%%%   source scripts/env.sh otp
%%%   sudo -n env "HOME=$HOME" "PATH=$PATH" \
%%%       escript scripts/check-discovery-raw.escript
%%%
%%% Код возврата: 0 — обязательные проверки пройдены; 1 — провал;
%%% 2 — нет привилегий/сборки/не Linux.
%%% @end
%%%-------------------------------------------------------------------

main(_Args) ->
    Ebin = ebin_path(),
    case filelib:is_dir(Ebin) of
        false ->
            io:format("Сборка не найдена: ~s. Запустите make build.~n", [Ebin]),
            halt(2);
        true ->
            ok
    end,
    true = code:add_pathz(Ebin),
    io:format("== trawler discovery raw loopback runner ==~n"),
    case os:type() of
        {unix, linux} ->
            ok;
        Other ->
            io:format("raw-методы поддерживаются только на Linux: ~p~n", [Other]),
            halt(2)
    end,
    Caps = trawler_discovery_probe:capabilities(),
    io:format("capabilities: ~p~n", [Caps]),
    case maps:get(icmp, Caps, false) of
        false ->
            io:format("Нет raw-привилегий (reason=~p). Запустите с root.~n",
                      [maps:get(reason, Caps)]),
            halt(2);
        true ->
            ok
    end,
    Lo = {127, 0, 0, 1},
    {ok, Interfaces} = trawler_discovery_route:interfaces(),
    Loopback = find_interface("lo", Interfaces),
    io:format("lo: ifindex=~p addresses=~p~n",
              [maps:get(ifindex, Loopback), maps:get(addresses, Loopback)]),
    {ok, Route} = trawler_discovery_route:lookup(Lo),
    io:format("route: ~p~n", [Route]),
    io:format("~n"),
    Results = [raw_check("ICMP echo", icmp_echo, Lo, Route),
               raw_check("ICMP timestamp", icmp_timestamp, Lo, Route),
               raw_check("raw SYN 443", tcp_syn, Lo, Route),
               raw_check("raw ACK 80", tcp_ack, Lo, Route),
               simple_check("ARP codec", fun arp_codec/0),
               simple_check("AF_PACKET bind lo", fun() -> packet_bind(Loopback) end),
               simple_check("AF_PACKET recv ifindex", fun() -> packet_recv_ifindex(Loopback) end),
               port_status_check(Lo),
               simple_check("TCP open/refused", fun() -> tcp_endpoints(Lo, Route) end),
               simple_check("auto local shortcut", fun() -> auto_local(Lo, Route) end)],
    print_report(Results),
    case [Label || {Label, failed} <- Results] of
        [] ->
            io:format("~nВсе обязательные проверки пройдены.~n"),
            halt(0);
        Failed ->
            io:format("~nНепройденные проверки: ~p~n", [Failed]),
            halt(1)
    end.

%%% ------------------------------------------------------------------
%%% Проверки
%%% ------------------------------------------------------------------

%% Один raw-вид: подтверждение обязательно; ICMP timestamp может быть не
%% поддержан ядром — тогда это пропуск, а не провал.
raw_check(Label, Kind, Lo, Route) ->
    Result = trawler_discovery_probe:run_kind(Kind, Lo, Route,
                                              #{timeout_ms => 3000, retries => 1}),
    io:format("~-20ts -> ~p~n", [Label, Result]),
    Status = case {maps:get(state, Result), maps:get(method, Result, undefined)} of
                 {up, local} -> failed;
                 {up, _Method} -> ok;
                 {no_response, _} when Kind =:= icmp_timestamp -> skipped;
                 {no_response, _} -> failed;
                 {error, _} -> failed
             end,
    {Label, Status}.

simple_check(Label, Fun) ->
    Status = try Fun() of
                 ok -> ok;
                 {fail, Reason} ->
                     io:format("~-20ts -> ошибка: ~p~n", [Label, Reason]),
                     failed
             catch
                 Class:Reason:Stack ->
                     io:format("~-20ts -> исключение ~p:~p~n  ~p~n",
                               [Label, Class, Reason, Stack]),
                     failed
             end,
    case Status of
        ok -> io:format("~-20ts -> ok~n", [Label]);
        _ -> ok
    end,
    {Label, Status}.

%% ARP codec: синтетический ответ принимается, запрос имеет формат кадра.
arp_codec() ->
    OurMac = <<2, 3, 4, 5, 6, 7>>,
    PeerMac = <<16#12, 16#34, 16#56, 16#78, 16#9A, 16#BC>>,
    OurIP = {10, 0, 0, 5},
    TargetIP = {10, 0, 0, 9},
    Request = trawler_discovery_packet:arp_request(OurMac, OurIP, TargetIP),
    case byte_size(Request) of
        60 -> ok;
        Size -> throw({arp_request_size, Size})
    end,
    Frame = <<OurMac:6/binary, PeerMac:6/binary, 16#0806:16, 1:16, 16#0800:16,
              6:8, 4:8, 2:16, PeerMac:6/binary, (ip_bin(TargetIP))/binary,
              OurMac:6/binary, (ip_bin(OurIP))/binary>>,
    case trawler_discovery_packet:arp_reply(Frame, TargetIP, OurIP, OurMac) of
        {ok, PeerMac} -> ok;
        Other -> {fail, {arp_reply, Other}}
    end.

%% AF_PACKET: привязка sockaddr_ll по ifindex из ядра и протоколу ARP.
packet_bind(Loopback) ->
    Ifindex = maps:get(ifindex, Loopback),
    <<Protocol:16/native>> = <<16#0806:16/big>>,
    Addr = trawler_discovery_packet:native_packet_address(Ifindex, 16#0806, <<>>),
    case socket:open(17, raw, Protocol) of
        {ok, Socket} ->
            try socket:bind(Socket, Addr)
            after
                _ = socket:close(Socket)
            end;
        {error, Reason} ->
            {fail, {open, Reason}}
    end.

%% Реальный приём кадра на loopback: привязка AF_PACKET с ETH_P_ALL,
%% генерация loopback-трафика и проверка, что декодер OTP отдаёт
%% sockaddr с family=packet и ifindex привязанного интерфейса, который
%% разбирает trawler_discovery_probe:packet_ifindex/1.
packet_recv_ifindex(Loopback) ->
    Ifindex = maps:get(ifindex, Loopback),
    <<Protocol:16/native>> = <<3:16/big>>,          %% ETH_P_ALL
    Addr = trawler_discovery_packet:native_packet_address(Ifindex, 3, <<>>),
    case socket:open(17, raw, Protocol) of
        {ok, Socket} ->
            try
                case socket:bind(Socket, Addr) of
                    ok ->
                        Self = self(),
                        _ = spawn(fun() -> Self ! {generated, generate_loopback()} end),
                        _ = receive {generated, _} -> ok after 500 -> ok end,
                        recv_ifindex(Socket, Ifindex)
                    ;
                    {error, Reason} ->
                        {fail, {bind, Reason}}
                end
            after
                _ = socket:close(Socket)
            end;
        {error, Reason} ->
            {fail, {open, Reason}}
    end.

recv_ifindex(Socket, Ifindex) ->
    case socket:recvfrom(Socket, 0, 1500) of
        {ok, {SockAddr, _Frame}} ->
            case trawler_discovery_probe:packet_ifindex(SockAddr) of
                Ifindex -> ok;
                Other -> {fail, {ifindex, SockAddr, Other}}
            end;
        Other ->
            {fail, {recv, Other}}
    end.

generate_loopback() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(Listen),
    {ok, Conn} = gen_tcp:connect({127, 0, 0, 1}, Port, [inet, {active, false}], 500),
    _ = gen_tcp:close(Conn),
    _ = gen_tcp:close(Listen),
    ok.

%% Состояние портов 80/443 на loopback: только сообщается, чтобы не
%% сталкиваться с чужой службой. Закрытый порт тоже квалифицирован.
port_status_check(Lo) ->
    Is443 = is_listening(Lo, 443),
    Is80 = is_listening(Lo, 80),
    io:format("~-18ts -> :443 ~ts, :80 ~ts~n",
              ["порты 80/443", open_state(Is443), open_state(Is80)]),
    {"порты 80/443", ok}.

open_state(true) -> "открыт";
open_state(false) -> "закрыт".

%% TCP connect без привилегий: динамический открытый и закрытый порт.
tcp_endpoints(Lo, Route) ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {active, false}]),
    {ok, {_Addr, OpenPort}} = inet:sockname(Listen),
    OpenResult = trawler_discovery_probe:run(Lo, Route,
                                             #{method => tcp, ports => [OpenPort],
                                               timeout_ms => 2000}),
    _ = gen_tcp:close(Listen),
    ClosedPort = closed_port(),
    ClosedResult = trawler_discovery_probe:run(Lo, Route,
                                               #{method => tcp, ports => [ClosedPort],
                                                 timeout_ms => 2000}),
    io:format("  open ~p: ~p~n  closed ~p: ~p~n",
              [OpenPort, OpenResult, ClosedPort, ClosedResult]),
    case {OpenResult, ClosedResult} of
        {#{state := up, method := tcp_open, port := OpenPort},
         #{state := up, method := tcp_refused, port := ClosedPort}} ->
            ok;
        Other ->
            {fail, {tcp_endpoints, Other}}
    end.

%% auto на loopback сокращается до local: это документированный путь,
%% отличный от прямых raw-проб, которые loopback до local не сокращают.
auto_local(Lo, Route) ->
    Result = trawler_discovery_probe:run(Lo, Route,
                                         #{method => auto, timeout_ms => 1000}),
    io:format("  auto -> ~p~n", [Result]),
    case Result of
        #{state := up, method := local} -> ok;
        Other -> {fail, {auto_local, Other}}
    end.

%%% ------------------------------------------------------------------
%%% Вспомогательные функции
%%% ------------------------------------------------------------------

ebin_path() ->
    filename:join([project_root(), "_build", "default", "lib", "trawler", "ebin"]).

project_root() ->
    case os:getenv("TRAWLER_ROOT") of
        false -> script_root();
        "" -> script_root();
        Dir -> Dir
    end.

script_root() ->
    filename:absname(filename:dirname(filename:dirname(escript:script_name()))).

find_interface(Name, Interfaces) ->
    case [I || I <- Interfaces, maps:get(name, I) =:= Name] of
        [Interface | _] -> Interface;
        [] -> abort("интерфейс ~s не найден", [Name])
    end.

closed_port() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {active, false}]),
    {ok, {_Addr, Port}} = inet:sockname(Listen),
    _ = gen_tcp:close(Listen),
    Port.

is_listening(IP, Port) ->
    case gen_tcp:connect(IP, Port, [inet, {active, false}], 200) of
        {ok, Socket} -> _ = gen_tcp:close(Socket), true;
        {error, _Reason} -> false
    end.

ip_bin({A, B, C, D}) ->
    <<A, B, C, D>>.

print_report(Results) ->
    io:format("~n-- итог --~n"),
    lists:foreach(
      fun({Label, ok}) -> io:format("PASS ~ts~n", [Label]);
         ({Label, skipped}) -> io:format("SKIP ~ts (не подтверждено, не провал)~n", [Label]);
         ({Label, failed}) -> io:format("FAIL ~ts~n", [Label])
      end, Results).

abort(Format, Args) ->
    io:format(Format ++ "~n", Args),
    halt(2).
