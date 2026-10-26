%%%-------------------------------------------------------------------
%%% @doc EUnit-тесты транспортного слоя trawler_discovery_probe.
%%%
%%% Детерминированные тесты покрывают capabilities, выбор метода
%%% (prepare), нормализацию портов и планирование отправок без сети.
%%% Реальные пробы ограничены loopback: TCP connect к открытому и
%%% закрытому локальному порту. Raw-пробы на loopback не сокращаются до
%%% `local' — это проверяется отдельно; их фактическую работу выполняет
%%% opt-in runner с привилегиями, поэтому здесь допускается исход
%%% `error' (нет прав) без подмены результата.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_probe_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LO, {127, 0, 0, 1}).

%%% ------------------------------------------------------------------
%%% Вспомогательные функции
%%% ------------------------------------------------------------------

synthetic_caps(Arp, Icmp, RawTcp) ->
    #{arp => Arp, icmp => Icmp, raw_tcp => RawTcp, reason => undefined}.

lo_route() ->
    {ok, Route} = trawler_discovery_route:lookup(?LO),
    Route.

%% Открытый локальный порт: слушающий сокет остаётся живым до конца пробы.
open_port() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {active, false}]),
    {ok, {_Addr, Port}} = inet:sockname(Listen),
    {Listen, Port}.

%% Закрытый локальный порт: слушатель создан и сразу закрыт.
closed_port() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {active, false}]),
    {ok, {_Addr, Port}} = inet:sockname(Listen),
    gen_tcp:close(Listen),
    Port.

%%% ------------------------------------------------------------------
%%% capabilities
%%% ------------------------------------------------------------------

capabilities_shape_test() ->
    Caps = trawler_discovery_probe:capabilities(),
    ?assert(is_boolean(maps:get(arp, Caps))),
    ?assert(is_boolean(maps:get(icmp, Caps))),
    ?assert(is_boolean(maps:get(raw_tcp, Caps))),
    ?assert(maps:is_key(reason, Caps)).

%%% ------------------------------------------------------------------
%%% prepare
%%% ------------------------------------------------------------------

prepare_auto_uses_raw_test() ->
    ?assertEqual({ok, auto, []},
                 trawler_discovery_probe:prepare(auto, synthetic_caps(true, true, true))).

prepare_auto_falls_back_to_tcp_test() ->
    ?assertEqual({ok, tcp, [tcp_fallback]},
                 trawler_discovery_probe:prepare(auto, synthetic_caps(false, false, false))).

prepare_explicit_icmp_ok_test() ->
    ?assertEqual({ok, icmp, []},
                 trawler_discovery_probe:prepare(icmp, synthetic_caps(false, true, false))).

prepare_explicit_icmp_unavailable_test() ->
    ?assertEqual({error, {method_unavailable, icmp}},
                 trawler_discovery_probe:prepare(icmp, synthetic_caps(true, false, true))).

prepare_explicit_arp_unavailable_test() ->
    ?assertEqual({error, {method_unavailable, arp}},
                 trawler_discovery_probe:prepare(arp, synthetic_caps(false, true, true))).

prepare_explicit_raw_tcp_unavailable_test() ->
    ?assertEqual({error, {method_unavailable, raw_tcp}},
                 trawler_discovery_probe:prepare(raw_tcp, synthetic_caps(true, true, false))).

prepare_tcp_always_ok_test() ->
    ?assertEqual({ok, tcp, []},
                 trawler_discovery_probe:prepare(tcp, synthetic_caps(false, false, false))).

prepare_invalid_method_test() ->
    ?assertMatch({error, {invalid_method, _}},
                 trawler_discovery_probe:prepare(bogus, synthetic_caps(true, true, true))).

%%% ------------------------------------------------------------------
%%% normalize_ports
%%% ------------------------------------------------------------------

normalize_ports_dedup_sorted_test() ->
    ?assertEqual({ok, [80, 443]}, trawler_discovery_probe:normalize_ports([443, 80, 443])).

normalize_ports_accepts_many_test() ->
    ?assertEqual({ok, lists:seq(1, 17)},
                 trawler_discovery_probe:normalize_ports(lists:seq(17, 1, -1))),
    ?assertEqual({ok, lists:seq(1, 65535)},
                 trawler_discovery_probe:normalize_ports(
                   lists:seq(65535, 1, -1))).

normalize_ports_rejects_invalid_test() ->
    ?assertMatch({error, _}, trawler_discovery_probe:normalize_ports([0])),
    ?assertMatch({error, _}, trawler_discovery_probe:normalize_ports([65536])),
    ?assertMatch({error, _}, trawler_discovery_probe:normalize_ports([])),
    ?assertMatch({error, _}, trawler_discovery_probe:normalize_ports(not_a_list)).

%%% ------------------------------------------------------------------
%%% plan: число отправок, деление бюджета, абсолютный предел
%%% ------------------------------------------------------------------

plan_splits_budget_test() ->
    ?assertEqual([{a, 250}, {b, 250}, {c, 250}, {d, 250}],
                 trawler_discovery_probe:plan([a, b, c, d], 0, 1000, 1000)).

plan_uses_rto_when_small_test() ->
    ?assertEqual([{a, 100}, {b, 100}, {a, 100}, {b, 100}],
                 trawler_discovery_probe:plan([a, b], 1, 1000, 100)).

plan_covers_all_kinds_in_tiny_budget_test() ->
    Plan = trawler_discovery_probe:plan([a, b, c, d], 0, 30, 1000),
    ?assertEqual([a, b, c, d], [Kind || {Kind, _} <- Plan]),
    ?assertEqual(30, lists:sum([Wait || {_, Wait} <- Plan])).

plan_never_exceeds_budget_test() ->
    lists:foreach(
      fun(Budget) ->
          Plan = trawler_discovery_probe:plan([a, b, c], 2, Budget, 1000),
          ?assertEqual(9, length(Plan)),
          ?assert(lists:sum([Wait || {_, Wait} <- Plan]) =< Budget)
      end, [1, 2, 5, 17, 100, 999, 1000, 5000]).

%%% ------------------------------------------------------------------
%%% run: loopback
%%% ------------------------------------------------------------------

run_auto_local_shortcut_test() ->
    Result = trawler_discovery_probe:run(?LO, lo_route(),
                                         #{method => auto, timeout_ms => 1000}),
    ?assertEqual(?LO, maps:get(ip, Result)),
    ?assertEqual(up, maps:get(state, Result)),
    ?assertEqual(local, maps:get(method, Result)),
    ?assert(maps:get(elapsed_ms, Result) >= 0).

run_tcp_open_loopback_test() ->
    {Listen, Port} = open_port(),
    Result = trawler_discovery_probe:run(?LO, lo_route(),
                                         #{method => tcp, ports => [Port],
                                           timeout_ms => 2000}),
    gen_tcp:close(Listen),
    ?assertEqual(up, maps:get(state, Result)),
    ?assertEqual(tcp_open, maps:get(method, Result)),
    ?assertEqual(Port, maps:get(port, Result)).

run_tcp_refused_loopback_test() ->
    %% loopback-маршрут помечен local, но tcp не сокращает пробу:
    %% закрытый порт подтверждает хост ответом RST.
    Port = closed_port(),
    Result = trawler_discovery_probe:run(?LO, lo_route(),
                                         #{method => tcp, ports => [Port],
                                           timeout_ms => 2000}),
    ?assertEqual(up, maps:get(state, Result)),
    ?assertEqual(tcp_refused, maps:get(method, Result)),
    ?assertEqual(Port, maps:get(port, Result)).

run_icmp_explicit_not_local_test() ->
    Result = trawler_discovery_probe:run(?LO, lo_route(),
                                         #{method => icmp, timeout_ms => 1000}),
    ?assert(lists:member(maps:get(state, Result), [up, no_response, error])),
    ?assertNotEqual(local, maps:get(method, Result, undefined)).

run_raw_tcp_explicit_not_local_test() ->
    Result = trawler_discovery_probe:run(?LO, lo_route(),
                                         #{method => raw_tcp, timeout_ms => 1000}),
    ?assert(lists:member(maps:get(state, Result), [up, no_response, error])),
    ?assertNotEqual(local, maps:get(method, Result, undefined)).

run_arp_explicit_loopback_error_test() ->
    %% ARP на loopback (не Ethernet) не сокращается до local и не
    %% подтверждает адрес без реального ответа.
    Result = trawler_discovery_probe:run(?LO, lo_route(),
                                         #{method => arp, timeout_ms => 500}),
    ?assertEqual(?LO, maps:get(ip, Result)),
    ?assertEqual(error, maps:get(state, Result)),
    ?assertEqual({method_not_applicable, not_ethernet}, maps:get(reason, Result)).

run_ports_require_tcp_test() ->
    Result = trawler_discovery_probe:run(?LO, lo_route(),
                                         #{method => icmp, ports => [80],
                                           timeout_ms => 500}),
    ?assertEqual(error, maps:get(state, Result)),
    ?assertEqual({invalid_options, ports}, maps:get(reason, Result)).

run_invalid_ip_test() ->
    Result = trawler_discovery_probe:run({127, 0, 0}, #{},
                                         #{method => tcp, timeout_ms => 100}),
    ?assertEqual(error, maps:get(state, Result)).

%%% ------------------------------------------------------------------
%%% Регрессии: выбор видов auto и явный ARP
%%% ------------------------------------------------------------------

%% На подключённом Ethernet с MAC и доступным ARP auto использует
%% только ARP: молчание сегмента не должно запускать ICMP/TCP.
auto_onlink_ether_arp_only_test() ->
    Route = #{local => false, ethernet => true, on_link => true,
              mac => <<1, 2, 3, 4, 5, 6>>,
              source => {10, 0, 0, 5}, ifindex => 2, interface => "eth0"},
    ?assertEqual({ok, [arp]},
                 trawler_discovery_probe:candidate_kinds(
                   auto, Route, #{caps => synthetic_caps(true, true, true)})).

%% ARP остаётся единственным видом, даже если других raw-возможностей нет.
auto_onlink_arp_without_raw_test() ->
    Route = #{local => false, ethernet => true, on_link => true,
              mac => <<1, 2, 3, 4, 5, 6>>},
    ?assertEqual({ok, [arp]},
                 trawler_discovery_probe:candidate_kinds(
                   auto, Route, #{caps => synthetic_caps(true, false, false)})).

%% Маршрут через шлюз (on_link = false) не получает ARP в auto.
auto_gateway_excludes_arp_test() ->
    Route = #{local => false, ethernet => true, on_link => false,
              mac => <<1, 2, 3, 4, 5, 6>>},
    ?assertEqual({ok, [icmp_echo, icmp_timestamp, tcp_syn, tcp_ack]},
                 trawler_discovery_probe:candidate_kinds(
                   auto, Route, #{caps => synthetic_caps(true, true, true)})).

%% Собственный адрес подтверждается как local независимо от caps.
auto_local_prefers_local_test() ->
    Route = #{local => true, ethernet => true, on_link => true, mac => <<>>},
    ?assertEqual({ok, [local]},
                 trawler_discovery_probe:candidate_kinds(
                   auto, Route, #{caps => synthetic_caps(true, true, true)})).

%% Переданная карта caps используется как есть: auto не пересчитывает
%% capabilities/0 заново (иначе выбор зависел бы от реальных прав, а не
%% от указанной карты).
lazy_caps_icmp_test() ->
    Route = #{local => false, ethernet => false, on_link => false},
    ?assertEqual({ok, [icmp_echo, icmp_timestamp]},
                 trawler_discovery_probe:candidate_kinds(
                   auto, Route, #{caps => synthetic_caps(false, true, false)})).

lazy_caps_tcp_test() ->
    Route = #{local => false, ethernet => false, on_link => false},
    ?assertEqual({ok, [tcp]},
                 trawler_discovery_probe:candidate_kinds(
                   auto, Route, #{caps => synthetic_caps(false, false, false)})).

%% При наличии опции caps функция capabilities/0 не вызывается вовсе
%% (иначе значение по умолчанию вычислялось бы на каждый адрес). Здесь
%% это проверяется трассировкой вызовов без учёта прав и не подменяет
%% поведение продакшена.
lazy_caps_not_recomputed_test() ->
    Self = self(),
    _ = dbg:tracer(process,
                   {fun(_Msg, Pid) -> Pid ! capability_called, Pid end, Self}),
    try
        _ = dbg:p(self(), [call]),
        _ = dbg:tpl(trawler_discovery_probe, capabilities, 0, []),
        Route = #{local => false, ethernet => false, on_link => false},
        Caps = synthetic_caps(false, true, false),
        ?assertEqual({ok, [icmp_echo, icmp_timestamp]},
                     trawler_discovery_probe:candidate_kinds(
                       auto, Route, #{caps => Caps})),
        %% Доставка трассировки асинхронная: ограниченно ждём сигнал.
        ?assertEqual(timeout, await_capability_call(200)),
        %% Без опции caps функция действительно вызывается.
        _ = trawler_discovery_probe:candidate_kinds(auto, Route, #{}),
        ?assertEqual(ok, await_capability_call(1000))
    after
        _ = dbg:ctpl(trawler_discovery_probe, capabilities, 0),
        _ = dbg:stop()
    end.

await_capability_call(Timeout) ->
    receive
        capability_called -> ok
    after Timeout -> timeout
    end.

%% Явный ARP для маршрута через шлюз — ошибка, а не отправка ARP.
arp_gateway_rejected_test() ->
    Route = #{ethernet => true, on_link => false, mac => <<1, 2, 3, 4, 5, 6>>},
    ?assertEqual({error, {method_not_applicable, not_on_link}},
                 trawler_discovery_probe:candidate_kinds(arp, Route, #{})).

arp_ethernet_required_test() ->
    Route = #{ethernet => false, on_link => false},
    ?assertEqual({error, {method_not_applicable, not_ethernet}},
                 trawler_discovery_probe:candidate_kinds(arp, Route, #{})).

%%% ------------------------------------------------------------------
%%% Регрессии: номера отправок (правило Карна) и RTT
%%% ------------------------------------------------------------------

schedule_send_numbers_test() ->
    ?assertEqual([{a, 250, 1}, {b, 250, 1}, {c, 250, 1}, {d, 250, 1}],
                 trawler_discovery_probe:schedule([a, b, c, d], 0, 1000, 1000)),
    ?assertEqual([{a, 100, 1}, {b, 100, 1}, {a, 100, 2}, {b, 100, 2}],
                 trawler_discovery_probe:schedule([a, b], 1, 1000, 100)).

%% RTT сохраняется только для первой отправки вида.
confirmation_extra_karn_test() ->
    ?assertEqual(#{port => 80, rtt_ms => 5},
                 trawler_discovery_probe:confirmation_extra(
                   #{port => 80, rtt_ms => 5}, 1)),
    ?assertEqual(#{port => 80},
                 trawler_discovery_probe:confirmation_extra(
                   #{port => 80, rtt_ms => 5}, 2)),
    ?assertEqual(#{mac => <<1, 2, 3, 4, 5, 6>>, rtt_ms => 0},
                 trawler_discovery_probe:confirmation_extra(
                   #{mac => <<1, 2, 3, 4, 5, 6>>, rtt_ms => 0}, 1)).

run_tcp_open_includes_rtt_test() ->
    {Listen, Port} = open_port(),
    Result = trawler_discovery_probe:run(?LO, lo_route(),
                                         #{method => tcp, ports => [Port],
                                           retries => 0, timeout_ms => 2000}),
    gen_tcp:close(Listen),
    ?assertEqual(up, maps:get(state, Result)),
    ?assertEqual(tcp_open, maps:get(method, Result)),
    ?assert(is_integer(maps:get(rtt_ms, Result))),
    ?assert(maps:get(rtt_ms, Result) >= 0).

%% Суммарное ожидание tcp-пробы не умножается на число портов: один
%% абсолютный срок делится между оставшимися портами.
tcp_connect_budget_deadline_test() ->
    Saturated = [saturated_port() || _ <- lists:seq(1, 4)],
    Ports = [Port || {_Listen, _Holder, Port} <- Saturated],
    try
        Result = trawler_discovery_probe:run(
                   ?LO, lo_route(),
                   #{method => tcp, ports => Ports, retries => 0,
                     timeout_ms => 400}),
        ?assertEqual(no_response, maps:get(state, Result)),
        %% Один бюджет 400 мс, а не 4 x 400.
        ?assert(maps:get(elapsed_ms, Result) < 900)
    after
        [begin
             _ = gen_tcp:close(Listen),
             _ = gen_tcp:close(Holder)
         end || {Listen, Holder, _Port} <- Saturated]
    end.

%%% ------------------------------------------------------------------
%%% Регрессии: разбор sockaddr_ll
%%% ------------------------------------------------------------------

%% Декодер OTP отдаёт `family => packet, ifindex => N'; числовая
%% native-форма принимается как запасная.
packet_ifindex_forms_test() ->
    ?assertEqual(7, trawler_discovery_probe:packet_ifindex(
                      #{family => packet, ifindex => 7,
                        hatype => loopback, pkttype => host,
                        addr => <<1, 2, 3, 4, 5, 6>>})),
    Native = #{family => 17,
               addr => <<0, 3, 7, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>},
    ?assertEqual(7, trawler_discovery_probe:packet_ifindex(Native)),
    ?assertEqual(undefined, trawler_discovery_probe:packet_ifindex(#{family => inet})),
    ?assertEqual(undefined, trawler_discovery_probe:packet_ifindex({127, 0, 0, 1})).

%%% ------------------------------------------------------------------
%%% Вспомогательные функции (регрессионные тесты)
%%% ------------------------------------------------------------------

%% Слушатель с заполненной очередью приёма: первый connect проходит,
%% последующие блокируются до таймаута. Детерминированный «медленный»
%% tcp-адресат на loopback без внешних хостов.
saturated_port() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {ip, {127, 0, 0, 1}},
                                      {active, false}, {backlog, 0}]),
    {ok, Port} = inet:port(Listen),
    {ok, Holder} = gen_tcp:connect({127, 0, 0, 1}, Port,
                                   [inet, {active, false}], 500),
    {Listen, Holder, Port}.
