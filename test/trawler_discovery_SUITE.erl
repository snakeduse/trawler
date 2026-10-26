%%%-------------------------------------------------------------------
%%% @doc Common Test сетевой интеграции обнаружения на loopback.
%%%
%%% Публичное API проверяется на реальных локальных сокетах: открытый и
%%% закрытый порт, эквивалентность синхронного и асинхронного режимов и
%%% совместная ёмкость планировщика со scan. Жизненный цикл (отмена,
%%% deadline, падение воркера, выход владельца) покрыт EUnit-модулем
%%% trawler_discovery_tests. «Медленный» адресат — слушатель с
%%% заполненной очередью приёма.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_SUITE).

-export([all/0, init_per_suite/1, end_per_suite/1,
         loopback_open_sync/1, loopback_refused_sync/1,
         sync_async_equivalent/1, shared_capacity_with_scan/1,
         inspection_fields_sync/1, inspection_sync_async_equivalent/1,
         auto_ports_closed_up/1]).

-define(LO, <<"127.0.0.1">>).

all() ->
    [loopback_open_sync, loopback_refused_sync, sync_async_equivalent,
     shared_capacity_with_scan, inspection_fields_sync,
     inspection_sync_async_equivalent, auto_ports_closed_up].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(trawler),
    Config.

end_per_suite(_Config) ->
    _ = application:stop(trawler),
    ok.

%%% ------------------------------------------------------------------
%%% Публичное API на loopback
%%% ------------------------------------------------------------------

loopback_open_sync(_Config) ->
    {Socket, Port} = open_listener(),
    try
        {ok, [Result], Summary} =
            trawler:discover(?LO, #{method => tcp, ports => [Port],
                                    retries => 0}),
        {127, 0, 0, 1} = maps:get(ip, Result),
        up = maps:get(state, Result),
        tcp_open = maps:get(method, Result),
        Port = maps:get(port, Result),
        true = is_integer(maps:get(rtt_ms, Result)),
        #{total := 1, completed := 1} = Summary,
        #{up := 1} = maps:with([up], maps:get(counters, Summary))
    after
        ok = gen_tcp:close(Socket)
    end,
    ok.

loopback_refused_sync(_Config) ->
    Port = closed_port(),
    {ok, [Result], _Summary} =
        trawler:discover(?LO, #{method => tcp, ports => [Port], retries => 0}),
    up = maps:get(state, Result),
    tcp_refused = maps:get(method, Result),
    Port = maps:get(port, Result),
    ok.

sync_async_equivalent(_Config) ->
    {Socket, Open} = open_listener(),
    Closed = closed_port(),
    Opts = #{method => tcp, ports => [Open, Closed], retries => 0},
    try
        {ok, SyncResults, _Summary} = trawler:discover(?LO, Opts),
        {ok, Ref} = trawler:start_discovery(?LO, Opts#{recipient => self()}),
        {AsyncResults, _AsyncSummary} = receive_until_done(Ref, 5000, []),
        Keys = [ip, state, method, port],
        SyncKeyed = [maps:with(Keys, R) || R <- SyncResults],
        AsyncKeyed = [maps:with(Keys, R) || R <- AsyncResults],
        SyncKeyed = AsyncKeyed
    after
        ok = gen_tcp:close(Socket)
    end,
    ok.

%% Совокупная нагрузка scan и discover не превышает глобальный лимит и
%% полностью освобождается к концу обоих заданий.
shared_capacity_with_scan(_Config) ->
    Max = max_concurrency(),
    {Listen, Holder, Port} = slow_target(),
    Owner = self(),
    TagScan = make_ref(),
    TagDisc = make_ref(),
    try
        _ = spawn(fun() ->
            Result = trawler:scan(<<"127.0.0.1">>, <<"1-4000">>,
                                  #{concurrency => 4}),
            Owner ! {TagScan, Result}
        end),
        _ = spawn(fun() ->
            Result = trawler:discover(?LO, #{method => tcp, ports => [Port],
                                             timeout_ms => 3000,
                                             concurrency => 2}),
            Owner ! {TagDisc, Result}
        end),
        Peak = sample_peak(0, now_ms() + 200),
        true = Peak =< Max,
        receive {TagScan, _} -> ok
        after 20000 -> ct:fail(scan_no_result)
        end,
        receive {TagDisc, _} -> ok
        after 20000 -> ct:fail(disc_no_result)
        end,
        0 = await_in_flight(0, 3000)
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder)
    end,
    ok.

%% Публичное API: явные порты и os_detection дают сортированные
%% port_results, только явные open_ports и карту os с безопасными
%% основаниями; ОС-порты в открытые выбранные порты не попадают.
inspection_fields_sync(_Config) ->
    {BannerPid, Open} = banner_listener(),
    Closed = closed_port(),
    try
        {ok, [Result], Summary} =
            trawler:discover(?LO, #{method => tcp,
                                    ports => [Open, Closed],
                                    os_detection => true,
                                    retries => 0,
                                    timeout_ms => 3000}),
        up = maps:get(state, Result),
        true = lists:member(maps:get(method, Result), [tcp_open, tcp_refused]),
        Rows = maps:get(port_results, Result),
        PortsSorted = lists:sort([Open, Closed]),
        PortsSorted = [maps:get(port, Row) || Row <- Rows],
        open = maps:get(state, row(Open, Rows)),
        closed = maps:get(state, row(Closed, Rows)),
        [Open] = maps:get(open_ports, Result),
        Os = maps:get(os, Result),
        linux = maps:get(family, Os),
        medium = maps:get(confidence, Os),
        true = is_list(maps:get(evidence, Os)),
        false = maps:is_key(inspection_error, Result),
        #{total := 1, completed := 1} = Summary,
        #{up := 1} = maps:with([up], maps:get(counters, Summary))
    after
        exit(BannerPid, kill)
    end,
    ok.

%% Публичное API: sync и async эквивалентны по дополнительным полям без
%% учёта длительностей.
inspection_sync_async_equivalent(_Config) ->
    {BannerPid, Open} = banner_listener(),
    Closed = closed_port(),
    Opts = #{method => tcp, ports => [Open, Closed], os_detection => true,
             retries => 0, timeout_ms => 3000},
    try
        {ok, [Sync], _SyncSummary} = trawler:discover(?LO, Opts),
        {ok, Ref} = trawler:start_discovery(?LO, Opts#{recipient => self()}),
        {[Async], _AsyncSummary} = receive_until_done(Ref, 5000, []),
        up = maps:get(state, Sync),
        up = maps:get(state, Async),
        SyncRows = strip_elapsed(maps:get(port_results, Sync)),
        AsyncRows = strip_elapsed(maps:get(port_results, Async)),
        SyncRows = AsyncRows,
        SyncOpen = maps:get(open_ports, Sync),
        SyncOpen = maps:get(open_ports, Async),
        SyncOs = maps:get(os, Sync),
        SyncOs = maps:get(os, Async)
    after
        exit(BannerPid, kill)
    end,
    ok.

%% auto на loopback подтверждается как local, а закрытые явные порты не
%% фильтруют находку.
auto_ports_closed_up(_Config) ->
    Closed = closed_port(),
    {ok, [Result], _Summary} =
        trawler:discover(?LO, #{method => auto, ports => [Closed],
                               retries => 0}),
    up = maps:get(state, Result),
    local = maps:get(method, Result),
    [#{port := Closed, state := closed}] = maps:get(port_results, Result),
    [] = maps:get(open_ports, Result),
    ok.

%%% ------------------------------------------------------------------
%%% Вспомогательные функции
%%% ------------------------------------------------------------------

open_listener() ->
    {ok, Socket} = gen_tcp:listen(
                     0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(Socket),
    {Socket, Port}.

closed_port() ->
    {ok, Socket} = gen_tcp:listen(
                     0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(Socket),
    ok = gen_tcp:close(Socket),
    Port.

%% Слушатель с корректной SSH identification: каждый connect получает
%% Ubuntu-баннер, поэтому классификация детерминирована и не зависит от
%% реального sshd на 127.0.0.1:22.
banner_listener() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {ip, {127, 0, 0, 1}},
                                      {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Listen),
    Pid = spawn(fun() -> banner_accept_loop(Listen) end),
    {Pid, Port}.

banner_accept_loop(Listen) ->
    case gen_tcp:accept(Listen) of
        {ok, Socket} ->
            _ = gen_tcp:send(Socket,
                             <<"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n">>),
            _ = gen_tcp:close(Socket),
            banner_accept_loop(Listen);
        {error, _Reason} ->
            _ = gen_tcp:close(Listen),
            ok
    end.

strip_elapsed(Rows) ->
    [maps:remove(elapsed_ms, Row) || Row <- Rows].

row(Port, Rows) ->
    hd([Row || #{port := P} = Row <- Rows, P =:= Port]).

%% Слушатель с заполненной очередью приёма: connect к нему блокируется
%% до таймаута, поэтому воркер остаётся активным детерминированно.
slow_target() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {ip, {127, 0, 0, 1}},
                                      {active, false}, {backlog, 0}]),
    {ok, Port} = inet:port(Listen),
    {ok, Holder} = gen_tcp:connect({127, 0, 0, 1}, Port,
                                   [inet, {active, false}], 500),
    {Listen, Holder, Port}.

receive_until_done(Ref, Timeout, Acc) ->
    receive
        {trawler_discovery, Ref, {result, Result}} ->
            receive_until_done(Ref, Timeout, [Result | Acc]);
        {trawler_discovery, Ref, {warning, _}} ->
            receive_until_done(Ref, Timeout, Acc);
        {trawler_discovery, Ref, {done, Summary}} ->
            {lists:reverse(Acc), Summary}
    after Timeout ->
        ct:fail(no_done_event)
    end.

in_flight() ->
    maps:get(in_flight, sys:get_state(trawler_scheduler)).

await_in_flight(Expected, Timeout) ->
    await_in_flight_loop(Expected, now_ms() + Timeout).

await_in_flight_loop(Expected, Deadline) ->
    case in_flight() of
        Expected -> Expected;
        _Other ->
            case now_ms() > Deadline of
                true -> ct:fail({in_flight_stuck, in_flight()});
                false -> timer:sleep(10),
                         await_in_flight_loop(Expected, Deadline)
            end
    end.

%% Наблюдаемый максимум in_flight при опросе до дедлайна.
sample_peak(Peak, Deadline) ->
    N = in_flight(),
    case now_ms() > Deadline of
        true -> max(Peak, N);
        false -> timer:sleep(5), sample_peak(max(Peak, N), Deadline)
    end.

max_concurrency() ->
    case application:get_env(trawler, max_concurrency, 256) of
        Limit when is_integer(Limit), Limit >= 1 -> Limit;
        _ -> 256
    end.

now_ms() ->
    erlang:monotonic_time(millisecond).
