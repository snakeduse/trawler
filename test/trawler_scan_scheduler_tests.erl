%%%-------------------------------------------------------------------
%%% @doc EUnit-тесты модулей trawler_scheduler и trawler_probe.
%%%
%%% Тесты планировщика используют процессы-ретрансляторы: каждый
%%% «скан» — отдельный процесс, который пересылает полученное
%%% разрешение `{trawler_scheduler, grant}' в тестовый процесс вместе
%%% со своим pid. Это позволяет отличать получателей разрешений.
%%% Сетевые тесты используют только loopback и локальные сокеты.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_scan_scheduler_tests).

-include_lib("eunit/include/eunit.hrl").

%%% ------------------------------------------------------------------
%%% Планировщик: ограничение параллелизма
%%% ------------------------------------------------------------------

%% Выдаётся не более Max разрешений, остальные ждут в очереди.
max_concurrency_grants_test() ->
    with_scheduler(2,
      fun() ->
              W1 = new_scan(), W2 = new_scan(), W3 = new_scan(),
              ok = trawler_scheduler:request(W1),
              ok = trawler_scheduler:request(W2),
              ok = trawler_scheduler:request(W3),
              ?assertEqual([W1, W2], lists:sort(collect_grants(2))),
              %% Третий запрос стоит в очереди, ёмкости нет.
              ?assertEqual(no_grant, expect_grant(100)),
              %% Освобождение ёмкости выдаёт разрешение третьему.
              ok = trawler_scheduler:release(),
              ?assertEqual(W3, expect_grant(1000))
      end).

%% Порядок разрешений соответствует порядку запросов (FIFO).
fifo_order_test() ->
    with_scheduler(1,
      fun() ->
              W1 = new_scan(), W2 = new_scan(), W3 = new_scan(),
              ok = trawler_scheduler:request(W1),
              ok = trawler_scheduler:request(W2),
              ok = trawler_scheduler:request(W3),
              ?assertEqual(W1, expect_grant(1000)),
              ok = trawler_scheduler:release(),
              ?assertEqual(W2, expect_grant(1000)),
              ok = trawler_scheduler:release(),
              ?assertEqual(W3, expect_grant(1000)),
              ok = trawler_scheduler:release(),
              ?assertEqual(no_grant, expect_grant(100))
      end).

%% retract убирает ожидающего из очереди и не выдаёт ему разрешение.
retract_prevents_grant_test() ->
    with_scheduler(1,
      fun() ->
              W1 = new_scan(), W2 = new_scan(),
              ok = trawler_scheduler:request(W1),
              ?assertEqual(W1, expect_grant(1000)),
              ok = trawler_scheduler:request(W2),
              ?assertEqual(no_grant, expect_grant(50)),
              %% Идемпотентность: повторный retract не мешает.
              ok = trawler_scheduler:retract(W2),
              ok = trawler_scheduler:retract(W2),
              ok = trawler_scheduler:release(),
              ?assertEqual(no_grant, expect_grant(100)),
              %% Ёмкость освобождена: новый запрос получает разрешение.
              W3 = new_scan(),
              ok = trawler_scheduler:request(W3),
              ?assertEqual(W3, expect_grant(1000)),
              ok = trawler_scheduler:release()
      end).

%% Два запроса одного процесса дают одно вхождение в очереди.
request_dedup_test() ->
    with_scheduler(1,
      fun() ->
              W0 = new_scan(), W1 = new_scan(),
              ok = trawler_scheduler:request(W0),
              ?assertEqual(W0, expect_grant(1000)),
              ok = trawler_scheduler:request(W1),
              ok = trawler_scheduler:request(W1),
              ?assertEqual(no_grant, expect_grant(50)),
              ok = trawler_scheduler:release(),
              ?assertEqual(W1, expect_grant(1000)),
              %% После освобождения всех разрешений — ни одного лишнего.
              ok = trawler_scheduler:release(),
              ?assertEqual(no_grant, expect_grant(100))
      end).

%% release при нулевом числе выданных разрешений безопасен.
release_without_in_flight_test() ->
    with_scheduler(2,
      fun() ->
              ok = trawler_scheduler:release(),
              ok = trawler_scheduler:release(),
              %% Состояние не испорчено: ёмкость по-прежнему доступна.
              W1 = new_scan(),
              ok = trawler_scheduler:request(W1),
              ?assertEqual(W1, expect_grant(1000)),
              ok = trawler_scheduler:release()
      end).

%%% ------------------------------------------------------------------
%%% Классификация исхода пробы (детерминированная)
%%% ------------------------------------------------------------------

classify_test() ->
    ?assertEqual(open, trawler_probe:classify(ok)),
    ?assertEqual(closed, trawler_probe:classify({error, econnrefused})),
    ?assertEqual(timeout, trawler_probe:classify({error, timeout})),
    ?assertEqual(unreachable, trawler_probe:classify({error, enetunreach})),
    ?assertEqual(unreachable, trawler_probe:classify({error, ehostunreach})),
    ?assertEqual(error, trawler_probe:classify({error, other})),
    ?assertEqual(error, trawler_probe:classify({error, eaddrinuse})).

%%% ------------------------------------------------------------------
%%% Проба по loopback
%%% ------------------------------------------------------------------

%% Открытый порт: состояние open, поле reason отсутствует.
run_open_port_test() ->
    {ok, ListenSocket} = gen_tcp:listen(
                           0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(ListenSocket),
    try
        Result = trawler_probe:run({127, 0, 0, 1}, Port, 1000),
        ?assertEqual(open, maps:get(state, Result)),
        ?assertEqual({127, 0, 0, 1}, maps:get(ip, Result)),
        ?assertEqual(Port, maps:get(port, Result)),
        ?assert(maps:get(elapsed_ms, Result) >= 0),
        ?assertNot(maps:is_key(reason, Result))
    after
        ok = gen_tcp:close(ListenSocket)
    end.

%% Закрытый порт: состояние closed, поле reason отсутствует.
run_closed_port_test() ->
    {ok, ListenSocket} = gen_tcp:listen(
                           0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(ListenSocket),
    ok = gen_tcp:close(ListenSocket),
    Result = trawler_probe:run({127, 0, 0, 1}, Port, 1000),
    ?assertEqual(closed, maps:get(state, Result)),
    ?assertEqual({127, 0, 0, 1}, maps:get(ip, Result)),
    ?assertEqual(Port, maps:get(port, Result)),
    ?assert(maps:get(elapsed_ms, Result) >= 0),
    ?assertNot(maps:is_key(reason, Result)).

%%% ------------------------------------------------------------------
%%% Вспомогательные функции тестов
%%% ------------------------------------------------------------------

%% Запускает планировщик с заданным лимитом и гарантированно
%% останавливает его, восстанавливая прежнее значение окружения.
with_scheduler(Max, Fun) ->
    Previous = application:get_env(trawler, max_concurrency),
    ok = application:set_env(trawler, max_concurrency, Max),
    {ok, Sched} = trawler_scheduler:start_link(),
    erase(trawler_test_scans),
    flush(),
    try
        Fun()
    after
        safe_stop(Sched),
        kill_scans(),
        flush(),
        restore_max_concurrency(Previous)
    end.

safe_stop(Sched) ->
    try
        gen_server:stop(Sched)
    catch
        exit:_ -> ok
    end.

%% Процесс-ретранслятор: получает разрешение и пересылает его в тест.
new_scan() ->
    Tester = self(),
    Scan = spawn(fun() -> scan_loop(Tester) end),
    put(trawler_test_scans, [Scan | scans()]),
    Scan.

scans() ->
    case get(trawler_test_scans) of
        undefined -> [];
        List -> List
    end.

scan_loop(Tester) ->
    receive
        {trawler_scheduler, grant} ->
            Tester ! {grant, self()},
            scan_loop(Tester);
        stop ->
            ok
    end.

kill_scans() ->
    Scans = erase(trawler_test_scans),
    case Scans of
        undefined -> ok;
        _ -> _ = [exit(Scan, kill) || Scan <- Scans], ok
    end.

collect_grants(0) ->
    [];
collect_grants(Remaining) ->
    case expect_grant(1000) of
        no_grant -> [];
        ScanPid -> [ScanPid | collect_grants(Remaining - 1)]
    end.

expect_grant(Timeout) ->
    receive
        {grant, ScanPid} -> ScanPid
    after Timeout -> no_grant
    end.

flush() ->
    receive
        _ -> flush()
    after 0 -> ok
    end.

restore_max_concurrency({ok, Value}) ->
    application:set_env(trawler, max_concurrency, Value);
restore_max_concurrency(undefined) ->
    application:unset_env(trawler, max_concurrency).
