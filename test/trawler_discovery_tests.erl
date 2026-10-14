%%%-------------------------------------------------------------------
%%% @doc EUnit-тесты публичного API обнаружения и жизненного цикла.
%%%
%%% Детерминированные проверки неверного входа (до сети), сортировки,
%%% событий и предупреждений, сохранности чужого ящика, отмены, deadline,
%%% выхода владельца/получателя, падения воркера и остановки приложения.
%%% Сеть ограничена loopback: открытый/закрытый локальный порт и
%%% «медленный» адресат — слушатель с заполненной очередью приёма.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LO, <<"127.0.0.1">>).

discovery_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
         [?_test(validation_no_network()),
          ?_test(not_started()),
          ?_test(status_cancel_unknown()),
          ?_test(sync_results_sorted()),
          ?_test(sync_preserves_foreign_messages()),
          ?_test(async_terminal_once_with_warnings()),
          ?_test(one_result_per_ip()),
          ?_test(cancel_queued_saturated()),
          ?_test(deadline_queued_saturated()),
          ?_test(worker_crash()),
          ?_test(recipient_down()),
          ?_test(owner_down()),
          ?_test(app_stop_cleanup()),
          ?_test(ports_only_tcp()),
          ?_test(cancel_status_kept_after_recipient_exit()),
          ?_test(cancel_status_kept_after_owner_exit()),
          ?_test(stale_worker_exit_ignored()),
          ?_test(cancel_running_releases_before_event()),
          ?_test(deadline_running_releases_before_event()),
          ?_test(route_lookup_honours_timeout()),
          ?_test(address_budget_bounded())]
     end}.

setup() ->
    {ok, _} = application:ensure_all_started(trawler),
    ok.

cleanup(_) ->
    _ = application:stop(trawler),
    ok.

%%% ------------------------------------------------------------------
%%% Проверка входа до сети (задача 3.1)
%%% ------------------------------------------------------------------

validation_no_network() ->
    PortsBefore = length(erlang:ports()),
    ?assertEqual(0, in_flight()),
    ?assertEqual({error, {invalid_options, {method, bogus}}},
                 trawler:discover(?LO, #{method => bogus})),
    ?assertEqual({error, {invalid_options, {unknown_option, foo}}},
                 trawler:discover(?LO, #{foo => 1})),
    ?assertEqual({error, {invalid_options, recipient}},
                 trawler:start_discovery(?LO, #{recipient => not_a_pid})),
    ?assertEqual({error, {invalid_options, {retries, 9}}},
                 trawler:discover(?LO, #{retries => 9})),
    ?assertEqual({error, {invalid_options, {concurrency, 0}}},
                 trawler:discover(?LO, #{concurrency => 0})),
    ?assertEqual({error, {invalid_options, {timeout_ms, 0}}},
                 trawler:discover(?LO, #{timeout_ms => 0})),
    ?assertEqual({error, {invalid_options, {deadline_ms, 0}}},
                 trawler:discover(?LO, #{deadline_ms => 0})),
    ?assertEqual({error, {invalid_options, ports}},
                 trawler:discover(?LO, #{method => arp, ports => [80]})),
    ?assertEqual({error, {invalid_options, {too_many_ports, 17}}},
                 trawler:discover(?LO, #{method => tcp,
                                         ports => lists:seq(1, 17)})),
    ?assertMatch({error, {invalid_targets, _}}, trawler:discover(<<>>, #{})),
    ?assertMatch({error, {invalid_ports, _}},
                 trawler:discover(?LO, #{method => tcp, ports => <<"0">>})),
    %% Ни одного сокета и ни одного разрешения планировщика.
    ?assertEqual(PortsBefore, length(erlang:ports())),
    ?assertEqual(0, in_flight()).

not_started() ->
    ok = application:stop(trawler),
    try
        ?assertEqual({error, not_started},
                     trawler:start_discovery(?LO, #{})),
        ?assertEqual({error, not_started}, trawler:discover(?LO, #{}))
    after
        {ok, _} = application:ensure_all_started(trawler)
    end.

status_cancel_unknown() ->
    Ref = make_ref(),
    ?assertEqual({error, not_found}, trawler:discovery_status(Ref)),
    ?assertEqual({error, not_found}, trawler:cancel_discovery(Ref)).

%%% ------------------------------------------------------------------
%%% Синхронный сбор (задача 3.1)
%%% ------------------------------------------------------------------

sync_results_sorted() ->
    {Socket, Open} = open_listener(),
    Closed = closed_port(),
    try
        {ok, Results, Summary} =
            trawler:discover(<<"127.0.0.1-3">>,
                             #{method => tcp, ports => [Open, Closed],
                               retries => 0}),
        3 = length(Results),
        Ips = [maps:get(ip, R) || R <- Results],
        [{127, 0, 0, 1}, {127, 0, 0, 2}, {127, 0, 0, 3}] = Ips,
        #{total := 3, completed := 3} = Summary,
        #{up := 3} = maps:with([up], maps:get(counters, Summary))
    after
        gen_tcp:close(Socket)
    end.

sync_preserves_foreign_messages() ->
    {Socket, Port} = open_listener(),
    try
        self() ! {foreign, marker},
        {ok, [_], _Summary} =
            trawler:discover(?LO, #{method => tcp, ports => [Port],
                                    retries => 0}),
        receive
            {foreign, marker} -> ok
        after 1000 ->
            ?assert(false)
        end
    after
        gen_tcp:close(Socket)
    end.

%%% ------------------------------------------------------------------
%%% Асинхронные события и предупреждения (задача 3.1)
%%% ------------------------------------------------------------------

async_terminal_once_with_warnings() ->
    Caps = trawler_discovery_probe:capabilities(),
    {ok, Ref} = trawler:start_discovery(?LO, #{method => auto,
                                               recipient => self()}),
    {_Results, SummaryWarnings, Warnings} =
        receive_until_done_warnings(Ref, 5000, [], []),
    RawAvailable = maps:get(icmp, Caps) andalso maps:get(raw_tcp, Caps),
    case RawAvailable of
        true -> ?assertEqual([], SummaryWarnings);
        false -> ?assertEqual([tcp_fallback], SummaryWarnings)
    end,
    ?assertEqual(SummaryWarnings, Warnings),
    %% После завершения событий больше нет.
    ensure_no_more(Ref, 300).

one_result_per_ip() ->
    Closed = closed_port(),
    {ok, Results, _Summary} =
        trawler:discover(<<"127.0.0.1-2">>,
                         #{method => tcp, ports => [Closed], retries => 0}),
    2 = length(Results),
    2 = length(lists:usort([maps:get(ip, R) || R <- Results])).

%%% ------------------------------------------------------------------
%%% Отмена и deadline (задача 3.2)
%%% ------------------------------------------------------------------

cancel_queued_saturated() ->
    Max = saturate_scheduler(),
    try
        {ok, Ref} = trawler:start_discovery(<<"127.0.0.1-4">>,
                                            #{method => tcp,
                                              concurrency => 1,
                                              recipient => self()}),
        ?assertEqual(ok, trawler:cancel_discovery(Ref)),
        ?assertEqual(ok, trawler:cancel_discovery(Ref)),
        Summary = receive_cancelled(Ref, 5000),
        #{total := 4, completed := 0} = Summary,
        {ok, Status} = trawler:discovery_status(Ref),
        ?assertEqual(cancelled, maps:get(state, Status)),
        %% Отмена уже отменённого идемпотентна.
        ?assertEqual(ok, trawler:cancel_discovery(Ref))
    after
        release_grants(Max)
    end.

deadline_queued_saturated() ->
    Max = saturate_scheduler(),
    try
        {ok, Ref} = trawler:start_discovery(<<"127.0.0.1-4">>,
                                            #{method => tcp,
                                              concurrency => 1,
                                              deadline_ms => 100,
                                              recipient => self()}),
        Summary = receive_error(Ref, deadline_exceeded, 5000),
        #{total := 4, completed := 0} = Summary,
        {ok, Status} = trawler:discovery_status(Ref),
        ?assertEqual(failed, maps:get(state, Status))
    after
        release_grants(Max)
    end.

%%% ------------------------------------------------------------------
%%% Падение воркера, выход владельца/получателя, остановка (задача 3.2)
%%% ------------------------------------------------------------------

worker_crash() ->
    {Listen, Holder, Port} = slow_target(),
    try
        {ok, Ref} = trawler:start_discovery(?LO,
                                            #{method => tcp, ports => [Port],
                                              timeout_ms => 5000,
                                              retries => 0,
                                              concurrency => 1,
                                              recipient => self()}),
        Worker = await_worker(coordinator(Ref), 2000),
        exit(Worker, kill),
        {Results, Summary} = receive_until_done(Ref, 5000, []),
        ?assertMatch([#{ip := {127, 0, 0, 1}, state := error,
                        reason := worker_failed}], Results),
        #{counters := #{error := 1}} = Summary,
        0 = await_in_flight(0, 2000)
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder)
    end.

recipient_down() ->
    {Listen, Holder, Port} = slow_target(),
    Recipient = spawn(fun() -> receive stop -> ok end end),
    try
        {ok, Ref} = trawler:start_discovery(?LO,
                                            #{method => tcp, ports => [Port],
                                              timeout_ms => 4000,
                                              recipient => Recipient}),
        exit(Recipient, kill),
        ok = wait_not_found(Ref, 3000),
        0 = await_in_flight(0, 2000)
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder)
    end.

owner_down() ->
    Test = self(),
    {Listen, Holder, Port} = slow_target(),
    Owner = spawn(fun() ->
        {ok, Ref} = trawler:start_discovery(
                      ?LO, #{method => tcp, ports => [Port],
                             timeout_ms => 4000, recipient => Test}),
        Test ! {ref, Ref},
        receive stop -> ok end
    end),
    try
        Ref = receive {ref, R} -> R after 2000 -> ?assert(false) end,
        _ = await_worker(coordinator(Ref), 2000),
        exit(Owner, kill),
        ok = wait_not_found(Ref, 3000),
        0 = await_in_flight(0, 2000)
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder)
    end.

app_stop_cleanup() ->
    {Listen, Holder, Port} = slow_target(),
    try
        {ok, Ref} = trawler:start_discovery(?LO,
                                            #{method => tcp, ports => [Port],
                                              timeout_ms => 5000,
                                              recipient => self()}),
        Coord = coordinator(Ref),
        Worker = await_worker(Coord, 2000),
        ok = application:stop(trawler),
        ?assertEqual(undefined, whereis(trawler_sup)),
        ?assertNot(is_process_alive(Coord)),
        %% Остановка приложения убивает и воркер, а не только координатор.
        ?assertNot(is_process_alive(Worker))
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder),
        {ok, _} = application:ensure_all_started(trawler)
    end.

%%% ------------------------------------------------------------------
%%% Регрессии портов, жизненного цикла и бюджета адреса
%%% ------------------------------------------------------------------

%% Порты допустимы только для явного TCP connect. `auto' с ключом ports
%% отклоняется, чтобы намерение не терялось; атом default передаётся
%% существующему parser'у и отклоняется как too_many_ports (1000), а не
%% молча подменяется набором 80/443.
ports_only_tcp() ->
    ?assertEqual({error, {invalid_options, ports}},
                 trawler:discover(?LO, #{ports => [80]})),
    ?assertEqual({error, {invalid_options, ports}},
                 trawler:discover(?LO, #{method => auto, ports => [80]})),
    ?assertEqual({error, {invalid_options, ports}},
                 trawler:discover(?LO, #{method => icmp, ports => [80]})),
    ?assertEqual({error, {invalid_options, {too_many_ports, 1000}}},
                 trawler:discover(?LO, #{method => tcp, ports => default})),
    %% Валидный tcp остаётся валидным.
    ?assertMatch({error, _},
                 trawler:discover(?LO, #{method => tcp, ports => <<"0">>})).

%% После отмены сохранённый статус не теряется при выходе получателя в
%% течение обещанного срока хранения (60 с): мониторы жизненного цикла
%% снимаются на терминальном переходе.
cancel_status_kept_after_recipient_exit() ->
    Max = saturate_scheduler(),
    try
        Recipient = spawn(fun() -> receive stop -> ok end end),
        {ok, Ref} = trawler:start_discovery(<<"127.0.0.1-4">>,
                                            #{method => tcp,
                                              concurrency => 1,
                                              recipient => Recipient}),
        ?assertEqual(ok, trawler:cancel_discovery(Ref)),
        require_cancelled_status(Ref),
        exit(Recipient, kill),
        timer:sleep(300),
        require_cancelled_status(Ref)
    after
        release_grants(Max)
    end.

%% То же при выходе владельца: после отмены выход владельца не стирает
%% сохранённый cancelled-статус.
cancel_status_kept_after_owner_exit() ->
    Max = saturate_scheduler(),
    Test = self(),
    Owner = spawn(fun() ->
        {ok, Ref} = trawler:start_discovery(<<"127.0.0.1-4">>,
                                            #{method => tcp,
                                              concurrency => 1,
                                              recipient => Test}),
        Test ! {ref, Ref},
        receive stop -> ok end
    end),
    try
        Ref = receive {ref, R} -> R after 3000 -> error(no_ref) end,
        ?assertEqual(ok, trawler:cancel_discovery(Ref)),
        require_cancelled_status(Ref),
        exit(Owner, kill),
        timer:sleep(300),
        require_cancelled_status(Ref)
    after
        release_grants(Max)
    end.

%% Поздний EXIT уже завершённого воркера (после DOWN) не должен
%% останавливать координатор, пока трудится другой адрес. Инъекция без
%% production-переключателей: завершённый pid берётся из links.
stale_worker_exit_ignored() ->
    {L1, L2, H1, H2, Port} = slow_pair(),
    try
        {ok, Ref} = trawler:start_discovery(<<"127.0.0.1-2">>,
                                            #{method => tcp, ports => [Port],
                                              timeout_ms => 1500,
                                              retries => 0,
                                              concurrency => 1,
                                              recipient => self()}),
        Coord = coordinator(Ref),
        First = await_worker(Coord, 2000),
        Result1 = receive_result(Ref, 5000),
        ?assertEqual(no_response, maps:get(state, Result1)),
        ?assertNot(is_process_alive(First)),
        %% Поздний EXIT завершённого воркера, пока второй адрес ещё в работе.
        Coord ! {'EXIT', First, normal},
        Result2 = receive_result(Ref, 5000),
        ?assertEqual(no_response, maps:get(state, Result2)),
        Summary = receive_done(Ref, 5000),
        ?assertEqual(2, maps:get(completed, Summary)),
        ?assert(is_process_alive(Coord))
    after
        gen_tcp:close(L1),
        gen_tcp:close(L2),
        gen_tcp:close(H1),
        gen_tcp:close(H2)
    end.

%% Отмена работающего адреса: до чтения завершающего события воркер уже
%% мёртв, слот планировщика свободен, событий после отмены нет, а
%% повторная отмена идемпотентна.
cancel_running_releases_before_event() ->
    {Listen, Holder, Port} = slow_target(),
    try
        {ok, Ref} = trawler:start_discovery(?LO,
                                            #{method => tcp, ports => [Port],
                                              timeout_ms => 5000,
                                              retries => 0,
                                              recipient => self()}),
        Coord = coordinator(Ref),
        Worker = await_worker(Coord, 2000),
        ?assertEqual(ok, trawler:cancel_discovery(Ref)),
        %% Синхронная очистка уже выполнена, событие ещё не прочитано.
        ?assertNot(is_process_alive(Worker)),
        ?assertEqual(0, in_flight()),
        Summary = receive_cancelled(Ref, 5000),
        ?assertEqual(0, maps:get(completed, Summary)),
        ?assertEqual(ok, trawler:cancel_discovery(Ref)),
        ensure_no_more(Ref, 300)
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder)
    end.

%% Истечение deadline во время работы адреса: воркер мёртв и ёмкость
%% освобождена, после завершающего события решений нет.
deadline_running_releases_before_event() ->
    {Listen, Holder, Port} = slow_target(),
    try
        {ok, Ref} = trawler:start_discovery(?LO,
                                            #{method => tcp, ports => [Port],
                                              timeout_ms => 5000,
                                              deadline_ms => 300,
                                              retries => 0,
                                              recipient => self()}),
        Coord = coordinator(Ref),
        Worker = await_worker(Coord, 2000),
        Summary = receive_error(Ref, deadline_exceeded, 5000),
        ?assertEqual(0, maps:get(completed, Summary)),
        ?assertNot(is_process_alive(Worker)),
        ?assertEqual(0, in_flight()),
        {ok, Status} = trawler:discovery_status(Ref),
        ?assertEqual(failed, maps:get(state, Status)),
        ensure_no_more(Ref, 200)
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder)
    end.

%% lookup/2 ограничивает ожидание ядра переданным сроком, не растягивая
%% адресный бюджет: нулевой срок возвращает timeout немедленно.
route_lookup_honours_timeout() ->
    Start = now_ms(),
    ?assertEqual({error, timeout},
                 trawler_discovery_route:lookup({127, 0, 0, 1}, 0)),
    ?assert(now_ms() - Start < 1000).

%% Бюджет адреса конечен: медленный адресат даёт no_response, а общее
%% время адреса не выходит далеко за настроенный timeout (маршрут входит
%% в бюджет, а не добавляется к нему).
address_budget_bounded() ->
    {Listen, Holder, Port} = slow_target(),
    try
        Start = now_ms(),
        {ok, [Result], Summary} =
            trawler:discover(?LO, #{method => tcp, ports => [Port],
                                    timeout_ms => 200, retries => 0}),
        Wall = now_ms() - Start,
        ?assertEqual(no_response, maps:get(state, Result)),
        ?assert(maps:get(elapsed_ms, Result) =< 1500),
        ?assert(Wall < 2000),
        ?assertEqual(1, maps:get(completed, Summary))
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder)
    end.

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

slow_target() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {ip, {127, 0, 0, 1}},
                                      {active, false}, {backlog, 0}]),
    {ok, Port} = inet:port(Listen),
    {ok, Holder} = gen_tcp:connect({127, 0, 0, 1}, Port,
                                   [inet, {active, false}], 500),
    {Listen, Holder, Port}.

%% Два «медленных» адреса 127.0.0.1 и 127.0.0.2 на одном порту: у каждого
%% свой слушатель с заполненной очередью приёма, поэтому connect обоих
%% адресов блокируется детерминированно.
slow_pair() ->
    {ok, L1} = gen_tcp:listen(0, [inet, {ip, {127, 0, 0, 1}},
                                  {active, false}, {backlog, 0}]),
    {ok, Port} = inet:port(L1),
    {ok, L2} = gen_tcp:listen(Port, [inet, {ip, {127, 0, 0, 2}},
                                     {active, false}, {backlog, 0}]),
    {ok, H1} = gen_tcp:connect({127, 0, 0, 1}, Port,
                               [inet, {active, false}], 500),
    {ok, H2} = gen_tcp:connect({127, 0, 0, 2}, Port,
                               [inet, {active, false}], 500),
    {L1, L2, H1, H2, Port}.

coordinator(Ref) ->
    case trawler_discovery_registry:lookup(Ref) of
        {ok, Pid} -> Pid;
        {error, not_found} -> error(no_coordinator)
    end.

await_worker(Coordinator, Timeout) ->
    await_worker(Coordinator, whereis(trawler_discovery_sup), now_ms() + Timeout).

await_worker(Coordinator, Sup, Deadline) ->
    case process_info(Coordinator, links) of
        {links, Links} ->
            case [P || P <- Links, P =/= Sup] of
                [Worker | _] -> Worker;
                [] ->
                    case now_ms() > Deadline of
                        true -> error(no_worker);
                        false -> timer:sleep(5),
                                 await_worker(Coordinator, Sup, Deadline)
                    end
            end;
        undefined ->
            error(coordinator_dead)
    end.

receive_until_done(Ref, Timeout, Acc) ->
    receive
        {trawler_discovery, Ref, {result, Result}} ->
            receive_until_done(Ref, Timeout, [Result | Acc]);
        {trawler_discovery, Ref, {warning, _}} ->
            receive_until_done(Ref, Timeout, Acc);
        {trawler_discovery, Ref, {done, Summary}} ->
            {lists:reverse(Acc), Summary}
    after Timeout ->
        error(no_done_event)
    end.

receive_until_done_warnings(Ref, Timeout, Acc, Warnings) ->
    receive
        {trawler_discovery, Ref, {result, Result}} ->
            receive_until_done_warnings(Ref, Timeout, [Result | Acc], Warnings);
        {trawler_discovery, Ref, {warning, Warning}} ->
            receive_until_done_warnings(Ref, Timeout, Acc, [Warning | Warnings]);
        {trawler_discovery, Ref, {done, Summary}} ->
            {lists:reverse(Acc), maps:get(warnings, Summary),
             lists:reverse(Warnings)}
    after Timeout ->
        error(no_done_event)
    end.

receive_cancelled(Ref, Timeout) ->
    receive
        {trawler_discovery, Ref, {result, _}} -> receive_cancelled(Ref, Timeout);
        {trawler_discovery, Ref, {warning, _}} -> receive_cancelled(Ref, Timeout);
        {trawler_discovery, Ref, {cancelled, Summary}} -> Summary
    after Timeout ->
        error(no_cancelled_event)
    end.

receive_error(Ref, Reason, Timeout) ->
    receive
        {trawler_discovery, Ref, {result, _}} ->
            receive_error(Ref, Reason, Timeout);
        {trawler_discovery, Ref, {warning, _}} ->
            receive_error(Ref, Reason, Timeout);
        {trawler_discovery, Ref, {error, Reason, Summary}} ->
            Summary
    after Timeout ->
        error(no_error_event)
    end.

ensure_no_more(Ref, Timeout) ->
    receive
        {trawler_discovery, Ref, _Event} -> error(event_after_done)
    after Timeout ->
        ok
    end.

saturate_scheduler() ->
    Max = max_concurrency(),
    _ = [trawler_scheduler:request(self()) || _ <- lists:seq(1, Max)],
    _ = [receive {trawler_scheduler, grant} -> ok
         after 2000 -> error(no_grant) end || _ <- lists:seq(1, Max)],
    Max.

release_grants(0) ->
    ok;
release_grants(N) ->
    ok = trawler_scheduler:release(),
    release_grants(N - 1).

in_flight() ->
    maps:get(in_flight, sys:get_state(trawler_scheduler)).

await_in_flight(Expected, Timeout) ->
    await_in_flight_loop(Expected, now_ms() + Timeout).

await_in_flight_loop(Expected, Deadline) ->
    case in_flight() of
        Expected -> Expected;
        _Other ->
            case now_ms() > Deadline of
                true -> error({in_flight_stuck, in_flight()});
                false -> timer:sleep(10),
                         await_in_flight_loop(Expected, Deadline)
            end
    end.

max_concurrency() ->
    case application:get_env(trawler, max_concurrency, 256) of
        Limit when is_integer(Limit), Limit >= 1 -> Limit;
        _ -> 256
    end.

wait_not_found(Ref, Timeout) ->
    wait_not_found_loop(Ref, now_ms() + Timeout).

wait_not_found_loop(Ref, Deadline) ->
    case trawler:discovery_status(Ref) of
        {error, not_found} ->
            ok;
        {ok, _Status} ->
            case now_ms() > Deadline of
                true -> error(still_present);
                false -> timer:sleep(10),
                         wait_not_found_loop(Ref, Deadline)
            end
    end.

require_cancelled_status(Ref) ->
    require_status(Ref, cancelled, now_ms() + 3000).

require_status(Ref, State, Deadline) ->
    case trawler:discovery_status(Ref) of
        {ok, Status} ->
            case maps:get(state, Status) of
                State -> ok;
                _Other ->
                    case now_ms() > Deadline of
                        true -> error({unexpected_status, Status});
                        false -> timer:sleep(10),
                                 require_status(Ref, State, Deadline)
                    end
            end;
        {error, not_found} ->
            case now_ms() > Deadline of
                true -> error(status_not_found);
                false -> timer:sleep(10),
                         require_status(Ref, State, Deadline)
            end
    end.

receive_result(Ref, Timeout) ->
    receive
        {trawler_discovery, Ref, {result, Result}} -> Result;
        {trawler_discovery, Ref, {warning, _}} -> receive_result(Ref, Timeout)
    after Timeout ->
        error(no_result_event)
    end.

receive_done(Ref, Timeout) ->
    receive
        {trawler_discovery, Ref, {result, _}} -> receive_done(Ref, Timeout);
        {trawler_discovery, Ref, {warning, _}} -> receive_done(Ref, Timeout);
        {trawler_discovery, Ref, {done, Summary}} -> Summary
    after Timeout ->
        error(no_done_event)
    end.

now_ms() ->
    erlang:monotonic_time(millisecond).
