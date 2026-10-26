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
-define(LO_IP, {127, 0, 0, 1}).

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
          ?_test(default_request_no_extra_fields()),
          ?_test(auto_ports_closed_up_no_filter()),
          ?_test(explicit_many_ports_accepted()),
          ?_test(inspection_sync_async_equivalent()),
          ?_test(inspection_elapsed_includes_banner_read()),
          ?_test(os_only_without_explicit_ports()),
          ?_test(budget_exhausted_up_preserved()),
          ?_test(no_response_skips_inspector()),
          ?_test(error_skips_inspector()),
          ?_test(inspection_exception_keeps_requested_fields()),
          ?_test(ports_validation_all_methods()),
          ?_test(cancel_during_banner_read()),
          ?_test(deadline_during_banner_read()),
          ?_test(owner_down_during_banner_read()),
          ?_test(recipient_down_during_banner_read()),
          ?_test(app_stop_during_banner_read()),
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
    ?assertEqual({error, {invalid_options, {os_detection, 1}}},
                 trawler:discover(?LO, #{os_detection => 1})),
    ?assertEqual({error, {invalid_options, {os_detection, <<"true">>}}},
                 trawler:discover(?LO, #{os_detection => <<"true">>})),
    ?assertMatch({error, {invalid_targets, _}}, trawler:discover(<<>>, #{})),
    ?assertMatch({error, {invalid_ports, _}},
                 trawler:discover(?LO, #{method => tcp, ports => <<"0">>})),
    ?assertMatch({error, {invalid_ports, _}},
                 trawler:discover(?LO, #{method => auto, ports => [0]})),
    ?assertMatch({error, {invalid_ports, _}},
                 trawler:discover(?LO, #{method => arp,
                                         ports => [65536]})),
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

%% Порты проверяются до сети при любом методе; сами номера остаются
%% строгими, а прежний запрет 16 значений снят.
ports_validation_all_methods() ->
    lists:foreach(
      fun(Method) ->
              ?assertMatch({error, {invalid_ports, _}},
                           trawler:discover(?LO, #{method => Method,
                                                   ports => [0]}))
      end, [auto, arp, icmp, tcp, raw_tcp]),
    ?assertEqual({error, {invalid_options, {unknown_option, foo}}},
                 trawler:discover(?LO, #{foo => 1})).

%% Прежний запрос без ports/os_detection не получает дополнительных
%% полей. Транспорт при этом по-прежнему получает набор 80/443, а
%% инспектор вызывается с undefined/false и возвращает пустую карту.
default_request_no_extra_fields() ->
    Calls = with_traces([{trawler_discovery_probe, run, 3},
                         {trawler_host_inspection, inspect, 4}],
                        fun() ->
                                {ok, [Result], _Summary} =
                                    trawler:discover(?LO, #{method => tcp,
                                                           retries => 0}),
                                ?assertEqual(up, maps:get(state, Result)),
                                ?assertNot(maps:is_key(port_results, Result)),
                                ?assertNot(maps:is_key(open_ports, Result)),
                                ?assertNot(maps:is_key(os, Result)),
                                ?assertNot(maps:is_key(inspection_error, Result))
                        end, 300),
    [ProbeArgs] = [Args || {trawler_discovery_probe, run, Args} <- Calls],
    ProbeOpts = lists:nth(3, ProbeArgs),
    ?assertEqual([80, 443], maps:get(ports, ProbeOpts)),
    ?assertNot(maps:is_key(os_detection, ProbeOpts)),
    [InspectArgs] = [Args || {trawler_host_inspection, inspect, Args} <- Calls],
    ?assertMatch([_IP, undefined, false, _Deadline], InspectArgs).

%% auto на loopback подтверждается как local; явные закрытые порты не
%% фильтруют находку и не попадают в публичные ports транспорта вместе с
%% os_detection.
auto_ports_closed_up_no_filter() ->
    Closed = closed_port(),
    Calls = with_traces([{trawler_discovery_probe, run, 3},
                         {trawler_host_inspection, inspect, 4}],
                        fun() ->
                                {ok, [Result], _Summary} =
                                    trawler:discover(?LO,
                                                     #{method => auto,
                                                       ports => [Closed],
                                                       retries => 0}),
                                ?assertEqual(up, maps:get(state, Result)),
                                ?assertEqual(local, maps:get(method, Result)),
                                #{port_results := Rows, open_ports := []} =
                                    Result,
                                ?assertEqual([Closed],
                                             [maps:get(port, Row)
                                              || Row <- Rows]),
                                ?assertEqual(closed,
                                             maps:get(state, hd(Rows))),
                                ?assert(maps:get(elapsed_ms, hd(Rows)) >= 0)
                        end, 300),
    [ProbeArgs] = [Args || {trawler_discovery_probe, run, Args} <- Calls],
    ProbeOpts = lists:nth(3, ProbeArgs),
    ?assertEqual([Closed], maps:get(ports, ProbeOpts)),
    ?assertNot(maps:is_key(os_detection, ProbeOpts)),
    [InspectArgs] = [Args || {trawler_host_inspection, inspect, Args} <- Calls],
    ?assertMatch([_IP, [Closed], false, _Deadline], InspectArgs).

%% Более 16 явных портов принимается без подмены и проверяется линейно.
explicit_many_ports_accepted() ->
    Ports = closed_ports(17),
    {ok, [Result], _Summary} =
        trawler:discover(?LO, #{method => tcp, ports => Ports, retries => 0,
                               timeout_ms => 3000}),
    ?assertEqual(up, maps:get(state, Result)),
    Rows = maps:get(port_results, Result),
    ?assertEqual(lists:sort(Ports), [maps:get(port, Row) || Row <- Rows]),
    ?assert(lists:all(fun(Row) -> maps:get(state, Row) =:= closed end,
                      Rows)),
    ?assertEqual([], maps:get(open_ports, Result)).

%% Синхронный и асинхронный API отдают одинаковые дополнительные данные
%% без учёта длительностей.
inspection_sync_async_equivalent() ->
    {BannerPid, Open} = banner_server(),
    Closed = closed_port(),
    Opts = #{method => tcp, ports => [Open, Closed], os_detection => true,
             retries => 0, timeout_ms => 3000},
    try
        {ok, [Sync], _SyncSummary} = trawler:discover(?LO, Opts),
        {ok, Ref} = trawler:start_discovery(?LO, Opts#{recipient => self()}),
        {[Async], _AsyncSummary} = receive_until_done(Ref, 5000, []),
        ?assertEqual(up, maps:get(state, Sync)),
        ?assertEqual(up, maps:get(state, Async)),
        ?assertEqual(strip_elapsed(maps:get(port_results, Sync)),
                     strip_elapsed(maps:get(port_results, Async))),
        ?assertEqual(maps:get(open_ports, Sync),
                     maps:get(open_ports, Async)),
        ?assertEqual(maps:get(os, Sync), maps:get(os, Async))
    after
        exit(BannerPid, kill)
    end.

%% Совокупный elapsed_ms адреса включает чтение молчащих баннеров
%% дополнительных проверок, а не только обнаружение.
inspection_elapsed_includes_banner_read() ->
    Fixtures = banner_fixtures(2),
    Ports = fixture_ports(Fixtures),
    try
        {ok, [Result], _Summary} =
            trawler:discover(?LO, #{method => auto, ports => Ports,
                                   os_detection => true,
                                   timeout_ms => 3000, retries => 0}),
        ?assertEqual(up, maps:get(state, Result)),
        ?assertEqual(local, maps:get(method, Result)),
        ?assertEqual(lists:sort(Ports),
                     [maps:get(port, Row)
                      || Row <- maps:get(port_results, Result)]),
        ?assert(lists:all(fun(#{state := State}) -> State =:= open end,
                          maps:get(port_results, Result))),
        %% Две попытки по 200 мс; порог ниже суммы, чтобы не зависеть от
        %% планировщика, но заметно больше мгновенного обнаружения.
        ?assert(maps:get(elapsed_ms, Result) >= 300)
    after
        stop_fixtures(Fixtures)
    end.

%% Классификация без явных портов добавляет только os и не публикует
%% служебный набор как port_results/open_ports.
os_only_without_explicit_ports() ->
    {ok, [Result], _Summary} =
        trawler:discover(?LO, #{method => auto, os_detection => true,
                               timeout_ms => 1000, retries => 0}),
    ?assertEqual(up, maps:get(state, Result)),
    ?assertEqual(local, maps:get(method, Result)),
    ?assertNot(maps:is_key(port_results, Result)),
    ?assertNot(maps:is_key(open_ports, Result)),
    Os = maps:get(os, Result),
    ?assert(lists:member(maps:get(family, Os), [windows, linux, unknown])),
    ?assert(lists:member(maps:get(confidence, Os), [medium, low, none])),
    ?assert(is_list(maps:get(evidence, Os))).

%% Исчерпанный бюджет не отменяет подтверждение up: часть явных портов
%% возвращается skipped, а не закрывается или теряется.
budget_exhausted_up_preserved() ->
    Ports = lists:seq(1, 65535),
    Start = now_ms(),
    {ok, [Result], _Summary} =
        trawler:discover(?LO, #{method => auto, ports => Ports,
                               timeout_ms => 100, retries => 0}),
    Wall = now_ms() - Start,
    ?assertEqual(up, maps:get(state, Result)),
    ?assertEqual(local, maps:get(method, Result)),
    Rows = maps:get(port_results, Result),
    ?assertEqual(65535, length(Rows)),
    ?assertEqual(Ports, [maps:get(port, Row) || Row <- Rows]),
    ?assert(lists:any(fun(Row) -> maps:get(state, Row) =:= skipped end, Rows)),
    ?assert(lists:all(fun(Row) ->
                              lists:member(maps:get(state, Row),
                                           [open, closed, timeout, unreachable,
                                            error, skipped])
                      end, Rows)),
    ?assert(Wall < 2000).

%% no_response не запускает инспектор: трассировка реального вызова
%% inspect/4 пуста.
no_response_skips_inspector() ->
    {Listen, Holder, Port} = slow_target(),
    try
        Calls = with_traces([{trawler_host_inspection, inspect, 4}],
                            fun() ->
                                    {ok, [Result], _Summary} =
                                        trawler:discover(
                                          ?LO, #{method => tcp, ports => [Port],
                                                 os_detection => true,
                                                 timeout_ms => 200,
                                                 retries => 0}),
                                    ?assertEqual(no_response,
                                                 maps:get(state, Result))
                            end, 200),
        ?assertEqual([], Calls)
    after
        gen_tcp:close(Listen),
        gen_tcp:close(Holder)
    end.

%% Ошибка пробы также не запускает инспектор и не превращается в up.
%% Сценарий ограничен loopback: координатор запускается напрямую с
%% методом arp, а маршрут 127.0.0.1 не является Ethernet, поэтому проба
%% детерминированно даёт method_not_applicable ещё до raw-сокета. Ни
%% внешний адрес, ни сетевые привилегии, ни подмена ядра не нужны.
error_skips_inspector() ->
    Calls = with_traces([{trawler_host_inspection, inspect, 4}],
                        fun() ->
                                {Ref, _Pid} = start_direct_coordinator(
                                                loopback_error_options()),
                                {Results, Summary} =
                                    receive_until_done(Ref, 5000, []),
                                ?assertMatch(
                                   [#{state := error,
                                      reason := {method_not_applicable,
                                                 not_ethernet}}],
                                   Results),
                                [Result] = Results,
                                ?assertEqual(?LO_IP, maps:get(ip, Result)),
                                ?assertNot(maps:is_key(port_results, Result)),
                                ?assertNot(maps:is_key(open_ports, Result)),
                                ?assertNot(maps:is_key(os, Result)),
                                ?assertNot(maps:is_key(inspection_error, Result)),
                                ?assertMatch(#{total := 1, completed := 1},
                                             Summary),
                                ?assertMatch(#{error := 1},
                                             maps:get(counters, Summary))
                        end, 200),
    ?assertEqual([], Calls).

%% Постоянное исключение инспектора не должно терять обязательные
%% запрошенные поля: fallback строит наблюдения сам, без повторного
%% вызова сломанного модуля. Подмена модуля выполняется в изолированной
%% Erlang VM (compile:forms + code:load_abs в отдельном процессе `erl'),
%% поэтому production-кода и общих переключателей это не касается.
inspection_exception_keeps_requested_fields() ->
    Dir = fixture_dir("inspection_exception"),
    try
        ok = filelib:ensure_dir(filename:join(Dir, "keep")),
        {ok, trawler_host_inspection, Binary} =
            compile:forms(stub_inspector_forms(), [binary, return_errors]),
        BeamName = filename:join(Dir, "trawler_host_inspection"),
        ok = file:write_file(BeamName ++ ".beam", Binary),
        Output = run_isolated_discovery(Dir),
        {ok, [#{state := up} = Result], _Summary} = Output,
        ?assertEqual(local, maps:get(method, Result)),
        Ports = [22, 445],
        ?assertEqual(
           [#{port => 22, state => skipped, elapsed_ms => 0,
              reason => inspection_error},
            #{port => 445, state => skipped, elapsed_ms => 0,
              reason => inspection_error}],
           maps:get(port_results, Result)),
        ?assertEqual([], maps:get(open_ports, Result)),
        ?assertMatch(#{family := unknown, confidence := none, evidence := []},
                     maps:get(os, Result)),
        ?assertMatch({error, fixture_failure},
                     maps:get(inspection_error, Result)),
        ?assertEqual(Ports, [maps:get(port, Row)
                             || Row <- maps:get(port_results, Result)])
    after
        _ = file:del_dir_r(Dir)
    end.

%% Отмена во время чтения молчащего баннера: слот удерживается до
%% инспекции, а после отмены воркер и сокет прекращены до terminal event.
cancel_during_banner_read() ->
    Fixtures = banner_fixtures(3),
    try
        Ports = fixture_ports(Fixtures),
        {ok, Ref} = start_banner_discovery(Ports, #{}),
        Worker = await_worker(coordinator(Ref), 2000),
        Accepted = await_banner_accept(Ports),
        ?assertEqual(1, in_flight()),
        ?assertEqual(ok, trawler:cancel_discovery(Ref)),
        ?assertNot(is_process_alive(Worker)),
        ?assertEqual(0, in_flight()),
        await_banner_closed(Accepted),
        Summary = receive_cancelled(Ref, 5000),
        ?assertEqual(0, maps:get(completed, Summary)),
        ensure_no_more(Ref, 200)
    after
        stop_fixtures(Fixtures)
    end.

%% Deadline во время чтения баннера освобождает слот до терминального
%% события; результат адреса не учитывается как завершённый.
deadline_during_banner_read() ->
    Fixtures = banner_fixtures(3),
    try
        Ports = fixture_ports(Fixtures),
        {ok, Ref} = start_banner_discovery(Ports, #{deadline_ms => 500}),
        Worker = await_worker(coordinator(Ref), 2000),
        Accepted = await_banner_accept(Ports),
        ?assertEqual(0, await_in_flight(0, 3000)),
        ?assertNot(is_process_alive(Worker)),
        await_banner_closed(Accepted),
        Summary = receive_error(Ref, deadline_exceeded, 5000),
        ?assertEqual(0, maps:get(completed, Summary))
    after
        stop_fixtures(Fixtures)
    end.

%% Выход владельца останавливает воркер, читающий баннер.
owner_down_during_banner_read() ->
    Fixtures = banner_fixtures(3),
    Ports = fixture_ports(Fixtures),
    Test = self(),
    Owner = spawn(fun() ->
                          {ok, Ref} = start_banner_discovery(
                                        Ports, #{recipient => Test}),
                          Test ! {banner_ref, Ref},
                          receive stop -> ok end
                  end),
    try
        Ref = receive {banner_ref, R} -> R after 3000 -> error(no_ref) end,
        Worker = await_worker(coordinator(Ref), 2000),
        Accepted = await_banner_accept(Ports),
        exit(Owner, kill),
        ok = wait_not_found(Ref, 3000),
        ?assertNot(is_process_alive(Worker)),
        ?assertEqual(0, await_in_flight(0, 2000)),
        await_banner_closed(Accepted)
    after
        exit(Owner, kill),
        stop_fixtures(Fixtures)
    end.

%% Выход получателя останавливает воркер, читающий баннер.
recipient_down_during_banner_read() ->
    Fixtures = banner_fixtures(3),
    try
        Ports = fixture_ports(Fixtures),
        Recipient = spawn(fun() -> receive stop -> ok end end),
        {ok, Ref} = start_banner_discovery(Ports, #{recipient => Recipient}),
        Worker = await_worker(coordinator(Ref), 2000),
        Accepted = await_banner_accept(Ports),
        exit(Recipient, kill),
        ok = wait_not_found(Ref, 3000),
        ?assertNot(is_process_alive(Worker)),
        ?assertEqual(0, await_in_flight(0, 2000)),
        await_banner_closed(Accepted)
    after
        stop_fixtures(Fixtures)
    end.

%% Остановка приложения во время чтения баннера убивает координатор и
%% воркер, а сокет закрывается.
app_stop_during_banner_read() ->
    Fixtures = banner_fixtures(3),
    try
        Ports = fixture_ports(Fixtures),
        {ok, Ref} = start_banner_discovery(Ports, #{}),
        Coord = coordinator(Ref),
        Worker = await_worker(Coord, 2000),
        Accepted = await_banner_accept(Ports),
        ok = application:stop(trawler),
        ?assertEqual(undefined, whereis(trawler_sup)),
        ?assertNot(is_process_alive(Coord)),
        ?assertNot(is_process_alive(Worker)),
        await_banner_closed(Accepted)
    after
        stop_fixtures(Fixtures),
        {ok, _} = application:ensure_all_started(trawler)
    end.

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

%% Несколько закрытых локальных портов: слушатели создаются заранее,
%% поэтому номера уникальны, и сразу закрываются.
closed_ports(N) ->
    Listeners = [begin
                     {ok, Listen} = gen_tcp:listen(
                                      0, [inet, {ip, ?LO_IP},
                                          {active, false}]),
                     {ok, Port} = inet:port(Listen),
                     {Listen, Port}
                 end || _ <- lists:seq(1, N)],
    [begin
         ok = gen_tcp:close(Listen),
         Port
     end || {Listen, Port} <- Listeners].

%% Дополнительные данные без длительностей: sync и async могут
%% различаться только elapsed_ms.
strip_elapsed(Rows) ->
    [maps:remove(elapsed_ms, Row) || Row <- Rows].

%% Слушатель с корректным Ubuntu SSH-баннером на каждое соединение:
%% классификация не зависит от реального sshd на loopback.
banner_server() ->
    {ok, Listen} = gen_tcp:listen(
                     0, [inet, {ip, ?LO_IP}, {active, false},
                         {reuseaddr, true}]),
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

%% Трассировка вызовов заданных MFA во всех процессах. Сообщения dbg
%% складываются в ящик теста и разбираются после завершения сценария.
with_traces(MFAs, Fun, Timeout) ->
    Self = self(),
    _ = dbg:tracer(process,
                   {fun(Msg, Acc) -> Acc ! {trace_msg, Msg}, Acc end, Self}),
    try
        _ = [dbg:tpl(M, F, A, []) || {M, F, A} <- MFAs],
        _ = dbg:p(all, [call]),
        _ = Fun(),
        collect_traces(Timeout, [])
    after
        _ = [dbg:ctpl(M, F, A) || {M, F, A} <- MFAs],
        _ = dbg:stop()
    end.

collect_traces(Timeout, Acc) ->
    receive
        {trace_msg, {trace, _Pid, call, {M, F, Args}}} ->
            collect_traces(Timeout, [{M, F, Args} | Acc]);
        {trace_msg, _Other} ->
            collect_traces(Timeout, Acc)
    after Timeout ->
        lists:reverse(Acc)
    end.

%% Прямой запуск координатора под штатным supervisor: детерминированная
%% ошибка пробы проверяется на loopback без внешних адресов и без
%% production-переключателей.
start_direct_coordinator(Options) ->
    Ref = make_ref(),
    Args = #{ref => Ref,
             addrs => [?LO_IP],
             options => Options,
             warnings => [],
             owner => self()},
    ChildSpec = #{id => Ref,
                  start => {trawler_discovery_scan, start_link, [Args]},
                  restart => temporary,
                  shutdown => 5000,
                  type => worker,
                  modules => [trawler_discovery_scan]},
    {ok, Pid} = supervisor:start_child(trawler_discovery_sup, ChildSpec),
    {Ref, Pid}.

%% Нормализованные внутренние опции координатора: ARP объявлен
%% доступным, но loopback не Ethernet, поэтому проба завершается
%% method_not_applicable до открытия raw-сокета.
loopback_error_options() ->
    #{method => arp,
      timeout_ms => 500,
      concurrency => 1,
      retries => 0,
      deadline_ms => infinity,
      recipient => self(),
      caps => #{arp => true, icmp => false, raw_tcp => false,
                reason => undefined},
      ports => [80],
      os_detection => true}.

%% Каталог fixture-модуля в _build: не попадает в отслеживаемые файлы.
fixture_dir(Name) ->
    BuildRoot = filename:dirname(filename:dirname(code:lib_dir(trawler))),
    Unique = integer_to_list(erlang:unique_integer([positive, monotonic])),
    filename:join([BuildRoot, "trawler_test_fixtures", Name, Unique]).

%% Заглушка инспектора, которая всегда завершается исключением. Модуль
%% компилируется из форм и загружается только в отдельной VM.
stub_inspector_forms() ->
    Sources = ["-module(trawler_host_inspection).",
               "-export([inspect/4, classify/1]).",
               "inspect(_IP, _RequestedPorts, _OSDetection, _Deadline) ->"
               "    error(fixture_failure).",
               "classify(_Observations) ->"
               "    #{family => unknown, confidence => none, evidence => []}."],
    [scan_form(Source) || Source <- Sources].

scan_form(Source) ->
    {ok, Tokens, _EndLine} = erl_scan:string(Source),
    {ok, Form} = erl_parse:parse_form(Tokens),
    Form.

%% Отдельная Erlang VM: реальное приложение, подменённый модуль и
%% публичный API. Результат возвращается одной строкой `RESULT'.
run_isolated_discovery(Dir) ->
    Erl = case os:find_executable("erl") of
              false -> error(erl_executable_not_found);
              Path -> Path
          end,
    Ebin = filename:join(code:lib_dir(trawler), "ebin"),
    Eval = isolated_eval(filename:join(Dir, "trawler_host_inspection")),
    Port = open_port(
             {spawn_executable, Erl},
             [binary, exit_status, use_stdio, stderr_to_stdout,
              {args, ["-noshell", "-pa", Ebin, "-pa", Dir, "-eval", Eval]}]),
    parse_isolated_output(collect_isolated(Port, <<>>, 15000)).

isolated_eval(BeamAbs) ->
    Quoted = lists:flatten(io_lib:format("\"~ts\"", [BeamAbs])),
    lists:flatten(
      ["{ok, _} = application:ensure_all_started(trawler), ",
       "_ = code:purge(trawler_host_inspection), ",
       "_ = code:delete(trawler_host_inspection), ",
       "{module, trawler_host_inspection} = code:load_abs(", Quoted, "), ",
       "R = trawler:discover(<<\"127.0.0.1\">>, ",
       "#{method => auto, ports => [22,445], os_detection => true, ",
       "timeout_ms => 500, retries => 0}), ",
       "io:format(\"RESULT ~w~n\", [R]), erlang:halt(0)."]).

collect_isolated(Port, Acc, Timeout) ->
    receive
        {Port, {data, Data}} ->
            collect_isolated(Port, <<Acc/binary, Data/binary>>, Timeout);
        {Port, {exit_status, 0}} ->
            Acc;
        {Port, {exit_status, Status}} ->
            error({isolated_vm_failed, Status, Acc})
    after Timeout ->
        port_close(Port),
        error(isolated_vm_timeout)
    end.

parse_isolated_output(Output) ->
    Lines = binary:split(Output, <<"\n">>, [global]),
    case [Rest || <<"RESULT ", Rest/binary>> <- Lines] of
        [TermText | _] ->
            {ok, Tokens, _EndLine} =
                erl_scan:string(binary_to_list(TermText) ++ "."),
            {ok, Term} = erl_parse:parse_term(Tokens),
            Term;
        [] ->
            error({isolated_result_missing, Output})
    end.

%% Слушатель, который принимает одно соединение и молчит: воркер
%% остаётся в чтении баннера до отмены/deadline/выхода. Событие accept
%% подтверждает, что явный ephemeral-порт проверяется первым.
banner_fixtures(N) ->
    [banner_fixture() || _ <- lists:seq(1, N)].

banner_fixture() ->
    {ok, Listen} = gen_tcp:listen(
                     0, [inet, {ip, ?LO_IP}, {active, false},
                         {reuseaddr, true}]),
    {ok, Port} = inet:port(Listen),
    Test = self(),
    Pid = spawn(fun() -> banner_fixture_loop(Listen, Port, Test) end),
    {Pid, Port}.

banner_fixture_loop(Listen, Port, Test) ->
    case gen_tcp:accept(Listen, 5000) of
        {ok, Socket} ->
            _ = gen_tcp:close(Listen),
            Test ! {banner_accepted, Port},
            Result = gen_tcp:recv(Socket, 0, 5000),
            Test ! {banner_closed, Port, Result},
            _ = gen_tcp:close(Socket),
            ok;
        {error, _Reason} ->
            _ = gen_tcp:close(Listen),
            ok
    end.

fixture_ports(Fixtures) ->
    [Port || {_Pid, Port} <- Fixtures].

stop_fixtures(Fixtures) ->
    _ = [exit(Pid, kill) || {Pid, _Port} <- Fixtures],
    ok.

start_banner_discovery(Ports, Extra) ->
    Base = #{method => auto, ports => Ports, os_detection => true,
             timeout_ms => 5000, retries => 0, concurrency => 1,
             recipient => self()},
    trawler:start_discovery(?LO, maps:merge(Base, Extra)).

await_banner_accept(Ports) ->
    receive
        {banner_accepted, Port} ->
            case lists:member(Port, Ports) of
                true -> Port;
                false -> await_banner_accept(Ports)
            end
    after 3000 ->
        error(no_banner_accept)
    end.

await_banner_closed(Port) ->
    receive
        {banner_closed, Port, {error, closed}} ->
            ok;
        {banner_closed, Port, Other} ->
            error({unexpected_banner_close, Other})
    after 3000 ->
        error(no_banner_close)
    end.

now_ms() ->
    erlang:monotonic_time(millisecond).
