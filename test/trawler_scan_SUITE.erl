%%%-------------------------------------------------------------------
%%% @doc Common Test публичного API сканирования на loopback.
%%%
%%% Все сетевые проверки используют только адрес 127.0.0.1 и локальные
%%% слушающие сокеты. Закрытые порты резервируются через bind-close,
%%% а сканирование, которое должно оставаться активным при отмене и
%%% выходе процессов жизненного цикла, опирается на большой объём
%%% продуцируемых проб, а не на случайные задержки.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_scan_SUITE).

-export([all/0, init_per_suite/1, end_per_suite/1,
         open_port/1, closed_port/1, multiple_ports/1, concurrent_scans/1,
         async_done/1, status_progress/1, cancel_active/1, cancel_after_done/1,
         unknown_ref/1, not_started/1, invalid_input/1, recipient_down/1,
         owner_down/1, deadline_exceeded/1, sync_preserves_foreign_messages/1]).

%%% ------------------------------------------------------------------
%%% Конфигурация набора
%%% ------------------------------------------------------------------

all() ->
    [open_port, closed_port, multiple_ports, concurrent_scans, async_done,
     status_progress, cancel_active, cancel_after_done, unknown_ref,
     not_started, invalid_input, recipient_down, owner_down,
     deadline_exceeded, sync_preserves_foreign_messages].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(trawler),
    Config.

end_per_suite(_Config) ->
    _ = application:stop(trawler),
    ok.

%%% ------------------------------------------------------------------
%%% Наблюдаемые исходы соединений
%%% ------------------------------------------------------------------

open_port(_Config) ->
    {Socket, Port} = open_listener(),
    try
        {ok, [Result]} = trawler:scan(<<"127.0.0.1">>, integer_to_binary(Port),
                                      #{}),
        {127, 0, 0, 1} = maps:get(ip, Result),
        Port = maps:get(port, Result),
        open = maps:get(state, Result),
        true = maps:get(elapsed_ms, Result) >= 0
    after
        ok = gen_tcp:close(Socket)
    end,
    ok.

closed_port(_Config) ->
    Port = reserve_closed_port(),
    {ok, [Result]} = trawler:scan(<<"127.0.0.1">>, integer_to_binary(Port), #{}),
    {127, 0, 0, 1} = maps:get(ip, Result),
    Port = maps:get(port, Result),
    closed = maps:get(state, Result),
    true = maps:get(elapsed_ms, Result) >= 0,
    ok.

multiple_ports(_Config) ->
    {S1, P1} = open_listener(),
    {S2, P2} = open_listener(),
    {S3, P3} = open_listener(),
    P4 = reserve_closed_port(),
    try
        {ok, Results} = trawler:scan(<<"127.0.0.1">>, [P1, P2, P3, P4], #{}),
        4 = length(Results),
        Expected = lists:sort([{P1, open}, {P2, open}, {P3, open},
                               {P4, closed}]),
        Actual = lists:sort([{maps:get(port, R), maps:get(state, R)}
                             || R <- Results]),
        Expected = Actual
    after
        ok = gen_tcp:close(S1),
        ok = gen_tcp:close(S2),
        ok = gen_tcp:close(S3)
    end,
    ok.

%%% ------------------------------------------------------------------
%%% Ограничение нагрузки между сканированиями
%%% ------------------------------------------------------------------

concurrent_scans(_Config) ->
    {S1, P1} = open_listener(),
    {S2, P2} = open_listener(),
    Parent = self(),
    Tag1 = make_ref(),
    Tag2 = make_ref(),
    _ = spawn(fun() ->
        Outcome = trawler:scan(<<"127.0.0.1">>, integer_to_binary(P1),
                               #{concurrency => 4}),
        Parent ! {Tag1, Outcome}
    end),
    _ = spawn(fun() ->
        Outcome = trawler:scan(<<"127.0.0.1">>, integer_to_binary(P2),
                               #{concurrency => 4}),
        Parent ! {Tag2, Outcome}
    end),
    try
        Outcome1 = receive {Tag1, O1} -> O1 after 5000 -> ct:fail(no_result_1) end,
        Outcome2 = receive {Tag2, O2} -> O2 after 5000 -> ct:fail(no_result_2) end,
        {ok, [Result1]} = Outcome1,
        {ok, [Result2]} = Outcome2,
        open = maps:get(state, Result1),
        open = maps:get(state, Result2),
        P1 = maps:get(port, Result1),
        P2 = maps:get(port, Result2)
    after
        ok = gen_tcp:close(S1),
        ok = gen_tcp:close(S2)
    end,
    ok.

%%% ------------------------------------------------------------------
%%% Жизненный цикл асинхронного сканирования
%%% ------------------------------------------------------------------

async_done(_Config) ->
    {Socket, Open} = open_listener(),
    Closed = reserve_closed_port(),
    try
        {ok, Ref} = trawler:start_scan(<<"127.0.0.1">>, [Open, Closed], #{}),
        {Results, Summary} = receive_until_done(Ref, 5000, []),
        2 = length(Results),
        #{total := 2, completed := 2, counters := Counters,
          elapsed_ms := Elapsed} = Summary,
        true = Elapsed >= 0,
        #{open := 1, closed := 1} = maps:with([open, closed], Counters),
        %% После завершающего события результатов больше нет.
        ok = ensure_no_more(Ref, 300)
    after
        ok = gen_tcp:close(Socket)
    end,
    ok.

status_progress(_Config) ->
    {Socket, Open} = open_listener(),
    Closed = [reserve_closed_port() || _ <- lists:seq(1, 9)],
    Ports = [Open | Closed],
    try
        {ok, Ref} = trawler:start_scan(<<"127.0.0.1">>, Ports,
                                       #{concurrency => 2}),
        {Results, _Summary, Statuses} =
            poll_until_done(Ref, now_ms() + 5000, [], []),
        10 = length(Results),
        true = length(Statuses) >= 1,
        {ok, Final} = trawler:status(Ref),
        completed = maps:get(state, Final),
        10 = maps:get(total, Final),
        10 = maps:get(completed, Final),
        ExpectedCounters = state_counts(Results),
        ExpectedCounters = maps:get(counters, Final)
    after
        ok = gen_tcp:close(Socket)
    end,
    ok.

%%% ------------------------------------------------------------------
%%% Статус и отмена
%%% ------------------------------------------------------------------

cancel_active(_Config) ->
    %% Большая выборка портов и индивидуальный лимит 1 не позволяют
    %% сканированию завершиться мгновенно.
    {ok, Ref} = trawler:start_scan(<<"127.0.0.1">>, <<"1-5000">>,
                                   #{concurrency => 1}),
    ok = trawler:cancel(Ref),
    ok = trawler:cancel(Ref),
    Summary = receive
                  {trawler, Ref, {cancelled, S}} -> S
              after 5000 ->
                  ct:fail(no_cancelled_event)
              end,
    #{total := Total, completed := Completed, counters := Counters} = Summary,
    true = Total > 0,
    true = Completed =< Total,
    Completed = counter_sum(Counters),
    {ok, Status} = trawler:status(Ref),
    cancelled = maps:get(state, Status),
    ok.

cancel_after_done(_Config) ->
    {Socket, Port} = open_listener(),
    try
        {ok, Ref} = trawler:start_scan(<<"127.0.0.1">>, integer_to_binary(Port),
                                       #{}),
        _ = receive_until_done(Ref, 5000, []),
        {error, already_finished} = trawler:cancel(Ref)
    after
        ok = gen_tcp:close(Socket)
    end,
    ok.

unknown_ref(_Config) ->
    Ref = make_ref(),
    {error, not_found} = trawler:status(Ref),
    {error, not_found} = trawler:cancel(Ref),
    ok.

%%% ------------------------------------------------------------------
%%% Ошибки жизненного цикла и ввода
%%% ------------------------------------------------------------------

not_started(_Config) ->
    ok = application:stop(trawler),
    try
        {error, not_started} = trawler:start_scan(<<"127.0.0.1">>, <<"80">>, #{}),
        {error, not_started} = trawler:scan(<<"127.0.0.1">>, <<"80">>, #{})
    after
        {ok, _} = application:ensure_all_started(trawler)
    end,
    ok.

invalid_input(_Config) ->
    {error, {invalid_targets, _}} =
        trawler:start_scan(<<"">>, <<"80">>, #{}),
    {error, {invalid_ports, _}} =
        trawler:start_scan(<<"127.0.0.1">>, <<"0">>, #{}),
    {error, {invalid_options, _}} =
        trawler:start_scan(<<"127.0.0.1">>, <<"80">>, #{foo => 1}),
    {error, {invalid_options, recipient}} =
        trawler:start_scan(<<"127.0.0.1">>, <<"80">>, #{recipient => not_a_pid}),
    ok.

recipient_down(_Config) ->
    Recipient = spawn(fun() -> receive stop -> ok end end),
    {ok, Ref} = trawler:start_scan(<<"127.0.0.1">>, <<"1-5000">>,
                                   #{concurrency => 1, recipient => Recipient}),
    exit(Recipient, kill),
    ok = wait_not_found(Ref, 2000).

owner_down(_Config) ->
    TestPid = self(),
    Owner = spawn(fun() ->
        {ok, Ref} = trawler:start_scan(<<"127.0.0.1">>, <<"1-5000">>,
                                       #{concurrency => 1,
                                         recipient => TestPid}),
        TestPid ! {ref, Ref},
        receive stop -> ok end
    end),
    Ref = receive {ref, R} -> R after 2000 -> ct:fail(no_ref) end,
    %% Сканирование ещё активно: успеваем получить хотя бы одно событие.
    ok = wait_for_event(Ref, 2000),
    exit(Owner, kill),
    ok = wait_not_found(Ref, 2000).

%%% ------------------------------------------------------------------
%%% Предельный срок и сохранность ящика вызывающего
%%% ------------------------------------------------------------------

deadline_exceeded(_Config) ->
    %% Синхронно: 5000 портов с concurrency 1 не успевают за 50 мс,
    %% поэтому возвращается ошибка, а не частичный список результатов.
    {error, deadline_exceeded} =
        trawler:scan(<<"127.0.0.1">>, <<"1-5000">>,
                     #{concurrency => 1, deadline_ms => 50}),
    %% Асинхронно: результаты приходят как обычно, а терминальным
    %% событием оказывается error с причиной deadline_exceeded.
    {ok, Ref} = trawler:start_scan(<<"127.0.0.1">>, <<"1-5000">>,
                                   #{concurrency => 1, deadline_ms => 50,
                                     recipient => self()}),
    {_Results, Summary} = receive_until_error(Ref, 5000, [], deadline_exceeded),
    #{total := Total, completed := Completed, counters := Counters} = Summary,
    true = Total > 0,
    true = Completed =< Total,
    Completed = counter_sum(Counters),
    {ok, Status} = trawler:status(Ref),
    failed = maps:get(state, Status),
    ok.

sync_preserves_foreign_messages(_Config) ->
    {Socket, Port} = open_listener(),
    try
        Self = self(),
        %% Постороннее сообщение кладём в ящик до синхронного вызова.
        Self ! {foreign, marker},
        {ok, [_]} = trawler:scan(<<"127.0.0.1">>, integer_to_binary(Port), #{}),
        %% Selective receive процесса сбора не должен поглотить сообщение.
        receive
            {foreign, marker} -> ok
        after 1000 ->
            ct:fail(foreign_message_lost)
        end
    after
        ok = gen_tcp:close(Socket)
    end,
    ok.

%%% ------------------------------------------------------------------
%%% Вспомогательные функции
%%% ------------------------------------------------------------------

%% Локальный слушающий сокет на loopback; вызывающий закрывает его.
open_listener() ->
    {ok, Socket} = gen_tcp:listen(
                     0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(Socket),
    {Socket, Port}.

%% Резервирует и сразу освобождает порт: он остаётся закрытым.
reserve_closed_port() ->
    {ok, Socket} = gen_tcp:listen(
                     0, [binary, {ip, {127, 0, 0, 1}}, {active, false}]),
    {ok, Port} = inet:port(Socket),
    ok = gen_tcp:close(Socket),
    Port.

%% Принимает результаты до завершающего события done.
receive_until_done(Ref, Timeout, Acc) ->
    receive
        {trawler, Ref, {result, Result}} ->
            receive_until_done(Ref, Timeout, [Result | Acc]);
        {trawler, Ref, {done, Summary}} ->
            {lists:reverse(Acc), Summary}
    after Timeout ->
        ct:fail(no_done_event)
    end.

%% Принимает результаты до терминального события error с ожидаемой
%% причиной; порядок гарантирован FIFO сообщений координатора.
receive_until_error(Ref, Timeout, Acc, Reason) ->
    receive
        {trawler, Ref, {result, Result}} ->
            receive_until_error(Ref, Timeout, [Result | Acc], Reason);
        {trawler, Ref, {error, Reason, Summary}} ->
            {lists:reverse(Acc), Summary}
    after Timeout ->
        ct:fail(no_error_event)
    end.

%% Проверяет, что после завершающего события результатов не приходит.
ensure_no_more(Ref, Timeout) ->
    receive
        {trawler, Ref, _Event} -> ct:fail(event_after_done)
    after Timeout ->
        ok
    end.

%% Опрашивает status/1, накапливая результаты и снимки состояния.
poll_until_done(Ref, Deadline, Results, Statuses) ->
    Collected = drain_results(Ref, Results),
    case take_done(Ref) of
        {done, Summary} ->
            {lists:reverse(Collected), Summary, lists:reverse(Statuses)};
        pending ->
            case trawler:status(Ref) of
                {ok, Status} ->
                    case now_ms() > Deadline of
                        true ->
                            ct:fail(scan_timeout);
                        false ->
                            timer:sleep(5),
                            poll_until_done(Ref, Deadline, Collected,
                                            [Status | Statuses])
                    end;
                {error, Other} ->
                    ct:fail({status_error, Other})
            end
    end.

drain_results(Ref, Acc) ->
    receive
        {trawler, Ref, {result, Result}} -> drain_results(Ref, [Result | Acc])
    after 0 ->
        Acc
    end.

take_done(Ref) ->
    receive
        {trawler, Ref, {done, Summary}} -> {done, Summary}
    after 0 ->
        pending
    end.

%% Счётчики по исходам, включая нулевые значения для невстреченных.
state_counts(Results) ->
    Zero = #{open => 0, closed => 0, timeout => 0, unreachable => 0, error => 0},
    lists:foldl(fun(Result, Acc) ->
        Key = maps:get(state, Result),
        maps:update_with(Key, fun(N) -> N + 1 end, Acc)
    end, Zero, Results).

counter_sum(Counters) ->
    lists:sum(maps:values(maps:with([open, closed, timeout, unreachable, error],
                                    Counters))).

wait_for_event(Ref, Timeout) ->
    receive
        {trawler, Ref, _Event} -> ok
    after Timeout ->
        ct:fail(no_event)
    end.

%% Ожидает исчезновения ссылки из реестра.
wait_not_found(Ref, Timeout) ->
    wait_not_found_loop(Ref, now_ms() + Timeout).

wait_not_found_loop(Ref, Deadline) ->
    case trawler:status(Ref) of
        {error, not_found} ->
            ok;
        {ok, _Status} ->
            case now_ms() > Deadline of
                true -> ct:fail(still_present);
                false ->
                    timer:sleep(10),
                    wait_not_found_loop(Ref, Deadline)
            end
    end.

now_ms() ->
    erlang:monotonic_time(millisecond).
