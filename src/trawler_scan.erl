%%%-------------------------------------------------------------------
%%% @doc Координатор одного сканирования.
%%%
%%% Временный `gen_server' под {@link trawler_scan_sup}. Хранит только
%%% нормализованные выборки адресов и портов и счётчики по исходам:
%%% полное декартово произведение «адреса x порты» не материализуется.
%%% Задания выдаются по одному через глобальный планировщик
%%% {@link trawler_scheduler}, воркеры поднимаются через
%%% `spawn_monitor' и вызывают {@link trawler_probe:run/3}.
%%%
%%% Координатор следит через monitor за процессом-владельцем и
%%% получателем результатов. Выход любого из них прекращает
%%% оставшуюся работу и освобождает ресурсы. Ровно одно завершающее
%%% событие отправляется получателю: `done', `cancelled' или `error'.
%%% После завершения статус хранится 60 секунд, затем координатор
%%% останавливается.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_scan).

-behaviour(gen_server).

%% Публичный API
-export([start_link/1, cancel/1, status/1]).
%% Обратные вызовы gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-export_type([status_map/0, summary_map/0, result_map/0, state_name/0]).

-type ip4() :: {0..255, 0..255, 0..255, 0..255}.
-type result_state() :: open | closed | timeout | unreachable | error.
-type state_name() :: queued | running | completed | cancelled | failed.

%% Сводка по исходам проб.
-type counters() :: #{open := non_neg_integer(),
                      closed := non_neg_integer(),
                      timeout := non_neg_integer(),
                      unreachable := non_neg_integer(),
                      error := non_neg_integer()}.

%% Результат одной пробы; `reason' присутствует только для состояний
%% `unreachable' и `error'.
-type result_map() :: #{ip := ip4(),
                        port := 1..65535,
                        state := result_state(),
                        elapsed_ms := non_neg_integer(),
                        reason => atom()}.

%% Текущее состояние и счётчики сканирования.
-type status_map() :: #{state := state_name(),
                        total := non_neg_integer(),
                        completed := non_neg_integer(),
                        counters := counters()}.

%% Итоговая сводка завершающего события.
-type summary_map() :: #{total := non_neg_integer(),
                         completed := non_neg_integer(),
                         counters := counters(),
                         elapsed_ms := non_neg_integer()}.

%% Опции координатора (получатель всегда задан).
-type options() :: #{timeout_ms := pos_integer(),
                     concurrency := pos_integer(),
                     deadline_ms := pos_integer() | infinity,
                     recipient := pid()}.

-type state() :: #{status := state_name(),
                   total := non_neg_integer(),
                   completed := non_neg_integer(),
                   counters := counters(),
                   next := non_neg_integer(),
                   active := non_neg_integer(),
                   active_monitors := #{reference() => pid()},
                   pending := boolean(),
                   cancelled := boolean(),
                   start_time := integer(),
                   ref := reference(),
                   addrs := [non_neg_integer()],
                   ports := [1..65535],
                   np := pos_integer(),
                   options := options(),
                   recipient := pid(),
                   owner := pid(),
                   owner_mon := reference(),
                   recipient_mon := reference(),
                   deadline_tref := reference() | undefined}.

%% Время хранения завершённого статуса до остановки координатора, мс.
-define(STATUS_TTL, 60000).

%% Верхняя граница ожидания уже выданного разрешения при выходе
%% владельца или получателя, мс.
-define(GRANT_DRAIN_MS, 20).

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

%% @doc Запускает координатор сканирования.
%%
%% `Args' содержит `ref' (ссылка сканирования), нормализованные
%% `targets' и `ports', карту `options' и pid `owner'.
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%% @doc Отменяет активное сканирование.
%%
%% Идемпотентно для уже отменённого сканирования (`ok'); для
%% завершённого или неуспешного возвращает `{error, already_finished}'.
-spec cancel(pid()) -> ok | {error, already_finished}.
cancel(Pid) ->
    gen_server:call(Pid, cancel).

%% @doc Возвращает текущее состояние и счётчики сканирования.
-spec status(pid()) -> status_map().
status(Pid) ->
    gen_server:call(Pid, status).

%%% ------------------------------------------------------------------
%%% Обратные вызовы gen_server
%%% ------------------------------------------------------------------

-spec init(map()) -> {ok, state()}.
init(#{ref := Ref, targets := Targets, ports := Ports,
       options := Options, owner := Owner}) ->
    %% Координатор под supervision: перехватываем выходы, чтобы
    %% terminate/2 снял запись из реестра при остановке приложения.
    process_flag(trap_exit, true),
    Addrs = expand_addr_ranges(Targets),
    PortNums = expand_port_ranges(Ports),
    Total = length(Addrs) * length(PortNums),
    NP = length(PortNums),
    Recipient = maps:get(recipient, Options),
    State0 = #{status => queued,
               total => Total,
               completed => 0,
               counters => zero_counters(),
               next => 0,
               active => 0,
               active_monitors => #{},
               pending => false,
               cancelled => false,
               start_time => erlang:monotonic_time(millisecond),
               ref => Ref,
               addrs => Addrs,
               ports => PortNums,
               np => NP,
               options => Options,
               recipient => Recipient,
               owner => Owner,
               owner_mon => erlang:monitor(process, Owner),
               recipient_mon => erlang:monitor(process, Recipient),
               deadline_tref => undefined},
    State = start_deadline(Options, State0),
    case Total of
        0 ->
            {ok, finalize(completed, done, State)};
        _ ->
            ok = trawler_scheduler:request(self()),
            {ok, State#{pending := true}}
    end.

-spec handle_call(term(), gen_server:from(), state()) ->
    {reply, term(), state()}.
handle_call(status, _From, State) ->
    {reply, status_map(State), State};
handle_call(cancel, _From, State) ->
    case maps:get(status, State) of
        completed ->
            {reply, {error, already_finished}, State};
        failed ->
            {reply, {error, already_finished}, State};
        cancelled ->
            {reply, ok, State};
        _ ->
            {reply, ok, do_cancel(State)}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast(_Message, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) ->
    {noreply, state()} | {stop, normal, state()}.
handle_info({trawler_scheduler, grant}, State) ->
    {noreply, handle_grant(State#{pending := false})};
handle_info({probe_result, Ref, Result}, #{ref := Ref} = State) ->
    {noreply, handle_probe_result(Result, State)};
handle_info({probe_result, _OtherRef, _Result}, State) ->
    {noreply, State};
handle_info({'DOWN', _Mon, process, Pid, _Reason}, #{owner := Owner} = State)
  when Pid =:= Owner ->
    {stop, normal, cancel_for_lifecycle(State)};
handle_info({'DOWN', _Mon, process, Pid, _Reason},
            #{recipient := Recipient} = State)
  when Pid =:= Recipient ->
    {stop, normal, cancel_for_lifecycle(State)};
handle_info({'DOWN', Mon, process, _Pid, _Reason}, State) ->
    {noreply, handle_worker_down(Mon, State)};
handle_info({timeout, TRef, deadline}, #{deadline_tref := TRef} = State) ->
    {noreply, handle_deadline(State)};
handle_info({timeout, _TRef, deadline}, State) ->
    {noreply, State};
handle_info({timeout, _TRef, shutdown}, State) ->
    {stop, normal, State};
handle_info(shutdown, State) ->
    {stop, normal, State};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, State) ->
    try
        case maps:find(ref, State) of
            {ok, Ref} -> trawler_scan_registry:remove(Ref);
            error -> ok
        end
    catch
        _:_ -> ok
    end.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% ------------------------------------------------------------------
%%% Выдача заданий
%%% ------------------------------------------------------------------

%% Разрешение планировщика: либо запускаем одну пробу, либо возвращаем
%% неиспользованное разрешение.
handle_grant(State) ->
    case can_take(State) of
        true -> take_job(State);
        false ->
            ok = trawler_scheduler:release(),
            State
    end.

%% Запускает следующую пробу и, если работа ещё есть и ёмкость не
%% исчерпана, сразу запрашивает следующее разрешение.
take_job(State) ->
    Next = maps:get(next, State),
    NP = maps:get(np, State),
    Addrs = maps:get(addrs, State),
    PortNums = maps:get(ports, State),
    Addr = lists:nth(Next div NP + 1, Addrs),
    Port = lists:nth(Next rem NP + 1, PortNums),
    IP = trawler_targets:int_to_ip(Addr),
    Ref = maps:get(ref, State),
    Timeout = maps:get(timeout_ms, maps:get(options, State)),
    Coordinator = self(),
    {Pid, Mon} = spawn_monitor(fun() ->
        Result = trawler_probe:run(IP, Port, Timeout),
        Coordinator ! {probe_result, Ref, Result}
    end),
    Status = case maps:get(status, State) of
                 queued -> running;
                 Other -> Other
             end,
    State1 = State#{next := Next + 1,
                    active := maps:get(active, State) + 1,
                    active_monitors := maps:put(Mon, Pid,
                                                maps:get(active_monitors, State)),
                    status := Status,
                    pending := false},
    case can_request(State1) of
        true ->
            ok = trawler_scheduler:request(self()),
            State1#{pending := true};
        false ->
            State1
    end.

%% Есть ли работа и свободная индивидуальная ёмкость для нового запроса.
can_request(State) ->
    is_active(State) andalso
        maps:get(next, State) < maps:get(total, State) andalso
        maps:get(active, State) < concurrency(State).

%% Можно ли немедленно взять задание по полученному разрешению.
can_take(State) ->
    can_request(State).

%%% ------------------------------------------------------------------
%%% Результаты и выходы воркеров
%%% ------------------------------------------------------------------

handle_probe_result(Result, State) ->
    case is_active(State) of
        true ->
            Key = maps:get(state, Result),
            Recipient = maps:get(recipient, State),
            Ref = maps:get(ref, State),
            Recipient ! {trawler, Ref, {result, Result}},
            Counters = maps:update_with(Key, fun(N) -> N + 1 end,
                                        maps:get(counters, State)),
            State#{completed := maps:get(completed, State) + 1,
                   counters := Counters};
        false ->
            State
    end.

handle_worker_down(Mon, State) ->
    Monitors = maps:get(active_monitors, State),
    case maps:take(Mon, Monitors) of
        {_Pid, Rest} ->
            ok = trawler_scheduler:release(),
            State1 = State#{active_monitors := Rest,
                            active := max(maps:get(active, State) - 1, 0)},
            maybe_advance(State1);
        error ->
            State
    end.

%% Решает, завершить сканирование или запросить следующее задание.
maybe_advance(State) ->
    case is_active(State) of
        true ->
            Next = maps:get(next, State),
            Total = maps:get(total, State),
            Active = maps:get(active, State),
            case Next >= Total andalso Active =:= 0 of
                true ->
                    finalize(completed, done, State);
                false ->
                    case can_request(State) andalso not maps:get(pending, State) of
                        true ->
                            ok = trawler_scheduler:request(self()),
                            State#{pending := true};
                        false ->
                            State
                    end
            end;
        false ->
            State
    end.

%%% ------------------------------------------------------------------
%%% Отмена и завершение
%%% ------------------------------------------------------------------

%% Отмена через API: возвращаем ёмкость через DOWN-уведомления
%% убитых воркеров, отправляем событие `cancelled' и удерживаем статус.
do_cancel(State) ->
    kill_workers(State),
    ok = trawler_scheduler:retract(self()),
    State1 = cancel_deadline(State#{status := cancelled, cancelled := true}),
    Summary = summary(State1),
    Ref = maps:get(ref, State1),
    Recipient = maps:get(recipient, State1),
    Recipient ! {trawler, Ref, {cancelled, Summary}},
    schedule_shutdown(),
    State1.

%% Истечение предельного срока: та же очистка, но завершающее событие
%% `error' и статус `failed'.
handle_deadline(State) ->
    case is_active(State) of
        true ->
            kill_workers(State),
            ok = trawler_scheduler:retract(self()),
            State1 = State#{cancelled := true},
            finalize(failed, {error, deadline_exceeded}, State1);
        false ->
            State
    end.

%% Выход владельца или получателя: прекращаем оставшуюся работу без
%% завершающего события и сразу останавливаемся. DOWN-уведомления убитых
%% воркеров уже не будут обработаны, поэтому освобождаем удержанную
%% ёмкость планировщика вручную. Запрос разрешения мог быть удовлетворён
%% одновременно с этим выходом; так как запрос уходит в планировщик
%% раньше retract, короткое ожидание надёжно получает уже выданное
%% разрешение.
cancel_for_lifecycle(State) ->
    Active = maps:get(active, State),
    Pids = maps:values(maps:get(active_monitors, State)),
    _ = [catch exit(Pid, kill) || Pid <- Pids],
    _ = [trawler_scheduler:release() || _ <- lists:seq(1, Active)],
    ok = trawler_scheduler:retract(self()),
    ok = drain_grants(),
    cancel_deadline(State#{cancelled := true,
                           status := cancelled,
                           active := 0,
                           active_monitors := #{}}).

%% Останавливает активные воркеры, не дожидаясь их DOWN: ёмкость
%% освободится при обработке соответствующих уведомлений monitor.
kill_workers(State) ->
    Pids = maps:values(maps:get(active_monitors, State)),
    _ = [catch exit(Pid, kill) || Pid <- Pids],
    ok.

%% Возвращает уже выданные, но неиспользованные разрешения. Ожидание
%% ограничено, чтобы согласоваться с планировщиком, обрабатывающим
%% отправленные ранее запросы и retract.
drain_grants() ->
    receive
        {trawler_scheduler, grant} ->
            ok = trawler_scheduler:release(),
            drain_grants()
    after ?GRANT_DRAIN_MS ->
        ok
    end.

%% Terminal-переход: снимок сводки, завершающее событие, снятие
%% мониторов и запланированная остановка.
finalize(FinalStatus, Kind, State) ->
    State1 = cancel_deadline(State),
    Summary = summary(State1),
    Ref = maps:get(ref, State1),
    Recipient = maps:get(recipient, State1),
    Event = case Kind of
                done -> {trawler, Ref, {done, Summary}};
                {error, Reason} -> {trawler, Ref, {error, Reason, Summary}}
            end,
    Recipient ! Event,
    _ = erlang:demonitor(maps:get(owner_mon, State1), [flush]),
    _ = erlang:demonitor(maps:get(recipient_mon, State1), [flush]),
    schedule_shutdown(),
    State1#{status := FinalStatus}.

schedule_shutdown() ->
    _ = erlang:send_after(?STATUS_TTL, self(), shutdown),
    ok.

%%% ------------------------------------------------------------------
%%% Таймер предельного срока
%%% ------------------------------------------------------------------

start_deadline(Options, State) ->
    case maps:get(deadline_ms, Options) of
        infinity ->
            State;
        DeadlineMs when is_integer(DeadlineMs), DeadlineMs > 0 ->
            TRef = erlang:start_timer(DeadlineMs, self(), deadline),
            State#{deadline_tref := TRef}
    end.

cancel_deadline(State) ->
    case maps:get(deadline_tref, State) of
        undefined ->
            State;
        TRef ->
            _ = erlang:cancel_timer(TRef),
            State#{deadline_tref := undefined}
    end.

%%% ------------------------------------------------------------------
%%% Вспомогательные функции
%%% ------------------------------------------------------------------

is_active(State) ->
    not maps:get(cancelled, State) andalso
        case maps:get(status, State) of
            queued -> true;
            running -> true;
            _ -> false
        end.

concurrency(State) ->
    maps:get(concurrency, maps:get(options, State)).

status_map(State) ->
    #{state => maps:get(status, State),
      total => maps:get(total, State),
      completed => maps:get(completed, State),
      counters => maps:get(counters, State)}.

summary(State) ->
    #{total => maps:get(total, State),
      completed => maps:get(completed, State),
      counters => maps:get(counters, State),
      elapsed_ms => erlang:monotonic_time(millisecond)
                    - maps:get(start_time, State)}.

zero_counters() ->
    #{open => 0, closed => 0, timeout => 0, unreachable => 0, error => 0}.

%% Разворачивает нормализованные включительные диапазоны адресов в
%% список целых значений в порядке следования диапазонов.
expand_addr_ranges(Ranges) ->
    lists:append([lists:seq(trawler_targets:ip_to_int(First),
                            trawler_targets:ip_to_int(Last))
                  || {First, Last} <- Ranges]).

%% Разворачивает нормализованные включительные диапазоны портов.
expand_port_ranges(Ranges) ->
    lists:append([lists:seq(First, Last) || {First, Last} <- Ranges]).
