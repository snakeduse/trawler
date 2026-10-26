%%%-------------------------------------------------------------------
%%% @doc Координатор одного обнаружения хостов IPv4.
%%%
%%% Временный `gen_server' под {@link trawler_discovery_sup}. На каждый
%%% уникальный адрес выдаётся один воркер; число одновременных воркеров
%%% ограничено `concurrency' и глобальным планировщиком
%%% {@link trawler_scheduler}, один слот которого покрывает активную
%%% пробу/сокет адреса. Адреса хранятся кортежем с курсором, полное
%%% произведение не материализуется.
%%%
%%% Воркер сначала спрашивает маршрут ядра
%%% ({@link trawler_discovery_route:lookup/1}), затем выполняет
%%% {@link trawler_discovery_probe:run/3} с остатком бюджета адреса
%%% `timeout_ms' (маршрут входит в бюджет; итоговый `elapsed_ms' считается
%%% от старта воркера). Воркер линкуется и мониторится: результат
%%% приходит до `DOWN', а падение воркера без результата синтезирует
%%% `error' с причиной `worker_failed', поэтому адрес не теряется.
%%%
%%% После подтверждения `up' тот же воркер в том же слоте и с тем же
%%% абсолютным сроком выполняет
%%% {@link trawler_host_inspection:inspect/4}: явный набор портов и
%%% необязательную классификацию ОС. Дополнительные ошибки не меняют
%%% `up'; неожиданное исключение сохраняет `up' и добавляет
%%% `inspection_error'. Сокет инспектора принадлежит воркеру, поэтому
%%% отмена, deadline и остановка приложения закрывают его вместе с
%%% процессом, а слот планировщика освобождается после `DOWN'.
%%%
%%% Координатор перехватывает выходы (`trap_exit') и следит за владельцем
%%% и получателем. Отмена, deadline, выход владельца/получателя и
%%% остановка приложения останавливают воркеры, снимают мониторы и
%%% возвращают каждый слот планировщика ровно один раз; ожидающее
%%% разрешение отзывается и сливается через упорядоченный барьер
%%% планировщика, без произвольных пауз. Ровно одно завершающее событие
%%% (`done', `cancelled', `error') отправляется получателю; после него
%%% выдача прекращается. Статус хранится 60 секунд, затем координатор
%%% останавливается.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_scan).

-behaviour(gen_server).

%% Публичный API
-export([start_link/1, cancel/1, status/1]).
%% Обратные вызовы gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-export_type([status_map/0, summary_map/0, result_map/0, state_name/0]).

-type ip4() :: {0..255, 0..255, 0..255, 0..255}.
-type result_state() :: up | no_response | error.
-type state_name() :: queued | running | completed | cancelled | failed.

%% Счётчики по исходам адресов.
-type counters() :: #{up := non_neg_integer(),
                      no_response := non_neg_integer(),
                      error := non_neg_integer()}.

%% Результат одного адреса. `method' присутствует у `up', `mac' — у ARP,
%% `port' — у TCP, `rtt_ms' — у подтверждённой первой отправки, `reason'
%% — у `error'. `port_results'/`open_ports' появляются при явном наборе,
%% `os' — при классификации, `inspection_error' — при неожиданной ошибке
%% инспектора без потери `up'.
-type result_map() :: #{ip := ip4(),
                        state := result_state(),
                        elapsed_ms := non_neg_integer(),
                        method => atom(),
                        mac => binary(),
                        port => 1..65535,
                        rtt_ms => non_neg_integer(),
                        reason => term(),
                        port_results =>
                            [trawler_host_inspection:port_result()],
                        open_ports => [trawler_host_inspection:tcp_port()],
                        os => trawler_host_inspection:os_map(),
                        inspection_error => term()}.

%% Снимок состояния обнаружения.
-type status_map() :: #{state := state_name(),
                        total := non_neg_integer(),
                        completed := non_neg_integer(),
                        counters := counters(),
                        warnings := [tcp_fallback]}.

%% Итоговая сводка завершающего события.
-type summary_map() :: #{total := non_neg_integer(),
                         completed := non_neg_integer(),
                         counters := counters(),
                         elapsed_ms := non_neg_integer(),
                         warnings := [tcp_fallback]}.

%% Нормализованные опции координатора (получатель и метод всегда заданы).
-type options() :: #{method := auto | arp | icmp | tcp | raw_tcp,
                     timeout_ms := pos_integer(),
                     concurrency := pos_integer(),
                     retries := 0..5,
                     deadline_ms := pos_integer() | infinity,
                     recipient := pid(),
                     caps := trawler_discovery_probe:caps(),
                     os_detection => boolean(),
                     ports => [1..65535],
                     probe_ports => [1..65535]}.

-type state() :: #{status := state_name(),
                   total := non_neg_integer(),
                   completed := non_neg_integer(),
                   counters := counters(),
                   cursor := non_neg_integer(),
                   active := non_neg_integer(),
                   monitors := #{reference() => #{ip := ip4(), pid := pid()}},
                   reported := #{ip4() => result_map()},
                   pending := boolean(),
                   cancelled := boolean(),
                   method := atom(),
                   caps := trawler_discovery_probe:caps(),
                   retries := 0..5,
                   ports := [1..65535] | undefined,
                   probe_ports := [1..65535] | undefined,
                   os_detection := boolean(),
                   timing := trawler_discovery_timing:state(),
                   start_time := integer(),
                   ref := reference(),
                   addrs := tuple(),
                   options := options(),
                   warnings := [tcp_fallback],
                   recipient := pid(),
                   owner := pid(),
                   parent => pid() | undefined,
                   owner_mon := reference(),
                   recipient_mon := reference(),
                   deadline_tref := reference() | undefined}.

%% Время хранения завершённого статуса до остановки координатора, мс.
-define(STATUS_TTL, 60000).

%% Страховочный предел ожидания DOWN остановленных воркеров, мс.
%% `DOWN' для убитого связанного процесса приходит гарантированно, поэтому
%% таймаут нужен только чтобы не зависнуть при аномалии.
-define(WORKER_DOWN_TIMEOUT_MS, 5000).

%% Предел ожидания ответа планировщика на барьер, мс.
-define(SCHEDULER_BARRIER_TIMEOUT_MS, 5000).

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

%% @doc Запускает координатор обнаружения.
%%
%% `Args' содержит `ref' (ссылка обнаружения), список уникальных адресов
%% `addrs', карту `options', список `warnings' и pid `owner'.
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_server:start_link(?MODULE, Args, []).

%% @doc Отменяет активное обнаружение.
%%
%% Идемпотентно для уже отменённого обнаружения (`ok'); для завершённого
%% или неуспешного возвращает `{error, already_finished}'.
-spec cancel(pid()) -> ok | {error, already_finished}.
cancel(Pid) ->
    gen_server:call(Pid, cancel).

%% @doc Возвращает текущее состояние и счётчики обнаружения.
-spec status(pid()) -> status_map().
status(Pid) ->
    gen_server:call(Pid, status).

%%% ------------------------------------------------------------------
%%% Обратные вызовы gen_server
%%% ------------------------------------------------------------------

-spec init(map()) -> {ok, state()}.
init(#{ref := Ref, addrs := Addrs, options := Options,
       warnings := Warnings, owner := Owner}) ->
    %% Координатор под supervision: перехватываем выходы, чтобы terminate/2
    %% выполнил очистку при остановке приложения.
    process_flag(trap_exit, true),
    Recipient = maps:get(recipient, Options),
    Parent = parent_pid(),
    AddrTuple = list_to_tuple(Addrs),
    Total = tuple_size(AddrTuple),
    State0 = #{status => queued,
               total => Total,
               completed => 0,
               counters => zero_counters(),
               cursor => 0,
               active => 0,
               monitors => #{},
               reported => #{},
               pending => false,
               cancelled => false,
               method => maps:get(method, Options),
               caps => maps:get(caps, Options),
               retries => maps:get(retries, Options),
               ports => maps:get(ports, Options, undefined),
               probe_ports => maps:get(probe_ports, Options, undefined),
               os_detection => maps:get(os_detection, Options, false),
               timing => trawler_discovery_timing:initial(
                           maps:get(timeout_ms, Options)),
               start_time => erlang:monotonic_time(millisecond),
               ref => Ref,
               addrs => AddrTuple,
               options => Options,
               warnings => Warnings,
               recipient => Recipient,
               owner => Owner,
               parent => Parent,
               owner_mon => erlang:monitor(process, Owner),
               recipient_mon => erlang:monitor(process, Recipient),
               deadline_tref => undefined},
    State1 = start_deadline(Options, State0),
    emit_warnings(Warnings, Ref, Recipient),
    case Total of
        0 ->
            {ok, finalize(completed, done, State1)};
        _ ->
            ok = trawler_scheduler:request(self()),
            {ok, State1#{pending := true}}
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
    {noreply, state()} | {stop, term(), state()}.
handle_info({trawler_scheduler, grant}, State) ->
    {noreply, handle_grant(State#{pending := false})};
handle_info({discovery_result, Ref, IP, Result}, #{ref := Ref} = State) ->
    {noreply, handle_result(IP, Result, State)};
handle_info({discovery_result, _OtherRef, _IP, _Result}, State) ->
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
handle_info({'EXIT', Pid, Reason}, #{parent := Parent} = State) ->
    case Pid =:= Parent of
        true ->
            %% Выход родителя/супервизора: очистка и остановка.
            {stop, Reason, cancel_for_lifecycle(State)};
        false ->
            %% Воркер или устаревший EXIT уже завершённого воркера.
            %% Координатор не останавливается: DOWN сам синтезирует
            %% error(worker_failed), если результат не пришёл, а поздний
            %% EXIT после DOWN не должен убивать оставшиеся воркеры.
            {noreply, State}
    end;
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
    best_effort(fun() ->
        case maps:find(ref, State) of
            {ok, Ref} -> trawler_discovery_registry:remove(Ref);
            error -> ok
        end
    end),
    best_effort(fun() -> cleanup(State) end),
    ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% ------------------------------------------------------------------
%%% Выдача заданий
%%% ------------------------------------------------------------------

%% Разрешение планировщика: либо запускаем один воркер, либо возвращаем
%% неиспользованное разрешение.
handle_grant(State) ->
    case can_take(State) of
        true -> start_worker(State);
        false ->
            ok = trawler_scheduler:release(),
            State
    end.

%% Запускает воркер следующего адреса и, если работа и ёмкость остались,
%% сразу запрашивает следующее разрешение.
start_worker(State) ->
    Cursor = maps:get(cursor, State),
    IP = element(Cursor + 1, maps:get(addrs, State)),
    Ref = maps:get(ref, State),
    Coordinator = self(),
    ProbeOpts = probe_options(State),
    InspectionOpts = inspection_options(State),
    Budget = maps:get(timeout_ms, maps:get(options, State)),
    {Pid, Mon} = spawn_opt(fun() ->
        worker(IP, Ref, Coordinator, ProbeOpts, InspectionOpts, Budget)
    end, [link, monitor]),
    Monitors = maps:put(Mon, #{ip => IP, pid => Pid}, maps:get(monitors, State)),
    Status = case maps:get(status, State) of
                 queued -> running;
                 Other -> Other
             end,
    State1 = State#{cursor := Cursor + 1,
                    active := maps:get(active, State) + 1,
                    monitors := Monitors,
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
        maps:get(cursor, State) < maps:get(total, State) andalso
        maps:get(active, State) < concurrency(State).

can_take(State) ->
    can_request(State).

%%% ------------------------------------------------------------------
%%% Воркер адреса
%%% ------------------------------------------------------------------

%% Воркер: маршрут, проба и дополнительные проверки делят один
%% абсолютный срок Deadline = Start + timeout_ms. Поиск маршрута
%% ограничен остатком бюджета (route:lookup/2), поэтому даже медленный
%% netlink не отодвигает пробу за пределы timeout_ms. Исчерпанный бюджет
%% даёт no_response (не error): время адреса вышло без подтверждения.
worker(IP, Ref, Coordinator, ProbeOpts, InspectionOpts, Budget) ->
    Start = erlang:monotonic_time(millisecond),
    Deadline = Start + Budget,
    Result0 = worker_probe(IP, ProbeOpts, Deadline),
    Result1 = inspect_after_up(IP, Result0, InspectionOpts, Deadline),
    Result = Result1#{elapsed_ms => elapsed(Start)},
    Coordinator ! {discovery_result, Ref, IP, Result}.

worker_probe(IP, ProbeOpts, Deadline) ->
    case remaining(Deadline) of
        Remaining when Remaining > 0 ->
            case trawler_discovery_route:lookup(IP, Remaining) of
                {ok, Route} ->
                    case remaining(Deadline) of
                        Remaining2 when Remaining2 > 0 ->
                            trawler_discovery_probe:run(
                              IP, Route, ProbeOpts#{timeout_ms => Remaining2});
                        _Exhausted ->
                            no_response_result(IP)
                    end;
                {error, Reason} ->
                    case remaining(Deadline) of
                        Left when Left > 0 ->
                            #{ip => IP, state => error, elapsed_ms => 0,
                              reason => Reason};
                        _Exhausted ->
                            no_response_result(IP)
                    end
            end;
        _Exhausted ->
            no_response_result(IP)
    end.

%% Дополнительные проверки выполняются только для подтверждённого адреса,
%% в том же процессе и с тем же абсолютным сроком. Пустой набор опций
%% возвращает пустую карту без сети.
inspect_after_up(_IP, #{state := State} = Result, _InspectionOpts, _Deadline)
  when State =/= up ->
    Result;
inspect_after_up(IP, Result, #{ports := Ports, os_detection := OSDetection},
                 Deadline) ->
    case safe_inspect(IP, Ports, OSDetection, Deadline) of
        {ok, Extra} ->
            maps:merge(Result, Extra);
        {error, Cause} ->
            %% Неожиданная ошибка инспектора не скрывает найденный хост:
            %% up сохраняется, явные порты получают skipped, ОС unknown.
            Extra = fallback_inspection(IP, Ports, OSDetection),
            maps:merge(Result, Extra#{inspection_error => Cause})
    end.

safe_inspect(IP, Ports, OSDetection, Deadline) ->
    try
        {ok, trawler_host_inspection:inspect(IP, Ports, OSDetection, Deadline)}
    catch
        Class:Reason ->
            {error, {Class, Reason}}
    end.

%% Запасные наблюдения строятся самостоятельно, без повторного вызова
%% инспектора: если модуль падает постоянно, второй вызов снова бросил
%% бы исключение и потерял обязательные запрошенные поля. Сокеты не
%% открываются, формы дополнительных полей сохраняются: явные порты
%% получают `skipped', запрошенная ОС — `unknown/none'.
fallback_inspection(_IP, undefined, false) ->
    #{};
fallback_inspection(_IP, undefined, true) ->
    #{os => unknown_os()};
fallback_inspection(_IP, Ports, OSDetection) when is_list(Ports) ->
    Base = #{port_results => skipped_rows(Ports), open_ports => []},
    case OSDetection of
        true -> Base#{os => unknown_os()};
        false -> Base
    end.

skipped_rows(Ports) ->
    [#{port => Port, state => skipped, elapsed_ms => 0,
       reason => inspection_error}
     || Port <- lists:sort(Ports)].

unknown_os() ->
    #{family => unknown, confidence => none, evidence => []}.

remaining(Deadline) ->
    Deadline - erlang:monotonic_time(millisecond).

elapsed(Start) ->
    max(0, erlang:monotonic_time(millisecond) - Start).

no_response_result(IP) ->
    #{ip => IP, state => no_response, elapsed_ms => 0}.

%%% ------------------------------------------------------------------
%%% Результаты и выходы воркеров
%%% ------------------------------------------------------------------

%% Результат до DOWN: сохраняем до обработки уведомления monitor и
%% переносим подтверждённый RTT в оценку ожидания для следующих адресов
%% (только при наличии rtt_ms — правило Карна).
handle_result(IP, Result, State) ->
    case is_active(State) of
        true ->
            Reported = maps:put(IP, Result, maps:get(reported, State)),
            observe_timing(Result, State#{reported := Reported});
        false ->
            State
    end.

observe_timing(Result, State) ->
    case maps:find(rtt_ms, Result) of
        {ok, Rtt} when is_integer(Rtt), Rtt >= 0 ->
            Timing = trawler_discovery_timing:observe(maps:get(timing, State),
                                                      Rtt),
            State#{timing := Timing};
        _Other ->
            State
    end.

%% DOWN воркера: результат берётся из сохранённого либо синтезируется
%% error(worker_failed); слот освобождается ровно один раз.
handle_worker_down(Mon, State) ->
    Monitors = maps:get(monitors, State),
    case maps:take(Mon, Monitors) of
        {#{ip := IP}, Rest} ->
            Reported = maps:get(reported, State),
            Result = case maps:find(IP, Reported) of
                         {ok, Stored} -> Stored;
                         error -> error_result(IP, worker_failed)
                     end,
            ok = trawler_scheduler:release(),
            State1 = State#{monitors := Rest,
                            active := max(maps:get(active, State) - 1, 0),
                            reported := maps:remove(IP, Reported)},
            State2 = case is_active(State1) of
                         true -> record_result(Result, State1);
                         false -> State1
                     end,
            maybe_advance(State2);
        error ->
            State
    end.

%% Считает адрес завершённым: событие результата, счётчик, completed.
record_result(Result, State) ->
    Key = maps:get(state, Result),
    Recipient = maps:get(recipient, State),
    Ref = maps:get(ref, State),
    Recipient ! {trawler_discovery, Ref, {result, Result}},
    Counters = maps:update_with(Key, fun(N) -> N + 1 end,
                                maps:get(counters, State)),
    State#{completed := maps:get(completed, State) + 1, counters := Counters}.

%% Решает, завершить обнаружение или запросить следующее задание.
maybe_advance(State) ->
    case is_active(State) of
        true ->
            Cursor = maps:get(cursor, State),
            Total = maps:get(total, State),
            Active = maps:get(active, State),
            case Cursor >= Total andalso Active =:= 0 of
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
%%% Отмена, deadline и завершение
%%% ------------------------------------------------------------------

%% Отмена через API: очистка, затем ровно одно событие cancelled.
do_cancel(State) ->
    State1 = cleanup(State#{status := cancelled, cancelled := true}),
    demonitor_lifecycles(State1),
    Summary = summary(State1),
    emit_terminal(cancelled, Summary, State1),
    schedule_shutdown(),
    State1.

%% Истечение предельного срока обнаружения.
handle_deadline(State) ->
    case is_active(State) of
        true ->
            State1 = cleanup(State#{cancelled := true}),
            finalize(failed, {error, deadline_exceeded}, State1);
        false ->
            State
    end.

%% Выход владельца/получателя или родителя: очистка без завершающего
%% события, немедленная остановка.
cancel_for_lifecycle(State) ->
    cleanup(State#{cancelled := true, status := cancelled}).

%% Очистка ресурсов: остановка воркеров, снятие мониторов, освобождение
%% каждого слота ровно один раз, отзыв и слив ожидающего разрешения.
%% Идемпотентна (повторный вызов при пустых мониторах — no-op).
cleanup(State) ->
    Monitors = maps:get(monitors, State),
    Pids = [Pid || #{pid := Pid} <- maps:values(Monitors)],
    _ = [catch exit(Pid, kill) || Pid <- Pids],
    ok = retract_pending(),
    ok = drain_workers(Monitors),
    ok = flush_worker_exits(Pids),
    cancel_deadline(State#{monitors := #{},
                           reported := #{},
                           active := 0,
                           pending := false}).

%% Отзывает ожидающее разрешение и дожидается обработки планировщиком
%% через барьер, затем сливает уже выданное разрешение. Без произвольных
%% пауз и без изменения поведения планировщика.
retract_pending() ->
    best_effort(fun() -> trawler_scheduler:retract(self()) end),
    best_effort(fun() ->
        gen_server:call(trawler_scheduler, barrier, ?SCHEDULER_BARRIER_TIMEOUT_MS)
    end),
    drain_grants().

%% Возвращает уже выданные, но неиспользованные разрешения.
drain_grants() ->
    receive
        {trawler_scheduler, grant} ->
            _ = catch trawler_scheduler:release(),
            drain_grants()
    after 0 ->
        ok
    end.

%% Дожидается DOWN каждого остановленного воркера и освобождает его слот
%% ровно один раз. Для убитого связанного процесса DOWN приходит
%% гарантированно, таймаут — только страховка.
drain_workers(Monitors) ->
    maps:foreach(
      fun(Mon, #{pid := Pid}) ->
          receive
              {'DOWN', Mon, process, Pid, _Reason} -> ok
          after ?WORKER_DOWN_TIMEOUT_MS -> ok
          end,
          _ = catch trawler_scheduler:release()
      end, Monitors),
    ok.

%% Снимает EXIT-уведомления об остановленных воркерах.
flush_worker_exits(Pids) ->
    lists:foreach(
      fun(Pid) ->
          receive
              {'EXIT', Pid, _Reason} -> ok
          after 0 -> ok
          end
      end, Pids),
    ok.

%% Terminal-переход: снимок сводки, завершающее событие, снятие
%% мониторов и запланированная остановка.
finalize(FinalStatus, Kind, State) ->
    State1 = cancel_deadline(State),
    Summary = summary(State1),
    emit_terminal(Kind, Summary, State1),
    demonitor_lifecycles(State1),
    schedule_shutdown(),
    State1#{status := FinalStatus}.

emit_terminal(done, Summary, State) ->
    emit({done, Summary}, State);
emit_terminal(cancelled, Summary, State) ->
    emit({cancelled, Summary}, State);
emit_terminal({error, Reason}, Summary, State) ->
    emit({error, Reason, Summary}, State).

emit(Event, State) ->
    Recipient = maps:get(recipient, State),
    Ref = maps:get(ref, State),
    Recipient ! {trawler_discovery, Ref, Event},
    ok.

%% Снимает мониторы владельца и получателя на терминальном переходе.
%% Иначе выход владельца/получателя после завершения (в течение TTL)
%% остановил бы координатор и стёр сохранённый статус раньше обещанного
%% срока хранения.
demonitor_lifecycles(State) ->
    _ = erlang:demonitor(maps:get(owner_mon, State), [flush]),
    _ = erlang:demonitor(maps:get(recipient_mon, State), [flush]),
    ok.

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

%% Родитель координатора: супервизор, запустивший процесс через
%% `supervisor:start_child/2'. Нужен, чтобы отличать выход супервизора от
%% позднего EXIT воркера.
parent_pid() ->
    case get('$ancestors') of
        [Parent | _Rest] when is_pid(Parent) -> Parent;
        _Other -> undefined
    end.

concurrency(State) ->
    maps:get(concurrency, maps:get(options, State)).

%% Опции пробы одного адреса: caps передаётся, чтобы не пересчитывать
%% capabilities/0 на каждый адрес; probe_ports включается только для
%% tcp/auto. Публичный явный набор `ports' в транспорт не передаётся:
%% для arp/icmp/raw_tcp его там быть не должно, а инспектор получает его
%% отдельно. Timing переносит оценку RTT между адресами, не сокращая
%% жёсткий бюджет.
probe_options(State) ->
    Base = #{method => maps:get(method, State),
             caps => maps:get(caps, State),
             retries => maps:get(retries, State),
             timing => maps:get(timing, State)},
    case maps:get(probe_ports, State) of
        undefined -> Base;
        Ports -> Base#{ports => Ports}
    end.

%% Полные явные порты и флаг классификации для того же воркера.
inspection_options(State) ->
    #{ports => maps:get(ports, State),
      os_detection => maps:get(os_detection, State)}.

status_map(State) ->
    #{state => maps:get(status, State),
      total => maps:get(total, State),
      completed => maps:get(completed, State),
      counters => maps:get(counters, State),
      warnings => maps:get(warnings, State)}.

summary(State) ->
    #{total => maps:get(total, State),
      completed => maps:get(completed, State),
      counters => maps:get(counters, State),
      elapsed_ms => erlang:monotonic_time(millisecond)
                    - maps:get(start_time, State),
      warnings => maps:get(warnings, State)}.

zero_counters() ->
    #{up => 0, no_response => 0, error => 0}.

error_result(IP, Reason) ->
    #{ip => IP, state => error, elapsed_ms => 0, reason => Reason}.

emit_warnings(Warnings, Ref, Recipient) ->
    _ = [Recipient ! {trawler_discovery, Ref, {warning, Warning}}
         || Warning <- Warnings],
    ok.

best_effort(Fun) ->
    try
        _ = Fun(),
        ok
    catch
        _:_ -> ok
    end.
