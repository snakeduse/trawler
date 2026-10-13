%%%-------------------------------------------------------------------
%% @doc Публичный Erlang API TCP-сканера IPv4.
%%
%% Одно ядро сканирования обслуживает Erlang-приложения и CLI.
%% Асинхронный API {@link start_scan/3} отправляет результаты
%% выбранному локальному процессу, синхронный {@link scan/3} собирает
%% их в отдельном процессе сбора и возвращает отсортированными.
%% {@link status/1} показывает прогресс, {@link cancel/1} идемпотентно
%% отменяет активное сканирование.
%%
%% Пример синхронного сканирования:
%% ```
%% {ok, _} = application:ensure_all_started(trawler),
%% {ok, Results} = trawler:scan(<<"127.0.0.1">>, <<"22,80,443">>, #{}),
%% [maps:get(state, R) || R <- Results].
%% '''
%%
%% Пример асинхронного сканирования:
%% ```
%% {ok, Ref} = trawler:start_scan(<<"192.0.2.0/30">>, <<"22,80">>, #{}),
%% receive
%%     {trawler, Ref, {result, Result}} -> Result;
%%     {trawler, Ref, {done, Summary}} -> Summary
%% end.
%% '''
%%
%% Для всех функций OTP-приложение должно быть запущено; иначе
%% возвращается `{error, not_started}'. Ссылки сканирования —
%% непрозрачные `reference()', действующие только в текущей
%% виртуальной машине. Запрос полностью проверяется до любых
%% сетевых операций.
%% @end
%%%-------------------------------------------------------------------
-module(trawler).

-export([start_scan/3, scan/3, status/1, cancel/1]).

-export_type([scan_ref/0, options/0, result/0, status/0, summary/0,
              result_state/0, scan_state/0]).

-type scan_ref() :: reference().
-type result_state() :: open | closed | timeout | unreachable | error.
-type scan_state() :: queued | running | completed | cancelled | failed.

-type ip4() :: {0..255, 0..255, 0..255, 0..255}.

%% Результат одной пробы; `reason' присутствует только для состояний
%% `unreachable' и `error'.
-type result() :: #{ip := ip4(),
                    port := 1..65535,
                    state := result_state(),
                    elapsed_ms := non_neg_integer(),
                    reason => atom()}.

-type counters() :: #{open := non_neg_integer(),
                      closed := non_neg_integer(),
                      timeout := non_neg_integer(),
                      unreachable := non_neg_integer(),
                      error := non_neg_integer()}.

%% Итоговая сводка завершающего асинхронного события.
-type summary() :: #{total := non_neg_integer(),
                     completed := non_neg_integer(),
                     counters := counters(),
                     elapsed_ms := non_neg_integer()}.

%% Снимок состояния сканирования.
-type status() :: #{state := scan_state(),
                    total := non_neg_integer(),
                    completed := non_neg_integer(),
                    counters := counters()}.

%% Опции сканирования. `recipient' используется только асинхронным API.
-type options() :: #{timeout_ms => pos_integer(),
                     concurrency => pos_integer(),
                     deadline_ms => pos_integer() | infinity,
                     recipient => pid()}.

-define(DEFAULT_TIMEOUT_MS, 1000).
-define(DEFAULT_CONCURRENCY, 64).
-define(DEFAULT_MAX_CONCURRENCY, 256).

%%% ------------------------------------------------------------------
%%% Асинхронный API
%%% ------------------------------------------------------------------

%% @doc Запускает асинхронное сканирование.
%%
%% Проверяет опции, адреса и порты, затем запускает координатор под
%% {@link trawler_scan_sup} и регистрирует ссылку сканирования.
%% Результаты и ровно одно завершающее событие получает процесс из
%% опции `recipient' (по умолчанию вызывающий процесс):
%% `{trawler, ScanRef, {result, Result}}',
%% `{trawler, ScanRef, {done, Summary}}',
%% `{trawler, ScanRef, {cancelled, Summary}}',
%% `{trawler, ScanRef, {error, Reason, Summary}}'.
-spec start_scan(trawler_targets:targets_input(),
                 trawler_targets:ports_input(),
                 options()) -> {ok, scan_ref()} | {error, term()}.
start_scan(Targets, Ports, Options) ->
    case application_started() of
        false ->
            {error, not_started};
        true ->
            case validate_options(Options, async) of
                {ok, Opts} -> start_scan_child(Targets, Ports, Opts);
                {error, _} = Error -> Error
            end
    end.

%%% ------------------------------------------------------------------
%%% Синхронный API
%%% ------------------------------------------------------------------

%% @doc Выполняет сканирование и возвращает все наблюдения.
%%
%% Результаты собираются отдельным процессом сбора и сортируются по
%% числовому IPv4-адресу, затем по порту. Посторонние сообщения
%% вызывающего процесса сохраняются. При истечении предельного срока
%% возвращается `{error, deadline_exceeded}', а не частичный список.
-spec scan(trawler_targets:targets_input(),
           trawler_targets:ports_input(),
           options()) -> {ok, [result()]} | {error, term()}.
scan(Targets, Ports, Options) ->
    case application_started() of
        false ->
            {error, not_started};
        true ->
            scan_started(Targets, Ports, Options)
    end.

%%% ------------------------------------------------------------------
%%% Статус и отмена
%%% ------------------------------------------------------------------

%% @doc Возвращает состояние и счётчики сканирования.
%%
%% Для неизвестной или устаревшей ссылки возвращает
%% `{error, not_found}'.
-spec status(scan_ref()) -> {ok, status()} | {error, not_found}.
status(Ref) ->
    case trawler_scan_registry:lookup(Ref) of
        {ok, Pid} ->
            try gen_server:call(Pid, status) of
                Status -> {ok, Status}
            catch
                exit:_ -> {error, not_found}
            end;
        {error, not_found} ->
            {error, not_found}
    end.

%% @doc Отменяет активное сканирование.
%%
%% Идемпотентно для уже отменённого сканирования (`ok'); для
%% завершённого или неуспешного возвращает `{error, already_finished}',
%% для неизвестной ссылки — `{error, not_found}'.
-spec cancel(scan_ref()) -> ok | {error, not_found | already_finished}.
cancel(Ref) ->
    case trawler_scan_registry:lookup(Ref) of
        {ok, Pid} ->
            try gen_server:call(Pid, cancel) of
                Reply -> Reply
            catch
                exit:_ -> {error, not_found}
            end;
        {error, not_found} ->
            {error, not_found}
    end.

%%% ------------------------------------------------------------------
%%% Внутренние функции
%%% ------------------------------------------------------------------

application_started() ->
    lists:keymember(trawler, 1, application:which_applications()).

%% Проверяет запрос и запускает координатор (общий шаг для обоих API).
start_scan_child(Targets, Ports, Opts) ->
    case trawler_targets:parse_targets(Targets) of
        {ok, AddrRanges} ->
            case trawler_targets:parse_ports(Ports) of
                {ok, PortRanges} ->
                    Ref = make_ref(),
                    Owner = self(),
                    case start_coordinator(Ref, AddrRanges, PortRanges,
                                           Opts, Owner) of
                        {ok, _Pid} -> {ok, Ref};
                        {error, _} = Error -> Error
                    end;
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end.

scan_started(Targets, Ports, Options) ->
    case validate_options(Options, sync) of
        {ok, Opts} ->
            case trawler_targets:parse_targets(Targets) of
                {ok, AddrRanges} ->
                    case trawler_targets:parse_ports(Ports) of
                        {ok, PortRanges} ->
                            Ref = make_ref(),
                            Owner = self(),
                            Collector = spawn(fun() ->
                                sync_collect(Ref, Owner, AddrRanges,
                                             PortRanges, Opts)
                            end),
                            receive
                                {Collector, Reply} -> Reply
                            end;
                        {error, _} = Error -> Error
                    end;
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end.

%% Запускает временного дочернего координатора и регистрирует ссылку.
start_coordinator(Ref, AddrRanges, PortRanges, Opts, Owner) ->
    Args = #{ref => Ref,
             targets => AddrRanges,
             ports => PortRanges,
             options => Opts,
             owner => Owner},
    ChildSpec = #{id => Ref,
                  start => {trawler_scan, start_link, [Args]},
                  restart => temporary,
                  shutdown => 5000,
                  type => worker,
                  modules => [trawler_scan]},
    case supervisor:start_child(trawler_scan_sup, ChildSpec) of
        {ok, Pid} ->
            ok = trawler_scan_registry:put(Ref, Pid),
            {ok, Pid};
        {error, _} = Error ->
            Error
    end.

%%% ------------------------------------------------------------------
%%% Процесс сбора синхронного API
%%% ------------------------------------------------------------------

%% Запускает координатор с получателем-собой и передаёт владельцу
%% первый же ответ: `{ok, Results}', `{error, Reason}' и т. п.
sync_collect(Ref, Owner, AddrRanges, PortRanges, Opts) ->
    CollectorOpts = Opts#{recipient => self()},
    case start_coordinator(Ref, AddrRanges, PortRanges, CollectorOpts, Owner) of
        {ok, Pid} ->
            MonCoordinator = erlang:monitor(process, Pid),
            MonOwner = erlang:monitor(process, Owner),
            collect_loop(Ref, Owner, Pid, MonCoordinator, MonOwner, []);
        {error, Reason} ->
            Owner ! {self(), {error, Reason}}
    end.

collect_loop(Ref, Owner, Pid, MonCoordinator, MonOwner, Acc) ->
    receive
        {trawler, Ref, {result, Result}} ->
            collect_loop(Ref, Owner, Pid, MonCoordinator, MonOwner,
                         [Result | Acc]);
        {trawler, Ref, {done, _Summary}} ->
            finish_collect(Owner, MonCoordinator, MonOwner,
                           {ok, lists:sort(fun compare_results/2, Acc)});
        {trawler, Ref, {cancelled, _Summary}} ->
            finish_collect(Owner, MonCoordinator, MonOwner,
                           {error, cancelled});
        {trawler, Ref, {error, Reason, _Summary}} ->
            finish_collect(Owner, MonCoordinator, MonOwner, {error, Reason});
        {'DOWN', MonCoordinator, process, Pid, Reason} ->
            finish_collect(Owner, MonCoordinator, MonOwner, {error, Reason});
        {'DOWN', MonOwner, process, Owner, _Reason} ->
            %% Владелец ушёл: сбор завершается без ответа.
            ok
    end.

finish_collect(Owner, MonCoordinator, MonOwner, Reply) ->
    _ = erlang:demonitor(MonCoordinator, [flush]),
    _ = erlang:demonitor(MonOwner, [flush]),
    Owner ! {self(), Reply},
    ok.

%% Порядок результатов: по числовому IPv4-адресу, затем по порту.
compare_results(A, B) ->
    AddrA = trawler_targets:ip_to_int(maps:get(ip, A)),
    AddrB = trawler_targets:ip_to_int(maps:get(ip, B)),
    case AddrA =:= AddrB of
        true -> maps:get(port, A) =< maps:get(port, B);
        false -> AddrA < AddrB
    end.

%%% ------------------------------------------------------------------
%%% Проверка опций
%%% ------------------------------------------------------------------

validate_options(Options, Mode) when is_map(Options) ->
    Known = [timeout_ms, concurrency, deadline_ms, recipient],
    case unknown_key(maps:keys(Options), Known) of
        ok -> validate_values(Options, Mode);
        {error, _} = Error -> Error
    end;
validate_options(Options, _Mode) ->
    {error, {invalid_options, Options}}.

unknown_key([], _Known) ->
    ok;
unknown_key([Key | Rest], Known) ->
    case lists:member(Key, Known) of
        true -> unknown_key(Rest, Known);
        false -> {error, {invalid_options, {unknown_option, Key}}}
    end.

validate_values(Options, Mode) ->
    Timeout = maps:get(timeout_ms, Options, ?DEFAULT_TIMEOUT_MS),
    Concurrency = maps:get(concurrency, Options, ?DEFAULT_CONCURRENCY),
    Deadline = maps:get(deadline_ms, Options, infinity),
    case valid_timeout(Timeout) of
        false ->
            {error, {invalid_options, {timeout_ms, Timeout}}};
        true ->
            case valid_concurrency(Concurrency) of
                false ->
                    {error, {invalid_options, {concurrency, Concurrency}}};
                true ->
                    case valid_deadline(Deadline) of
                        false ->
                            {error, {invalid_options, {deadline_ms, Deadline}}};
                        true ->
                            build_options(Options, Mode, Timeout,
                                          Concurrency, Deadline)
                    end
            end
    end.

build_options(_Options, sync, Timeout, Concurrency, Deadline) ->
    {ok, #{timeout_ms => Timeout,
           concurrency => clamp_concurrency(Concurrency),
           deadline_ms => Deadline}};
build_options(Options, async, Timeout, Concurrency, Deadline) ->
    case maps:get(recipient, Options, self()) of
        Recipient when is_pid(Recipient) ->
            {ok, #{timeout_ms => Timeout,
                   concurrency => clamp_concurrency(Concurrency),
                   deadline_ms => Deadline,
                   recipient => Recipient}};
        _Other ->
            {error, {invalid_options, recipient}}
    end.

valid_timeout(Timeout) when is_integer(Timeout), Timeout > 0 -> true;
valid_timeout(_) -> false.

valid_concurrency(Concurrency) when is_integer(Concurrency), Concurrency > 0 ->
    true;
valid_concurrency(_) -> false.

valid_deadline(infinity) -> true;
valid_deadline(Deadline) when is_integer(Deadline), Deadline > 0 -> true;
valid_deadline(_) -> false.

%% Индивидуальный лимит не может превышать глобальный.
clamp_concurrency(Concurrency) ->
    min(Concurrency, global_max_concurrency()).

global_max_concurrency() ->
    case application:get_env(trawler, max_concurrency,
                             ?DEFAULT_MAX_CONCURRENCY) of
        Limit when is_integer(Limit), Limit >= 1 -> Limit;
        _ -> ?DEFAULT_MAX_CONCURRENCY
    end.
