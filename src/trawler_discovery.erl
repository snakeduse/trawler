%%%-------------------------------------------------------------------
%%% @doc Фасад обнаружения IPv4-хостов.
%%%
%%% Нормализует цели, порты и опции, проверяет доступность raw-методов
%%% (без отправки пакетов) и запускает координатор
%%% {@link trawler_discovery_scan} под {@link trawler_discovery_sup}.
%%% Асинхронный {@link start/2} возвращает ссылку и потоково отправляет
%%% события получателю; синхронный {@link run/2} собирает сортированные
%%% результаты в отдельном процессе, не затрагивая ящик вызывающего.
%%%
%%% Публичный вход для приложений — функции {@link trawler:start_discovery/2},
%%% {@link trawler:discover/2}, {@link trawler:discovery_status/1} и
%%% {@link trawler:cancel_discovery/1}; они делегируют сюда. Для работы
%%% OTP-приложение `trawler' должно быть запущено, иначе возвращается
%%% `{error, not_started}'.
%%%
%%% Пример синхронного обнаружения на loopback:
%%% ```
%%% {ok, Results, Summary} = trawler_discovery:run(<<"127.0.0.1">>,
%%%                                                #{method => tcp,
%%%                                                  ports => [80, 443]}).
%%% '''
%%%
%%% Пример асинхронного обнаружения:
%%% ```
%%% {ok, Ref} = trawler_discovery:start(<<"127.0.0.1">>,
%%%                                     #{method => tcp, ports => [80]}),
%%% receive
%%%     {trawler_discovery, Ref, {result, Result}} -> Result;
%%%     {trawler_discovery, Ref, {done, Summary}} -> Summary
%%% end.
%%% '''
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery).

%% Публичный контракт.
-export([start/2, run/2, status/1, cancel/1]).

-export_type([discovery_ref/0, method/0, options/0, result/0, status/0,
              summary/0, counters/0, result_state/0, state_name/0, event/0]).

-type ip4() :: {0..255, 0..255, 0..255, 0..255}.
-type discovery_ref() :: reference().
-type method() :: auto | arp | icmp | tcp | raw_tcp.
-type result_state() :: up | no_response | error.
-type state_name() :: queued | running | completed | cancelled | failed.

%% Результат одного адреса; `method' присутствует у `up', `mac' — у ARP,
%% `port' — у TCP, `rtt_ms' — у подтверждённой первой отправки, `reason'
%% — у `error'.
-type result() :: #{ip := ip4(),
                    state := result_state(),
                    elapsed_ms := non_neg_integer(),
                    method => local | arp | icmp_echo | icmp_timestamp
                            | tcp_syn | tcp_ack | tcp_open | tcp_refused,
                    mac => binary(),
                    port => 1..65535,
                    rtt_ms => non_neg_integer(),
                    reason => term()}.

-type counters() :: #{up := non_neg_integer(),
                      no_response := non_neg_integer(),
                      error := non_neg_integer()}.

%% Сводка завершающего события.
-type summary() :: #{total := non_neg_integer(),
                     completed := non_neg_integer(),
                     counters := counters(),
                     elapsed_ms := non_neg_integer(),
                     warnings := [tcp_fallback]}.

%% Снимок состояния обнаружения.
-type status() :: #{state := state_name(),
                    total := non_neg_integer(),
                    completed := non_neg_integer(),
                    counters := counters(),
                    warnings := [tcp_fallback]}.

-type event() :: {result, result()}
               | {warning, tcp_fallback}
               | {done, summary()}
               | {cancelled, summary()}
               | {error, term(), summary()}.

%% Опции обнаружения. `recipient' — только для асинхронного API.
-type options() :: #{method => method(),
                     ports => trawler_targets:ports_input(),
                     timeout_ms => pos_integer(),
                     concurrency => pos_integer(),
                     retries => 0..5,
                     deadline_ms => pos_integer() | infinity,
                     recipient => pid()}.

-define(DEFAULT_TIMEOUT_MS, 1000).
-define(DEFAULT_CONCURRENCY, 64).
-define(DEFAULT_RETRIES, 2).
-define(MAX_RETRIES, 5).
-define(DEFAULT_MAX_CONCURRENCY, 256).
-define(MAX_PORTS, 16).
%% Порты TCP-обнаружения по умолчанию: меньше, чем у сканирования.
-define(DEFAULT_DISCOVERY_PORTS, [80, 443]).

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

%% @doc Запускает асинхронное обнаружение.
%%
%% Возвращает ссылку обнаружения. События вида
%% `{trawler_discovery, Ref, Event}' получает процесс из опции
%% `recipient' (по умолчанию вызывающий): `{result, Result}',
%% `{warning, tcp_fallback}', ровно одно из `{done, Summary}',
%% `{cancelled, Summary}' или `{error, Reason, Summary}'.
-spec start(trawler_targets:targets_input(), options()) ->
          {ok, discovery_ref()} | {error, term()}.
start(Targets, Options) ->
    case application_started() of
        false ->
            {error, not_started};
        true ->
            case prepare(Targets, Options, async) of
                {ok, Ref, Addrs, Opts, Warnings} ->
                    case start_child(Ref, Addrs, Opts, Warnings, self()) of
                        {ok, _Pid} -> {ok, Ref};
                        {error, _} = Error -> Error
                    end;
                {error, _} = Error ->
                    Error
            end
    end.

%% @doc Выполняет обнаружение и возвращает сортированные результаты и сводку.
%%
%% Результаты собирает отдельный процесс сбора; посторонние сообщения
%% вызывающего сохраняются. При истечении предельного срока возвращается
%% `{error, deadline_exceeded}', а не частичный список.
-spec run(trawler_targets:targets_input(), options()) ->
          {ok, [result()], summary()} | {error, term()}.
run(Targets, Options) ->
    case application_started() of
        false ->
            {error, not_started};
        true ->
            case prepare(Targets, Options, sync) of
                {ok, Ref, Addrs, Opts, Warnings} ->
                    Owner = self(),
                    Collector = spawn(fun() ->
                        collect_loop(Ref, Owner, Addrs, Opts, Warnings)
                    end),
                    Mon = erlang:monitor(process, Collector),
                    receive
                        {Collector, Reply} ->
                            _ = erlang:demonitor(Mon, [flush]),
                            Reply;
                        {'DOWN', Mon, process, Collector, Reason} ->
                            {error, Reason}
                    end;
                {error, _} = Error ->
                    Error
            end
    end.

%% @doc Возвращает состояние и счётчики обнаружения.
%%
%% Для неизвестной или устаревшей ссылки возвращает `{error, not_found}'.
-spec status(discovery_ref()) -> {ok, status()} | {error, not_found}.
status(Ref) ->
    case trawler_discovery_registry:lookup(Ref) of
        {ok, Pid} ->
            try gen_server:call(Pid, status) of
                Status -> {ok, Status}
            catch
                exit:_ -> {error, not_found}
            end;
        {error, not_found} ->
            {error, not_found}
    end.

%% @doc Отменяет активное обнаружение.
%%
%% Идемпотентно для уже отменённого (`ok'); для завершённого или
%% неуспешного возвращает `{error, already_finished}', для неизвестной
%% ссылки — `{error, not_found}'.
-spec cancel(discovery_ref()) ->
          ok | {error, not_found | already_finished}.
cancel(Ref) ->
    case trawler_discovery_registry:lookup(Ref) of
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
%%% Синхронный сбор
%%% ------------------------------------------------------------------

%% Собирает события до завершающего, сортирует результаты по адресу и
%% возвращает владельцу. Посторонние сообщения не читаются: их получает
%% другой процесс.
collect_loop(Ref, Owner, Addrs, Opts, Warnings) ->
    CollectorOpts = Opts#{recipient => self()},
    case start_child(Ref, Addrs, CollectorOpts, Warnings, Owner) of
        {ok, Pid} ->
            MonCoord = erlang:monitor(process, Pid),
            MonOwner = erlang:monitor(process, Owner),
            collect(Ref, Owner, Pid, MonCoord, MonOwner, []);
        {error, Reason} ->
            Owner ! {self(), {error, Reason}}
    end.

collect(Ref, Owner, Pid, MonCoord, MonOwner, Acc) ->
    receive
        {trawler_discovery, Ref, {result, Result}} ->
            collect(Ref, Owner, Pid, MonCoord, MonOwner, [Result | Acc]);
        {trawler_discovery, Ref, {warning, _Warning}} ->
            collect(Ref, Owner, Pid, MonCoord, MonOwner, Acc);
        {trawler_discovery, Ref, {done, Summary}} ->
            finish_collect(Owner, MonCoord, MonOwner,
                           {ok, sort_results(Acc), Summary});
        {trawler_discovery, Ref, {cancelled, _Summary}} ->
            finish_collect(Owner, MonCoord, MonOwner, {error, cancelled});
        {trawler_discovery, Ref, {error, Reason, _Summary}} ->
            finish_collect(Owner, MonCoord, MonOwner, {error, Reason});
        {'DOWN', MonCoord, process, Pid, Reason} ->
            finish_collect(Owner, MonCoord, MonOwner, {error, Reason});
        {'DOWN', MonOwner, process, Owner, _Reason} ->
            %% Владелец ушёл: сбор завершается без ответа.
            ok
    end.

finish_collect(Owner, MonCoord, MonOwner, Reply) ->
    _ = erlang:demonitor(MonCoord, [flush]),
    _ = erlang:demonitor(MonOwner, [flush]),
    Owner ! {self(), Reply},
    ok.

%% Порядок результатов: по возрастанию числового IPv4-адреса.
sort_results(Results) ->
    lists:sort(
      fun(A, B) ->
          trawler_targets:ip_to_int(maps:get(ip, A))
              =< trawler_targets:ip_to_int(maps:get(ip, B))
      end, Results).

%%% ------------------------------------------------------------------
%%% Подготовка запроса
%%% ------------------------------------------------------------------

%% Проверяет опции, цели и порты, считает caps один раз и применяет
%% prepare/2; ничего не отправляет и не открывает raw-сокетов до проверок.
prepare(Targets, Options, Mode) ->
    case validate_options(Options, Mode) of
        {error, _} = Error ->
            Error;
        {ok, Norm} ->
            prepare_targets(Targets, Norm, Mode)
    end.

prepare_targets(Targets, Norm, Mode) ->
    case trawler_targets:parse_targets(Targets) of
        {error, _} = Error ->
            Error;
        {ok, Ranges} ->
            Method = maps:get(method, Norm),
            case discovery_ports(Method, Norm) of
                {error, _} = Error ->
                    Error;
                {ok, Ports} ->
                    prepare_caps(Targets, Norm, Mode, Ranges, Method, Ports)
            end
    end.

prepare_caps(_Targets, Norm, Mode, Ranges, Method, Ports) ->
    Caps = trawler_discovery_probe:capabilities(),
    case trawler_discovery_probe:prepare(Method, Caps) of
        {error, _} = Error ->
            Error;
        {ok, _Effective, Warnings} ->
            Ref = make_ref(),
            Base = with_recipient(Norm#{caps => Caps},
                                  recipient(Mode, Norm)),
            Opts = case Ports of
                       undefined -> Base;
                       _ -> Base#{ports => Ports}
                   end,
            {ok, Ref, expand_addrs(Ranges), Opts, Warnings}
    end.

recipient(sync, _Norm) ->
    undefined;
recipient(async, Norm) ->
    maps:get(recipient, Norm).

%% Разворачивает включительные диапазоны адресов в список IPv4-кортежей
%% в порядке возрастания; parse_targets уже вернул уникальные адреса.
expand_addrs(Ranges) ->
    Ints = lists:append(
             [lists:seq(trawler_targets:ip_to_int(First),
                        trawler_targets:ip_to_int(Last))
              || {First, Last} <- Ranges]),
    [trawler_targets:int_to_ip(Int) || Int <- Ints].

%%% ------------------------------------------------------------------
%%% Запуск координатора
%%% ------------------------------------------------------------------

start_child(Ref, Addrs, Opts, Warnings, Owner) ->
    Args = #{ref => Ref,
             addrs => Addrs,
             options => Opts,
             warnings => Warnings,
             owner => Owner},
    ChildSpec = #{id => Ref,
                  start => {trawler_discovery_scan, start_link, [Args]},
                  restart => temporary,
                  shutdown => 5000,
                  type => worker,
                  modules => [trawler_discovery_scan]},
    case supervisor:start_child(trawler_discovery_sup, ChildSpec) of
        {ok, Pid} ->
            ok = trawler_discovery_registry:put(Ref, Pid),
            {ok, Pid};
        {error, _} = Error ->
            Error
    end.

%%% ------------------------------------------------------------------
%%% Проверка опций
%%% ------------------------------------------------------------------

validate_options(Options, Mode) when is_map(Options) ->
    Known = [method, ports, timeout_ms, concurrency, retries, deadline_ms,
             recipient],
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
    Method = maps:get(method, Options, auto),
    case valid_method(Method) of
        false ->
            {error, {invalid_options, {method, Method}}};
        true ->
            case validate_recipient(Options, Mode) of
                {error, _} = Error ->
                    Error;
                {ok, Recipient} ->
                    build_options(Options, Method, Recipient)
            end
    end.

validate_recipient(Options, async) ->
    case maps:get(recipient, Options, self()) of
        Recipient when is_pid(Recipient) -> {ok, Recipient};
        _Other -> {error, {invalid_options, recipient}}
    end;
validate_recipient(_Options, sync) ->
    {ok, undefined}.

build_options(Options, Method, Recipient) ->
    Timeout = maps:get(timeout_ms, Options, ?DEFAULT_TIMEOUT_MS),
    Concurrency = maps:get(concurrency, Options, ?DEFAULT_CONCURRENCY),
    Retries = maps:get(retries, Options, ?DEFAULT_RETRIES),
    Deadline = maps:get(deadline_ms, Options, infinity),
    case valid_timeout(Timeout) of
        false ->
            {error, {invalid_options, {timeout_ms, Timeout}}};
        true ->
            case valid_concurrency(Concurrency) of
                false ->
                    {error, {invalid_options, {concurrency, Concurrency}}};
                true ->
                    case valid_retries(Retries) of
                        false ->
                            {error, {invalid_options, {retries, Retries}}};
                        true ->
                            case valid_deadline(Deadline) of
                                false ->
                                    {error, {invalid_options,
                                             {deadline_ms, Deadline}}};
                                true ->
                                    Norm0 = #{method => Method,
                                              timeout_ms => Timeout,
                                              concurrency => clamp_concurrency(
                                                               Concurrency),
                                              retries => Retries,
                                              deadline_ms => Deadline},
                                    Norm = with_ports(Norm0, Options),
                                    {ok, with_recipient(Norm, Recipient)}
                            end
                    end
            end
    end.

%% Сырой ввод портов сохраняется в нормализованных опциях, чтобы
%% discovery_ports/2 мог либо разобрать его для tcp/auto, либо отклонить
%% для методов без TCP — намерение пользователя не теряется молча.
with_ports(Norm, Options) ->
    case maps:find(ports, Options) of
        {ok, Ports} -> Norm#{ports => Ports};
        error -> Norm
    end.

with_recipient(Norm, undefined) -> Norm;
with_recipient(Norm, Recipient) -> Norm#{recipient => Recipient}.

valid_method(Method) ->
    lists:member(Method, [auto, arp, icmp, tcp, raw_tcp]).

valid_timeout(Timeout) when is_integer(Timeout), Timeout > 0 -> true;
valid_timeout(_) -> false.

valid_concurrency(Concurrency) when is_integer(Concurrency), Concurrency > 0 ->
    true;
valid_concurrency(_) -> false.

valid_retries(Retries) when is_integer(Retries),
                            Retries >= 0, Retries =< ?MAX_RETRIES -> true;
valid_retries(_) -> false.

valid_deadline(infinity) -> true;
valid_deadline(Deadline) when is_integer(Deadline), Deadline > 0 -> true;
valid_deadline(_) -> false.

clamp_concurrency(Concurrency) ->
    min(Concurrency, global_max_concurrency()).

global_max_concurrency() ->
    case application:get_env(trawler, max_concurrency,
                             ?DEFAULT_MAX_CONCURRENCY) of
        Limit when is_integer(Limit), Limit >= 1 -> Limit;
        _ -> ?DEFAULT_MAX_CONCURRENCY
    end.

%%% ------------------------------------------------------------------
%%% Порты и служебные функции
%%% ------------------------------------------------------------------

%% Порты допустимы только для явного TCP connect. Для `tcp' без ключа
%% используется набор по умолчанию [80,443]; явный ввод разбирается
%% существующим parser'ом (атом default даёт 1000 портов и отклоняется
%% как too_many_ports, без молчаливой подмены значения). Для auto, arp,
%% icmp и raw_tcp ключ ports отклоняется: auto сам выбирает методы, а
%% явные порты здесь не подразумеваются.
discovery_ports(tcp, Norm) ->
    Input = maps:get(ports, Norm, ?DEFAULT_DISCOVERY_PORTS),
    case trawler_targets:parse_ports(Input) of
        {error, _} = Error ->
            Error;
        {ok, Ranges} ->
            Ports = lists:usort(flatten_ports(Ranges)),
            case length(Ports) =< ?MAX_PORTS of
                true -> {ok, Ports};
                false -> {error, {invalid_options,
                                  {too_many_ports, length(Ports)}}}
            end
    end;
discovery_ports(_Method, Norm) ->
    case maps:is_key(ports, Norm) of
        true -> {error, {invalid_options, ports}};
        false -> {ok, undefined}
    end.

flatten_ports(Ranges) ->
    lists:append([lists:seq(First, Last) || {First, Last} <- Ranges]).

application_started() ->
    lists:keymember(trawler, 1, application:which_applications()).
