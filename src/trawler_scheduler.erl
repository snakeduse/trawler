%%%-------------------------------------------------------------------
%%% @doc Глобальный планировщик ограничения параллелизма сканирования.
%%%
%%% Планировщик — один `gen_server' на всю виртуальную машину,
%%% зарегистрированный локально под именем `trawler_scheduler'. Он
%%% выдаёт разрешения (grant) процессам сканирований так, чтобы общее
%%% число одновременно выполняемых проб не превышало лимит
%%% `max_concurrency' (по умолчанию 256, читается из окружения
%%% приложения `trawler' в {@link init/1}).
%%%
%%% Счётчик `in_flight' — число выданных, но ещё не освобождённых
%%% разрешений. Разрешение выдаётся, пока `in_flight < max'. Процесс
%%% сканирования получает сообщение `{trawler_scheduler, grant}'.
%%%
%%% Очередь `waiters' хранит процессы ожидания в порядке поступления
%%% (FIFO). Запрос одного процесса не может стоять в очереди дважды.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_scheduler).

-behaviour(gen_server).

%% Публичный API
-export([start_link/0, request/1, release/0, retract/1]).
%% Обратные вызовы gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-type state() :: #{max := non_neg_integer(),
                   in_flight := non_neg_integer(),
                   waiters := queue:queue(pid())}.

-define(DEFAULT_MAX_CONCURRENCY, 256).

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

%% @doc Запускает планировщик под локальным именем `trawler_scheduler'.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Ставит процесс сканирования `ScanPid' в очередь ожидания.
%%
%% Если есть свободная ёмкость, разрешение выдаётся немедленно; иначе
%% процесс становится в хвост очереди. Возвращает `ok' сразу, не
%% дожидаясь выдачи разрешения.
-spec request(pid()) -> ok.
request(ScanPid) when is_pid(ScanPid) ->
    gen_server:cast(?MODULE, {request, ScanPid}).

%% @doc Сообщает о завершении одной пробы.
%%
%% Освобождает ёмкость и выдаёт разрешение следующему ожидающему, если
%% оно доступно. Возвращает `ok' сразу.
-spec release() -> ok.
release() ->
    gen_server:cast(?MODULE, release).

%% @doc Убирает процесс `ScanPid' из очереди ожидания.
%%
%% Используется при отмене или завершении сканирования. Не трогает
%% счётчик выданных разрешений. Идемпотентно.
-spec retract(pid()) -> ok.
retract(ScanPid) when is_pid(ScanPid) ->
    gen_server:cast(?MODULE, {retract, ScanPid}).

%%% ------------------------------------------------------------------
%%% Обратные вызовы gen_server
%%% ------------------------------------------------------------------

-spec init([]) -> {ok, state()}.
init([]) ->
    {ok, #{max => max_concurrency(), in_flight => 0, waiters => queue:new()}}.

-spec handle_call(term(), gen_server:from(), state()) -> {reply, ok, state()}.
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast({request, ScanPid}, State) ->
    Waiters = drop_pid(ScanPid, maps:get(waiters, State)),
    case maps:get(in_flight, State) < maps:get(max, State) of
        true ->
            grant(ScanPid),
            {noreply, State#{in_flight := maps:get(in_flight, State) + 1,
                             waiters := Waiters}};
        false ->
            {noreply, State#{waiters := queue:in(ScanPid, Waiters)}}
    end;
handle_cast(release, State) ->
    InFlight = maps:get(in_flight, State),
    {noreply, drain(State#{in_flight := max(InFlight - 1, 0)})};
handle_cast({retract, ScanPid}, State) ->
    {noreply, State#{waiters := drop_pid(ScanPid, maps:get(waiters, State))}};
handle_cast(_Message, State) ->
    {noreply, State}.

-spec handle_info(term(), state()) -> {noreply, state()}.
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), state()) -> ok.
terminate(_Reason, _State) ->
    ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%% ------------------------------------------------------------------
%%% Внутренние функции
%%% ------------------------------------------------------------------

%% Выдаёт разрешения, пока есть свободная ёмкость и непустая очередь.
drain(State) ->
    case maps:get(in_flight, State) < maps:get(max, State) of
        true ->
            case queue:out(maps:get(waiters, State)) of
                {{value, ScanPid}, Waiters} ->
                    grant(ScanPid),
                    drain(State#{in_flight := maps:get(in_flight, State) + 1,
                                 waiters := Waiters});
                {empty, _Waiters} ->
                    State
            end;
        false ->
            State
    end.

%% Удаляет все вхождения процесса из очереди ожидания.
drop_pid(ScanPid, Waiters) ->
    queue:filter(fun(Pid) -> Pid =/= ScanPid end, Waiters).

grant(ScanPid) ->
    ScanPid ! {?MODULE, grant},
    ok.

max_concurrency() ->
    case application:get_env(trawler, max_concurrency,
                             ?DEFAULT_MAX_CONCURRENCY) of
        Limit when is_integer(Limit), Limit >= 0 -> Limit;
        _ -> ?DEFAULT_MAX_CONCURRENCY
    end.
