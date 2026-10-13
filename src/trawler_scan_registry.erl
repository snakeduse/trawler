%%%-------------------------------------------------------------------
%%% @doc Реестр ссылок сканирований и их координаторов.
%%%
%%% Один `gen_server' на всю виртуальную машину, зарегистрированный
%%% локально под именем `trawler_scan_registry'. Хранит соответствие
%%% непрозрачной ссылки сканирования (`reference()') и pid процесса
%%% {@link trawler_scan}. Ссылки действуют только в текущей
%%% виртуальной машине.
%%%
%%% {@link lookup/1} считает запись отсутствующей, если её нет или если
%%% связанный с ней процесс уже мёртв; мёртвая запись при этом удаляется.
%%% {@link remove/1} идемпотентна.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_scan_registry).

-behaviour(gen_server).

%% Публичный API
-export([start_link/0, put/2, lookup/1, remove/1]).
%% Обратные вызовы gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-type state() :: #{entries := #{reference() => pid()}}.

%% init/1 возвращает пустой реестр: тип поля шире пустой карты, которую
%% выводит анализатор, поэтому предупреждение underspecs подавлено.
-dialyzer({no_underspecs, [init/1]}).

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

%% @doc Запускает реестр под локальным именем `trawler_scan_registry'.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Записывает соответствие `Ref' -> `Pid'.
%%
%% Повторная запись той же ссылки перезаписывает прежний pid.
-spec put(reference(), pid()) -> ok.
put(Ref, Pid) when is_reference(Ref), is_pid(Pid) ->
    gen_server:call(?MODULE, {put, Ref, Pid}).

%% @doc Возвращает pid координатора по ссылке сканирования.
%%
%% Если записи нет или связанный процесс уже не жив, возвращает
%% `{error, not_found}'. Мёртвая запись удаляется.
-spec lookup(reference()) -> {ok, pid()} | {error, not_found}.
lookup(Ref) when is_reference(Ref) ->
    gen_server:call(?MODULE, {lookup, Ref}).

%% @doc Удаляет запись по ссылке сканирования. Идемпотентно.
-spec remove(reference()) -> ok.
remove(Ref) when is_reference(Ref) ->
    gen_server:call(?MODULE, {remove, Ref}).

%%% ------------------------------------------------------------------
%%% Обратные вызовы gen_server
%%% ------------------------------------------------------------------

-spec init([]) -> {ok, state()}.
init([]) ->
    {ok, #{entries => maps:new()}}.

-spec handle_call(term(), gen_server:from(), state()) ->
    {reply, term(), state()}.
handle_call({put, Ref, Pid}, _From, State) ->
    Entries = maps:put(Ref, Pid, maps:get(entries, State)),
    {reply, ok, State#{entries := Entries}};
handle_call({lookup, Ref}, _From, State) ->
    Entries = maps:get(entries, State),
    case maps:find(Ref, Entries) of
        {ok, Pid} ->
            case is_process_alive(Pid) of
                true ->
                    {reply, {ok, Pid}, State};
                false ->
                    {reply, {error, not_found},
                     State#{entries := maps:remove(Ref, Entries)}}
            end;
        error ->
            {reply, {error, not_found}, State}
    end;
handle_call({remove, Ref}, _From, State) ->
    Entries = maps:remove(Ref, maps:get(entries, State)),
    {reply, ok, State#{entries := Entries}};
handle_call(_Request, _From, State) ->
    {reply, {error, not_found}, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
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
