%%%-------------------------------------------------------------------
%%% @doc Одна TCP-проба методом connect и чистая классификация исхода.
%%%
%%% Модуль не создаёт процессов и не хранит состояния: {@link run/3}
%%% выполняет одно соединение через `gen_tcp:connect/4' с таймаутом и
%%% возвращает карту результата. {@link classify/1} — чистая функция
%%% перевода ответа `gen_tcp:connect/4' в состояние пробы.
%%%
%%% Время измеряется монотонные часы
%%% ({@link erlang:monotonic_time/1}), поэтому `elapsed_ms' не зависит
%%% от изменения системных часов.
%%%
%%% Таймаут TCP не доказывает недоступность узла: состояние `timeout'
%%% означает только отсутствие ответа за отведённое время.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_probe).

-export([run/3, classify/1]).

-export_type([probe_result/0]).

-type ip4() :: {0..255, 0..255, 0..255, 0..255}.
-type probe_state() :: open | closed | timeout | unreachable | error.
-type probe_result() :: #{ip := ip4(),
                          port := 1..65535,
                          state := probe_state(),
                          elapsed_ms := non_neg_integer(),
                          reason => atom()}.

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

%% @doc Переводит ответ `gen_tcp:connect/4' в состояние пробы.
-spec classify(ok | {error, term()}) -> probe_state().
classify(ok) -> open;
classify({error, econnrefused}) -> closed;
classify({error, timeout}) -> timeout;
classify({error, enetunreach}) -> unreachable;
classify({error, ehostunreach}) -> unreachable;
classify({error, _}) -> error.

%% @doc Выполняет одну TCP-пробу по адресу `IP' и порту `Port'.
%%
%% Открывает соединение с таймаутом `TimeoutMs' миллисекунд. При
%% успешном подключении сокет сразу закрывается. Поле `reason' в
%% результате присутствует только для состояний `unreachable' и
%% `error'.
-spec run(ip4(), 1..65535, pos_integer()) -> probe_result().
run(IP, Port, TimeoutMs) ->
    Start = erlang:monotonic_time(millisecond),
    Result = gen_tcp:connect(IP, Port, [binary, {active, false}], TimeoutMs),
    Elapsed = erlang:monotonic_time(millisecond) - Start,
    build_result(IP, Port, Elapsed, Result).

%%% ------------------------------------------------------------------
%%% Внутренние функции
%%% ------------------------------------------------------------------

build_result(IP, Port, Elapsed, {ok, Socket}) ->
    ok = gen_tcp:close(Socket),
    #{ip => IP, port => Port, state => open, elapsed_ms => Elapsed};
build_result(IP, Port, Elapsed, {error, Reason}) ->
    State = classify({error, Reason}),
    Base = #{ip => IP, port => Port, state => State, elapsed_ms => Elapsed},
    case State of
        unreachable -> Base#{reason => Reason};
        error -> Base#{reason => Reason};
        _ -> Base
    end.
