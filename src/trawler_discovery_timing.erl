%%%-------------------------------------------------------------------
%%% @doc Политика ожидания ответа и адаптация к RTT для обнаружения.
%%%
%%% Модуль чистый и детерминированный: он не читает часов и не работает
%%% с сетью, а только пересчитывает оценку времени кругового обхода по
%%% формуле RFC 6298. Транспортный уровень
%%% ({@link trawler_discovery_probe}) берёт из состояния `rto/1' как
%%% ориентир ожидания и, получив подтверждённый ответ, передаёт RTT в
%%% `observe/2' для следующих адресов.
%%%
%%% Состояние: `srtt' и `rttvar' — сглаженные оценки (EWMA), `max' —
%%% верхняя граница (бюджет адреса, переданный координатором), `rto' —
%%% текущий интервал ожидания. RTO зажат в диапазон `[50, max]':
%%% слишком маленькое значение давало бы ложные повторы, слишком
%%% большое — расточительное ожидание. Начальная оценка не превышает
%%% бюджет, поэтому первое ожидание остаётся в его пределах; когда
%%% бюджет меньше минимального RTO, фактический срок всё равно
%%% ограничивается остатком дедлайна в транспорте.
%%%
%%% Повторная передача не обновляет оценку (правило Карна): вызывающая
%%% сторона обязана вызывать `observe/2' только для ответа, полученного
%%% без повторов. Модуль этого проверить не может и полагается на
%%% вызывающего; {@link trawler_discovery_probe} добавляет в результат
%%% `rtt_ms' только для неповторённой пробы.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_timing).

-export([initial/1, observe/2, rto/1]).

-export_type([state/0]).

%% Состояние политики ожидания. `srtt' и `rttvar' равны `undefined' до
%% первой выборки.
-type state() :: #{srtt := non_neg_integer() | undefined,
                   rttvar := non_neg_integer() | undefined,
                   max := pos_integer(),
                   rto := pos_integer()}.

%% Нижняя граница RTO: меньше ждать нельзя из-за разрешения таймеров.
-define(MIN_RTO, 50).
%% Начальная оценка RTO до первых измерений.
-define(INITIAL_GUESS, 1000).
%% Множители EWMA: alpha = 1/8 для SRTT, beta = 1/4 для RTTVAR.
-define(ALPHA_DIV, 8).
-define(BETA_DIV, 4).
%% Множитель RTTVAR в формуле RTO.
-define(K, 4).

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

%% @doc Начальное состояние для бюджета адреса в миллисекундах.
%%
%% `max' равен бюджету, но не ниже минимального RTO; стартовое `rto'
%% равно начальной оценке, зажатой в `[50, max]'.
-spec initial(pos_integer()) -> state().
initial(TimeoutMs) when is_integer(TimeoutMs), TimeoutMs > 0 ->
    Max = max(?MIN_RTO, TimeoutMs),
    #{srtt => undefined,
      rttvar => undefined,
      max => Max,
      rto => clamp(?INITIAL_GUESS, Max)}.

%% @doc Учитывает подтверждённый RTT (без повторов) и пересчитывает RTO.
%%
%% Первая выборка задаёт `srtt = R' и `rttvar = R/2'; последующие
%% применяют EWMA. Формула RTO: `srtt + max(1, 4*rttvar)', зажатая в
%% `[50, max]'.
-spec observe(state(), non_neg_integer()) -> state().
observe(#{srtt := undefined, rttvar := undefined} = State, RTTms)
  when is_integer(RTTms), RTTms >= 0 ->
    Max = maps:get(max, State),
    Srtt = RTTms,
    Rttvar = RTTms div 2,
    State#{srtt := Srtt, rttvar := Rttvar, rto := compute_rto(Srtt, Rttvar, Max)};
observe(#{srtt := Srtt0, rttvar := Rttvar0} = State, RTTms)
  when is_integer(RTTms), RTTms >= 0 ->
    Max = maps:get(max, State),
    Delta = abs(Srtt0 - RTTms),
    Rttvar = ((?BETA_DIV - 1) * Rttvar0 + Delta) div ?BETA_DIV,
    Srtt = ((?ALPHA_DIV - 1) * Srtt0 + RTTms) div ?ALPHA_DIV,
    State#{srtt := Srtt, rttvar := Rttvar, rto := compute_rto(Srtt, Rttvar, Max)}.

%% @doc Текущий интервал ожидания в миллисекундах.
-spec rto(state()) -> pos_integer().
rto(#{rto := Rto}) when is_integer(Rto), Rto > 0 ->
    Rto.

%%% ------------------------------------------------------------------
%%% Вспомогательные функции
%%% ------------------------------------------------------------------

compute_rto(Srtt, Rttvar, Max) ->
    clamp(Srtt + max(1, ?K * Rttvar), Max).

clamp(Value, Max) ->
    min(max(Value, ?MIN_RTO), Max).
