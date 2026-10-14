%%%-------------------------------------------------------------------
%%% @doc Детерминированные EUnit-тесты политики ожидания
%%% trawler_discovery_timing.
%%%
%%% Проверяются начальные границы RTO относительно бюджета адреса,
%%% детерминированный EWMA по SRTT/RTTVAR (RFC 6298) и зажим в
%%% диапазон [50, max] без сети и часов.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_timing_tests).

-include_lib("eunit/include/eunit.hrl").

%%% ------------------------------------------------------------------
%%% Начальное состояние
%%% ------------------------------------------------------------------

initial_clamps_to_small_budget_test() ->
    %% Бюджет 100 мс целиком ограничивает стартовое ожидание.
    State = trawler_discovery_timing:initial(100),
    ?assertEqual(100, trawler_discovery_timing:rto(State)),
    ?assertEqual(100, maps:get(max, State)),
    ?assertEqual(undefined, maps:get(srtt, State)).

initial_caps_large_budget_at_guess_test() ->
    %% Большой бюджет не раздувает стартовое ожидание сверх оценки 1000 мс.
    State = trawler_discovery_timing:initial(10000),
    ?assertEqual(1000, trawler_discovery_timing:rto(State)),
    ?assertEqual(10000, maps:get(max, State)).

initial_respects_minimum_test() ->
    %% Бюджет ниже минимального RTO: нижняя граница 50 мс.
    ?assertEqual(50, trawler_discovery_timing:rto(trawler_discovery_timing:initial(20))).

%%% ------------------------------------------------------------------
%%% Наблюдения RTT (EWMA)
%%% ------------------------------------------------------------------

observe_first_sample_test() ->
    %% Первая выборка: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4*RTTVAR.
    State = trawler_discovery_timing:observe(trawler_discovery_timing:initial(10000), 200),
    ?assertEqual(200, maps:get(srtt, State)),
    ?assertEqual(100, maps:get(rttvar, State)),
    ?assertEqual(600, trawler_discovery_timing:rto(State)).

observe_ewma_test() ->
    First = trawler_discovery_timing:observe(trawler_discovery_timing:initial(10000), 200),
    Second = trawler_discovery_timing:observe(First, 300),
    %% SRTT = (7*200 + 300)/8 = 212, RTTVAR = (3*100 + 100)/4 = 100.
    ?assertEqual(212, maps:get(srtt, Second)),
    ?assertEqual(100, maps:get(rttvar, Second)),
    ?assertEqual(612, trawler_discovery_timing:rto(Second)).

observe_clamps_lower_bound_test() ->
    State = trawler_discovery_timing:observe(trawler_discovery_timing:initial(10000), 10),
    %% SRTT + 4*RTTVAR = 10 + 20 = 30, поднимается до 50.
    ?assertEqual(50, trawler_discovery_timing:rto(State)).

observe_clamps_upper_bound_test() ->
    State = trawler_discovery_timing:observe(trawler_discovery_timing:initial(100), 500),
    %% 500 + 4*250 = 1500, опускается до бюджета 100.
    ?assertEqual(100, trawler_discovery_timing:rto(State)).

observe_zero_rtt_test() ->
    State = trawler_discovery_timing:observe(trawler_discovery_timing:initial(1000), 0),
    ?assertEqual(0, maps:get(srtt, State)),
    ?assertEqual(0, maps:get(rttvar, State)),
    ?assertEqual(50, trawler_discovery_timing:rto(State)).
