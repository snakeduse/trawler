%%%-------------------------------------------------------------------
%%% @doc EUnit-тесты модуля trawler_ports.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_ports_tests).

-include_lib("eunit/include/eunit.hrl").

%%% ------------------------------------------------------------------
%%% Размер и состав набора по умолчанию
%%% ------------------------------------------------------------------

length_test() ->
    ?assertEqual(1000, length(trawler_ports:default())).

unique_test() ->
    ?assertEqual(1000, length(lists:usort(trawler_ports:default()))).

range_test() ->
    ?assert(lists:all(fun(P) -> P >= 1 andalso P =< 65535 end,
                      trawler_ports:default())).

first_is_http_test() ->
    ?assertEqual(80, hd(trawler_ports:default())).

anchors_test() ->
    ?assert(lists:member(80, trawler_ports:default())),
    ?assert(lists:member(443, trawler_ports:default())).

deterministic_test() ->
    ?assertEqual(trawler_ports:default(), trawler_ports:default()).
