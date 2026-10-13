%%%-------------------------------------------------------------------
%%% @doc EUnit-тесты модуля trawler_targets.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_targets_tests).

-include_lib("eunit/include/eunit.hrl").

%%% ------------------------------------------------------------------
%%% Преобразование адресов
%%% ------------------------------------------------------------------

ip_to_int_test() ->
    ?assertEqual(0, trawler_targets:ip_to_int({0, 0, 0, 0})),
    ?assertEqual(1, trawler_targets:ip_to_int({0, 0, 0, 1})),
    ?assertEqual(4294967295, trawler_targets:ip_to_int({255, 255, 255, 255})),
    ?assertEqual(3232235777, trawler_targets:ip_to_int({192, 168, 1, 1})),
    ?assertEqual(3221225985, trawler_targets:ip_to_int({192, 0, 2, 1})).

int_to_ip_test() ->
    ?assertEqual({0, 0, 0, 0}, trawler_targets:int_to_ip(0)),
    ?assertEqual({0, 0, 0, 1}, trawler_targets:int_to_ip(1)),
    ?assertEqual({192, 168, 1, 1}, trawler_targets:int_to_ip(3232235777)),
    ?assertEqual({255, 255, 255, 255}, trawler_targets:int_to_ip(4294967295)).

ip_conversion_roundtrip_test() ->
    Addresses = [{0, 0, 0, 0}, {10, 0, 0, 1}, {127, 0, 0, 1},
                 {192, 0, 2, 7}, {255, 255, 255, 254}, {255, 255, 255, 255}],
    lists:foreach(
      fun(Address) ->
              ?assertEqual(Address,
                           trawler_targets:int_to_ip(
                             trawler_targets:ip_to_int(Address)))
      end, Addresses).

%%% ------------------------------------------------------------------
%%% Одиночные адреса
%%% ------------------------------------------------------------------

single_address_string_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 1}}]},
                 trawler_targets:parse_targets(<<"192.0.2.1">>)),
    ?assertEqual({ok, [{{127, 0, 0, 1}, {127, 0, 0, 1}}]},
                 trawler_targets:parse_targets(<<"127.0.0.1">>)).

single_address_list_test() ->
    ?assertEqual({ok, [{{10, 0, 0, 1}, {10, 0, 0, 1}}]},
                 trawler_targets:parse_targets([{10, 0, 0, 1}])),
    ?assertEqual({ok, [{{10, 0, 0, 1}, {10, 0, 0, 1}}]},
                 trawler_targets:parse_targets([<<"10.0.0.1">>])).

octet_boundaries_test() ->
    ?assertEqual({ok, [{{0, 0, 0, 0}, {0, 0, 0, 0}}]},
                 trawler_targets:parse_targets(<<"0.0.0.0">>)),
    ?assertEqual({ok, [{{255, 255, 255, 255}, {255, 255, 255, 255}}]},
                 trawler_targets:parse_targets(<<"255.255.255.255">>)),
    ?assertEqual({ok, [{{0, 0, 0, 0}, {0, 0, 0, 255}}]},
                 trawler_targets:parse_targets(<<"0.0.0.0-0.0.0.255">>)),
    ?assertEqual({ok, [{{255, 255, 255, 0}, {255, 255, 255, 255}}]},
                 trawler_targets:parse_targets(<<"255.255.255.0/24">>)).

%%% ------------------------------------------------------------------
%%% Списки и порядок
%%% ------------------------------------------------------------------

list_sorted_and_deduplicated_test() ->
    ?assertEqual({ok, [{{10, 0, 0, 1}, {10, 0, 0, 1}},
                       {{10, 0, 0, 3}, {10, 0, 0, 3}}]},
                 trawler_targets:parse_targets([{10, 0, 0, 3},
                                                {10, 0, 0, 1},
                                                {10, 0, 0, 1}])).

mixed_list_test() ->
    ?assertEqual({ok, [{{10, 0, 0, 0}, {10, 0, 0, 1}},
                       {{192, 0, 2, 4}, {192, 0, 2, 7}}]},
                 trawler_targets:parse_targets([{10, 0, 0, 0},
                                                <<"192.0.2.5/30">>,
                                                <<"10.0.0.1">>])).

string_list_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 2}}]},
                 trawler_targets:parse_targets(<<"192.0.2.1,192.0.2.2">>)).

%%% ------------------------------------------------------------------
%%% Диапазоны и CIDR
%%% ------------------------------------------------------------------

explicit_range_test() ->
    {ok, Ranges} = trawler_targets:parse_targets(<<"192.0.2.10-192.0.2.20">>),
    ?assertEqual([{{192, 0, 2, 10}, {192, 0, 2, 20}}], Ranges),
    ?assertEqual(11, trawler_targets:count_hosts(Ranges)).

single_address_range_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 5}, {192, 0, 2, 5}}]},
                 trawler_targets:parse_targets(<<"192.0.2.5-192.0.2.5">>)).

cidr_normalisation_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 4}, {192, 0, 2, 7}}]},
                 trawler_targets:parse_targets(<<"192.0.2.5/30">>)),
    ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 255}}]},
                 trawler_targets:parse_targets(<<"192.0.2.200/24">>)),
    ?assertEqual({ok, [{{198, 51, 100, 8}, {198, 51, 100, 15}}]},
                 trawler_targets:parse_targets(<<"198.51.100.9/29">>)).

cidr_slash_32_test() ->
    {ok, Ranges} = trawler_targets:parse_targets(<<"198.51.100.7/32">>),
    ?assertEqual([{{198, 51, 100, 7}, {198, 51, 100, 7}}], Ranges),
    ?assertEqual(1, trawler_targets:count_hosts(Ranges)).

cidr_slash_31_test() ->
    {ok, Ranges} = trawler_targets:parse_targets(<<"192.0.2.1/31">>),
    ?assertEqual([{{192, 0, 2, 0}, {192, 0, 2, 1}}], Ranges),
    ?assertEqual(2, trawler_targets:count_hosts(Ranges)).

cidr_count_test() ->
    {ok, Full} = trawler_targets:parse_targets(<<"10.0.0.0/16">>),
    ?assertEqual(65536, trawler_targets:count_hosts(Full)),
    {ok, Single} = trawler_targets:parse_targets(<<"10.0.0.0/32">>),
    ?assertEqual(1, trawler_targets:count_hosts(Single)).

%%% ------------------------------------------------------------------
%%% Объединение пересекающихся и смежных диапазонов
%%% ------------------------------------------------------------------

merge_overlap_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 10}}]},
                 trawler_targets:parse_targets(
                   <<"192.0.2.1-192.0.2.10,192.0.2.5">>)),
    ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 3}}]},
                 trawler_targets:parse_targets(<<"192.0.2.0/30,192.0.2.1">>)).

merge_adjacent_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 3}}]},
                 trawler_targets:parse_targets(
                   <<"192.0.2.1-192.0.2.2,192.0.2.3">>)),
    %% Подсеть CIDR и следующий за ней адрес образуют один диапазон.
    ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 4}}]},
                 trawler_targets:parse_targets(<<"192.0.2.0/30,192.0.2.4">>)).

merge_non_adjacent_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 1}},
                       {{192, 0, 2, 3}, {192, 0, 2, 3}}]},
                 trawler_targets:parse_targets(<<"192.0.2.1,192.0.2.3">>)).

merge_at_top_of_space_test() ->
    ?assertEqual({ok, [{{255, 255, 255, 254}, {255, 255, 255, 255}}]},
                 trawler_targets:parse_targets(
                   <<"255.255.255.254-255.255.255.255,255.255.255.255">>)).

merge_covers_inner_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 15}}]},
                 trawler_targets:parse_targets(
                   <<"192.0.2.0/28,192.0.2.4/30,192.0.2.7">>)).

%%% ------------------------------------------------------------------
%%% Пробелы
%%% ------------------------------------------------------------------

trim_whitespace_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 1}}]},
                 trawler_targets:parse_targets(<<"  192.0.2.1  ">>)),
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 2}}]},
                 trawler_targets:parse_targets(<<" 192.0.2.1 , 192.0.2.2 ">>)),
    %% Пробелы внутри элемента не допускаются.
    ?assertEqual({error, {invalid_targets, <<"192.0.2.5 / 30">>}},
                 trawler_targets:parse_targets(<<"  192.0.2.5 / 30  ">>)).

trim_whitespace_in_list_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 1}}]},
                 trawler_targets:parse_targets([<<" 192.0.2.1 ">>])).

%%% ------------------------------------------------------------------
%%% Пустой ввод
%%% ------------------------------------------------------------------

empty_targets_test() ->
    ?assertEqual({error, {invalid_targets, <<>>}},
                 trawler_targets:parse_targets(<<>>)),
    ?assertEqual({error, {invalid_targets, []}},
                 trawler_targets:parse_targets([])),
    ?assertEqual({error, {invalid_targets, <<>>}},
                 trawler_targets:parse_targets(<<"   ">>)),
    ?assertEqual({error, {invalid_targets, <<>>}},
                 trawler_targets:parse_targets(<<"192.0.2.1,">>)),
    ?assertEqual({error, {invalid_targets, <<>>}},
                 trawler_targets:parse_targets(<<",192.0.2.1">>)),
    ?assertEqual({error, {invalid_targets, <<>>}},
                 trawler_targets:parse_targets(<<"192.0.2.1,,192.0.2.2">>)),
    ?assertEqual({error, {invalid_targets, <<>>}},
                 trawler_targets:parse_targets([<<>>])),
    ?assertEqual({error, {invalid_targets, <<>>}},
                 trawler_targets:parse_targets([<<"   ">>])).

empty_ports_test() ->
    ?assertEqual({error, {invalid_ports, <<>>}},
                 trawler_targets:parse_ports(<<>>)),
    ?assertEqual({error, {invalid_ports, []}},
                 trawler_targets:parse_ports([])),
    ?assertEqual({error, {invalid_ports, <<>>}},
                 trawler_targets:parse_ports(<<"22,">>)),
    ?assertEqual({error, {invalid_ports, <<>>}},
                 trawler_targets:parse_ports(<<",22">>)),
    ?assertEqual({error, {invalid_ports, <<>>}},
                 trawler_targets:parse_ports(<<"22,,80">>)),
    ?assertEqual({error, {invalid_ports, <<>>}},
                 trawler_targets:parse_ports([<<>>])).

%%% ------------------------------------------------------------------
%%% Ошибочный ввод адресов
%%% ------------------------------------------------------------------

invalid_octet_test() ->
    ?assertEqual({error, {invalid_targets, <<"192.0.2.256">>}},
                 trawler_targets:parse_targets(<<"192.0.2.256">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.300">>}},
                 trawler_targets:parse_targets(<<"192.0.2.300">>)),
    ?assertEqual({error, {invalid_targets, <<"256.0.0.1">>}},
                 trawler_targets:parse_targets(<<"256.0.0.1">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.-1">>}},
                 trawler_targets:parse_targets(<<"192.0.2.-1">>)).

leading_zero_octet_test() ->
    ?assertEqual({error, {invalid_targets, <<"192.0.2.01">>}},
                 trawler_targets:parse_targets(<<"192.0.2.01">>)),
    ?assertEqual({error, {invalid_targets, <<"010.0.0.1">>}},
                 trawler_targets:parse_targets(<<"010.0.0.1">>)).

empty_octet_test() ->
    ?assertEqual({error, {invalid_targets, <<"192..2.1">>}},
                 trawler_targets:parse_targets(<<"192..2.1">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.">>}},
                 trawler_targets:parse_targets(<<"192.0.2.">>)),
    ?assertEqual({error, {invalid_targets, <<".192.0.2.1">>}},
                 trawler_targets:parse_targets(<<".192.0.2.1">>)).

wrong_shape_test() ->
    ?assertEqual({error, {invalid_targets, <<"192.0.2">>}},
                 trawler_targets:parse_targets(<<"192.0.2">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.1.2">>}},
                 trawler_targets:parse_targets(<<"192.0.2.1.2">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.1.2.3">>}},
                 trawler_targets:parse_targets(<<"192.0.2.1.2.3">>)).

non_ipv4_test() ->
    ?assertEqual({error, {invalid_targets, <<"example.com">>}},
                 trawler_targets:parse_targets(<<"example.com">>)),
    ?assertEqual({error, {invalid_targets, <<"2001:db8::1">>}},
                 trawler_targets:parse_targets(<<"2001:db8::1">>)),
    ?assertEqual({error, {invalid_targets, <<"localhost">>}},
                 trawler_targets:parse_targets(<<"localhost">>)).

invalid_cidr_test() ->
    ?assertEqual({error, {invalid_targets, <<"192.0.2.0/33">>}},
                 trawler_targets:parse_targets(<<"192.0.2.0/33">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.0/64">>}},
                 trawler_targets:parse_targets(<<"192.0.2.0/64">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.0/">>}},
                 trawler_targets:parse_targets(<<"192.0.2.0/">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.0/-1">>}},
                 trawler_targets:parse_targets(<<"192.0.2.0/-1">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.0/24/8">>}},
                 trawler_targets:parse_targets(<<"192.0.2.0/24/8">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.0/abc">>}},
                 trawler_targets:parse_targets(<<"192.0.2.0/abc">>)).

reversed_range_test() ->
    ?assertEqual({error, {invalid_targets, <<"192.0.2.10-192.0.2.1">>}},
                 trawler_targets:parse_targets(<<"192.0.2.10-192.0.2.1">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.1-">>}},
                 trawler_targets:parse_targets(<<"192.0.2.1-">>)),
    ?assertEqual({error, {invalid_targets, <<"-192.0.2.1">>}},
                 trawler_targets:parse_targets(<<"-192.0.2.1">>)).

%%% ------------------------------------------------------------------
%%% Лимит числа хостов
%%% ------------------------------------------------------------------

valid_range_under_limit_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 3}}]},
                 trawler_targets:parse_targets(<<"192.0.2.0/30">>)).

too_many_hosts_default_test() ->
    without_max_hosts(
      fun() ->
              %% По умолчанию max_hosts = 65536.
              ?assertMatch({ok, _},
                           trawler_targets:parse_targets(<<"10.0.0.0/16">>)),
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(<<"10.0.0.0/15">>))
      end).

too_many_hosts_env_test() ->
    with_max_hosts(4,
      fun() ->
              ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 3}}]},
                           trawler_targets:parse_targets(<<"192.0.2.0/30">>)),
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(<<"192.0.2.0/29">>)),
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(<<"192.0.2.0/0">>))
      end).

too_many_hosts_counts_merged_test() ->
    with_max_hosts(10,
      fun() ->
              %% Пересекающиеся выборки не удваивают число хостов.
              ?assertMatch({ok, _},
                           trawler_targets:parse_targets(
                             <<"192.0.2.1-192.0.2.10,192.0.2.5">>)),
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(
                             <<"192.0.2.1-192.0.2.11,192.0.2.5">>))
      end).

%%% ------------------------------------------------------------------
%%% Порты
%%% ------------------------------------------------------------------

single_port_test() ->
    ?assertEqual({ok, [{80, 80}]}, trawler_targets:parse_ports(<<"80">>)),
    ?assertEqual({ok, [{443, 443}]}, trawler_targets:parse_ports(<<"443">>)).

port_bounds_test() ->
    ?assertEqual({ok, [{1, 1}]}, trawler_targets:parse_ports(<<"1">>)),
    ?assertEqual({ok, [{65535, 65535}]},
                 trawler_targets:parse_ports(<<"65535">>)),
    ?assertEqual({ok, [{1, 65535}]}, trawler_targets:parse_ports(<<"1-65535">>)).

mixed_ports_test() ->
    {ok, Ranges} = trawler_targets:parse_ports(<<"22,80,80-82">>),
    ?assertEqual([{22, 22}, {80, 82}], Ranges),
    ?assertEqual(4, trawler_targets:count_ports(Ranges)),
    ?assertEqual([22, 80, 81, 82], expand_ports(Ranges)).

port_range_test() ->
    {ok, Ranges} = trawler_targets:parse_ports(<<"8000-8010">>),
    ?assertEqual([{8000, 8010}], Ranges),
    ?assertEqual(11, trawler_targets:count_ports(Ranges)).

port_merge_adjacent_test() ->
    ?assertEqual({ok, [{20, 23}]},
                 trawler_targets:parse_ports(<<"20-21,22,23">>)),
    ?assertEqual({ok, [{1, 2}, {4, 4}]},
                 trawler_targets:parse_ports(<<"1,2,4">>)).

port_merge_overlap_test() ->
    ?assertEqual({ok, [{80, 90}]},
                 trawler_targets:parse_ports(<<"80-90,85,80">>)).

ports_list_test() ->
    ?assertEqual({ok, [{22, 22}, {80, 82}]},
                 trawler_targets:parse_ports([22, {range, 80, 82}])),
    ?assertEqual({ok, [{443, 443}]},
                 trawler_targets:parse_ports([<<"443">>])),
    ?assertEqual({ok, [{1, 1}, {80, 80}]},
                 trawler_targets:parse_ports([80, 1, 80])),
    ?assertEqual({ok, [{22, 22}, {80, 80}, {443, 443}]},
                 trawler_targets:parse_ports([443, 22, 80])).

ports_whitespace_test() ->
    ?assertEqual({ok, [{22, 22}, {80, 82}]},
                 trawler_targets:parse_ports(<<" 22 , 80 , 80-82 ">>)),
    ?assertEqual({ok, [{22, 22}]},
                 trawler_targets:parse_ports([<<" 22 ">>])).

invalid_ports_test() ->
    ?assertEqual({error, {invalid_ports, <<"0">>}},
                 trawler_targets:parse_ports(<<"0">>)),
    ?assertEqual({error, {invalid_ports, <<"0-10">>}},
                 trawler_targets:parse_ports(<<"0-10">>)),
    ?assertEqual({error, {invalid_ports, <<"65536">>}},
                 trawler_targets:parse_ports(<<"65536">>)),
    ?assertEqual({error, {invalid_ports, <<"80000">>}},
                 trawler_targets:parse_ports(<<"80000">>)),
    ?assertEqual({error, {invalid_ports, <<"abc">>}},
                 trawler_targets:parse_ports(<<"abc">>)),
    ?assertEqual({error, {invalid_ports, <<"80.5">>}},
                 trawler_targets:parse_ports(<<"80.5">>)),
    ?assertEqual({error, {invalid_ports, <<"-">>}},
                 trawler_targets:parse_ports(<<"-">>)),
    ?assertEqual({error, {invalid_ports, <<"22-">>}},
                 trawler_targets:parse_ports(<<"22-">>)),
    ?assertEqual({error, {invalid_ports, <<"-22">>}},
                 trawler_targets:parse_ports(<<"-22">>)),
    ?assertEqual({error, {invalid_ports, <<"22-80-90">>}},
                 trawler_targets:parse_ports(<<"22-80-90">>)).

reversed_port_range_test() ->
    ?assertEqual({error, {invalid_ports, <<"80-22">>}},
                 trawler_targets:parse_ports(<<"80-22">>)),
    ?assertEqual({error, {invalid_ports, {range, 80, 22}}},
                 trawler_targets:parse_ports([{range, 80, 22}])).

%%% ------------------------------------------------------------------
%%% Счётчики
%%% ------------------------------------------------------------------

count_hosts_test() ->
    {ok, Ranges} = trawler_targets:parse_targets(
                     <<"192.0.2.0/31,192.0.2.4-192.0.2.6">>),
    ?assertEqual([{{192, 0, 2, 0}, {192, 0, 2, 1}},
                  {{192, 0, 2, 4}, {192, 0, 2, 6}}], Ranges),
    ?assertEqual(5, trawler_targets:count_hosts(Ranges)).

count_empty_test() ->
    ?assertEqual(0, trawler_targets:count_hosts([])),
    ?assertEqual(0, trawler_targets:count_ports([])).

%%% ------------------------------------------------------------------
%%% Вспомогательные функции тестов
%%% ------------------------------------------------------------------

expand_ports(Ranges) ->
    lists:append([[First | lists:seq(First + 1, Last)]
                  || {First, Last} <- Ranges]).

with_max_hosts(Limit, Fun) ->
    Previous = application:get_env(trawler, max_hosts),
    ok = application:set_env(trawler, max_hosts, Limit),
    try
        Fun()
    after
        restore_max_hosts(Previous)
    end.

without_max_hosts(Fun) ->
    Previous = application:get_env(trawler, max_hosts),
    ok = application:unset_env(trawler, max_hosts),
    try
        Fun()
    after
        restore_max_hosts(Previous)
    end.

restore_max_hosts({ok, Value}) ->
    application:set_env(trawler, max_hosts, Value);
restore_max_hosts(undefined) ->
    application:unset_env(trawler, max_hosts).
