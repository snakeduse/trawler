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
    %% Пробел внутри одного выражения больше не часть старого элемента:
    %% ввод делится на фрагменты, и в причину ошибки попадает первый
    %% неразобранный фрагмент.
    ?assertEqual({error, {invalid_targets, <<"/">>}},
                 trawler_targets:parse_targets(<<"  192.0.2.5 / 30  ">>)),
    %% Пробел разделяет две обычные цели.
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 2}}]},
                 trawler_targets:parse_targets(<<"192.0.2.1 192.0.2.2">>)).

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
                 trawler_targets:parse_targets(<<"256.0.0.1">>)).

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
    %% Двойной дефис и обратный диапазон внутри октета остаются ошибками.
    ?assertEqual({error, {invalid_targets, <<"192.0.2.1-3-4">>}},
                 trawler_targets:parse_targets(<<"192.0.2.1-3-4">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.5-3">>}},
                 trawler_targets:parse_targets(<<"192.0.2.5-3">>)).

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
%%% Пооктетные выражения
%%% ------------------------------------------------------------------

octet_ranges_in_all_four_octets_test() ->
    %% Точное декартово произведение сверяется с независимым эталоном.
    assert_octets(<<"10-11.20-21.30-31.40-41">>,
                  [{10, 11}, {20, 21}, {30, 31}, {40, 41}]).

octet_lists_and_ranges_test() ->
    assert_octets(<<"192.168.3-5,7.1,3-4">>,
                  [192, 168, [3, 4, 5, 7], [1, 3, 4]]).

octet_lists_with_adjacent_suffix_test() ->
    assert_octets(<<"192.0.2.1,5,9">>, [192, 0, 2, [1, 5, 9]]),
    assert_octets(<<"255.0.0.250-255">>, [255, 0, 0, {250, 255}]).

octet_repeated_values_test() ->
    %% Повторы внутри октета объединяются: остаются значения 1..4.
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 4}}]},
                 trawler_targets:parse_targets(<<"192.0.2.1,1,1-3,2-4">>)).

octet_open_bounds_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 10}, {192, 0, 2, 255}}]},
                 trawler_targets:parse_targets(<<"192.0.2.10-">>)),
    ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 20}}]},
                 trawler_targets:parse_targets(<<"192.0.2.-20">>)),
    ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 255}}]},
                 trawler_targets:parse_targets(<<"192.0.2.-">>)),
    %% Ранее ошибочная запись становится диапазоном последнего октета 0..1.
    assert_octets(<<"192.0.2.-1">>, [192, 0, 2, {0, 1}]).

octet_open_bounds_in_each_octet_test() ->
    %% Пропущенная граница допустима в любом октете.
    assert_octets(<<"-2.0.2.1">>, [{0, 2}, 0, 2, 1]),
    assert_octets(<<"2-.0.2.1">>, [{2, 255}, 0, 2, 1]),
    assert_octets(<<"1.-1.2.3">>, [1, {0, 1}, 2, 3]),
    assert_octets(<<"1.2.-3.4">>, [1, 2, {0, 3}, 4]),
    assert_octets(<<"1.2.3.4-">>, [1, 2, 3, {4, 255}]),
    assert_octets(<<"1.2.3.-">>, [1, 2, 3, {0, 255}]).

octet_boundary_values_test() ->
    assert_octets(<<"0.0.0.0">>, [0, 0, 0, 0]),
    assert_octets(<<"255.255.255.255">>, [255, 255, 255, 255]),
    assert_octets(<<"0-255.0.0.-">>, [{0, 255}, 0, 0, {0, 255}]).

octet_merges_with_legacy_targets_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 3}}]},
                 trawler_targets:parse_targets(
                   <<"192.0.2.1-3 192.0.2.3/32">>)),
    ?assertEqual({ok, [{{192, 0, 2, 0}, {192, 0, 2, 4}}]},
                 trawler_targets:parse_targets(
                   <<"192.0.2.0/30 192.0.2.3-4">>)).

%%% ------------------------------------------------------------------
%%% Пооктетные цели в списках и смешанный бинарный ввод
%%% ------------------------------------------------------------------

octet_in_erlang_list_test() ->
    %% Каждый бинарный элемент списка — одна цель, теперь и пооктетная.
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 3}}]},
                 trawler_targets:parse_targets([<<"192.0.2.1-3">>,
                                                {192, 0, 2, 2}])),
    ?assertEqual({ok, [{{10, 0, 0, 1}, {10, 0, 0, 1}},
                       {{10, 0, 0, 4}, {10, 0, 0, 6}}]},
                 trawler_targets:parse_targets([<<"10.0.0.1">>,
                                                <<"10.0.0.4-6">>])),
    %% Обрезка пробелов вокруг элемента списка сохраняется.
    ?assertEqual({ok, [{{10, 0, 0, 2}, {10, 0, 0, 3}}]},
                 trawler_targets:parse_targets([<<"  10.0.0.2-3  ">>])).

legacy_spaced_list_test() ->
    ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 1}},
                       {{192, 0, 2, 4}, {192, 0, 2, 7}},
                       {{192, 0, 2, 10}, {192, 0, 2, 11}}]},
                 trawler_targets:parse_targets(
                   <<" 192.0.2.1 , 192.0.2.4/30 , 192.0.2.10-192.0.2.11 ">>)).

mixed_fragments_test() ->
    Expected = {ok, [{{192, 0, 2, 1}, {192, 0, 2, 1}},
                     {{192, 0, 2, 3}, {192, 0, 2, 4}},
                     {{198, 51, 100, 0}, {198, 51, 100, 3}},
                     {{198, 51, 100, 7}, {198, 51, 100, 7}}]},
    ?assertEqual(Expected,
                 trawler_targets:parse_targets(
                   <<"192.0.2.1,3-4 198.51.100.0/30,198.51.100.7">>)),
    ?assertEqual(Expected,
                 trawler_targets:parse_targets(
                   <<"192.0.2.1,3-4\t198.51.100.0/30,198.51.100.7">>)),
    ?assertEqual(Expected,
                 trawler_targets:parse_targets(
                   <<"192.0.2.1,3-4\n198.51.100.0/30,198.51.100.7">>)),
    ?assertEqual(Expected,
                 trawler_targets:parse_targets(
                   <<"192.0.2.1,3-4\r\n198.51.100.0/30,198.51.100.7">>)),
    %% Пробел разделяет две обычные цели без запятой.
    ?assertEqual({ok, [{{10, 0, 0, 1}, {10, 0, 0, 1}},
                       {{10, 0, 0, 9}, {10, 0, 0, 9}}]},
                 trawler_targets:parse_targets(<<"10.0.0.1 10.0.0.9">>)).

%%% ------------------------------------------------------------------
%%% Ошибочные пооктетные цели и разделение
%%% ------------------------------------------------------------------

invalid_octet_target_test() ->
    %% CIDR сочетается только с обычным одиночным адресом.
    ?assertEqual({error, {invalid_targets, <<"10-11.20.30.40/24">>}},
                 trawler_targets:parse_targets(<<"10-11.20.30.40/24">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.1-3/24">>}},
                 trawler_targets:parse_targets(<<"192.0.2.1-3/24">>)),
    %% Фрагмент с запятой не разбирается ни старым списком, ни октетами;
    %% причина — первый неразобранный элемент старого разбора.
    ?assertEqual({error, {invalid_targets, <<"3/24">>}},
                 trawler_targets:parse_targets(<<"192.0.2.1,3/24">>)),
    %% Значение, ведущие нули, пустой октет и пустой элемент.
    ?assertEqual({error, {invalid_targets, <<"192.0.2.256">>}},
                 trawler_targets:parse_targets(<<"192.0.2.256">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.01">>}},
                 trawler_targets:parse_targets(<<"192.0.2.01">>)),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.">>}},
                 trawler_targets:parse_targets(<<"192.0.2.">>)),
    %% Пустой элемент через запятую сохраняет прежнюю причину.
    ?assertEqual({error, {invalid_targets, <<>>}},
                 trawler_targets:parse_targets(<<"192.0.2.1,,">>)),
    %% Пробел внутри выражения остаётся ошибкой.
    ?assertEqual({error, {invalid_targets, <<"192.0.2.">>}},
                 trawler_targets:parse_targets(<<"192.0.2. 1">>)).

invalid_targets_in_erlang_list_test() ->
    ?assertEqual({error, {invalid_targets, <<"10-11.20.30.40/24">>}},
                 trawler_targets:parse_targets([<<"10-11.20.30.40/24">>])),
    ?assertEqual({error, {invalid_targets, <<"192.0.2.256">>}},
                 trawler_targets:parse_targets([<<"192.0.2.256">>])).

%%% ------------------------------------------------------------------
%%% Лимит пооктетного произведения
%%% ------------------------------------------------------------------

octet_huge_product_test() ->
    %% Огромное произведение отклоняется без разворачивания пространства.
    ?assertEqual({error, too_many_hosts},
                 trawler_targets:parse_targets(<<"-.-.-.-">>)),
    with_max_hosts(65536,
      fun() ->
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(<<"-.-.-.-">>))
      end),
    with_max_hosts(4,
      fun() ->
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(<<"-.-.-.-">>)),
              %% Цель сверх лимита отклоняется независимо от соседних целей.
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(
                             <<"192.0.2.1 -.-.-.-">>))
      end).

octet_product_at_limit_test() ->
    with_max_hosts(256,
      fun() ->
              ?assertEqual({ok, [{{0, 0, 0, 0}, {0, 0, 0, 255}}]},
                           trawler_targets:parse_targets(<<"0.0.0.-">>))
      end),
    with_max_hosts(255,
      fun() ->
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(<<"0.0.0.-">>))
      end).

octet_intersections_at_limit_test() ->
    with_max_hosts(4,
      fun() ->
              %% Пересечение и повторы считаются по объединению, а не сумме.
              ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 4}}]},
                           trawler_targets:parse_targets(
                             <<"192.0.2.1-4 192.0.2.2-3">>)),
              ?assertEqual({ok, [{{192, 0, 2, 1}, {192, 0, 2, 4}}]},
                           trawler_targets:parse_targets(
                             <<"192.0.2.1-4 192.0.2.2,3,4">>)),
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(
                             <<"192.0.2.1-4 192.0.2.2-3 192.0.2.5">>)),
              ?assertEqual({error, too_many_hosts},
                           trawler_targets:parse_targets(
                             <<"192.0.2.1-4 192.0.2.2,3,4,5">>)),
              %% Ошибочный синтаксис обнаруживается независимо от порядка.
              ?assertEqual({error, {invalid_targets, <<"192.0.2.300">>}},
                           trawler_targets:parse_targets(
                             <<"-.-.-.- 192.0.2.300">>)),
              ?assertEqual({error, {invalid_targets, <<"192.0.2.300">>}},
                           trawler_targets:parse_targets(
                             <<"192.0.2.300 -.-.-.-">>))
      end).

%%% ------------------------------------------------------------------
%%% Слияние больших и пересекающихся разреженных целей
%%% ------------------------------------------------------------------

%% Большое разреженное произведение: 65536 одиночных интервалов. Прежняя
%% вставка по одному интервалу копировала префикс накопленного списка и
%% была квадратичной по числу интервалов. Бюджет по reductions (плюс
%% таймаут теста) ловит возврат к такой вставке, а независимое
%% перечисление подтверждает, что выбраны все точные адреса.
big_sparse_product_65536_test_() ->
    {timeout, 60, fun big_sparse_product_65536/0}.

big_sparse_product_65536() ->
    {_, Before} = erlang:process_info(self(), reductions),
    {ok, Ranges} = trawler_targets:parse_targets(<<"-.-.0.1">>),
    {_, After} = erlang:process_info(self(), reductions),
    Expected = [{A, B, 0, 1}
                || A <- lists:seq(0, 255), B <- lists:seq(0, 255)],
    ?assertEqual(Expected, expand_ranges(Ranges)),
    ?assertEqual(65536, length(Ranges)),
    ?assertEqual(65536, trawler_targets:count_hosts(Ranges)),
    %% Линейное слияние укладывается в миллионы reductions; квадратичный
    %% путь потратил бы порядка 2*10^9.
    ?assert(After - Before < 100000000).

%% Пересечение двух разреженных выражений с мостящими диапазонами:
%% диапазон 0.0.0.1-3 мостит точки 0.0.0.0, 0.0.0.2 и 0.0.0.4 первого
%% выражения, а адрес 0.0.0.2 входит в оба выражения. Ожидаемый набор
%% строится независимым перечислением обоих произведений.
octet_sparse_overlap_bridging_test() ->
    assert_octet_union(<<"0-1.0.0.0,2,4 0.0.0.1-3">>,
                       [[{0, 1}, 0, 0, [0, 2, 4]], [0, 0, 0, {1, 3}]]).

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

default_ports_test() ->
    {ok, Ranges} = trawler_targets:parse_ports(default),
    ?assertEqual(1000, length(Ranges)),
    ?assertEqual(1000, trawler_targets:count_ports(Ranges)),
    ?assertEqual({80, 80}, hd(Ranges)),
    ?assertEqual([{P, P} || P <- trawler_ports:default()], Ranges).

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

%% Точная выборка сверяется с независимым эталонным перечислением
%% маленького произведения: наборы значений каждого октета перебираются
%% напрямую, без обращения к логике парсера.
assert_octets(Target, OctetValues) ->
    {ok, Ranges} = trawler_targets:parse_targets(Target),
    Expected = octet_product(OctetValues),
    ?assertEqual(Expected, expand_ranges(Ranges)),
    ?assertEqual(length(Expected), trawler_targets:count_hosts(Ranges)).

%% Объединение нескольких пооктетных выражений сверяется с независимым
%% перечислением: наборы каждого выражения перебираются напрямую, затем
%% объединяются без повторов.
assert_octet_union(Input, OctetSpecs) ->
    {ok, Ranges} = trawler_targets:parse_targets(Input),
    Expected = lists:usort(
                 lists:append([octet_product(Spec) || Spec <- OctetSpecs])),
    ?assertEqual(Expected, expand_ranges(Ranges)),
    ?assertEqual(length(Expected), trawler_targets:count_hosts(Ranges)).

octet_product([V1, V2, V3, V4]) ->
    lists:sort([{A, B, C, D}
                || A <- octet_values(V1), B <- octet_values(V2),
                   C <- octet_values(V3), D <- octet_values(V4)]).

octet_values(Value) when is_integer(Value) ->
    [Value];
octet_values({First, Last}) ->
    lists:seq(First, Last);
octet_values(Values) when is_list(Values) ->
    lists:usort(Values).

%% Разворачивание нормализованных диапазонов в возрастающий список
%% адресов; повторы в результате сравнения не скрываются.
expand_ranges(Ranges) ->
    lists:append(
      [[trawler_targets:int_to_ip(Int)
        || Int <- lists:seq(trawler_targets:ip_to_int(First),
                            trawler_targets:ip_to_int(Last))]
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
