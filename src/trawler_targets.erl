%%%-------------------------------------------------------------------
%%% @doc Разбор и нормализация выборок IPv4-адресов и TCP-портов.
%%%
%%% Модуль является чистой библиотекой: он не создаёт процессов и не
%%% зависит от состояния приложения. Единственное чтение состояния —
%%% лимит `max_hosts' из окружения приложения `trawler' (по умолчанию
%%% 65536). Все выборки нормализуются, сортируются и очищаются от
%%% повторов до любых сетевых операций.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_targets).

-export_type([ip4/0, addr_range/0, port_range/0, targets_input/0,
              ports_input/0, reason/0]).

-export([parse_targets/1, parse_ports/1, count_hosts/1, count_ports/1,
         ip_to_int/1, int_to_ip/1]).

-type ip4() :: {0..255, 0..255, 0..255, 0..255}.
%% Включительный диапазон адресов; первая граница не больше последней.
-type addr_range() :: {ip4(), ip4()}.
%% Включительный диапазон портов; первая граница не больше последней.
-type port_range() :: {1..65535, 1..65535}.
-type targets_input() :: binary() | [ip4() | binary()].
-type ports_input() :: binary() | [1..65535 | {range, 1..65535, 1..65535}].
-type reason() :: {invalid_targets, term()} | {invalid_ports, term()}
                | too_many_hosts.

-define(MAX_PORT, 65535).
-define(MAX_IPV4_INT, 4294967295).
-define(MAX_PREFIX, 32).
-define(DEFAULT_MAX_HOSTS, 65536).

%%% ------------------------------------------------------------------
%%% Публичный API
%%% ------------------------------------------------------------------

-spec parse_targets(targets_input()) -> {ok, [addr_range()]} | {error, reason()}.
parse_targets(Input) when is_binary(Input) ->
    parse_target_elements(binary:split(Input, <<",">>, [global]));
parse_targets(Input) when is_list(Input) ->
    case Input of
        [] -> {error, {invalid_targets, []}};
        _ -> parse_target_elements(Input)
    end.

-spec parse_ports(ports_input()) -> {ok, [port_range()]} | {error, reason()}.
parse_ports(Input) when is_binary(Input) ->
    parse_port_elements(binary:split(Input, <<",">>, [global]));
parse_ports(Input) when is_list(Input) ->
    case Input of
        [] -> {error, {invalid_ports, []}};
        _ -> parse_port_elements(Input)
    end.

-spec count_hosts([addr_range()]) -> non_neg_integer().
count_hosts(Ranges) ->
    lists:foldl(fun({First, Last}, Acc) ->
                        Acc + ip_to_int(Last) - ip_to_int(First) + 1
                end, 0, Ranges).

-spec count_ports([port_range()]) -> non_neg_integer().
count_ports(Ranges) ->
    lists:foldl(fun({First, Last}, Acc) -> Acc + Last - First + 1 end,
                0, Ranges).

-spec ip_to_int(ip4()) -> 0..4294967295.
ip_to_int({A, B, C, D}) ->
    (A * 16777216) + (B * 65536) + (C * 256) + D.

-spec int_to_ip(0..4294967295) -> ip4().
int_to_ip(Int) when is_integer(Int), Int >= 0, Int =< ?MAX_IPV4_INT ->
    {(Int bsr 24) band 255, (Int bsr 16) band 255,
     (Int bsr 8) band 255, Int band 255}.

%%% ------------------------------------------------------------------
%%% Адреса
%%% ------------------------------------------------------------------

parse_target_elements(Elements) ->
    case target_ranges(Elements, []) of
        {ok, Ranges} ->
            IntRanges = [addr_to_int_range(Range) || Range <- Ranges],
            Merged = [int_to_addr_range(Range)
                      || Range <- merge_ranges(IntRanges)],
            check_host_limit(Merged);
        {error, Reason} ->
            {error, Reason}
    end.

addr_to_int_range({First, Last}) ->
    {ip_to_int(First), ip_to_int(Last)}.

int_to_addr_range({First, Last}) ->
    {int_to_ip(First), int_to_ip(Last)}.

target_ranges([], Acc) ->
    {ok, Acc};
target_ranges([Element | Rest], Acc) ->
    case element_range(Element) of
        {ok, Range} -> target_ranges(Rest, [Range | Acc]);
        {error, Bad} -> {error, {invalid_targets, Bad}}
    end.

%% Один элемент входной выборки: либо готовый ip4()-кортеж, либо
%% бинарная строка с одиночным адресом, диапазоном или CIDR.
element_range(Bin) when is_binary(Bin) ->
    Trimmed = string:trim(Bin),
    case element_range_bin(Trimmed) of
        {ok, Range} -> {ok, Range};
        error -> {error, Trimmed}
    end;
element_range({A, B, C, D}) when is_integer(A), A >= 0, A =< 255,
                                 is_integer(B), B >= 0, B =< 255,
                                 is_integer(C), C >= 0, C =< 255,
                                 is_integer(D), D >= 0, D =< 255 ->
    {ok, {{A, B, C, D}, {A, B, C, D}}}.

element_range_bin(<<>>) ->
    error;
element_range_bin(Bin) ->
    case binary:match(Bin, <<"/">>) of
        {_, _} -> cidr_range(Bin);
        nomatch ->
            case binary:match(Bin, <<"-">>) of
                {_, _} -> address_range(Bin);
                nomatch -> single_range(Bin)
            end
    end.

single_range(Bin) ->
    case parse_ip(Bin) of
        {ok, Addr} -> {ok, {Addr, Addr}};
        error -> error
    end.

address_range(Bin) ->
    case binary:split(Bin, <<"-">>, [global]) of
        [FirstBin, LastBin] ->
            case {parse_ip(FirstBin), parse_ip(LastBin)} of
                {{ok, First}, {ok, Last}} ->
                    case ip_to_int(First) =< ip_to_int(Last) of
                        true -> {ok, {First, Last}};
                        false -> error
                    end;
                _ -> error
            end;
        _ -> error
    end.

cidr_range(Bin) ->
    case binary:split(Bin, <<"/">>, [global]) of
        [AddrBin, PrefixBin] ->
            case {parse_ip(AddrBin), parse_decimal(PrefixBin, ?MAX_PREFIX)} of
                {{ok, Addr}, {ok, Prefix}} ->
                    Base = ip_to_int(Addr) band cidr_mask(Prefix),
                    Size = 1 bsl (?MAX_PREFIX - Prefix),
                    {ok, {int_to_ip(Base), int_to_ip(Base + Size - 1)}};
                _ -> error
            end;
        _ -> error
    end.

cidr_mask(Prefix) ->
    (16#FFFFFFFF bsl (?MAX_PREFIX - Prefix)) band 16#FFFFFFFF.

%% Строгий разбор IPv4: ровно четыре октета, десятичные числа 0..255
%% без знака и без ведущих нулей.
parse_ip(Bin) ->
    case binary:split(Bin, <<".">>, [global]) of
        [A, B, C, D] ->
            case {parse_octet(A), parse_octet(B), parse_octet(C), parse_octet(D)} of
                {{ok, O1}, {ok, O2}, {ok, O3}, {ok, O4}} ->
                    {ok, {O1, O2, O3, O4}};
                _ -> error
            end;
        _ -> error
    end.

parse_octet(<<>>) ->
    error;
parse_octet(<<$0>>) ->
    {ok, 0};
parse_octet(<<C, _/binary>> = Bin) when C >= $1, C =< $9 ->
    parse_decimal(Bin, 255);
parse_octet(_) ->
    error.

%% Десятичное число без знака. Ведущие нули допускаются только там, где
%% это явно разрешено вызывающим кодом (префикс CIDR и порты); октеты
%% используют отдельную проверку выше.
parse_decimal(<<>>, _Max) ->
    error;
parse_decimal(Bin, Max) ->
    case is_all_digits(Bin) of
        true ->
            Value = digits_to_int(Bin),
            case Value =< Max of
                true -> {ok, Value};
                false -> error
            end;
        false -> error
    end.

is_all_digits(<<>>) ->
    true;
is_all_digits(<<C, Rest/binary>>) when C >= $0, C =< $9 ->
    is_all_digits(Rest);
is_all_digits(_) ->
    false.

digits_to_int(Bin) ->
    digits_to_int(Bin, 0).

digits_to_int(<<>>, Acc) ->
    Acc;
digits_to_int(<<C, Rest/binary>>, Acc) ->
    digits_to_int(Rest, Acc * 10 + (C - $0)).

%% Объединение пересекающихся и смежных диапазонов. Работает с парами
%% целых (числовые границы адресов или номера портов).
merge_ranges(Ranges) ->
    lists:reverse(merge_sorted(lists:sort(Ranges), [])).

merge_sorted([], Acc) ->
    Acc;
merge_sorted([Range | Rest], []) ->
    merge_sorted(Rest, [Range]);
merge_sorted([{First, Last} | Rest], [{PrevFirst, PrevLast} | AccRest]) ->
    case First =< PrevLast + 1 of
        true ->
            NewLast = case Last >= PrevLast of
                          true -> Last;
                          false -> PrevLast
                      end,
            merge_sorted(Rest, [{PrevFirst, NewLast} | AccRest]);
        false ->
            merge_sorted(Rest, [{First, Last}, {PrevFirst, PrevLast} | AccRest])
    end.

check_host_limit(Ranges) ->
    case count_hosts(Ranges) > max_hosts() of
        true -> {error, too_many_hosts};
        false -> {ok, Ranges}
    end.

max_hosts() ->
    case application:get_env(trawler, max_hosts, ?DEFAULT_MAX_HOSTS) of
        Limit when is_integer(Limit), Limit >= 0 -> Limit;
        _ -> ?DEFAULT_MAX_HOSTS
    end.

%%% ------------------------------------------------------------------
%%% Порты
%%% ------------------------------------------------------------------

parse_port_elements(Elements) ->
    case port_ranges(Elements, []) of
        {ok, Ranges} -> {ok, merge_ranges(Ranges)};
        {error, Reason} -> {error, Reason}
    end.

port_ranges([], Acc) ->
    {ok, Acc};
port_ranges([Element | Rest], Acc) ->
    case element_port_range(Element) of
        {ok, Range} -> port_ranges(Rest, [Range | Acc]);
        {error, Bad} -> {error, {invalid_ports, Bad}}
    end.

element_port_range(Bin) when is_binary(Bin) ->
    Trimmed = string:trim(Bin),
    case element_port_range_bin(Trimmed) of
        {ok, Range} -> {ok, Range};
        error -> {error, Trimmed}
    end;
element_port_range(Port) when is_integer(Port), Port >= 1, Port =< ?MAX_PORT ->
    {ok, {Port, Port}};
element_port_range({range, First, Last})
  when is_integer(First), First >= 1, First =< ?MAX_PORT,
       is_integer(Last), Last >= 1, Last =< ?MAX_PORT ->
    case First =< Last of
        true -> {ok, {First, Last}};
        false -> {error, {range, First, Last}}
    end.

element_port_range_bin(<<>>) ->
    error;
element_port_range_bin(Bin) ->
    case binary:split(Bin, <<"-">>, [global]) of
        [Single] ->
            case parse_port(Single) of
                {ok, Port} -> {ok, {Port, Port}};
                error -> error
            end;
        [FirstBin, LastBin] ->
            case {parse_port(FirstBin), parse_port(LastBin)} of
                {{ok, First}, {ok, Last}} when First =< Last -> {ok, {First, Last}};
                _ -> error
            end;
        _ -> error
    end.

%% Порт: десятичное число 1..65535.
parse_port(Bin) ->
    case parse_decimal(Bin, ?MAX_PORT) of
        {ok, Port} when Port >= 1 -> {ok, Port};
        _ -> error
    end.
