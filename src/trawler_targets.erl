%%%-------------------------------------------------------------------
%%% @doc Разбор и нормализация выборок IPv4-адресов и TCP-портов.
%%%
%%% Модуль является чистой библиотекой: он не создаёт процессов и не
%%% зависит от состояния приложения. Единственное чтение состояния —
%%% лимит `max_hosts' из окружения приложения `trawler' (по умолчанию
%%% 65536). Все выборки нормализуются, сортируются и очищаются от
%%% повторов до любых сетевых операций.
%%%
%%% Выборка адресов принимает старые формы (одиночный адрес, CIDR,
%%% включительный диапазон полных адресов через дефис) и пооктетные
%%% выражения: ровно четыре октета через точку, октет — непустой
%%% список десятичных чисел 0..255 и включительных диапазонов через
%%% запятую, например `10-11.20-21.30-31.40-41' или
%%% `192.168.3-5,7.1,3-4'. Пропущенная левая граница диапазона
%%% означает 0, правая — 255: `192.0.2.-' задаёт весь последний октет,
%%% `192.0.2.-1' — значения 0 и 1, `192.0.2.10-' — 10..255. Ведущие
%%% нули, знак, обратные границы, двойной дефис, пустые элементы и
%%% пробелы внутри выражения запрещены; CIDR сочетается только с
%%% обычным одиночным адресом.
%%%
%%% Общий бинарный ввод сначала проверяется как старый список через
%%% запятую с обрезкой пробелов; иначе он делится по ASCII-пробелу,
%%% табуляции, CR и LF, и каждый фрагмент — старый список либо одно
%%% пооктетное выражение. Выбор грамматики не зависит от `max_hosts'.
%%% Размер пооктетного произведения проверяется до его разворачивания,
%%% а лимит применяется к объединению уникальных адресов всех целей.
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
-type ports_input() :: binary() | [1..65535 | {range, 1..65535, 1..65535}]
                     | default.
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
    parse_binary_input(Input);
parse_targets(Input) when is_list(Input) ->
    case Input of
        [] ->
            {error, {invalid_targets, []}};
        _ ->
            case list_specs(Input, []) of
                {ok, Specs} -> finish(Specs);
                {error, Reason} -> {error, Reason}
            end
    end.

-spec parse_ports(ports_input()) -> {ok, [port_range()]} | {error, reason()}.
parse_ports(default) ->
    {ok, [{P, P} || P <- trawler_ports:default()]};
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

%% Числовой интервал адресов, включительно.
-type int_range() :: {non_neg_integer(), non_neg_integer()}.
%% Объединение значений одного октета: отсортированные несмежные интервалы.
-type octet_union() :: [{0..255, 0..255}].
%% Пооктетная цель: объединения значений четырёх октетов.
-type octet_spec() :: {octet_union(), octet_union(), octet_union(), octet_union()}.
%% Разобранная цель: сжатый интервал либо пооктетное произведение.
-type target_spec() :: {range, int_range()} | {octets, octet_spec()}.

%% Общий бинарный ввод: сначала старый список через запятую, иначе
%% фрагменты по ASCII-пробельным символам.
-spec parse_binary_input(binary()) ->
          {ok, [addr_range()]}
        | {error, {invalid_targets, binary()} | too_many_hosts}.
parse_binary_input(Bin) ->
    case legacy_list_specs(Bin) of
        {ok, Specs} ->
            finish(Specs);
        {error, _Reason} ->
            case whitespace_fragments(Bin) of
                [] -> {error, {invalid_targets, <<>>}};
                Fragments -> finish_specs(fragment_specs(Fragments, []))
            end
    end.

finish_specs({ok, Specs}) -> finish(Specs);
finish_specs({error, Reason}) -> {error, Reason}.

%% Старый список: элементы через запятую с обрезкой пробелов. При
%% ошибке возвращается первый неразобранный элемент, включая пустой.
-spec legacy_list_specs(binary()) -> {ok, [target_spec()]} | {error, binary()}.
legacy_list_specs(Bin) ->
    legacy_list_specs(binary:split(Bin, <<",">>, [global]), []).

legacy_list_specs([], Acc) ->
    {ok, lists:reverse(Acc)};
legacy_list_specs([Element | Rest], Acc) ->
    Trimmed = string:trim(Element),
    case element_range_bin(Trimmed) of
        {ok, Range} -> legacy_list_specs(Rest, [{range, Range} | Acc]);
        error -> {error, Trimmed}
    end.

%% Пробельное разделение новых целей: пробел, табуляция, CR и LF.
whitespace_fragments(Bin) ->
    [Fragment
     || Fragment <- binary:split(Bin, [<<" ">>, <<"\t">>, <<"\r">>, <<"\n">>],
                                 [global]),
        Fragment =/= <<>>].

fragment_specs([], Acc) ->
    {ok, lists:append(lists:reverse(Acc))};
fragment_specs([Fragment | Rest], Acc) ->
    case fragment_specs_one(Fragment) of
        {ok, Specs} -> fragment_specs(Rest, [Specs | Acc]);
        {error, _} = Error -> Error
    end.

%% Один фрагмент: старый список либо одно пооктетное выражение.
%% Выбор грамматики не зависит от лимита хостов.
fragment_specs_one(Fragment) ->
    case legacy_list_specs(Fragment) of
        {ok, Specs} ->
            {ok, Specs};
        {error, BadElement} ->
            case octet_spec(Fragment) of
                {ok, Spec} -> {ok, [{octets, Spec}]};
                error -> {error, {invalid_targets, BadElement}}
            end
    end.

-spec list_specs([ip4() | binary()], [target_spec()]) ->
          {ok, [target_spec()]} | {error, {invalid_targets, binary()}}.
list_specs([], Acc) ->
    {ok, lists:reverse(Acc)};
list_specs([Element | Rest], Acc) ->
    case element_spec(Element) of
        {ok, Spec} -> list_specs(Rest, [Spec | Acc]);
        {error, _} = Error -> Error
    end.

%% Элемент Erlang-списка: ip4()-кортеж либо одна цель в бинарной
%% строке (старая форма или пооктетное выражение).
element_spec(Bin) when is_binary(Bin) ->
    Trimmed = string:trim(Bin),
    case element_range_bin(Trimmed) of
        {ok, Range} ->
            {ok, {range, Range}};
        error ->
            case octet_spec(Trimmed) of
                {ok, Spec} -> {ok, {octets, Spec}};
                error -> {error, {invalid_targets, Trimmed}}
            end
    end;
element_spec({A, B, C, D}) when is_integer(A), A >= 0, A =< 255,
                                is_integer(B), B >= 0, B =< 255,
                                is_integer(C), C >= 0, C =< 255,
                                is_integer(D), D >= 0, D =< 255 ->
    Addr = ip_to_int({A, B, C, D}),
    {ok, {range, {Addr, Addr}}}.

%% Старая форма одной цели: одиночный IPv4, CIDR или включительный
%% диапазон полных адресов. Возвращается числовой интервал адресов.
-spec element_range_bin(binary()) -> {ok, int_range()} | error.
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
        {ok, Addr} -> {ok, single_int_range(Addr)};
        error -> error
    end.

address_range(Bin) ->
    case binary:split(Bin, <<"-">>, [global]) of
        [FirstBin, LastBin] ->
            case {parse_ip(FirstBin), parse_ip(LastBin)} of
                {{ok, First}, {ok, Last}} ->
                    FirstInt = ip_to_int(First),
                    LastInt = ip_to_int(Last),
                    case FirstInt =< LastInt of
                        true -> {ok, {FirstInt, LastInt}};
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
                    {ok, {Base, Base + Size - 1}};
                _ -> error
            end;
        _ -> error
    end.

single_int_range(Addr) ->
    Int = ip_to_int(Addr),
    {Int, Int}.

%%% ------------------------------------------------------------------
%%% Пооктетная грамматика
%%% ------------------------------------------------------------------

%% Пооктетная цель: ровно четыре октета через точку.
-spec octet_spec(binary()) -> {ok, octet_spec()} | error.
octet_spec(Bin) ->
    case binary:split(Bin, <<".">>, [global]) of
        [F1, F2, F3, F4] ->
            case {octet_union(F1), octet_union(F2),
                  octet_union(F3), octet_union(F4)} of
                {{ok, U1}, {ok, U2}, {ok, U3}, {ok, U4}} ->
                    {ok, {U1, U2, U3, U4}};
                _ -> error
            end;
        _ -> error
    end.

%% Октет: непустой список элементов через запятую.
-spec octet_union(binary()) -> {ok, octet_union()} | error.
octet_union(<<>>) ->
    error;
octet_union(Bin) ->
    octet_elements(binary:split(Bin, <<",">>, [global]), []).

octet_elements([], Acc) ->
    {ok, merge_ranges(Acc)};
octet_elements([Element | Rest], Acc) ->
    case octet_element(Element) of
        {ok, Range} -> octet_elements(Rest, [Range | Acc]);
        error -> error
    end.

%% Элемент октета: число 0..255 либо диапазон a-b, a-, -b, -.
octet_element(<<>>) ->
    error;
octet_element(Bin) ->
    case binary:split(Bin, <<"-">>, [global]) of
        [Single] ->
            case parse_octet(Single) of
                {ok, Value} -> {ok, {Value, Value}};
                error -> error
            end;
        [FirstBin, LastBin] ->
            octet_bounds(FirstBin, LastBin);
        _ ->
            error
    end.

%% Пропущенная граница диапазона означает 0 слева и 255 справа.
octet_bounds(<<>>, <<>>) ->
    {ok, {0, 255}};
octet_bounds(<<>>, LastBin) ->
    case parse_octet(LastBin) of
        {ok, Last} -> {ok, {0, Last}};
        error -> error
    end;
octet_bounds(FirstBin, <<>>) ->
    case parse_octet(FirstBin) of
        {ok, First} -> {ok, {First, 255}};
        error -> error
    end;
octet_bounds(FirstBin, LastBin) ->
    case {parse_octet(FirstBin), parse_octet(LastBin)} of
        {{ok, First}, {ok, Last}} when First =< Last -> {ok, {First, Last}};
        _ -> error
    end.

%% Декартово произведение октетов в возрастающем порядке: значения
%% каждого октета упорядочены, поэтому интервалы собираются за проход.
product_intervals({U1, U2, U3, U4}) ->
    Addresses = [O1 * 16777216 + O2 * 65536 + O3 * 256 + O4
                 || O1 <- union_values(U1), O2 <- union_values(U2),
                    O3 <- union_values(U3), O4 <- union_values(U4)],
    addresses_to_intervals(Addresses).

union_values(Union) ->
    lists:append([lists:seq(First, Last) || {First, Last} <- Union]).

addresses_to_intervals([]) ->
    [];
addresses_to_intervals([Address | Rest]) ->
    addresses_to_intervals(Rest, Address, Address, []).

addresses_to_intervals([], Start, End, Acc) ->
    lists:reverse([{Start, End} | Acc]);
addresses_to_intervals([Address | Rest], Start, End, Acc)
  when Address =:= End + 1 ->
    addresses_to_intervals(Rest, Start, Address, Acc);
addresses_to_intervals([Address | Rest], Start, End, Acc) ->
    addresses_to_intervals(Rest, Address, Address, [{Start, End} | Acc]).

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

%% Объединение всех целей в отсортированные несмежные интервалы с
%% инкрементальной проверкой общего лимита уникальных адресов.
finish(Specs) ->
    Limit = max_hosts(),
    case union_specs(Specs, [], Limit) of
        {ok, Intervals} ->
            {ok, [int_to_addr_range(Interval) || Interval <- Intervals]};
        {error, Reason} ->
            {error, Reason}
    end.

int_to_addr_range({First, Last}) ->
    {int_to_ip(First), int_to_ip(Last)}.

-spec union_specs([target_spec()], [int_range()], non_neg_integer()) ->
          {ok, [int_range()]} | {error, too_many_hosts}.
union_specs([], Acc, _Limit) ->
    {ok, Acc};
union_specs([Spec | Rest], Acc, Limit) ->
    case spec_intervals(Spec, Limit) of
        {ok, Intervals} ->
            {Merged, Count} = merge_intervals(Intervals, Acc),
            case Count > Limit of
                true -> {error, too_many_hosts};
                false -> union_specs(Rest, Merged, Limit)
            end;
        {error, _} = Error ->
            Error
    end.

%% Интервалы одной цели. Размер пооктетного произведения проверяется
%% до разворачивания, поэтому чрезмерная цель не материализуется.
-spec spec_intervals(target_spec(), non_neg_integer()) ->
          {ok, [int_range()]} | {error, too_many_hosts}.
spec_intervals({range, Range}, _Limit) ->
    {ok, [Range]};
spec_intervals({octets, Octets}, Limit) ->
    case product_size(Octets) > Limit of
        true -> {error, too_many_hosts};
        false -> {ok, product_intervals(Octets)}
    end.

product_size({U1, U2, U3, U4}) ->
    union_size(U1) * union_size(U2) * union_size(U3) * union_size(U4).

union_size(Union) ->
    lists:sum([Last - First + 1 || {First, Last} <- Union]).

%% Линейное слияние пакета отсортированных интервалов одной цели с
%% накопленным отсортированным списком. Оба списка упорядочены по
%% первой границе, поэтому слияние и нормализация выполняется за один
%% проход по обоим спискам, а число уникальных адресов считается по
%% итоговым несмежным интервалам без материализации отдельных адресов.
%% Это заменяет прежнюю вставку по одному интервалу, которая копировала
%% префикс накопленного списка и была квадратичной по числу интервалов.
-spec merge_intervals([int_range()], [int_range()]) ->
          {[int_range()], non_neg_integer()}.
merge_intervals(Intervals, Acc) ->
    normalize_intervals(lists:merge(Intervals, Acc), undefined, 0, []).

normalize_intervals([], undefined, Count, Acc) ->
    {lists:reverse(Acc), Count};
normalize_intervals([], {Start, End}, Count, Acc) ->
    {lists:reverse([{Start, End} | Acc]), Count + End - Start + 1};
normalize_intervals([{First, Last} | Rest], undefined, Count, Acc) ->
    normalize_intervals(Rest, {First, Last}, Count, Acc);
normalize_intervals([{First, Last} | Rest], {Start, End}, Count, Acc)
  when First =< End + 1 ->
    normalize_intervals(Rest, {Start, max(End, Last)}, Count, Acc);
normalize_intervals([{First, Last} | Rest], {Start, End}, Count, Acc) ->
    normalize_intervals(Rest, {First, Last}, Count + End - Start + 1,
                        [{Start, End} | Acc]).

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
