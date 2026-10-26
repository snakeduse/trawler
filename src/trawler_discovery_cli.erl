%%%-------------------------------------------------------------------
%%% @doc CLI-адаптер обнаружения хостов IPv4 (команда discover).
%%%
%%% Разбирает аргументы discover, вызывает публичный API
%%% {@link trawler:start_discovery/2} или {@link trawler:discover/2} и
%%% возвращает код выхода `0 | 1 | 2'. Виртуальную машину завершает
%%% только {@link trawler_cli}; этот модуль ничего не останавливает сам,
%%% поэтому при ошибке статуса успевает отменить собственное задание
%%% перед возвратом кода 1.
%%%
%%% Текстовый режим работает через асинхронный API и печатает
%%% подтверждённые адреса по мере получения (`IP METHOD MAC', MAC — при
%%% наличии); при `--os' добавляется столбец приблизительной ОС с
%%% уверенностью, при `--ports' — открытые выбранные порты. Закрытые и
%%% молчащие порты не фильтруют находки. Остальные исходы видны только с
%%% `--verbose'. Прогресс идёт в stderr: одна обновляемая строка в
%%% терминале (очистка строки ДО печати заголовка и находки) и редкие
%%% строки без ANSI при перенаправлении по абсолютному сроку. JSON
%%% использует синхронный API и отдаёт один полный объект без прогресса;
%%% состояния всех запрошенных портов, открытые порты, ОС с основаниями и
%%% строковая причина ошибки инспектора сохраняются полностью.
%%% Предупреждения при этом направляются в stderr.
%%%
%%% `--ports' разрешён при любом методе и означает дополнительные
%%% проверки найденных адресов; это не фильтр IP. `--os' — неповторяемый
%%% флаг, по умолчанию определение ОС выключено. Внутренние порты
%%% обнаружения tcp/auto (80/443 без явного набора) в предупреждении о
%%% fallback не перечисляются: явный `--ports' заменяет этот набор.
%%%
%%% Коды выхода: 2 — неверные аргументы или отклонённый запрос до проб;
%%% 1 — недоступный метод, ошибка запуска или выполнения; 0 — поиск
%%% закончился, независимо от числа находок и ошибок отдельных адресов.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_cli).

-export([run/1, help/0]).

%% Частота обновления прогресса в терминале и при перенаправлении, мс.
-define(TTY_INTERVAL_MS, 250).
-define(PLAIN_INTERVAL_MS, 2000).

%%% ------------------------------------------------------------------
%%% Точка входа
%%% ------------------------------------------------------------------

%% @doc Выполняет команду discover и возвращает код выхода.
%%
%% Завершение виртуальной машины остаётся за {@link trawler_cli}.
-spec run([string()]) -> 0 | 1 | 2.
run(["--help"]) ->
    help(),
    0;
run(["-h"]) ->
    help(),
    0;
run(Args) ->
    case parse(Args, #{}, []) of
        {ok, Parsed} -> execute(Parsed);
        {error, Message} ->
            diagnostic("trawler discover: " ++ Message),
            2
    end.

%% @doc Печатает справку по команде discover в stdout.
-spec help() -> ok.
help() ->
    io:put_chars(
        "trawler discover - поиск отвечающих IPv4-хостов\n\n"
        "Использование:\n"
        "  trawler discover --targets <TARGETS> [--method <METHOD>] [опции]\n\n"
        "Методы обнаружения (--method):\n"
        "  auto       По маршруту ядра: ARP в подключённом Ethernet, иначе\n"
        "             ICMP echo/timestamp и raw TCP SYN/ACK; без raw-прав —\n"
        "             переход на TCP connect к выбранным портам, а без\n"
        "             --ports — к 80/443 (по умолчанию)\n"
        "  arp        Только ARP (Linux, raw, подключённый Ethernet)\n"
        "  icmp       ICMP echo и timestamp (Linux, raw)\n"
        "  tcp        TCP connect к указанным или 80/443 портам (без root)\n"
        "  raw_tcp    TCP SYN 443 и ACK 80 (Linux, raw)\n\n"
        "Параметры:\n"
        "  --targets <TARGETS>   Обязательно. Адреса IPv4, сети и пооктетные\n"
        "                        выражения: 127.0.0.1,10.0.0.0/30,\n"
        "                        192.168.3-5,7.1,3-4.\n"
        "  --method <METHOD>     Метод: auto|arp|icmp|tcp|raw_tcp.\n"
        "  --ports <PORTS>       Необязательно, при любом методе. Порты и\n"
        "                        диапазоны через запятую: проверяются у\n"
        "                        каждого найденного адреса, но НЕ фильтруют\n"
        "                        находки. Без явного набора tcp/auto\n"
        "                        проверяют 80/443. Ограничения в 16 портов\n"
        "                        нет; большой набор может не успеть за бюджет\n"
        "                        адреса, тогда оставшиеся порты получают\n"
        "                        skipped.\n"
        "  --os                  Приблизительно определить ОС (windows|linux|\n"
        "                        unknown) по SSH-баннеру и открытым служебным\n"
        "                        портам. По умолчанию выключено; уверенность\n"
        "                        medium|low|none, unknown допустим. Открытый\n"
        "                        SSH или SMB не доказывает семью ОС.\n"
        "  --timeout <N>         Бюджет одного адреса в миллисекундах (N > 0);\n"
        "                        общий для поиска маршрута, пробы, чтения\n"
        "                        баннера и проверки портов\n"
        "  --concurrency <N>     Одновременных адресов (N > 0)\n"
        "  --retries <N>         Повторов каждой пробы, 0..5\n"
        "  --json                Один полный JSON-объект вместо таблицы\n"
        "  --verbose             Показать состояние каждого адреса\n"
        "  --no-progress         Отключить прогресс и heartbeat в stderr\n\n"
        "Поведение:\n"
        "  подтверждённые адреса печатаются сразу как IP, метод и MAC;\n"
        "  с --os добавляется столбец ОС с уверенностью и пометкой\n"
        "  предположения, с --ports — открытые выбранные порты. Адрес\n"
        "  печатается даже при неизвестной ОС и всех закрытых портах.\n"
        "  TCP-таймаут не означает отсутствия компьютера. Прогресс и\n"
        "  предупреждения идут в stderr, находки и JSON — в stdout. Nmap\n"
        "  не используется; установка ПО, выдача прав и точное совпадение\n"
        "  с Nmap не обещаются.\n\n"
        "Коды выхода:\n"
        "  0  поиск завершён, включая отсутствие находок и ошибки адресов\n"
        "  1  недоступный метод, ошибка запуска или выполнения\n"
        "  2  неверные аргументы или отклонённый запрос\n\n"),
    ok.

%%% ------------------------------------------------------------------
%%% Разбор аргументов
%%% ------------------------------------------------------------------

parse([Option | Rest], Acc, Seen) ->
    case flag_key(Option) of
        {ok, Key} -> set_flag(Key, Option, Rest, Acc, Seen);
        error -> parse_value(Option, Rest, Acc, Seen)
    end;
parse([], Acc, Seen) ->
    case lists:member(targets, Seen) of
        false -> {error, "missing required option --targets"};
        true -> {ok, Acc}
    end.

flag_key("--os") -> {ok, os};
flag_key("--json") -> {ok, json};
flag_key("--verbose") -> {ok, verbose};
flag_key("--no-progress") -> {ok, no_progress};
flag_key(_Other) -> error.

set_flag(Key, Option, Rest, Acc, Seen) ->
    case lists:member(Key, Seen) of
        true -> {error, "duplicate option " ++ Option};
        false -> parse(Rest, Acc#{Key => true}, [Key | Seen])
    end.

parse_value(Option, Rest, Acc, Seen) ->
    case option_key(Option) of
        {ok, Key} ->
            case Rest of
                [Value | Rest1] -> set_option(Key, Option, Value, Rest1, Acc, Seen);
                [] -> {error, "option " ++ Option ++ " requires a value"}
            end;
        error ->
            {error, "unknown option " ++ Option}
    end.

option_key("--targets") -> {ok, targets};
option_key("--method") -> {ok, method};
option_key("--ports") -> {ok, ports};
option_key("--timeout") -> {ok, timeout};
option_key("--concurrency") -> {ok, concurrency};
option_key("--retries") -> {ok, retries};
option_key(_Other) -> error.

set_option(Key, Option, Value, Rest, Acc, Seen) ->
    case lists:member(Key, Seen) of
        true ->
            {error, "duplicate option " ++ Option};
        false ->
            case option_value(Key, Value) of
                {ok, Parsed} -> parse(Rest, Acc#{Key => Parsed}, [Key | Seen]);
                error -> {error, "invalid value for " ++ Option ++ ": " ++ Value}
            end
    end.

option_value(targets, Value) -> {ok, Value};
option_value(ports, Value) -> {ok, Value};
option_value(timeout, Value) -> positive_int(Value);
option_value(concurrency, Value) -> positive_int(Value);
option_value(retries, Value) -> retries_int(Value);
option_value(method, Value) -> method_value(Value).

%% Статическое преобразование строки в известный метод: атомы из
%% пользовательского ввода не создаются.
method_value("auto") -> {ok, auto};
method_value("arp") -> {ok, arp};
method_value("icmp") -> {ok, icmp};
method_value("tcp") -> {ok, tcp};
method_value("raw_tcp") -> {ok, raw_tcp};
method_value(_Other) -> error.

positive_int(Value) ->
    case string:to_integer(string:trim(Value)) of
        {Int, []} when is_integer(Int), Int > 0 -> {ok, Int};
        _Other -> error
    end.

retries_int(Value) ->
    case string:to_integer(string:trim(Value)) of
        {Int, []} when is_integer(Int), Int >= 0, Int =< 5 -> {ok, Int};
        _Other -> error
    end.

%%% ------------------------------------------------------------------
%%% Выполнение запроса
%%% ------------------------------------------------------------------

execute(Parsed) ->
    start_and_dispatch(Parsed).

start_and_dispatch(Parsed) ->
    case application:ensure_all_started(trawler) of
        {ok, _Started} ->
            dispatch(Parsed);
        {error, Reason} ->
            diagnostic("trawler discover: cannot start trawler: "
                       ++ format_reason(Reason)),
            1
    end.

dispatch(Parsed) ->
    case request(Parsed) of
        {ok, Targets, Options} ->
            case maps:get(json, Parsed, false) of
                true -> json_mode(Targets, Options);
                false -> text_mode(Parsed, Targets, Options)
            end;
        {error, Code} ->
            Code
    end.

request(Parsed) ->
    case to_binary(maps:get(targets, Parsed)) of
        {ok, Targets} -> request_ports(Parsed, Targets);
        error -> encode_error()
    end.

request_ports(Parsed, Targets) ->
    case maps:find(ports, Parsed) of
        error ->
            {ok, Targets, discover_options(Parsed)};
        {ok, PortsValue} ->
            case to_binary(PortsValue) of
                {ok, PortsBin} ->
                    {ok, Targets, discover_options(Parsed#{ports := PortsBin})};
                error ->
                    encode_error()
            end
    end.

discover_options(Parsed) ->
    O0 = add_option(method, method, Parsed, #{}),
    O1 = add_option(ports, ports, Parsed, O0),
    O2 = add_option(timeout, timeout_ms, Parsed, O1),
    O3 = add_option(concurrency, concurrency, Parsed, O2),
    O4 = add_option(retries, retries, Parsed, O3),
    add_option(os, os_detection, Parsed, O4).

%% Ключи по умолчанию не добавляются: их применяет публичный API.
add_option(CliKey, ApiKey, Parsed, Acc) ->
    case maps:find(CliKey, Parsed) of
        {ok, Value} -> Acc#{ApiKey => Value};
        error -> Acc
    end.

to_binary(Value) ->
    case unicode:characters_to_binary(Value) of
        Bin when is_binary(Bin) -> {ok, Bin};
        _Error -> error
    end.

encode_error() ->
    diagnostic("trawler discover: cannot encode arguments as UTF-8"),
    {error, 1}.

%%% ------------------------------------------------------------------
%%% JSON-режим (синхронный)
%%% ------------------------------------------------------------------

json_mode(Targets, Options) ->
    case trawler:discover(Targets, Options) of
        {ok, Results, Summary} ->
            print_warnings(Summary),
            print_json(Results, Summary),
            0;
        {error, Reason} ->
            report_error(Reason)
    end.

%%% ------------------------------------------------------------------
%%% Текстовый режим (асинхронный, потоковый)
%%% ------------------------------------------------------------------

text_mode(Parsed, Targets, Options) ->
    RecipientOptions = Options#{recipient => self()},
    case trawler:start_discovery(Targets, RecipientOptions) of
        {ok, Ref} ->
            run_text(Ref, progress_mode(Parsed),
                     maps:get(verbose, Parsed, false), Parsed);
        {error, Reason} ->
            report_error(Reason)
    end.

%% Статус используется только для общего числа адресов (и как признак
%% жизни): промежуточные completed и счётчики считаются исключительно по
%% обработанным событиям, а итоговые числа авторитетно задаёт завершающая
%% сводка. Иначе при быстром задании статус уже равен total, и повторный
%% учёт событий удваивал бы прогресс и находки.
run_text(Ref, Mode, Verbose, Parsed) ->
    Start = erlang:monotonic_time(millisecond),
    Interval = progress_interval(Mode),
    State0 = #{ref => Ref,
               mode => Mode,
               verbose => Verbose,
               with_os => maps:get(os, Parsed, false),
               with_ports => maps:is_key(ports, Parsed),
               total => status_total(Ref),
               completed => 0,
               counters => zero_counters(),
               elapsed => 0,
               start => Start,
               interval => Interval,
               next_update => Start + Interval,
               header => false},
    text_loop(erlang:monotonic_time(millisecond), emit_progress(State0)).

%% Плановый срок обновления абсолютный: непрерывный поток событий не
%% откладывает ни прогресс, ни контроль статуса.
text_loop(Now, State) ->
    Ref = maps:get(ref, State),
    Timeout = max(maps:get(next_update, State) - Now, 0),
    receive
        {trawler_discovery, Ref, {result, Result}} ->
            case text_result(Result, State) of
                {continue, State1} ->
                    text_loop(erlang:monotonic_time(millisecond), State1);
                {stop, Code} ->
                    Code
            end;
        {trawler_discovery, Ref, {warning, Warning}} ->
            print_warning(Warning),
            Now2 = erlang:monotonic_time(millisecond),
            case Now2 >= maps:get(next_update, State) of
                true ->
                    case text_tick(State) of
                        {continue, State1} -> text_loop(Now2, State1);
                        {stop, Code} -> Code
                    end;
                false ->
                    text_loop(Now2, State)
            end;
        {trawler_discovery, Ref, {done, Summary}} ->
            finish_done(Summary, State);
        {trawler_discovery, Ref, {cancelled, Summary}} ->
            finish_failed(cancelled, Summary, State);
        {trawler_discovery, Ref, {error, Reason, Summary}} ->
            finish_failed(Reason, Summary, State)
    after Timeout ->
        case text_tick(State) of
            {continue, State1} ->
                text_loop(erlang:monotonic_time(millisecond), State1);
            {stop, Code} ->
                Code
        end
    end.

text_result(Result, State) ->
    State1 = account_result(Result, State),
    State2 = print_finding(Result, State1),
    Now = erlang:monotonic_time(millisecond),
    case Now >= maps:get(next_update, State2) of
        true -> text_tick(State2);
        false -> {continue, State2}
    end.

%% Периодическое обновление: прогресс по обработанным событиям и контроль
%% доступности статуса. Статус служит только признаком жизни: его
%% completed и счётчики не копируются, иначе они учитывались бы дважды
%% (см. run_text/4). Потеря статуса отменяет своё задание, чтобы не
%% оставить воркер после возврата кода 1.
text_tick(State) ->
    Ref = maps:get(ref, State),
    case discovery_status(Ref) of
        {ok, _Status} ->
            {continue, emit_progress(State)};
        {error, _Reason} ->
            cancel_own_job(Ref),
            finish_progress(State),
            progress_diagnostic("discovery state is not available"),
            {stop, 1}
    end.

cancel_own_job(Ref) ->
    _ = try trawler:cancel_discovery(Ref) catch _:_ -> ok end,
    ok.

account_result(Result, State) ->
    Key = maps:get(state, Result),
    Counters = maps:update_with(Key, fun(N) -> N + 1 end,
                                maps:get(counters, State)),
    State#{completed := maps:get(completed, State) + 1,
           counters := Counters}.

%% Текстовый режим печатает подтверждённые адреса всегда, остальные
%% исходы — только с --verbose.
print_finding(Result, State) ->
    Show = maps:get(verbose, State) orelse maps:get(state, Result) =:= up,
    case Show of
        true ->
            State1 = clear_progress_line(State),
            State2 = print_header(State1),
            print_result(Result, State2),
            redraw_progress(State2);
        false ->
            State
    end.

print_header(#{header := false} = State) ->
    print_columns(header_columns(State)),
    State#{header := true};
print_header(State) ->
    State.

%% Столбцы IP/METHOD/MAC сохраняются всегда; столбцы ОС и открытых
%% выбранных портов добавляются только по запрошенным опциям. Последний
%% столбец не дополняется пробелами, поэтому прежний вывод без опций
%% побайтно совпадает со старым форматом.
header_columns(State) ->
    [{<<"IP">>, 16}, {<<"МЕТОД"/utf8>>, 12}, {<<"MAC">>, 18}] ++
        header_optional_columns(State).

finding_columns(Result, State) ->
    [{ip_bin(Result), 16},
     {method_bin(Result), 12},
     {mac_bin(Result), 18}] ++ finding_optional_columns(Result, State).

header_optional_columns(State) ->
    header_os_columns(State) ++ header_ports_columns(State).

header_os_columns(#{with_os := true}) ->
    [{<<"ОС"/utf8>>, 32}];
header_os_columns(_State) ->
    [].

header_ports_columns(#{with_ports := true}) ->
    [{<<"ОТКРЫТЫЕ ПОРТЫ"/utf8>>, 0}];
header_ports_columns(_State) ->
    [].

finding_optional_columns(Result, #{with_os := true}) ->
    [{os_cell(Result), 32}];
finding_optional_columns(_Result, _State) ->
    [].

%% Открытые порты — последний столбец и печатаются без выравнивания.
ports_column(#{with_ports := true}, Result) ->
    [{ports_cell(Result), 0}];
ports_column(_State, _Result) ->
    [].

print_result(Result, State) ->
    case maps:get(state, Result) of
        up ->
            print_columns(finding_columns(Result, State) ++
                              ports_column(State, Result));
        Other ->
            io:format("~-16ts ~ts~n",
                      [ip_bin(Result), atom_to_binary(Other, utf8)])
    end.

print_columns(Columns) ->
    {Init, [{_Last, _Width}]} =
        lists:split(length(Columns) - 1, Columns),
    Format = lists:flatten(
               [["~-", integer_to_list(Width), "ts "] || {_Value, Width} <- Init]
               ++ ["~ts~n"]),
    Values = [Value || {Value, _Ignored} <- Columns],
    io:format(Format, Values).

%% Приблизительная ОС: unknown печатается как есть, распознанная семья —
%% с уверенностью и явной пометкой предположения.
os_cell(Result) ->
    case maps:find(os, Result) of
        {ok, #{family := unknown}} ->
            <<"unknown">>;
        {ok, #{family := Family, confidence := Confidence}} ->
            <<(atom_to_binary(Family, utf8))/binary, " (",
              (atom_to_binary(Confidence, utf8))/binary,
              ", предположение)"/utf8>>;
        _Other ->
            <<"-">>
    end.

%% Только открытые ЯВНО выбранные порты; пустой список печатается как
%% прочерк, а адрес остаётся находкой.
ports_cell(Result) ->
    case maps:find(open_ports, Result) of
        {ok, [_ | _] = Ports} ->
            iolist_to_binary(lists:join(
                               <<",">>,
                               [integer_to_binary(Port) || Port <- Ports]));
        _Other ->
            <<"-">>
    end.

method_bin(Result) ->
    case maps:find(method, Result) of
        {ok, Method} -> atom_to_binary(Method, utf8);
        error -> <<"-">>
    end.

mac_bin(Result) ->
    case maps:find(mac, Result) of
        {ok, Mac} -> mac_colon(Mac);
        error -> <<"-">>
    end.

%%% ------------------------------------------------------------------
%%% Завершение
%%% ------------------------------------------------------------------

finish_done(Summary, State) ->
    State1 = final_state(Summary, State),
    finish_progress(State1),
    print_summary(State1),
    0.

finish_failed(Reason, Summary, State) ->
    State1 = final_state(Summary, State),
    finish_progress(State1),
    report_error(Reason).

%% Завершающая сводка ядра авторитетна для итоговых чисел.
final_state(#{total := Total, completed := Completed, counters := Counters,
              elapsed_ms := Elapsed}, State) ->
    State#{total := Total, completed := Completed, counters := Counters,
           elapsed := Elapsed}.

print_summary(State) ->
    Counters = maps:get(counters, State),
    io:format("Завершено: ~b из ~b адресов за ~b мс~n",
              [maps:get(completed, State), maps:get(total, State),
               maps:get(elapsed, State)]),
    print_up_count(maps:get(up, Counters)),
    io:format("Без ответа: ~b~n", [maps:get(no_response, Counters)]),
    io:format("Ошибки: ~b~n", [maps:get(error, Counters)]).

print_up_count(0) ->
    io:put_chars("Отвечающих адресов не найдено\n");
print_up_count(Up) ->
    io:format("Найдено отвечающих адресов: ~b~n", [Up]).

%%% ------------------------------------------------------------------
%%% Прогресс
%%% ------------------------------------------------------------------

progress_mode(Parsed) ->
    case maps:get(no_progress, Parsed, false) of
        true -> off;
        false ->
            case stderr_is_terminal() of
                true -> tty;
                false -> plain
            end
    end.

stderr_is_terminal() ->
    try proplists:get_value(stderr, io:getopts(standard_io), false) of
        true -> true;
        _Other -> false
    catch
        _:_ -> false
    end.

progress_interval(tty) -> ?TTY_INTERVAL_MS;
progress_interval(_Other) -> ?PLAIN_INTERVAL_MS.

emit_progress(State) ->
    advance(print_progress(State)).

print_progress(State) ->
    case maps:get(mode, State) of
        off -> State;
        tty ->
            io:format(standard_error, "\r\e[K~ts", [progress_line(State)]),
            State;
        plain ->
            io:format(standard_error, "~ts~n", [progress_line(State)]),
            State
    end.

finish_progress(State) ->
    case maps:get(mode, State) of
        off -> ok;
        tty ->
            io:format(standard_error, "\r\e[K~ts~n", [progress_line(State)]);
        plain ->
            io:format(standard_error, "~ts~n", [progress_line(State)])
    end.

clear_progress_line(#{mode := tty} = State) ->
    io:format(standard_error, "\r\e[K", []),
    State;
clear_progress_line(State) ->
    State.

redraw_progress(#{mode := tty} = State) ->
    io:format(standard_error, "\r\e[K~ts", [progress_line(State)]),
    State;
redraw_progress(State) ->
    State.

advance(State) ->
    Now = erlang:monotonic_time(millisecond),
    State#{next_update := Now + maps:get(interval, State)}.

progress_line(State) ->
    Completed = maps:get(completed, State),
    Total = maps:get(total, State),
    Up = maps:get(up, maps:get(counters, State)),
    io_lib:format("Проверено ~b/~b (~b%) | найдено ~b | ~b с",
                  [Completed, Total, percent(Completed, Total), Up,
                   elapsed_seconds(State)]).

percent(_Completed, 0) -> 100;
percent(Completed, Total) -> Completed * 100 div Total.

elapsed_seconds(State) ->
    (erlang:monotonic_time(millisecond) - maps:get(start, State)) div 1000.

%% Любой исход приводится к {ok, Status} | {error, Reason}: исключение или
%% неожиданный ответ ядра не должны давать case_clause в вызывающем коде,
%% иначе задание остаётся без отмены, а выход — без контроля. `catch'
%% превращает throw, error и exit в значение, поэтому за это сопоставление
%% не выходит ни один исход.
discovery_status(Ref) ->
    case catch trawler:discovery_status(Ref) of
        {ok, Status} -> {ok, Status};
        {error, Reason} -> {error, Reason};
        Other -> {error, {status_unavailable, Other}}
    end.

%% Доступный статус даёт общее число адресов, недоступный — 0. Ни
%% completed, ни счётчики из статуса здесь не берутся.
status_total(Ref) ->
    case discovery_status(Ref) of
        {ok, Status} -> maps:get(total, Status, 0);
        {error, _Reason} -> 0
    end.

%%% ------------------------------------------------------------------
%%% Сводка и JSON
%%% ------------------------------------------------------------------

zero_counters() ->
    #{up => 0, no_response => 0, error => 0}.

print_json(Results, Summary) ->
    Json = #{<<"results">> => [result_json(R) || R <- Results],
             <<"summary">> => summary_json(Summary)},
    io:put_chars([json:encode(Json), $\n]).

result_json(Result) ->
    Base = #{<<"ip">> => ip_bin(Result),
             <<"state">> => atom_to_binary(maps:get(state, Result), utf8),
             <<"elapsed_ms">> => maps:get(elapsed_ms, Result)},
    R1 = maybe_put(<<"method">>, find_binary(method, Result), Base),
    R2 = maybe_put(<<"mac">>, find_mac(Result), R1),
    R3 = maybe_put(<<"port">>, maps:find(port, Result), R2),
    R4 = maybe_put(<<"reason">>, find_reason(Result), R3),
    R5 = maybe_put(<<"port_results">>, find_port_results(Result), R4),
    R6 = maybe_put(<<"open_ports">>, find_open_ports(Result), R5),
    R7 = maybe_put(<<"os">>, find_os(Result), R6),
    maybe_put(<<"inspection_error">>, find_inspection_error(Result), R7).

maybe_put(Key, {ok, Value}, Map) -> Map#{Key => Value};
maybe_put(_Key, error, Map) -> Map.

find_binary(Key, Result) ->
    case maps:find(Key, Result) of
        {ok, Atom} when is_atom(Atom) -> {ok, atom_to_binary(Atom, utf8)};
        _Other -> error
    end.

find_mac(Result) ->
    case maps:find(mac, Result) of
        {ok, Mac} -> {ok, mac_colon(Mac)};
        error -> error
    end.

%% Причина может быть произвольным термом; форматируется без создания
%% атомов из пользовательского ввода.
find_reason(Result) ->
    case maps:find(reason, Result) of
        {ok, Reason} -> {ok, reason_binary(Reason)};
        error -> error
    end.

%% Полный список состояний всех явно выбранных портов, включая skipped и
%% ошибки; причина каждого порта сериализуется так же безопасно, как
%% причина адреса.
find_port_results(Result) ->
    case maps:find(port_results, Result) of
        {ok, Rows} when is_list(Rows) -> {ok, [port_result_json(R) || R <- Rows]};
        _Other -> error
    end.

port_result_json(#{port := Port, state := State, elapsed_ms := Elapsed} = Row) ->
    Base = #{<<"port">> => Port,
             <<"state">> => atom_to_binary(State, utf8),
             <<"elapsed_ms">> => Elapsed},
    case maps:find(reason, Row) of
        {ok, Reason} -> Base#{<<"reason">> => reason_binary(Reason)};
        error -> Base
    end.

find_open_ports(Result) ->
    case maps:find(open_ports, Result) of
        {ok, Ports} when is_list(Ports) -> {ok, Ports};
        _Other -> error
    end.

find_os(Result) ->
    case maps:find(os, Result) of
        {ok, Os} when is_map(Os) -> {ok, os_json(Os)};
        _Other -> error
    end.

%% Основания ОС — безопасные метки; передаются без потерь.
os_json(Os) ->
    #{<<"family">> => atom_to_binary(maps:get(family, Os, unknown), utf8),
      <<"confidence">> => atom_to_binary(maps:get(confidence, Os, none), utf8),
      <<"evidence">> => [evidence_bin(Item)
                         || Item <- maps:get(evidence, Os, [])]}.

evidence_bin(Item) when is_binary(Item) -> Item;
evidence_bin(Item) -> reason_binary(Item).

%% Неожиданная ошибка инспектора не теряет найденный адрес; в JSON это
%% строка причины, а не произвольный вложенный терм.
find_inspection_error(Result) ->
    case maps:find(inspection_error, Result) of
        {ok, Reason} -> {ok, reason_binary(Reason)};
        error -> error
    end.

%% Причина в JSON — строка, а не массив кодов символов: `format_reason'
%% возвращает список, который кодировщик JSON принял бы за массив.
reason_binary(Reason) ->
    case unicode:characters_to_binary(format_reason(Reason)) of
        Bin when is_binary(Bin) -> Bin;
        _Error -> <<"unknown">>
    end.

summary_json(#{total := Total, completed := Completed, counters := Counters,
               elapsed_ms := Elapsed} = Summary) ->
    #{<<"total">> => Total,
      <<"completed">> => Completed,
      <<"counters">> => #{<<"up">> => maps:get(up, Counters),
                          <<"no_response">> => maps:get(no_response, Counters),
                          <<"error">> => maps:get(error, Counters)},
      <<"elapsed_ms">> => Elapsed,
      <<"warnings">> => warnings_json(maps:get(warnings, Summary, []))}.

warnings_json(Warnings) ->
    [atom_to_binary(Warning, utf8) || Warning <- Warnings].

mac_colon(<<A, B, C, D, E, F>>) ->
    iolist_to_binary(
      io_lib:format("~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b:~2.16.0b",
                    [A, B, C, D, E, F])).

%%% ------------------------------------------------------------------
%%% Диагностика
%%% ------------------------------------------------------------------

%% Предупреждение о TCP fallback печатается в stderr всегда, включая
%% --no-progress; JSON-режим печатает его из сводки, без прогресса.
print_warnings(Summary) ->
    case maps:get(warnings, Summary, []) of
        [] -> ok;
        Warnings ->
            _ = [print_warning(Warning) || Warning <- Warnings],
            ok
    end.

print_warning(tcp_fallback) ->
    io:format(standard_error,
              "trawler discover: предупреждение: raw-методы недоступны, "
              "обнаружение через TCP connect; набор портов задаёт --ports, "
              "без него используются порты по умолчанию~n", []);
print_warning(Warning) ->
    io:format(standard_error,
              "trawler discover: предупреждение: ~ts~n",
              [format_reason(Warning)]).

report_error(Reason) ->
    case usage_error(Reason) of
        true -> diagnostic("trawler discover: invalid request: "
                           ++ format_reason(Reason)), 2;
        false -> diagnostic("trawler discover: discovery failed: "
                            ++ format_reason(Reason)), 1
    end.

usage_error({invalid_targets, _Detail}) -> true;
usage_error({invalid_ports, _Detail}) -> true;
usage_error({invalid_options, _Detail}) -> true;
usage_error(too_many_hosts) -> true;
usage_error(_Other) -> false.

progress_diagnostic(Message) ->
    io:format(standard_error, "trawler discover: ~ts~n", [Message]).

diagnostic(Message) ->
    io:format(standard_error, "~ts~n", [Message]),
    io:put_chars(standard_error, "Run trawler --help for usage.\n").

format_reason(Reason) ->
    lists:flatten(io_lib:format("~tp", [Reason])).

ip_bin(#{ip := {A, B, C, D}}) ->
    iolist_to_binary(io_lib:format("~b.~b.~b.~b", [A, B, C, D])).
