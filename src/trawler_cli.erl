%%%-------------------------------------------------------------------
%%% @doc Адаптер командной строки trawler.
%%%
%%% Разбирает аргументы, вызывает публичный API {@link trawler} и
%%% завершает виртуальную машину одним из кодов: 0 — сканирование
%%% завершено, 1 — ошибка выполнения, 2 — неверные аргументы или
%%% неизвестная команда. Результаты печатаются в stdout, вся
%%% диагностика направляется в stderr.
%%%
%%% Текстовый поиск работает через асинхронный API и печатает открытые
%%% порты по мере получения; остальные исходы видны только в итоговой
%%% сводке, а `--verbose' возвращает все пробы. Прогресс идёт в stderr:
%%% одна обновляемая строка в терминале и редкие строки без управляющих
%%% последовательностей при перенаправлении. JSON сохраняет прежний
%%% синхронный полный вывод без прогресса.
%%%
%%% Модуль работает поверх escript и не содержит логики сканирования:
%%% разбор аргументов, проверку значений и печать завершает только он
%%% сам, а исходы соединений полностью определяет библиотечное ядро.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_cli).

-export([main/1]).

%% Частота обновления прогресса в терминале и при перенаправлении, мс.
%% Для `off' значение задаёт период проверки доступности статуса.
-define(TTY_INTERVAL_MS, 250).
-define(PLAIN_INTERVAL_MS, 2000).

-spec main([string()]) -> no_return().
main([]) ->
    help();
main(["--help"]) ->
    help();
main(["-h"]) ->
    help();
main(["--version"]) ->
    version();
main(["scan" | Args]) ->
    scan(Args);
main(["discover" | Args]) ->
    erlang:halt(trawler_discovery_cli:run(Args));
main(_Args) ->
    unsupported().

%%% ------------------------------------------------------------------
%%% Справка и версия
%%% ------------------------------------------------------------------

-spec help() -> no_return().
help() ->
    io:put_chars(
        "Trawler - встраиваемый сканер сети на Erlang/OTP\n\n"
        "Использование:\n"
        "  trawler [--help | -h | --version]\n"
        "  trawler scan --targets <TARGETS> [--ports <PORTS>] [опции]\n"
        "  trawler discover --targets <TARGETS> [--method <METHOD>] [опции]\n\n"
        "Команды:\n"
        "  scan                  Просканировать адреса и порты по TCP\n"
        "  discover              Найти отвечающие хосты методами ARP/ICMP/TCP\n\n"
        "Параметры scan:\n"
        "  --targets <TARGETS>   Обязательно. Адреса IPv4, сети и\n"
        "                        пооктетные выражения. Старый список целей\n"
        "                        через запятую: 127.0.0.1,10.0.0.0/30.\n"
        "                        Новые цели разделяются пробелом,\n"
        "                        табуляцией или переводом строки. Октет -\n"
        "                        список чисел и диапазонов через запятую:\n"
        "                        192.168.3-5,7.1,3-4. Пропущенная граница\n"
        "                        диапазона означает 0 слева и 255 справа:\n"
        "                        192.0.2.10- (10..255), -20.0.0.1 (0..20),\n"
        "                        192.0.2.- (0..255), 192.0.2.-1 (0 и 1).\n"
        "  --ports <PORTS>       Необязательно. Порты и/или диапазоны через\n"
        "                        запятую: 22,80,8000-8010. По умолчанию —\n"
        "                        1000 наиболее популярных портов.\n"
        "  --json                Вывести один JSON-объект вместо таблицы\n"
        "  --verbose             Показать каждую пробу с IP, портом и\n"
        "                        состоянием; по умолчанию перечисляются\n"
        "                        только открытые порты\n"
        "  --no-progress         Отключить строку прогресса в stderr\n"
        "  --timeout <N>         Таймаут одной пробы в миллисекундах (N > 0)\n"
        "  --concurrency <N>     Одновременных проб на сканирование (N > 0)\n\n"
        "Поведение текстового поиска:\n"
        "  открытые порты печатаются по мере обнаружения, остальные\n"
        "  исходы видны счётчиками в сводке. Прогресс идёт в stderr:\n"
        "  одна обновляемая строка в терминале и редкие строки без ANSI\n"
        "  при перенаправлении. Таймаут относится к одной пробе и не\n"
        "  означает отсутствие компьютера.\n\n"
        "Параметры discover:\n"
        "  --method <METHOD>     auto|arp|icmp|tcp|raw_tcp (по умолчанию auto).\n"
        "                        raw-методы (arp, icmp, raw_tcp) требуют Linux\n"
        "                        и сетевых прав; без них auto переходит на TCP\n"
        "                        connect 80/443 и сообщает об этом в stderr.\n"
        "  --ports <PORTS>       Только с --method tcp. По умолчанию 80/443.\n"
        "  --retries <N>         Повторов каждой пробы, 0..5\n"
        "Поведение discover:\n"
        "  подтверждённые адреса печатаются сразу как IP, метод и MAC;\n"
        "  отсутствие ответа не означает отсутствие компьютера. Бюджет\n"
        "  --timeout относится ко всему адресу, включая поиск маршрута.\n\n"
        "Общие параметры:\n"
        "  -h, --help            Показать эту справку\n"
        "  --version             Показать версию приложения\n\n"
        "Коды выхода:\n"
        "  0  сканирование завершено, включая отсутствие открытых портов\n"
        "  1  ошибка выполнения\n"
        "  2  неверные аргументы или неизвестная команда\n\n"
        "Результат печатается в stdout, диагностика - в stderr.\n"),
    erlang:halt(0).

-spec version() -> no_return().
version() ->
    %% Справка о версии доступна и без запуска приложения: достаточно
    %% загрузить описание приложения.
    case application:load(trawler) of
        ok -> ok;
        {error, {already_loaded, trawler}} -> ok;
        {error, Reason} ->
            io:format(standard_error, "Cannot load trawler: ~tp~n", [Reason]),
            erlang:halt(1)
    end,
    {ok, Version} = application:get_key(trawler, vsn),
    io:format("trawler ~ts~n", [Version]),
    erlang:halt(0).

%% Неизвестная команда или неподдерживаемая опция первого уровня.
-spec unsupported() -> no_return().
unsupported() ->
    io:put_chars(standard_error,
        "Unsupported arguments. Run trawler --help for usage.\n"),
    erlang:halt(2).

%%% ------------------------------------------------------------------
%%% Команда scan
%%% ------------------------------------------------------------------

%% Разбирает аргументы scan, запускает приложение и печатает результат.
-spec scan([string()]) -> no_return().
scan(Args) ->
    case parse_args(Args, #{}, []) of
        {ok, Parsed} ->
            erlang:halt(run_scan(Parsed));
        {error, Message} ->
            usage_diagnostic(Message),
            erlang:halt(2)
    end.

%% Разбор аргументов: обязательный --targets, необязательные --ports,
%% --timeout N, --concurrency N и флаги --json, --verbose, --no-progress.
%% Порядок не важен, повтор любого ключа — ошибка.
parse_args([Option | Rest], Acc, Seen) ->
    case flag_key(Option) of
        {ok, Key} ->
            set_flag(Key, Option, Rest, Acc, Seen);
        error ->
            parse_args_value(Option, Rest, Acc, Seen)
    end;
parse_args([], Acc, Seen) ->
    case lists:member(targets, Seen) of
        false ->
            {error, "missing required option --targets"};
        true ->
            {ok, Acc}
    end.

%% Флаги без значения.
flag_key("--json") -> {ok, json};
flag_key("--verbose") -> {ok, verbose};
flag_key("--no-progress") -> {ok, no_progress};
flag_key(_Other) -> error.

set_flag(Key, Option, Rest, Acc, Seen) ->
    case lists:member(Key, Seen) of
        true ->
            {error, "duplicate option " ++ Option};
        false ->
            parse_args(Rest, Acc#{Key => true}, [Key | Seen])
    end.

parse_args_value(Option, Rest, Acc, Seen) ->
    case option_key(Option) of
        {ok, Key} ->
            case Rest of
                [Value | Rest1] ->
                    set_option(Key, Option, Value, Rest1, Acc, Seen);
                [] ->
                    {error, "option " ++ Option ++ " requires a value"}
            end;
        error ->
            {error, "unknown option " ++ Option}
    end.

option_key("--targets") -> {ok, targets};
option_key("--ports") -> {ok, ports};
option_key("--timeout") -> {ok, timeout};
option_key("--concurrency") -> {ok, concurrency};
option_key(_Other) -> error.

set_option(Key, Option, Value, Rest, Acc, Seen) ->
    case lists:member(Key, Seen) of
        true ->
            {error, "duplicate option " ++ Option};
        false ->
            case option_value(Key, Value) of
                {ok, Parsed} ->
                    parse_args(Rest, Acc#{Key => Parsed}, [Key | Seen]);
                error ->
                    {error, "invalid value for " ++ Option ++ ": " ++ Value}
            end
    end.

option_value(targets, Value) -> {ok, Value};
option_value(ports, Value) -> {ok, Value};
option_value(timeout, Value) -> positive_int(Value);
option_value(concurrency, Value) -> positive_int(Value).

positive_int(Value) ->
    case string:to_integer(string:trim(Value)) of
        {Int, []} when is_integer(Int), Int > 0 -> {ok, Int};
        _Other -> error
    end.

%% Запускает приложение, выполняет сканирование и возвращает код выхода.
run_scan(Parsed) ->
    case application:ensure_all_started(trawler) of
        {ok, _Started} ->
            do_scan(Parsed);
        {error, Reason} ->
            io:format(standard_error,
                      "trawler scan: cannot start trawler: ~tp~n", [Reason]),
            1
    end.

%% JSON сохраняет прежний синхронный путь и полный список наблюдений без
%% прогресса. Текст использует асинхронный API и печатает находки по мере
%% получения. Оба пути проверяются до сетевых операций.
do_scan(Parsed) ->
    Targets = to_binary(maps:get(targets, Parsed)),
    Ports = ports_value(Parsed),
    Options = scan_options(Parsed),
    case maps:get(json, Parsed, false) of
        true -> do_json_scan(Targets, Ports, Options);
        false -> do_text_scan(Targets, Ports, Options, Parsed)
    end.

do_json_scan(Targets, Ports, Options) ->
    Start = erlang:monotonic_time(millisecond),
    case trawler:scan(Targets, Ports, Options) of
        {ok, Results} ->
            Elapsed = erlang:monotonic_time(millisecond) - Start,
            print_json(Results, build_summary(Results, Elapsed)),
            0;
        {error, Reason} ->
            report_scan_error(Reason)
    end.

do_text_scan(Targets, Ports, Options, Parsed) ->
    case trawler:start_scan(Targets, Ports, Options) of
        {ok, Ref} ->
            run_text_scan(Ref, progress_mode(Parsed),
                          maps:get(verbose, Parsed, false));
        {error, Reason} ->
            report_scan_error(Reason)
    end.

%% Ключи по умолчанию не добавляются: их применяет публичный API.
scan_options(Parsed) ->
    Options1 = add_option(timeout, timeout_ms, Parsed, #{}),
    add_option(concurrency, concurrency, Parsed, Options1).

add_option(CliKey, ApiKey, Parsed, Acc) ->
    case maps:find(CliKey, Parsed) of
        {ok, Value} -> Acc#{ApiKey => Value};
        error -> Acc
    end.

%% Без --ports используется набор по умолчанию из публичного API.
ports_value(Parsed) ->
    case maps:find(ports, Parsed) of
        {ok, Value} -> to_binary(Value);
        error -> default
    end.

to_binary(Value) ->
    case unicode:characters_to_binary(Value) of
        Bin when is_binary(Bin) ->
            Bin;
        _Error ->
            io:put_chars(standard_error,
                "trawler scan: cannot encode arguments as UTF-8\n"),
            erlang:halt(1)
    end.

usage_diagnostic(Message) ->
    io:format(standard_error, "trawler scan: ~ts~n", [Message]),
    io:put_chars(standard_error, "Run trawler --help for usage.\n").

%% Неверные аргументы и запросы — код 2, ошибки выполнения — код 1.
report_scan_error(Reason) ->
    case usage_error(Reason) of
        true ->
            io:format(standard_error,
                      "trawler scan: invalid request: ~ts~n",
                      [format_reason(Reason)]),
            2;
        false ->
            io:format(standard_error,
                      "trawler scan: scan failed: ~ts~n",
                      [format_reason(Reason)]),
            1
    end.

usage_error({invalid_targets, _Detail}) -> true;
usage_error({invalid_ports, _Detail}) -> true;
usage_error({invalid_options, _Detail}) -> true;
usage_error(too_many_hosts) -> true;
usage_error(_Other) -> false.

format_reason(Reason) ->
    lists:flatten(io_lib:format("~tp", [Reason])).

%%% ------------------------------------------------------------------
%%% Сводка
%%% ------------------------------------------------------------------

build_summary(Results, Elapsed) ->
    #{total => length(Results),
      completed => length(Results),
      counters => count_states(Results),
      elapsed_ms => Elapsed}.

zero_counters() ->
    #{open => 0, closed => 0, timeout => 0, unreachable => 0, error => 0}.

count_states(Results) ->
    lists:foldl(fun count_state/2, zero_counters(), Results).

count_state(Result, Acc) ->
    State = maps:get(state, Result),
    case maps:is_key(State, Acc) of
        true -> Acc#{State => maps:get(State, Acc) + 1};
        false -> Acc
    end.

%%% ------------------------------------------------------------------
%%% Потоковый текстовый поиск и прогресс
%%% ------------------------------------------------------------------

%% Запускает текстовый поиск на существующем асинхронном API. Состояние
%% не хранит список результатов: находки печатаются по мере получения, а
%% локальные счётчики считают только полученные события.
run_text_scan(Ref, Mode, Verbose) ->
    Start = erlang:monotonic_time(millisecond),
    case scan_status(Ref) of
        {ok, Total} ->
            Interval = progress_interval(Mode),
            State0 = #{ref => Ref,
                       mode => Mode,
                       verbose => Verbose,
                       total => Total,
                       completed => 0,
                       counters => zero_counters(),
                       elapsed => 0,
                       start => Start,
                       interval => Interval,
                       next_update => Start + Interval,
                       header => false},
            text_loop(erlang:monotonic_time(millisecond),
                      emit_progress(State0));
        error ->
            report_progress_error("scan state is not available"),
            1
    end.

%% Основной цикл: приём событий асинхронного API, абсолютный срок
%% обновления прогресса и периодическая проверка доступности статуса.
%% Посторонние сообщения не разбираются и остаются в почтовом ящике.
text_loop(Now, State) ->
    Ref = maps:get(ref, State),
    Timeout = max(maps:get(next_update, State) - Now, 0),
    receive
        {trawler, Ref, {result, Result}} ->
            case text_result(Result, State) of
                {continue, State1} ->
                    text_loop(erlang:monotonic_time(millisecond), State1);
                {stop, Code} ->
                    Code
            end;
        {trawler, Ref, {done, Summary}} ->
            finish_done(Summary, State);
        {trawler, Ref, {cancelled, Summary}} ->
            finish_failed(cancelled, Summary, State);
        {trawler, Ref, {error, Reason, Summary}} ->
            finish_failed(Reason, Summary, State)
    after Timeout ->
        case text_tick(State) of
            {continue, State1} ->
                text_loop(erlang:monotonic_time(millisecond), State1);
            {stop, Code} ->
                Code
        end
    end.

%% Обработка одного результата: счётчики, печать и проверка абсолютного
%% срока обновления прямо на событии, чтобы непрерывный поток не отложил
%% прогресс. Наступивший срок проводит полноценный tick (контроль статуса
%% и обновление прогресса), поэтому на событиях возможен и {stop, _}.
%% Актуальное монотонное время берётся после ввода-вывода печати.
text_result(Result, State) ->
    State1 = account_result(Result, State),
    State2 = print_finding(Result, State1),
    Now = erlang:monotonic_time(millisecond),
    case Now >= maps:get(next_update, State2) of
        true -> text_tick(State2);
        false -> {continue, State2}
    end.

%% Периодическое обновление: прогресс и контроль статуса. Потеря статуса
%% завершает строку, сообщает диагностику и не даёт зависнуть.
text_tick(State) ->
    case scan_status(maps:get(ref, State)) of
        {ok, _Total} ->
            {continue, emit_progress(State)};
        error ->
            finish_progress(State),
            report_progress_error("scan state is not available"),
            {stop, 1}
    end.

account_result(Result, State) ->
    Counters = count_state(Result, maps:get(counters, State)),
    State#{completed := maps:get(completed, State) + 1,
           counters := Counters}.

%% Открытые порты печатаются всегда, остальные состояния — с --verbose.
%% Терминал очищает текущую строку прогресса ДО заголовка и результата,
%% иначе заголовок IP/PORT/STATE приклеивается к строке прогресса. После
%% находки строка прогресса перерисовывается без сдвига next_update.
print_finding(Result, State) ->
    Show = maps:get(verbose, State) orelse maps:get(state, Result) =:= open,
    case Show of
        true ->
            State1 = clear_progress_line(State),
            State2 = print_header(State1),
            print_result(Result),
            redraw_progress(State2);
        false ->
            State
    end.

%% Перерисовка строки прогресса после находки в терминале. Плановый срок
%% next_update НЕ сдвигается: иначе поток находок откладывал бы heartbeat
%% и периодический контроль статуса. При перенаправлении новых строк нет.
redraw_progress(#{mode := tty} = State) ->
    io:format(standard_error, "\r\e[K~ts", [progress_line(State)]),
    State;
redraw_progress(State) ->
    State.

print_header(#{header := false} = State) ->
    io:format("~-16ts ~-7ts ~ts~n", ["IP", "PORT", "STATE"]),
    State#{header := true};
print_header(State) ->
    State.

finish_done(Summary, State) ->
    State1 = final_state(Summary, State),
    finish_progress(State1),
    print_summary(State1),
    0.

finish_failed(Reason, Summary, State) ->
    State1 = final_state(Summary, State),
    finish_progress(State1),
    report_scan_error(Reason).

%% Завершающая сводка ядра авторитетна для итоговых счётчиков.
final_state(#{total := Total, completed := Completed, counters := Counters,
              elapsed_ms := Elapsed}, State) ->
    State#{total := Total,
           completed := Completed,
           counters := Counters,
           elapsed := Elapsed}.

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

%% Штатный способ OTP 27: `io:getopts(standard_io)' сообщает, является ли
%% именно stderr терминалом, независимо от stdout. При недоступности —
%% безопасный plain.
stderr_is_terminal() ->
    try proplists:get_value(stderr, io:getopts(standard_io), false) of
        true -> true;
        _Other -> false
    catch
        _:_ -> false
    end.

progress_interval(tty) -> ?TTY_INTERVAL_MS;
progress_interval(_Other) -> ?PLAIN_INTERVAL_MS.

%% Печатает строку прогресса (кроме off) и сдвигает абсолютный срок.
emit_progress(State) ->
    advance(print_progress(State)).

print_progress(State) ->
    case maps:get(mode, State) of
        off ->
            State;
        tty ->
            io:format(standard_error, "\r\e[K~ts", [progress_line(State)]),
            State;
        plain ->
            io:format(standard_error, "~ts~n", [progress_line(State)]),
            State
    end.

%% Завершение строки прогресса при выходе; в plain строка уже завершена,
%% но итоговая печатается ещё раз, чтобы показать полный прогресс.
finish_progress(State) ->
    case maps:get(mode, State) of
        off ->
            ok;
        tty ->
            io:format(standard_error, "\r\e[K~ts~n", [progress_line(State)]);
        plain ->
            io:format(standard_error, "~ts~n", [progress_line(State)])
    end.

%% Очистка текущей строки перед печатью находки; только терминал.
%% Возвращает состояние, чтобы вызывающий мог продолжить печать.
clear_progress_line(#{mode := tty} = State) ->
    io:format(standard_error, "\r\e[K", []),
    State;
clear_progress_line(State) ->
    State.

advance(State) ->
    Now = erlang:monotonic_time(millisecond),
    State#{next_update := Now + maps:get(interval, State)}.

progress_line(State) ->
    Completed = maps:get(completed, State),
    Total = maps:get(total, State),
    Open = maps:get(open, maps:get(counters, State)),
    io_lib:format("Проверено ~b/~b (~b%) | открыто ~b | ~b с",
                  [Completed, Total, percent(Completed, Total), Open,
                   elapsed_seconds(State)]).

percent(_Completed, 0) -> 100;
percent(Completed, Total) -> Completed * 100 div Total.

elapsed_seconds(State) ->
    (erlang:monotonic_time(millisecond) - maps:get(start, State)) div 1000.

scan_status(Ref) ->
    try trawler:status(Ref) of
        {ok, Status} -> {ok, maps:get(total, Status)};
        {error, _Reason} -> error
    catch
        _:_ -> error
    end.

report_progress_error(Message) ->
    io:format(standard_error, "trawler scan: ~ts~n", [Message]).

%%% ------------------------------------------------------------------
%%% Итоговая сводка
%%% ------------------------------------------------------------------

print_summary(State) ->
    Counters = maps:get(counters, State),
    io:format("Завершено: ~b из ~b проб за ~b мс~n",
              [maps:get(completed, State), maps:get(total, State),
               maps:get(elapsed, State)]),
    print_open_count(maps:get(open, Counters)),
    io:format("Закрыто: ~b~n", [maps:get(closed, Counters)]),
    io:format("Без ответа (таймаут): ~b~n", [maps:get(timeout, Counters)]),
    io:format("Недоступно: ~b~n", [maps:get(unreachable, Counters)]),
    io:format("Ошибки: ~b~n", [maps:get(error, Counters)]).

print_open_count(0) ->
    io:put_chars("Открытых портов не найдено\n");
print_open_count(Open) ->
    io:format("Открытых портов: ~b~n", [Open]).

print_result(Result) ->
    io:format("~-16ts ~-7ts ~ts~n",
              [ip_bin(Result),
               integer_to_binary(maps:get(port, Result)),
               atom_to_binary(maps:get(state, Result), utf8)]).

%%% ------------------------------------------------------------------
%%% JSON-вывод
%%% ------------------------------------------------------------------

print_json(Results, Summary) ->
    Json = #{<<"results">> => [result_json(R) || R <- Results],
             <<"summary">> => summary_json(Summary)},
    io:put_chars([json:encode(Json), $\n]).

result_json(Result) ->
    Base = #{<<"ip">> => ip_bin(Result),
             <<"port">> => maps:get(port, Result),
             <<"state">> => atom_to_binary(maps:get(state, Result), utf8),
             <<"elapsed_ms">> => maps:get(elapsed_ms, Result)},
    case maps:find(reason, Result) of
        {ok, Reason} -> Base#{<<"reason">> => atom_to_binary(Reason, utf8)};
        error -> Base
    end.

summary_json(#{total := Total, completed := Completed, counters := Counters,
               elapsed_ms := Elapsed}) ->
    #{<<"total">> => Total,
      <<"completed">> => Completed,
      <<"counters">> => #{<<"open">> => maps:get(open, Counters),
                          <<"closed">> => maps:get(closed, Counters),
                          <<"timeout">> => maps:get(timeout, Counters),
                          <<"unreachable">> => maps:get(unreachable, Counters),
                          <<"error">> => maps:get(error, Counters)},
      <<"elapsed_ms">> => Elapsed}.

ip_bin(#{ip := {A, B, C, D}}) ->
    iolist_to_binary(io_lib:format("~b.~b.~b.~b", [A, B, C, D])).
