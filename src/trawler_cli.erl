%%%-------------------------------------------------------------------
%%% @doc Адаптер командной строки trawler.
%%%
%%% Разбирает аргументы, вызывает публичный API {@link trawler} и
%%% завершает виртуальную машину одним из кодов: 0 — сканирование
%%% завершено, 1 — ошибка выполнения, 2 — неверные аргументы или
%%% неизвестная команда. Результаты печатаются в stdout, вся
%%% диагностика направляется в stderr.
%%%
%%% Модуль работает поверх escript и не содержит логики сканирования:
%%% разбор аргументов, проверку значений и печать завершает только он
%%% сам, а исходы соединений полностью определяет библиотечное ядро.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_cli).

-export([main/1]).

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
        "  trawler scan --targets <TARGETS> [--ports <PORTS>] [опции]\n\n"
        "Команды:\n"
        "  scan                  Просканировать адреса и порты по TCP\n\n"
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
        "  --timeout <N>         Таймаут одной пробы в миллисекундах (N > 0)\n"
        "  --concurrency <N>     Одновременных проб на сканирование (N > 0)\n\n"
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

%% Разбор аргументов: обязательный --targets, необязательные --ports, --json,
%% --timeout N, --concurrency N. Порядок не важен, повтор любого ключа — ошибка.
parse_args(["--json" | Rest], Acc, Seen) ->
    case lists:member(json, Seen) of
        true ->
            {error, "duplicate option --json"};
        false ->
            parse_args(Rest, Acc#{json => true}, [json | Seen])
    end;
parse_args([Option | Rest], Acc, Seen) ->
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
    end;
parse_args([], Acc, Seen) ->
    case lists:member(targets, Seen) of
        false ->
            {error, "missing required option --targets"};
        true ->
            {ok, Acc}
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

do_scan(Parsed) ->
    Targets = to_binary(maps:get(targets, Parsed)),
    Ports = ports_value(Parsed),
    Options = scan_options(Parsed),
    Start = erlang:monotonic_time(millisecond),
    case trawler:scan(Targets, Ports, Options) of
        {ok, Results} ->
            Elapsed = erlang:monotonic_time(millisecond) - Start,
            Summary = build_summary(Results, Elapsed),
            case maps:get(json, Parsed, false) of
                true -> print_json(Results, Summary);
                false -> print_text(Results, Summary)
            end,
            0;
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
%%% Текстовый вывод
%%% ------------------------------------------------------------------

print_text(Results, Summary) ->
    io:format("~-16ts ~-7ts ~ts~n", ["IP", "PORT", "STATE"]),
    lists:foreach(fun print_result/1, Results),
    print_summary(Summary).

print_result(Result) ->
    io:format("~-16ts ~-7ts ~ts~n",
              [ip_bin(Result),
               integer_to_binary(maps:get(port, Result)),
               atom_to_binary(maps:get(state, Result), utf8)]).

print_summary(#{total := Total, completed := Completed, counters := Counters,
                elapsed_ms := Elapsed}) ->
    io:format("Summary: total=~b completed=~b open=~b closed=~b timeout=~b "
              "unreachable=~b error=~b elapsed_ms=~b~n",
              [Total, Completed,
               maps:get(open, Counters),
               maps:get(closed, Counters),
               maps:get(timeout, Counters),
               maps:get(unreachable, Counters),
               maps:get(error, Counters),
               Elapsed]).

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
