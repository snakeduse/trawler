%%%-------------------------------------------------------------------
%%% @doc Common Test командной строки trawler.
%%%
%%% Набор запускает собранный escript и проверяет справку, версию,
%%% разбор аргументов, текстовый и JSON-вывод и коды завершения.
%%% Сетевые проверки остаются в пределах loopback 127.0.0.0/8: слушатель
%%% открывается в процессе Common Test на 127.0.0.1, а escript
%%% подключается к 127.0.0.1 и 127.0.0.2 как к обычным узлам сети.
%%% Диагностика проверяется раздельным захватом stdout и stderr.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_cli_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, help/1, version/1, unsupported/1,
         scan_text/1, scan_json/1, scan_invalid/1, scan_no_open/1,
         scan_default_ports/1, scan_mixed_targets/1, scan_invalid_streams/1]).

all() ->
    [help, version, unsupported,
     scan_text, scan_json, scan_invalid, scan_no_open, scan_default_ports,
     scan_mixed_targets, scan_invalid_streams].

%%% ------------------------------------------------------------------
%%% Справка, версия и неизвестная команда
%%% ------------------------------------------------------------------

help(Config) ->
    {0, Output} = run(["--help"], Config),
    must_contain(Output, <<"scan">>),
    must_contain(Output, <<"--targets">>),
    must_contain(Output, <<"--ports">>),
    %% Пооктетный список и диапазон, открытые границы диапазона и
    %% пробельное разделение новых целей.
    must_contain(Output, <<"192.168.3-5,7.1,3-4">>),
    must_contain(Output, <<"192.0.2.10-">>),
    must_contain(Output, <<"192.0.2.-1">>),
    must_contain(Output, <<"разделяются пробелом"/utf8>>),
    ok.

version(Config) ->
    {0, <<"trawler 0.1.0-dev\n">>} = run(["--version"], Config),
    ok.

%% Без команды scan аргументы сканирования остаются неподдерживаемыми.
unsupported(Config) ->
    {2, Output} = run(["--ports", "22", "127.0.0.1"], Config),
    must_contain(Output, <<"Unsupported">>),
    ok.

%%% ------------------------------------------------------------------
%%% Текстовый и JSON-вывод
%%% ------------------------------------------------------------------

scan_text(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Output} = run(["scan", "--targets", "127.0.0.1",
                           "--ports", integer_to_list(Port)], Config),
        must_contain(Output, <<"127.0.0.1">>),
        must_contain(Output, integer_to_binary(Port)),
        must_contain(Output, <<"open">>),
        must_contain(Output, <<"Summary:">>)
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

scan_json(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Output} = run(["scan", "--targets", "127.0.0.1",
                           "--ports", integer_to_list(Port), "--json"], Config),
        Map = json:decode(string:trim(Output)),
        [Result] = maps:get(<<"results">>, Map),
        <<"open">> = maps:get(<<"state">>, Result),
        <<"127.0.0.1">> = maps:get(<<"ip">>, Result),
        Port = maps:get(<<"port">>, Result),
        true = is_integer(maps:get(<<"elapsed_ms">>, Result)),
        Summary = maps:get(<<"summary">>, Map),
        1 = maps:get(<<"total">>, Summary),
        1 = maps:get(<<"completed">>, Summary),
        true = is_integer(maps:get(<<"elapsed_ms">>, Summary)),
        Counters = maps:get(<<"counters">>, Summary),
        1 = maps:get(<<"open">>, Counters),
        0 = maps:get(<<"closed">>, Counters),
        0 = maps:get(<<"timeout">>, Counters),
        0 = maps:get(<<"unreachable">>, Counters),
        0 = maps:get(<<"error">>, Counters)
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

%% Одним значением --targets смешаны пооктетное выражение и старый CIDR:
%% 127.0.0.1,1-2 даёт 127.0.0.1 и 127.0.0.2, а 127.0.0.1/32 — только
%% 127.0.0.1. Ожидаются ровно два результата без повторов и код 0.
scan_mixed_targets(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Output} = run(["scan", "--targets", "127.0.0.1,1-2 127.0.0.1/32",
                           "--ports", integer_to_list(Port), "--json"], Config),
        Map = json:decode(string:trim(Output)),
        Results = maps:get(<<"results">>, Map),
        2 = length(Results),
        [<<"127.0.0.1">>, <<"127.0.0.2">>] =
            lists:sort([maps:get(<<"ip">>, R) || R <- Results]),
        [Open] = [R || R <- Results, maps:get(<<"ip">>, R) =:= <<"127.0.0.1">>],
        <<"open">> = maps:get(<<"state">>, Open),
        Port = maps:get(<<"port">>, Open),
        [Closed] = [R || R <- Results, maps:get(<<"ip">>, R) =:= <<"127.0.0.2">>],
        <<"closed">> = maps:get(<<"state">>, Closed),
        Port = maps:get(<<"port">>, Closed),
        Summary = maps:get(<<"summary">>, Map),
        2 = maps:get(<<"total">>, Summary),
        2 = maps:get(<<"completed">>, Summary)
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

%%% ------------------------------------------------------------------
%%% Неверный ввод и отсутствие открытых портов
%%% ------------------------------------------------------------------

scan_invalid(Config) ->
    %% Нет обязательного --targets.
    {2, _} = run(["scan", "--ports", "80"], Config),
    %% Неверный адрес отклоняется до сетевых операций.
    {2, _} = run(["scan", "--targets", "256.0.0.1", "--ports", "80"], Config),
    %% Неизвестная опция.
    {2, _} = run(["scan", "--bogus", "1"], Config),
    %% Дубли ключа и неположительные значения.
    {2, _} = run(["scan", "--targets", "127.0.0.1", "--targets", "127.0.0.1",
                  "--ports", "80"], Config),
    {2, _} = run(["scan", "--targets", "127.0.0.1", "--ports", "80",
                  "--timeout", "0"], Config),
    {2, _} = run(["scan", "--targets", "127.0.0.1", "--ports", "80",
                  "--concurrency", "many"], Config),
    ok.

%% Обратный диапазон октета и значение 256 отклоняются с кодом 2;
%% диагностика уходит в stderr, а stdout остаётся пустым.
scan_invalid_streams(Config) ->
    {2, ReversedOut, ReversedErr} =
        run_split(["scan", "--targets", "192.0.2.5-3", "--ports", "80"], Config),
    <<>> = ReversedOut,
    must_contain(ReversedErr, <<"invalid">>),
    {2, BigOut, BigErr} =
        run_split(["scan", "--targets", "192.0.2.256", "--ports", "80"], Config),
    <<>> = BigOut,
    must_contain(BigErr, <<"invalid">>),
    ok.

scan_no_open(Config) ->
    Port = reserve_closed_port(),
    {0, Output} = run(["scan", "--targets", "127.0.0.1",
                       "--ports", integer_to_list(Port)], Config),
    must_contain(Output, <<"closed">>),
    must_contain(Output, <<"Summary:">>),
    ok.

%% Без --ports сканирование использует набор по умолчанию из 1000 портов.
scan_default_ports(Config) ->
    {0, Output} = run(["scan", "--targets", "127.0.0.1"], Config),
    must_contain(Output, <<"Summary:">>),
    must_contain(Output, <<"total=1000">>),
    ok.

%%% ------------------------------------------------------------------
%%% Вспомогательные функции
%%% ------------------------------------------------------------------

run(Args, _Config) ->
    Port = open_port({spawn_executable, executable()},
        [binary, exit_status, use_stdio, stderr_to_stdout, {args, Args}]),
    collect(Port, <<>>).

%% Запускает фиксированные тестовые аргументы через shell, раздельно
%% перенаправляя stdout и stderr в уникальные файлы в priv_dir, и
%% возвращает {КодВыхода, Stdout, Stderr}. Так проверяется, что
%% диагностика действительно уходит в stderr, а не сливается с выводом.
run_split(Args, Config) ->
    PrivDir = ?config(priv_dir, Config),
    Unique = integer_to_list(erlang:unique_integer([positive, monotonic])),
    OutFile = filename:join(PrivDir, "stdout_" ++ Unique),
    ErrFile = filename:join(PrivDir, "stderr_" ++ Unique),
    Command = lists:flatten(
        [shell_quote(executable()),
         [[$\s | shell_quote(Arg)] || Arg <- Args],
         " > ", shell_quote(OutFile),
         " 2> ", shell_quote(ErrFile),
         "; printf '%s' $?"]),
    Status = os:cmd(Command),
    {ok, Stdout} = file:read_file(OutFile),
    {ok, Stderr} = file:read_file(ErrFile),
    {list_to_integer(string:trim(Status)), Stdout, Stderr}.

executable() ->
    %% CT changes cwd to its log directory; resolve the project from its build.
    Root = filename:absname(filename:join(
        [code:lib_dir(trawler), "..", "..", "..", ".."])),
    %% Use the exported workspace root when running through the project wrapper.
    ProjectRoot = case os:getenv("TRAWLER_ROOT") of
        false -> Root;
        Path -> Path
    end,
    filename:join([ProjectRoot, "_build", "default", "bin", "trawler"]).

%% Квотирование одного аргумента для POSIX sh одинарными кавычками.
shell_quote(String) ->
    "'" ++ lists:flatten([shell_quote_char(C) || C <- String]) ++ "'".

shell_quote_char($') ->
    "'\\''";
shell_quote_char(C) ->
    [C].

collect(Port, Acc) ->
    receive
        {Port, {data, Data}} -> collect(Port, <<Acc/binary, Data/binary>>);
        {Port, {exit_status, Status}} -> {Status, Acc}
    after 10000 ->
        port_close(Port),
        ct:fail(cli_timeout)
    end.

open_listener() ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}},
                                      {active, false}]),
    {ok, Port} = inet:port(Listen),
    {Listen, Port}.

reserve_closed_port() ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}},
                                      {active, false}]),
    {ok, Port} = inet:port(Listen),
    ok = gen_tcp:close(Listen),
    Port.

must_contain(Output, Needle) ->
    case binary:match(Output, Needle) of
        nomatch -> ct:fail({missing_output, Needle, Output});
        _Match -> ok
    end.
