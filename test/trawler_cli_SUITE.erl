%%%-------------------------------------------------------------------
%%% @doc Common Test командной строки trawler.
%%%
%%% Набор запускает собранный escript и проверяет справку, версию,
%%% разбор аргументов, текстовый и JSON-вывод и коды завершения.
%%% Сетевые проверки используют только адрес 127.0.0.1: слушатель
%%% открывается в процессе Common Test, а escript подключается к нему
%%% как к обычному узлу сети.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_cli_SUITE).

-export([all/0, help/1, version/1, unsupported/1,
         scan_text/1, scan_json/1, scan_invalid/1, scan_no_open/1,
         scan_default_ports/1]).

all() ->
    [help, version, unsupported,
     scan_text, scan_json, scan_invalid, scan_no_open, scan_default_ports].

%%% ------------------------------------------------------------------
%%% Справка, версия и неизвестная команда
%%% ------------------------------------------------------------------

help(Config) ->
    {0, Output} = run(["--help"], Config),
    must_contain(Output, <<"scan">>),
    must_contain(Output, <<"--targets">>),
    must_contain(Output, <<"--ports">>),
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
    %% CT changes cwd to its log directory; resolve the project from its build.
    Root = filename:absname(filename:join(
        [code:lib_dir(trawler), "..", "..", "..", ".."])),
    %% Use the exported workspace root when running through the project wrapper.
    ProjectRoot = case os:getenv("TRAWLER_ROOT") of
        false -> Root;
        Path -> Path
    end,
    Executable = filename:join([ProjectRoot, "_build", "default", "bin", "trawler"]),
    Port = open_port({spawn_executable, Executable},
        [binary, exit_status, use_stdio, stderr_to_stdout, {args, Args}]),
    collect(Port, <<>>).

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
