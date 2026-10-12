-module(trawler_cli_SUITE).
-export([all/0, help/1, version/1, unsupported/1]).

all() -> [help, version, unsupported].

help(Config) ->
    {0, Output} = run(["--help"], Config),
    nomatch =/= binary:match(Output, <<"Usage: trawler">>) orelse ct:fail(Output),
    ok.

version(Config) ->
    {0, <<"trawler 0.1.0-dev\n">>} = run(["--version"], Config),
    ok.

unsupported(Config) ->
    {2, Output} = run(["--ports", "22", "127.0.0.1"], Config),
    nomatch =/= binary:match(Output, <<"not implemented yet">>) orelse ct:fail(Output),
    ok.

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
