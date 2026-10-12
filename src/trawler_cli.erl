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
    case application:load(trawler) of
        ok -> version();
        {error, {already_loaded, trawler}} -> version();
        {error, Reason} ->
            io:format(standard_error, "Cannot load trawler: ~p~n", [Reason]),
            erlang:halt(1)
    end;
main(_Args) ->
    io:put_chars(standard_error,
        "Unsupported arguments. Run trawler --help.\n"
        "Scanning is specified but not implemented yet.\n"),
    erlang:halt(2).

-spec help() -> no_return().
help() ->
    io:put_chars(
        "Trawler - embeddable Erlang/OTP network scanner\n\n"
        "Usage: trawler [--help | --version]\n\n"
        "  -h, --help    Show this help\n"
        "  --version     Show the application version\n\n"
        "This is the project foundation. TCP/IPv4 scanning is planned\n"
        "in the OpenSpec change add-tcp-ipv4-scanner.\n"),
    erlang:halt(0).

-spec version() -> no_return().
version() ->
    {ok, Version} = application:get_key(trawler, vsn),
    io:format("trawler ~ts~n", [Version]),
    erlang:halt(0).
