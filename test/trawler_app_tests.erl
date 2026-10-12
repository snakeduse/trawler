-module(trawler_app_tests).
-include_lib("eunit/include/eunit.hrl").

application_lifecycle_test() ->
    {ok, Started} = application:ensure_all_started(trawler),
    ?assert(lists:member(trawler, Started)),
    Supervisor = whereis(trawler_sup),
    ?assert(is_pid(Supervisor)),
    Monitor = erlang:monitor(process, Supervisor),
    ok = application:stop(trawler),
    receive
        {'DOWN', Monitor, process, Supervisor, _Reason} -> ok
    after 1000 ->
        ?assert(false)
    end,
    ?assertEqual(undefined, whereis(trawler_sup)).
