%%%-------------------------------------------------------------------
%%% @doc EUnit-тесты дополнительных проверок хоста
%%% trawler_host_inspection.
%%%
%%% Чистая эвристика classify/1 проверяется на синтетических
%%% наблюдениях: явные SSH-баннеры, слабые портовые признаки, конфликт
%%% семей, отсутствие признаков и повреждённые данные. Сетевые тесты
%%% inspect/4 ограничены loopback: открытый и закрытый локальный порт,
%%% исчерпанный deadline, отсутствие соединений без опций, молчащий
%%% сервис, фрагментированный баннер и чрезмерные данные.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_host_inspection_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LO, {127, 0, 0, 1}).

%%% ------------------------------------------------------------------
%%% classify: явные SSH-признаки
%%% ------------------------------------------------------------------

classify_linux_ssh_banner_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n">>}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(medium, maps:get(confidence, Result)),
    ?assert(lists:member(<<"ssh_banner:linux">>, maps:get(evidence, Result))).

classify_windows_ssh_banner_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-OpenSSH_for_Windows_8.6\r\n">>}]),
    ?assertEqual(windows, maps:get(family, Result)),
    ?assertEqual(medium, maps:get(confidence, Result)),
    ?assert(lists:member(<<"ssh_banner:windows">>, maps:get(evidence, Result))).

classify_windows_ssh_199_banner_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 2222, state => open,
                  banner => <<"SSH-1.99-OpenSSH_for_Windows_7.7\r\n">>}]),
    ?assertEqual(windows, maps:get(family, Result)),
    ?assertEqual(medium, maps:get(confidence, Result)).

classify_bsd_banner_is_not_linux_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-OpenSSH_9.6 FreeBSD-20240206\r\n">>}]),
    ?assertEqual(unknown, maps:get(family, Result)),
    ?assertEqual(none, maps:get(confidence, Result)),
    ?assert(lists:member(<<"ssh_banner:other">>, maps:get(evidence, Result))).

classify_darwin_banner_is_not_linux_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-OpenSSH_9.0 Darwin Kernel Version 23\r\n">>}]),
    ?assertEqual(unknown, maps:get(family, Result)),
    ?assertEqual(none, maps:get(confidence, Result)),
    ?assert(lists:member(<<"ssh_banner:other">>, maps:get(evidence, Result))).

classify_conflicting_banners_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n">>},
                #{port => 445, state => open,
                  banner => <<"SSH-2.0-OpenSSH_for_Windows_8.6\r\n">>}]),
    ?assertEqual(unknown, maps:get(family, Result)),
    ?assertEqual(none, maps:get(confidence, Result)),
    Evidence = maps:get(evidence, Result),
    ?assert(lists:member(<<"ssh_banner:linux">>, Evidence)),
    ?assert(lists:member(<<"ssh_banner:windows">>, Evidence)).

classify_generic_openssh_is_weak_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-OpenSSH_9.6\r\n">>}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(low, maps:get(confidence, Result)),
    ?assertEqual([<<"tcp_open:22">>], maps:get(evidence, Result)).

classify_preliminary_lines_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 2222, state => open,
                  banner => <<"Welcome to host\r\nSSH-2.0-OpenSSH_8.9 Alpine\r\n">>}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(medium, maps:get(confidence, Result)),
    ?assertEqual([<<"ssh_banner:linux">>], maps:get(evidence, Result)).

classify_windows_ports_low_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 445, state => open},
                #{port => 135, state => open},
                #{port => 3389, state => open}]),
    ?assertEqual(windows, maps:get(family, Result)),
    ?assertEqual(low, maps:get(confidence, Result)),
    Evidence = maps:get(evidence, Result),
    ?assert(lists:member(<<"tcp_open:135">>, Evidence)),
    ?assert(lists:member(<<"tcp_open:445">>, Evidence)).

classify_both_weak_families_unknown_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open},
                #{port => 445, state => open}]),
    ?assertEqual(unknown, maps:get(family, Result)),
    ?assertEqual(none, maps:get(confidence, Result)),
    Evidence = maps:get(evidence, Result),
    ?assert(lists:member(<<"tcp_open:22">>, Evidence)),
    ?assert(lists:member(<<"tcp_open:445">>, Evidence)).

classify_no_signals_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => closed},
                #{port => 8080, state => open}]),
    ?assertEqual(#{family => unknown, confidence => none, evidence => []}, Result).

classify_empty_observations_test() ->
    ?assertEqual(#{family => unknown, confidence => none, evidence => []},
                 trawler_host_inspection:classify([])).

classify_damaged_banner_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-OpenSSH_for_Windows_8.6">>}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(low, maps:get(confidence, Result)),
    ?assertEqual([<<"tcp_open:22">>], maps:get(evidence, Result)).

classify_non_ssh_garbage_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"HELLO Windows\r\n">>}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(low, maps:get(confidence, Result)).

classify_closed_banner_ignored_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => closed,
                  banner => <<"SSH-2.0-OpenSSH_for_Windows_8.6\r\n">>},
                #{port => 8080, state => open}]),
    ?assertEqual(#{family => unknown, confidence => none, evidence => []}, Result).

classify_internal_contradiction_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-OpenSSH_for_Windows_8.6 Ubuntu-3ubuntu0.1\r\n">>}]),
    ?assertEqual(unknown, maps:get(family, Result)),
    ?assertEqual(none, maps:get(confidence, Result)).

%% Управляющие байты делают identification повреждённой строкой: префикса
%% недостаточно для medium, а слабый признак порта 22 сохраняется.
classify_control_bytes_banner_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-\x00Windows\r\n">>}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(low, maps:get(confidence, Result)),
    ?assertEqual([<<"tcp_open:22">>], maps:get(evidence, Result)).

%% Чрезмерно длинная identification (больше предела RFC) — повреждённые
%% данные, даже если внутри есть слово Windows.
classify_oversized_identification_test() ->
    Banner = <<"SSH-2.0-",
               (binary:copy(<<"OpenSSH_for_Windows_8.6">>, 40))/binary,
               "\r\n">>,
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open, banner => Banner}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(low, maps:get(confidence, Result)),
    ?assertEqual([<<"tcp_open:22">>], maps:get(evidence, Result)).

%% Пустой softwareversion недопустим: комментарий не заменяет версию.
classify_empty_softwareversion_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0- Windows Server 2022\r\n">>}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(low, maps:get(confidence, Result)),
    ?assertEqual([<<"tcp_open:22">>], maps:get(evidence, Result)).

%% Повреждённая первая строка пропускается, а следующая корректная
%% identification даёт явный Linux-признак.
classify_invalid_then_valid_banner_test() ->
    Result = trawler_host_inspection:classify(
               [#{port => 22, state => open,
                  banner => <<"SSH-2.0-\x00Windows\r\n"
                              "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n">>}]),
    ?assertEqual(linux, maps:get(family, Result)),
    ?assertEqual(medium, maps:get(confidence, Result)),
    ?assertEqual([<<"ssh_banner:linux">>], maps:get(evidence, Result)).

%%% ------------------------------------------------------------------
%%% inspect: loopback-хелперы
%%% ------------------------------------------------------------------

now_ms() ->
    erlang:monotonic_time(millisecond).

%% Слушающий сокет без accept: connect к нему успешен, пока он открыт.
open_port() ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {active, false}, {ip, ?LO}]),
    {ok, {_Addr, Port}} = inet:sockname(Listen),
    {Listen, Port}.

%% Порт, который был открыт и сразу закрыт: connect получает отказ.
closed_port() ->
    {Listen, Port} = open_port(),
    ok = gen_tcp:close(Listen),
    Port.

%% Один сервер на одно соединение. `Fun' получает принятый сокет и
%% может отправить баннер; затем соединение удерживается, чтобы клиент
%% видел молчащий сервис до собственного срока попытки.
start_server(Fun) ->
    {ok, Listen} = gen_tcp:listen(0, [inet, {active, false}, {ip, ?LO},
                                      {reuseaddr, true}]),
    {ok, {_Addr, Port}} = inet:sockname(Listen),
    _Pid = spawn_link(fun() -> serve_once(Listen, Fun) end),
    Port.

serve_once(Listen, Fun) ->
    case gen_tcp:accept(Listen, 5000) of
        {ok, Socket} ->
            _ = gen_tcp:close(Listen),
            _ = (catch Fun(Socket)),
            timer:sleep(500),
            _ = gen_tcp:close(Socket),
            ok;
        {error, _Reason} ->
            _ = gen_tcp:close(Listen),
            ok
    end.

%%% ------------------------------------------------------------------
%%% inspect: открытый и закрытый порт
%%% ------------------------------------------------------------------

inspect_open_closed_test() ->
    {_Listen, OpenPort} = open_port(),
    ClosedPort = closed_port(),
    Result = trawler_host_inspection:inspect(
               ?LO, [OpenPort, ClosedPort], false, now_ms() + 5000),
    #{port_results := Rows, open_ports := Open} = Result,
    ?assertEqual(lists:sort([OpenPort, ClosedPort]),
                 [maps:get(port, Row) || Row <- Rows]),
    ?assertEqual([OpenPort], Open),
    States = maps:from_list([{maps:get(port, Row), maps:get(state, Row)}
                             || Row <- Rows]),
    ?assertEqual(open, maps:get(OpenPort, States)),
    ?assertEqual(closed, maps:get(ClosedPort, States)),
    ?assert(lists:all(fun(Row) -> maps:get(elapsed_ms, Row) >= 0 end, Rows)),
    ?assertEqual(false, maps:is_key(reason, hd(Rows))),
    ?assertEqual(false, maps:is_key(os, Result)),
    [OpenRow] = [Row || #{port := P} = Row <- Rows, P =:= OpenPort],
    ?assertEqual([elapsed_ms, port, state],
                 lists:sort(maps:keys(OpenRow))).

inspect_expired_deadline_test() ->
    Port = closed_port(),
    Result = trawler_host_inspection:inspect(
               ?LO, [Port], false, now_ms() - 1000),
    ?assertEqual(#{port_results =>
                       [#{port => Port, state => skipped, elapsed_ms => 0,
                          reason => budget_exhausted}],
                    open_ports => []},
                  Result).

%% Просроченный срок не должен даже начинать connect: проверка остатка
%% выполняется внутри попытки, а не только перед циклом.
inspect_expired_deadline_no_connect_test() ->
    {Listen, Port} = open_port(),
    Result = trawler_host_inspection:inspect(
               ?LO, [Port], false, now_ms() - 1),
    ?assertEqual(#{port_results =>
                       [#{port => Port, state => skipped, elapsed_ms => 0,
                          reason => budget_exhausted}],
                   open_ports => []},
                 Result),
    ?assertEqual({error, timeout}, gen_tcp:accept(Listen, 100)).

inspect_no_options_does_no_network_test() ->
    {Listen, _Port} = open_port(),
    ?assertEqual(#{}, trawler_host_inspection:inspect(
                        ?LO, undefined, false, now_ms() + 1000)),
    ?assertEqual({error, timeout}, gen_tcp:accept(Listen, 50)).

inspect_many_ports_expired_are_all_skipped_test() ->
    Ports = lists:seq(1, 200),
    Result = trawler_host_inspection:inspect(?LO, Ports, false,
                                             now_ms() - 1),
    #{port_results := Rows, open_ports := []} = Result,
    ?assertEqual(Ports, [maps:get(port, Row) || Row <- Rows]),
    ?assert(lists:all(fun(Row) ->
                              maps:get(state, Row) =:= skipped
                                  andalso maps:get(elapsed_ms, Row) =:= 0
                                  andalso maps:get(reason, Row) =:= budget_exhausted
                      end, Rows)).

%%% ------------------------------------------------------------------
%%% inspect: классификация и чтение баннера
%%% ------------------------------------------------------------------

inspect_os_false_does_not_read_test() ->
    Port = start_server(fun(_Socket) -> ok end),
    Start = now_ms(),
    Result = trawler_host_inspection:inspect(?LO, [Port], false,
                                             now_ms() + 5000),
    Elapsed = now_ms() - Start,
    #{port_results := [#{state := open, elapsed_ms := AttemptElapsed}]} = Result,
    ?assert(AttemptElapsed < 190),
    ?assert(Elapsed < 190).

inspect_fragmented_linux_banner_test() ->
    Port = start_server(
             fun(Socket) ->
                     ok = gen_tcp:send(Socket, <<"SSH-2.0-OpenSSH_8.9p1 ">>),
                     timer:sleep(10),
                     ok = gen_tcp:send(Socket, <<"Ubuntu-3ubuntu0.1\r\n">>)
             end),
    Result = trawler_host_inspection:inspect(?LO, [Port], true,
                                             now_ms() + 5000),
    #{port_results := [#{port := Port, state := open}],
      open_ports := [Port],
      os := Os} = Result,
    %% Локальный 22 может быть занят настоящим sshd, поэтому итоговая
    %% семья может стать unknown при конфликте; чтение баннера
    %% доказывает наличие linux-метки и отсутствие слабого low.
    ?assert(lists:member(<<"ssh_banner:linux">>, maps:get(evidence, Os))),
    ?assert(lists:member(maps:get(family, Os), [linux, unknown])),
    ?assertNotEqual(low, maps:get(confidence, Os)).

inspect_fragmented_windows_banner_test() ->
    Port = start_server(
             fun(Socket) ->
                     ok = gen_tcp:send(Socket, <<"SSH-2.0-OpenSSH_for_">>),
                     timer:sleep(10),
                     ok = gen_tcp:send(Socket, <<"Windows_8.6\r\n">>)
             end),
    Result = trawler_host_inspection:inspect(?LO, [Port], true,
                                             now_ms() + 5000),
    #{port_results := [#{port := Port, state := open}],
      os := Os} = Result,
    ?assert(lists:member(<<"ssh_banner:windows">>, maps:get(evidence, Os))),
    ?assert(lists:member(maps:get(family, Os), [windows, unknown])),
    ?assertNotEqual(low, maps:get(confidence, Os)).

inspect_silent_service_bounded_test() ->
    Port = start_server(fun(_Socket) -> ok end),
    Start = now_ms(),
    Result = trawler_host_inspection:inspect(?LO, [Port], true,
                                             now_ms() + 5000),
    Elapsed = now_ms() - Start,
    #{port_results := [#{port := Port, state := open}], os := Os} = Result,
    ?assert(lists:member(maps:get(family, Os), [windows, linux, unknown])),
    ?assert(is_list(maps:get(evidence, Os))),
    ?assert(Elapsed < 1000).

inspect_oversize_malformed_bounded_test() ->
    Port = start_server(
             fun(Socket) ->
                     ok = gen_tcp:send(Socket, binary:copy(<<"A">>, 8192))
             end),
    Start = now_ms(),
    Result = trawler_host_inspection:inspect(?LO, [Port], true,
                                             now_ms() + 5000),
    Elapsed = now_ms() - Start,
    #{port_results := [#{port := Port, state := open}], os := Os} = Result,
    ?assert(lists:member(maps:get(family, Os), [windows, linux, unknown])),
    ?assert(is_list(maps:get(evidence, Os))),
    ?assert(Elapsed < 1000).

%% Повреждённая строка с Windows не должна завершать чтение: следующая
%% корректная identification читается и даёт Linux-признак.
inspect_invalid_banner_then_valid_test() ->
    Port = start_server(
             fun(Socket) ->
                     ok = gen_tcp:send(Socket, <<"SSH-2.0-\x00Windows\r\n">>),
                     timer:sleep(10),
                     ok = gen_tcp:send(Socket,
                                       <<"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n">>)
             end),
    Result = trawler_host_inspection:inspect(?LO, [Port], true,
                                             now_ms() + 5000),
    #{port_results := [#{port := Port, state := open}], os := Os} = Result,
    ?assert(lists:member(<<"ssh_banner:linux">>, maps:get(evidence, Os))),
    ?assertNot(lists:member(<<"ssh_banner:windows">>, maps:get(evidence, Os))),
    ?assertNotEqual(windows, maps:get(family, Os)).

inspect_os_without_requested_ports_test() ->
    Result = trawler_host_inspection:inspect(?LO, undefined, true,
                                             now_ms() + 1000),
    ?assertNot(maps:is_key(port_results, Result)),
    ?assertNot(maps:is_key(open_ports, Result)),
    Os = maps:get(os, Result),
    ?assert(lists:member(maps:get(family, Os), [windows, linux, unknown])),
    ?assert(lists:member(maps:get(confidence, Os), [medium, low, none])),
    ?assert(is_list(maps:get(evidence, Os))).
