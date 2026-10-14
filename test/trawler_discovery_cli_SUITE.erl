%%%-------------------------------------------------------------------
%%% @doc Common Test команды discover.
%%%
%%% Отдельный набор от trawler_cli_SUITE: реальный escript проверяется на
%%% loopback 127.0.0.0/8 (обязательные/повторные опции, явная
%%% недоступность raw, текстовый и JSON-вывод, раздельные потоки), а
%%% медленный путь, отсутствие находок, непрерывный поток, потеря статуса
%%% и терминальная строка воспроизводятся локальным драйвером с тестовым
%%% двойником discovery-ядра. Двойник подменяет публичный API только через
%%% код-путь, без production-переключателей. Терминал проверяется под
%%% псевдотерминалом `script'.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_cli_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1,
         discover_help/1, discover_text/1, discover_no_progress/1,
         discover_json/1, discover_json_auto/1, discover_invalid/1,
         discover_duplicate_flags/1, discover_raw_unavailable/1,
         discover_heartbeat/1, discover_stream_pre_finish/1,
         discover_stream_status_lost/1, discover_stream_status_lost_no_progress/1,
         discover_tty_line/1, discover_warning_no_progress/1,
         discover_no_found_hidden/1, discover_no_found_verbose/1,
         discover_error_finish/1, discover_cancelled_finish/1,
         discover_json_sync_warning/1, discover_status_ahead/1,
         discover_status_ahead_tick/1, discover_status_exception/1]).

-define(LO, <<"127.0.0.1">>).

all() ->
    [discover_help, discover_text, discover_no_progress, discover_json,
     discover_json_auto, discover_invalid, discover_duplicate_flags,
     discover_raw_unavailable, discover_heartbeat, discover_stream_pre_finish,
     discover_stream_status_lost, discover_stream_status_lost_no_progress,
     discover_tty_line, discover_warning_no_progress, discover_no_found_hidden,
     discover_no_found_verbose, discover_error_finish,
     discover_cancelled_finish, discover_json_sync_warning,
     discover_status_ahead, discover_status_ahead_tick,
     discover_status_exception].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    ok.

%%% ------------------------------------------------------------------
%%% Справка и реальный escript на loopback
%%% ------------------------------------------------------------------

discover_help(Config) ->
    {0, Out} = run(["discover", "--help"], Config),
    must_contain(Out, <<"discover">>),
    must_contain(Out, <<"auto">>),
    must_contain(Out, <<"raw_tcp">>),
    must_contain(Out, <<"--method">>),
    must_contain(Out, <<"--no-progress">>),
    ok.

%% Открытый loopback-порт: находка и метод в stdout, прогресс без ANSI в
%% stderr, код 0.
discover_text(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Out, Err} =
            run_split(["discover", "--targets", "127.0.0.1", "--method", "tcp",
                       "--ports", integer_to_list(Port)], Config),
        must_contain(Out, <<"127.0.0.1">>),
        must_contain(Out, <<"tcp_open">>),
        must_contain(Out, <<"Найдено отвечающих адресов: 1"/utf8>>),
        must_contain(Out, <<"Завершено: 1 из 1"/utf8>>),
        true = progress_lines(Err) >= 2,
        must_contain(Err, <<"Проверено"/utf8>>),
        must_not_contain(Err, <<"\e">>),
        must_not_contain(Err, <<"\r">>)
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

%% --no-progress отключает прогресс; с методом tcp предупреждений нет,
%% поэтому stderr пуст.
discover_no_progress(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Out, Err} =
            run_split(["discover", "--targets", "127.0.0.1", "--method", "tcp",
                       "--ports", integer_to_list(Port), "--no-progress"],
                      Config),
        <<>> = Err,
        must_contain(Out, <<"tcp_open">>)
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

%% JSON: один полный объект, результаты отсортированы и содержат метод и
%% порт, warnings — список строк, прогресса в stderr нет.
discover_json(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Out, Err} =
            run_split(["discover", "--targets", "127.0.0.1,2", "--method", "tcp",
                       "--ports", integer_to_list(Port), "--json"], Config),
        <<>> = Err,
        Map = json:decode(string:trim(Out)),
        Results = maps:get(<<"results">>, Map),
        2 = length(Results),
        Ips = [maps:get(<<"ip">>, R) || R <- Results],
        [<<"127.0.0.1">>, <<"127.0.0.2">>] = Ips,
        [Open] = [R || R <- Results, maps:get(<<"ip">>, R) =:= <<"127.0.0.1">>],
        <<"up">> = maps:get(<<"state">>, Open),
        <<"tcp_open">> = maps:get(<<"method">>, Open),
        Port = maps:get(<<"port">>, Open),
        [Other] = [R || R <- Results, maps:get(<<"ip">>, R) =:= <<"127.0.0.2">>],
        <<"up">> = maps:get(<<"state">>, Other),
        <<"tcp_refused">> = maps:get(<<"method">>, Other),
        Summary = maps:get(<<"summary">>, Map),
        2 = maps:get(<<"total">>, Summary),
        2 = maps:get(<<"completed">>, Summary),
        Counters = maps:get(<<"counters">>, Summary),
        2 = maps:get(<<"up">>, Counters),
        [] = maps:get(<<"warnings">>, Summary)
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

%% JSON auto: валидный объект, в stderr нет прогресса (сердцебиения в JSON
%% не бывает независимо от доступности raw-методов).
discover_json_auto(Config) ->
    {0, Out, Err} = run_split(["discover", "--targets", "127.0.0.1",
                               "--json", "--method", "auto"], Config),
    Map = json:decode(string:trim(Out)),
    [Result] = maps:get(<<"results">>, Map),
    <<"127.0.0.1">> = maps:get(<<"ip">>, Result),
    map_size(maps:with([<<"warnings">>], maps:get(<<"summary">>, Map))) =:= 1
        orelse ct:fail(no_warnings_key),
    must_not_contain(Err, <<"Проверено"/utf8>>),
    ok.

discover_invalid(Config) ->
    {2, _} = run(["discover", "--method", "tcp"], Config),
    {2, _} = run(["discover", "--targets", "127.0.0.1", "--method", "bogus"],
                 Config),
    %% Порты вне tcp отклоняются до любых проб.
    {2, _} = run(["discover", "--targets", "127.0.0.1", "--ports", "80"], Config),
    {2, _} = run(["discover", "--targets", "127.0.0.1", "--method", "tcp",
                  "--retries", "9"], Config),
    {2, _} = run(["discover", "--targets", "127.0.0.1", "--bogus", "1"], Config),
    {2, _} = run(["discover", "--targets", "256.0.0.1", "--method", "tcp"],
                 Config),
    ok.

%% Повтор флага и ключа отклоняется с кодом 2 и диагностикой в stderr.
discover_duplicate_flags(Config) ->
    {2, Out1, Err1} = run_split(["discover", "--targets", "127.0.0.1",
                                 "--method", "tcp", "--json", "--json"], Config),
    <<>> = Out1,
    must_contain(Err1, <<"duplicate">>),
    {2, Out2, Err2} = run_split(["discover", "--targets", "127.0.0.1",
                                 "--method", "tcp", "--no-progress",
                                 "--no-progress"], Config),
    <<>> = Out2,
    must_contain(Err2, <<"duplicate">>),
    ok.

%% Явный raw-метод: без прав — код 1 и понятная диагностика; с правами —
%% успех. Ветка выбирается по реальным capabilities, без подмены.
discover_raw_unavailable(Config) ->
    Caps = trawler_discovery_probe:capabilities(),
    case maps:get(raw_tcp, Caps) of
        false ->
            {1, Out, Err} =
                run_split(["discover", "--targets", "127.0.0.1",
                           "--method", "raw_tcp", "--no-progress"], Config),
            <<>> = Out,
            must_contain(Err, <<"raw_tcp">>);
        true ->
            {0, _Out, _Err} =
                run_split(["discover", "--targets", "127.0.0.1",
                           "--method", "raw_tcp", "--no-progress"], Config),
            ok
    end,
    ok.

%%% ------------------------------------------------------------------
%%% Детерминированные пути на локальном драйвере
%%% ------------------------------------------------------------------

%% Heartbeat во время ожидания: прогресс виден до находок, итог 100%.
discover_heartbeat(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {sleep, 2200},
        {result, up_result({127, 0, 0, 1}, tcp_open)},
        {result, up_result({127, 0, 0, 2}, tcp_refused)},
        {done, summary(2, 2, #{up => 2})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, Err} = run_split_env(Driver, discover_args(), fake_env(ScriptFile),
                                  Config),
    true = progress_lines(Err) >= 3,
    must_contain(Err, <<"Проверено 0/2 (0%)"/utf8>>),
    must_contain(Err, <<"Проверено 2/2 (100%)"/utf8>>),
    must_contain(Out, <<"Завершено: 2 из 2"/utf8>>),
    must_contain(Out, <<"127.0.0.1">>),
    must_contain(Out, <<"tcp_open">>),
    must_contain(Out, <<"127.0.0.2">>),
    ok.

%% Находка приходит до завершения поиска.
discover_stream_pre_finish(Config) ->
    Script = #{total => 1, status => ok, steps => [
        {result, up_result({127, 0, 0, 1}, tcp_open)},
        {sleep, 1500},
        {done, summary(1, 1, #{up => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, _Out, Early} = run_stream_check(Driver, discover_args(),
                                        fake_env(ScriptFile), <<"tcp_open">>),
    true = Early,
    ok.

%% Потеря статуса во время непрерывного потока: завершение ограничено и
%% (с --no-progress тоже) приводит к коду 1.
discover_stream_status_lost(Config) ->
    Script = #{total => 1600, status => {status_after, 1}, steps => [
        {repeat, 1600, noresp_result({127, 0, 0, 1}), 5}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {Elapsed, {1, _Out, Err}} =
        run_split_timed(Driver, discover_args(), fake_env(ScriptFile), Config),
    must_contain(Err, <<"not available">>),
    true = Elapsed < 4500,
    ok.

discover_stream_status_lost_no_progress(Config) ->
    Script = #{total => 1600, status => {status_after, 1}, steps => [
        {repeat, 1600, noresp_result({127, 0, 0, 1}), 5}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {Elapsed, {1, _Out, Err}} =
        run_split_timed(Driver, discover_args() ++ ["--no-progress"],
                        fake_env(ScriptFile), Config),
    must_contain(Err, <<"not available">>),
    true = Elapsed < 4500,
    ok.

%% Терминал: строка прогресса очищается ДО заголовка и находки, вывод
%% завершается переводом строки.
discover_tty_line(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {result, up_result({127, 0, 0, 1}, tcp_open)},
        {sleep, 400},
        {result, up_result({127, 0, 0, 2}, tcp_refused)},
        {done, summary(2, 2, #{up => 2})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Raw} = run_pty(Driver, discover_args(), fake_env(ScriptFile), Config),
    must_contain(Raw, <<"\r">>),
    must_contain(Raw, <<"\e[K">>),
    must_contain(Raw, <<"\e[KIP">>),
    must_contain(Raw, <<"tcp_open">>),
    must_contain(Raw, <<"tcp_refused">>),
    true = binary:last(Raw) =:= $\n,
    ok.

%% Предупреждение о TCP fallback видно в stderr даже с --no-progress, а
%% находки не теряются.
discover_warning_no_progress(Config) ->
    Script = #{total => 1, status => ok, steps => [
        {warning, tcp_fallback},
        {result, up_result({127, 0, 0, 1}, tcp_open)},
        {done, summary(1, 1, #{up => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, Err} = run_split_env(Driver,
                                  discover_args() ++ ["--no-progress"],
                                  fake_env(ScriptFile), Config),
    must_contain(Err, <<"raw-методы недоступны"/utf8>>),
    must_not_contain(Err, <<"Проверено"/utf8>>),
    must_contain(Out, <<"tcp_open">>),
    ok.

%% Без verbose неуспешные исходы скрыты и представлены счётчиками; адрес
%% не объявляется отсутствующим.
discover_no_found_hidden(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {result, noresp_result({127, 0, 0, 2})},
        {result, noresp_result({127, 0, 0, 3})},
        {done, summary(2, 2, #{no_response => 2})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, _Err} = run_split_env(Driver,
                                   discover_args() ++ ["--no-progress"],
                                   fake_env(ScriptFile), Config),
    must_contain(Out, <<"Отвечающих адресов не найдено"/utf8>>),
    must_contain(Out, <<"Без ответа: 2"/utf8>>),
    must_not_contain(Out, <<"127.0.0.2">>),
    must_not_contain(Out, <<"127.0.0.3">>),
    must_not_contain(Out, <<"отсутству"/utf8>>),
    ok.

%% --verbose показывает состояние каждого адреса.
discover_no_found_verbose(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {result, noresp_result({127, 0, 0, 2})},
        {result, noresp_result({127, 0, 0, 3})},
        {done, summary(2, 2, #{no_response => 2})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, _Err} = run_split_env(Driver,
                                   discover_args() ++ ["--verbose",
                                                       "--no-progress"],
                                   fake_env(ScriptFile), Config),
    must_contain(Out, <<"127.0.0.2">>),
    must_contain(Out, <<"127.0.0.3">>),
    must_contain(Out, <<"no_response">>),
    ok.

%% Ошибка выполнения: прогресс завершён, диагностика в stderr, код 1.
discover_error_finish(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {result, up_result({127, 0, 0, 1}, tcp_open)},
        {sleep, 300},
        {error, boom, summary(2, 1, #{up => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {1, Out, Err} = run_split_env(Driver, discover_args(),
                                  fake_env(ScriptFile), Config),
    must_contain(Out, <<"tcp_open">>),
    must_contain(Err, <<"Проверено"/utf8>>),
    must_contain(Err, <<"boom">>),
    true = progress_terminated(Err),
    ok.

%% Отмена: прогресс завершён, код 1.
discover_cancelled_finish(Config) ->
    Script = #{total => 1, status => ok, steps => [
        {result, up_result({127, 0, 0, 1}, tcp_open)},
        {cancelled, summary(1, 1, #{up => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {1, _Out, Err} = run_split_env(Driver, discover_args(),
                                   fake_env(ScriptFile), Config),
    must_contain(Err, <<"cancelled">>),
    true = progress_terminated(Err),
    ok.

%% JSON с fallback: полный объект, warnings строкой в сводке, русское
%% предупреждение в stderr и никакого прогресса.
discover_json_sync_warning(Config) ->
    Summary = #{total => 1, completed => 1,
                counters => #{up => 1, no_response => 0, error => 0},
                elapsed_ms => 5, warnings => [tcp_fallback]},
    Result = #{ip => {127, 0, 0, 1}, state => up, method => local,
               elapsed_ms => 5},
    Script = #{total => 1, status => ok, steps => [],
               sync => {ok, [Result], Summary}},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, Err} = run_split_env(Driver,
                                  ["discover", "--targets", "127.0.0.1",
                                   "--json"],
                                  fake_env(ScriptFile), Config),
    Map = json:decode(string:trim(Out)),
    [R] = maps:get(<<"results">>, Map),
    <<"up">> = maps:get(<<"state">>, R),
    <<"local">> = maps:get(<<"method">>, R),
    SummaryJson = maps:get(<<"summary">>, Map),
    [<<"tcp_fallback">>] = maps:get(<<"warnings">>, SummaryJson),
    must_contain(Err, <<"raw-методы недоступны"/utf8>>),
    must_not_contain(Err, <<"Проверено"/utf8>>),
    ok.

%%% ------------------------------------------------------------------
%%% Status ahead: повторный учёт промежуточного прогресса
%%% ------------------------------------------------------------------

%% Быстрое задание: начальный статус уже завершён (completed = total и
%% up = total), а результаты ещё идут. Прогресс обязан считаться только по
%% обработанным событиям: каждый образец не больше total, счётчики
%% монотонны, финал — 100% и последовательность 0 -> 1 -> 2 для двух
%% адресов. Двойной учёт давал бы 2 -> 3 -> 4 (200%) и up вдвое больше.
discover_status_ahead(Config) ->
    Script = #{total => 2, status => ahead, steps => [
        {sleep, 350},
        {result, up_result({127, 0, 0, 1}, tcp_open)},
        {sleep, 350},
        {result, up_result({127, 0, 0, 2}, tcp_refused)},
        {done, summary(2, 2, #{up => 2})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Raw} = run_pty(Driver, discover_args(), fake_env(ScriptFile), Config),
    Samples = progress_samples(Raw),
    true = Samples =/= [],
    assert_bounded(Samples),
    assert_monotonic(Samples),
    assert_final(Samples, 2),
    [0, 1, 2] = dedup([C || {C, _T, _P, _U} <- Samples]),
    ok.

%% Периодический tick при незавершённом потоке: статус опережает события
%% (completed = total), но tick не должен подхватывать его completed и
%% счётчики. Прогресс монотонен, не превышает total и завершается 100%.
discover_status_ahead_tick(Config) ->
    Script = #{total => 2, status => ahead, steps => [
        {result, up_result({127, 0, 0, 1}, tcp_open)},
        {sleep, 2400},
        {result, up_result({127, 0, 0, 2}, tcp_refused)},
        {done, summary(2, 2, #{up => 2})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, Err} = run_split_env(Driver, discover_args(),
                                  fake_env(ScriptFile), Config),
    true = progress_lines(Err) >= 3,
    Samples = progress_samples(Err),
    true = Samples =/= [],
    assert_bounded(Samples),
    assert_monotonic(Samples),
    assert_final(Samples, 2),
    [0, 1, 2] = dedup([C || {C, _T, _P, _U} <- Samples]),
    must_contain(Out, <<"Завершено: 2 из 2"/utf8>>),
    must_contain(Out, <<"Найдено отвечающих адресов: 2"/utf8>>),
    ok.

%% Исключение или выход из ядра при запросе статуса: контролируемый код 1,
%% диагностика о недоступном состоянии и отмена собственного задания.
%% Атом-результат вместо кортежа раньше давал case_clause без отмены.
discover_status_exception(Config) ->
    _ = [assert_status_exception(Config, Mode)
         || Mode <- [throw_status, exit_status, atom_status]],
    ok.

assert_status_exception(Config, Mode) ->
    Script = #{total => 2, status => Mode, steps => []},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    PrivDir = ?config(priv_dir, Config),
    Marker = filename:join(PrivDir, "cancel_" ++ atom_to_list(Mode)),
    _ = file:delete(Marker),
    Env = fake_env(ScriptFile) ++ [{"TRAWLER_FAKE_CANCEL", Marker}],
    {Elapsed, {1, _Out, Err}} =
        run_split_timed(Driver, discover_args(), Env, Config),
    must_contain(Err, <<"not available">>),
    true = Elapsed < 4500,
    true = filelib:is_file(Marker),
    ok.

%%% ------------------------------------------------------------------
%%% Запуск реального escript и локального драйвера
%%% ------------------------------------------------------------------

run(Args, _Config) ->
    Port = open_port({spawn_executable, executable()},
        [binary, exit_status, use_stdio, stderr_to_stdout, {args, Args}]),
    collect(Port, <<>>, 20000).

run_split(Args, Config) ->
    run_split_env(executable(), Args, [], Config).

run_split_env(Exe, Args, Env, Config) ->
    PrivDir = ?config(priv_dir, Config),
    Unique = integer_to_list(erlang:unique_integer([positive, monotonic])),
    OutFile = filename:join(PrivDir, "stdout_" ++ Unique),
    ErrFile = filename:join(PrivDir, "stderr_" ++ Unique),
    Command = lists:flatten(
        [env_prefix(Env),
         shell_quote(Exe),
         [[$\s | shell_quote(Arg)] || Arg <- Args],
         " > ", shell_quote(OutFile),
         " 2> ", shell_quote(ErrFile),
         "; printf '%s' $?"]),
    Status = os:cmd(Command),
    {ok, Stdout} = file:read_file(OutFile),
    {ok, Stderr} = file:read_file(ErrFile),
    {list_to_integer(string:trim(Status)), Stdout, Stderr}.

run_split_timed(Exe, Args, Env, Config) ->
    Start = erlang:monotonic_time(millisecond),
    Result = run_split_env(Exe, Args, Env, Config),
    {erlang:monotonic_time(millisecond) - Start, Result}.

env_prefix([]) -> "";
env_prefix(Env) ->
    [[Key, $=, shell_quote(Value), $\s] || {Key, Value} <- Env].

run_stream_check(Exe, Args, Env, Needle) ->
    Port = open_port({spawn_executable, Exe},
        [binary, exit_status, use_stdio, stderr_to_stdout, {args, Args},
         {env, Env}]),
    collect_stream(Port, <<>>, Needle, undefined).

collect_stream(Port, Acc, Needle, NeedleAt) ->
    receive
        {Port, {data, Data}} ->
            Now = erlang:monotonic_time(millisecond),
            Acc1 = <<Acc/binary, Data/binary>>,
            NeedleAt1 = case NeedleAt of
                undefined ->
                    case binary:match(Data, Needle) of
                        nomatch -> undefined;
                        _Match -> Now
                    end;
                _Value -> NeedleAt
            end,
            collect_stream(Port, Acc1, Needle, NeedleAt1);
        {Port, {exit_status, Status}} ->
            ExitAt = erlang:monotonic_time(millisecond),
            Early = case NeedleAt of
                undefined -> false;
                SeenAt -> (ExitAt - SeenAt) > 500
            end,
            {Status, Acc, Early}
    after 20000 ->
        port_close(Port),
        ct:fail(cli_timeout)
    end.

run_pty(Exe, Args, Env, Config) ->
    case os:find_executable("script") of
        false ->
            ct:fail(script_not_available);
        _Script ->
            PrivDir = ?config(priv_dir, Config),
            Unique = integer_to_list(erlang:unique_integer([positive, monotonic])),
            TypeFile = filename:join(PrivDir, "pty_" ++ Unique),
            Command = lists:flatten(
                [env_prefix(Env),
                 shell_quote(Exe),
                 [[$\s | shell_quote(Arg)] || Arg <- Args]]),
            Status = os:cmd(
                "script -qec " ++ shell_quote(Command) ++ " "
                ++ shell_quote(TypeFile) ++ " >/dev/null 2>&1; printf '%s' $?"),
            {ok, Raw} = file:read_file(TypeFile),
            {list_to_integer(string:trim(Status)), Raw}
    end.

%%% ------------------------------------------------------------------
%%% Локальный драйвер с тестовым двойником discovery-ядра
%%% ------------------------------------------------------------------

fake_driver(Config, Script) ->
    PrivDir = ?config(priv_dir, Config),
    Unique = integer_to_list(erlang:unique_integer([positive, monotonic])),
    Dir = filename:join(PrivDir, "fake_" ++ Unique),
    Ebin = filename:join(Dir, "ebin"),
    ok = filelib:ensure_dir(filename:join(Ebin, "keep")),
    {ok, _} = file:copy(cli_beam(trawler_cli),
                        filename:join(Ebin, "trawler_cli.beam")),
    {ok, _} = file:copy(cli_beam(trawler_discovery_cli),
                        filename:join(Ebin, "trawler_discovery_cli.beam")),
    Src = filename:join(Dir, "trawler.erl"),
    ok = file:write_file(Src, unicode:characters_to_binary(fake_source())),
    {ok, trawler} = compile:file(Src, [{outdir, Ebin}, return_errors]),
    ok = file:write_file(filename:join(Ebin, "trawler.app"), fake_app()),
    ScriptFile = filename:join(Dir, "script.term"),
    ok = file:write_file(ScriptFile, io_lib:format("~p.~n", [Script])),
    Driver = filename:join(Dir, "driver"),
    ok = file:write_file(Driver, driver_source(Ebin)),
    ok = file:change_mode(Driver, 8#755),
    {Driver, ScriptFile}.

fake_source() ->
    "%% Тестовый двойник discovery-ядра: отдаёт заданные события.\n"
    "-module(trawler).\n"
    "-export([start_discovery/2, discover/2, discovery_status/1,\n"
    "         cancel_discovery/1]).\n"
    "start_discovery(_Targets, Options) ->\n"
    "    Script = script(),\n"
    "    Recipient = maps:get(recipient, Options, self()),\n"
    "    Ref = make_ref(),\n"
    "    put({disc, Ref}, Script),\n"
    "    put({disc_calls, Ref}, 0),\n"
    "    spawn(fun() -> run(Recipient, Ref, maps:get(steps, Script, [])) end),\n"
    "    {ok, Ref}.\n"
    "discover(_Targets, _Options) ->\n"
    "    Script = script(),\n"
    "    maps:get(sync, Script, {ok, [], summary(0, 0, #{})}).\n"
    "discovery_status(Ref) ->\n"
    "    case get({disc, Ref}) of\n"
    "        undefined ->\n"
    "            {error, not_found};\n"
    "        Script ->\n"
    "            N = get({disc_calls, Ref}),\n"
    "            put({disc_calls, Ref}, N + 1),\n"
    "            status_reply(maps:get(status, Script, ok), Script, N)\n"
    "    end.\n"
    "%% status => ahead: статус уже завершён (completed = total, up = total),\n"
    "%% хотя события ещё идут. throw/exit/atom воспроизводят сбой или\n"
    "%% неожиданный ответ ядра при запросе статуса.\n"
    "status_reply(not_found, _Script, _N) ->\n"
    "    {error, not_found};\n"
    "status_reply({status_after, Limit}, _Script, N) when N >= Limit ->\n"
    "    {error, not_found};\n"
    "status_reply(throw_status, _Script, _N) ->\n"
    "    throw(status_boom);\n"
    "status_reply(exit_status, _Script, _N) ->\n"
    "    exit(status_boom);\n"
    "status_reply(atom_status, _Script, _N) ->\n"
    "    unexpected_atom;\n"
    "status_reply(ahead, Script, _N) ->\n"
    "    Total = maps:get(total, Script, 0),\n"
    "    {ok, #{state => completed,\n"
    "           total => Total,\n"
    "           completed => Total,\n"
    "           counters => maps:merge(zero(), #{up => Total}),\n"
    "           warnings => []}};\n"
    "status_reply(_Other, Script, _N) ->\n"
    "    {ok, #{state => running,\n"
    "           total => maps:get(total, Script, 0),\n"
    "           completed => 0,\n"
    "           counters => zero(),\n"
    "           warnings => []}}.\n"
    "%% Отмена собственного задания отмечается файлом, если путь задан\n"
    "%% TRAWLER_FAKE_CANCEL — так тест видит, что перед выходом отмена была.\n"
    "cancel_discovery(_Ref) ->\n"
    "    case os:getenv(\"TRAWLER_FAKE_CANCEL\") of\n"
    "        false -> ok;\n"
    "        Path -> file:write_file(Path, <<\"cancelled\">>)\n"
    "    end.\n"
    "script() ->\n"
    "    {ok, [Script]} = file:consult(os:getenv(\"TRAWLER_FAKE_SCRIPT\")),\n"
    "    Script.\n"
    "zero() -> #{up => 0, no_response => 0, error => 0}.\n"
    "summary(Total, Completed, Partial) ->\n"
    "    #{total => Total, completed => Completed,\n"
    "      counters => maps:merge(zero(), Partial), elapsed_ms => 5,\n"
    "      warnings => []}.\n"
    "run(R, Ref, [{sleep, Ms} | Rest]) ->\n"
    "    timer:sleep(Ms), run(R, Ref, Rest);\n"
    "run(R, Ref, [{result, Value} | Rest]) ->\n"
    "    R ! {trawler_discovery, Ref, {result, Value}}, run(R, Ref, Rest);\n"
    "run(R, Ref, [{warning, Value} | Rest]) ->\n"
    "    R ! {trawler_discovery, Ref, {warning, Value}}, run(R, Ref, Rest);\n"
    "run(R, Ref, [{repeat, Count, Value, Delay} | Rest]) ->\n"
    "    repeat(R, Ref, Count, Value, Delay), run(R, Ref, Rest);\n"
    "run(R, Ref, [{done, S} | _]) ->\n"
    "    R ! {trawler_discovery, Ref, {done, S}};\n"
    "run(R, Ref, [{error, Reason, S} | _]) ->\n"
    "    R ! {trawler_discovery, Ref, {error, Reason, S}};\n"
    "run(R, Ref, [{cancelled, S} | _]) ->\n"
    "    R ! {trawler_discovery, Ref, {cancelled, S}};\n"
    "run(_R, _Ref, []) -> ok.\n"
    "repeat(_R, _Ref, 0, _Value, _Delay) -> ok;\n"
    "repeat(R, Ref, N, Value, Delay) ->\n"
    "    R ! {trawler_discovery, Ref, {result, Value}},\n"
    "    timer:sleep(Delay),\n"
    "    repeat(R, Ref, N - 1, Value, Delay).\n".

fake_app() ->
    "{application, trawler, [{description, \"test fake\"}, {vsn, \"0.0.0\"},\n"
    " {modules, []}, {registered, []}, {applications, [kernel, stdlib]}]}.\n".

driver_source(Ebin) ->
    io_lib:format(
        "#!/usr/bin/env escript\n"
        "%%! -pa ~ts\n"
        "main(Args) ->\n"
        "    trawler_cli:main(Args).\n",
        [Ebin]).

cli_beam(Module) ->
    Name = atom_to_list(Module) ++ ".beam",
    Default = filename:join([project_root(), "_build", "default", "lib",
                             "trawler", "ebin", Name]),
    case filelib:is_file(Default) of
        true -> Default;
        false -> filename:join([code:lib_dir(trawler), "ebin", Name])
    end.

project_root() ->
    Root = filename:absname(filename:join(
        [code:lib_dir(trawler), "..", "..", "..", ".."])),
    case os:getenv("TRAWLER_ROOT") of
        false -> Root;
        Path -> Path
    end.

executable() ->
    filename:join([project_root(), "_build", "default", "bin", "trawler"]).

%%% ------------------------------------------------------------------
%%% Данные сценариев и вспомогательные функции
%%% ------------------------------------------------------------------

up_result(IP, Method) ->
    #{ip => IP, state => up, method => Method, elapsed_ms => 1}.

noresp_result({A, B, C, D}) ->
    #{ip => {A, B, C, D}, state => no_response, elapsed_ms => 100}.

summary(Total, Completed, Partial) ->
    Zero = #{up => 0, no_response => 0, error => 0},
    #{total => Total,
      completed => Completed,
      counters => maps:merge(Zero, Partial),
      elapsed_ms => 5,
      warnings => []}.

discover_args() ->
    ["discover", "--targets", "127.0.0.1", "--method", "tcp", "--ports", "80"].

fake_env(ScriptFile) ->
    [{"TRAWLER_FAKE_SCRIPT", ScriptFile}].

progress_lines(Err) ->
    Lines = binary:split(Err, <<"\n">>, [global]),
    length([L || L <- Lines,
                 binary:match(L, <<"Проверено"/utf8>>) =/= nomatch]).

%% Все образцы строки прогресса: {Completed, Total, Percent, Up}.
progress_samples(Output) ->
    case re:run(Output,
                <<"Проверено (\\d+)/(\\d+) \\((\\d+)%\\) \\| найдено (\\d+)"/utf8>>,
                [global, {capture, all_but_first, binary}]) of
        nomatch ->
            [];
        {match, Matches} ->
            [{binary_to_integer(C), binary_to_integer(T),
              binary_to_integer(P), binary_to_integer(U)}
             || [C, T, P, U] <- Matches]
    end.

%% Ни один образец не превышает объявленный total: ни completed, ни up.
assert_bounded(Samples) ->
    case [S || {C, T, _P, U} = S <- Samples, C > T orelse U > T] of
        [] -> ok;
        Bad -> ct:fail({progress_exceeds_total, Bad})
    end.

%% Прогресс не откатывается назад ни по completed, ни по up.
assert_monotonic(Samples) ->
    ok = assert_non_decreasing([C || {C, _T, _P, _U} <- Samples], completed),
    ok = assert_non_decreasing([U || {_C, _T, _P, U} <- Samples], up).

assert_non_decreasing(Values, Field) ->
    Pairs = lists:zip(lists:droplast(Values), tl(Values)),
    case [P || {A, B} = P <- Pairs, B < A] of
        [] -> ok;
        Bad -> ct:fail({progress_not_monotonic, Field, Bad})
    end.

%% Финальный образец: завершено ровно total и 100%.
assert_final(Samples, Total) ->
    case lists:last(Samples) of
        {Total, Total, 100, _Up} -> ok;
        Last -> ct:fail({unexpected_final_progress, Last})
    end.

%% Соседние повторы убираются: возвращается порядок различных чисел.
dedup(Values) ->
    lists:reverse(
      lists:foldl(fun(V, [V | _] = Acc) -> Acc;
                     (V, Acc) -> [V | Acc]
                  end, [], Values)).

progress_terminated(Err) ->
    case binary:matches(Err, <<"Проверено"/utf8>>) of
        [] ->
            false;
        Matches ->
            {Pos, _Len} = lists:last(Matches),
            Scope = {Pos, byte_size(Err) - Pos},
            binary:match(Err, <<"\n">>, [{scope, Scope}]) =/= nomatch
    end.

shell_quote(String) ->
    "'" ++ lists:flatten([shell_quote_char(C) || C <- String]) ++ "'".

shell_quote_char($') ->
    "'\\''";
shell_quote_char(C) ->
    [C].

collect(Port, Acc, Timeout) ->
    receive
        {Port, {data, Data}} -> collect(Port, <<Acc/binary, Data/binary>>, Timeout);
        {Port, {exit_status, Status}} -> {Status, Acc}
    after Timeout ->
        port_close(Port),
        ct:fail(cli_timeout)
    end.

open_listener() ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}},
                                      {active, false}]),
    {ok, Port} = inet:port(Listen),
    {Listen, Port}.

must_contain(Output, Needle) ->
    case binary:match(Output, Needle) of
        nomatch -> ct:fail({missing_output, Needle, Output});
        _Match -> ok
    end.

must_not_contain(Output, Needle) ->
    case binary:match(Output, Needle) of
        nomatch -> ok;
        _Match -> ct:fail({unexpected_output, Needle, Output})
    end.
