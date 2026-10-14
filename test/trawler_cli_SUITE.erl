%%%-------------------------------------------------------------------
%%% @doc Common Test командной строки trawler.
%%%
%%% Набор запускает собранный escript и проверяет справку, версию,
%%% разбор аргументов, компактный текстовый поиск, прогресс, JSON-вывод
%%% и коды завершения. Сетевые проверки остаются в пределах loopback
%%% 127.0.0.0/8: слушатель открывается в процессе Common Test на
%%% 127.0.0.1, а escript подключается к 127.0.0.1 и 127.0.0.2 как к
%%% обычным узлам сети.
%%%
%%% Медленный путь, таймаут и потеря статуса воспроизводятся локальным
%%% драйвером: он запускает реальный модуль `trawler_cli' в одном
%%% каталоге с тестовым модулем `trawler', который отдаёт заранее
%%% заданные события. Это тестовая инъекция через код-путь, без
%%% production-переключателей. Терминальная строка прогресса
%%% проверяется под псевдотерминалом (`script').
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_cli_SUITE).

-include_lib("common_test/include/ct.hrl").

-export([all/0, help/1, version/1, unsupported/1,
         scan_text/1, scan_json/1, scan_verbose/1, scan_no_open/1,
         scan_default_ports/1, scan_mixed_targets/1, scan_invalid/1,
         scan_invalid_streams/1, scan_duplicate_flags/1,
         scan_progress_off/1, scan_heartbeat/1, scan_continuous/1,
         scan_stream_throttle/1, scan_stream_status_lost/1,
         scan_stream_status_lost_tty/1, scan_stream_no_progress/1,
         scan_timeout_hidden/1, scan_stream_pre_finish/1,
         scan_error_finish/1, scan_cancelled_finish/1,
         scan_error_finish_tty/1, scan_cancelled_finish_tty/1,
         scan_verbose_failures/1, scan_default_counters/1, scan_status_lost/1,
         scan_tty_line/1]).

all() ->
    [help, version, unsupported,
     scan_text, scan_json, scan_verbose, scan_no_open, scan_default_ports,
     scan_mixed_targets, scan_invalid, scan_invalid_streams,
     scan_duplicate_flags, scan_progress_off, scan_heartbeat,
     scan_continuous, scan_stream_throttle, scan_stream_status_lost,
     scan_stream_status_lost_tty, scan_stream_no_progress,
     scan_timeout_hidden, scan_stream_pre_finish, scan_error_finish,
     scan_cancelled_finish, scan_error_finish_tty, scan_cancelled_finish_tty,
     scan_verbose_failures, scan_default_counters, scan_status_lost,
     scan_tty_line].

%%% ------------------------------------------------------------------
%%% Справка, версия и неизвестная команда
%%% ------------------------------------------------------------------

help(Config) ->
    {0, Output} = run(["--help"], Config),
    must_contain(Output, <<"scan">>),
    must_contain(Output, <<"--targets">>),
    must_contain(Output, <<"--ports">>),
    %% Новые режимы поиска и компактное поведение по умолчанию.
    must_contain(Output, <<"--verbose">>),
    must_contain(Output, <<"--no-progress">>),
    must_contain(Output, <<"открытые порты"/utf8>>),
    must_contain(Output, <<"Таймаут"/utf8>>),
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

%% Открытый локальный порт: находка печатается в stdout, компактная
%% русская сводка считает исходы, а прогресс уходит в stderr без ANSI.
scan_text(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Out, Err} = run_split(["scan", "--targets", "127.0.0.1",
                                   "--ports", integer_to_list(Port)], Config),
        must_contain(Out, <<"127.0.0.1">>),
        must_contain(Out, integer_to_binary(Port)),
        must_contain(Out, <<"open">>),
        must_contain(Out, <<"Открытых портов: 1"/utf8>>),
        must_contain(Out, <<"Завершено"/utf8>>),
        %% Начало и завершение прогресса обязательны, перенаправление
        %% использует строки без ANSI и возврата каретки.
        true = progress_lines(Err) >= 2,
        must_contain(Err, <<"Проверено"/utf8>>),
        must_not_contain(Err, <<"\e">>),
        must_not_contain(Err, <<"\r">>)
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

%% JSON остаётся прежним полным объектом без прогресса: ни при обычном
%% запуске, ни с --verbose stderr не содержит прогресс.
scan_json(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Out, Err} = run_split(["scan", "--targets", "127.0.0.1",
                                   "--ports", integer_to_list(Port),
                                   "--json"], Config),
        <<>> = Err,
        Map = json:decode(string:trim(Out)),
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
        0 = maps:get(<<"error">>, Counters),
        %% --verbose рядом с --json не включает прогресс.
        {0, VerboseOut, VerboseErr} =
            run_split(["scan", "--targets", "127.0.0.1",
                       "--ports", integer_to_list(Port), "--json",
                       "--verbose"], Config),
        <<>> = VerboseErr,
        VerboseMap = json:decode(string:trim(VerboseOut)),
        1 = length(maps:get(<<"results">>, VerboseMap))
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

%% --verbose перечисляет каждую пробу с IP, портом и состоянием: открытый
%% порт 127.0.0.1 и закрытый 127.0.0.2.
scan_verbose(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Out, _Err} = run_split(["scan", "--targets", "127.0.0.1,2",
                                    "--ports", integer_to_list(Port),
                                    "--verbose"], Config),
        must_contain(Out, <<"127.0.0.1">>),
        must_contain(Out, <<"open">>),
        must_contain(Out, <<"127.0.0.2">>),
        must_contain(Out, <<"closed">>),
        must_contain(Out, <<"Открытых портов: 1"/utf8>>),
        must_contain(Out, <<"Закрыто: 1"/utf8>>)
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

%% Закрытый порт: код 0, явное сообщение об отсутствии находок и счётчик
%% закрытых; адрес не объявляется отсутствующим в сети.
scan_no_open(Config) ->
    Port = reserve_closed_port(),
    {0, Out, _Err} = run_split(["scan", "--targets", "127.0.0.1",
                                "--ports", integer_to_list(Port)], Config),
    must_contain(Out, <<"Открытых портов не найдено"/utf8>>),
    must_contain(Out, <<"Закрыто: 1"/utf8>>),
    must_not_contain(Out, <<"отсутству"/utf8>>),
    ok.

%% Без --ports сканирование использует набор по умолчанию из 1000 портов.
scan_default_ports(Config) ->
    {0, Output} = run(["scan", "--targets", "127.0.0.1", "--json"], Config),
    Map = json:decode(string:trim(Output)),
    Summary = maps:get(<<"summary">>, Map),
    1000 = maps:get(<<"total">>, Summary),
    ok.

%% Повтор нового флага отклоняется с кодом 2 и диагностикой в stderr,
%% stdout при этом пуст.
scan_duplicate_flags(Config) ->
    {2, Out1, Err1} = run_split(["scan", "--targets", "127.0.0.1",
                                 "--ports", "80", "--verbose", "--verbose"],
                                Config),
    <<>> = Out1,
    must_contain(Err1, <<"duplicate">>),
    {2, Out2, Err2} = run_split(["scan", "--targets", "127.0.0.1",
                                 "--ports", "80", "--no-progress",
                                 "--no-progress"], Config),
    <<>> = Out2,
    must_contain(Err2, <<"duplicate">>),
    {2, Out3, Err3} = run_split(["scan", "--targets", "127.0.0.1",
                                 "--ports", "80", "--json", "--json"], Config),
    <<>> = Out3,
    must_contain(Err3, <<"duplicate">>),
    ok.

%%% ------------------------------------------------------------------
%%% Прогресс и медленный путь на локальном драйвере
%%% ------------------------------------------------------------------

%% --no-progress отключает прогресс: stderr пуст, находки и сводка на месте.
scan_progress_off(Config) ->
    {Listen, Port} = open_listener(),
    try
        {0, Out, Err} = run_split(["scan", "--targets", "127.0.0.1",
                                   "--ports", integer_to_list(Port),
                                   "--no-progress"], Config),
        <<>> = Err,
        must_contain(Out, <<"open">>)
    after
        ok = gen_tcp:close(Listen)
    end,
    ok.

%% Heartbeat во время ожидания: прогресс виден, пока результаты ещё не
%% пришли, а итоговый показывает все пары и 100 процентов. Сценарий
%% согласован: итоговой сводке open=2 соответствуют две находки.
scan_heartbeat(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {sleep, 2400},
        {result, open_result(9001)},
        {result, open_result(9002)},
        {done, summary(2, 2, #{open => 2})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, Err} = run_split_env(Driver, scan_args(), fake_env(ScriptFile),
                                  Config),
    true = progress_lines(Err) >= 3,
    must_contain(Err, <<"Проверено 0/2 (0%)"/utf8>>),
    must_contain(Err, <<"Проверено 2/2 (100%)"/utf8>>),
    must_contain(Out, <<"Завершено: 2 из 2"/utf8>>),
    must_contain(Out, <<"9001">>),
    must_contain(Out, <<"9002">>),
    ok.

%% Непрерывный поток скрытых результатов держит почтовый ящик непустым,
%% но не откладывает прогресс и не перерисовывает его на каждую пробу:
%% обновления идут по абсолютному сроку. Накопление счётчиков проверяется
%% авторитетной сводкой.
scan_continuous(Config) ->
    Script = #{total => 600, status => ok, steps => [
        {repeat, 600, timeout_result({127, 0, 0, 1}), 5},
        {done, summary(600, 600, #{timeout => 600})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, Err} = run_split_env(Driver, scan_args(), fake_env(ScriptFile),
                                  Config),
    %% Обновления есть, но их намного меньше числа проб (не по строке на
    %% пробу), и один из них приходится на непрерывный поток событий.
    true = progress_lines(Err) >= 3,
    true = progress_lines(Err) < 20,
    must_contain(Err, <<"Проверено 600/600 (100%)"/utf8>>),
    must_contain(Out, <<"Без ответа (таймаут): 600"/utf8>>),
    %% Скрытые таймауты не перечисляются в stdout.
    must_not_contain(Out, <<"127.0.0.1">>),
    ok.

%% Терминал: непрерывный поток скрытых результатов обновляет прогресс
%% только по плановому сроку, а не на каждую пробу. Число перерисовок
%% много меньше числа результатов, при этом heartbeat присутствует.
scan_stream_throttle(Config) ->
    Script = #{total => 600, status => ok, steps => [
        {repeat, 600, timeout_result({127, 0, 0, 1}), 5},
        {done, summary(600, 600, #{timeout => 600})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Raw} = run_pty(Driver, scan_args(), fake_env(ScriptFile), Config),
    Redraws = count_occurrences(Raw, <<"Проверено"/utf8>>),
    true = Redraws >= 2,
    true = Redraws < 100,
    %% Скрытые результаты не попадают в вывод и в терминале (состояние
    %% timeout не печатается; баннер `script' на строку --targets не смотрим).
    must_not_contain(Raw, <<"timeout">>),
    ok.

%% Потеря статуса распознаётся прямо во время непрерывного потока
%% событий: проверка статуса идёт по сроку, а не только когда события
%% стихли. Ожидание ограничено и без прогресса (--no-progress).
scan_stream_status_lost(Config) ->
    Script = #{total => 1600, status => {status_after, 1}, steps => [
        {repeat, 1600, timeout_result({127, 0, 0, 1}), 5}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {Elapsed, {1, _Out, Err}} = run_split_timed(Driver, scan_args(),
                                                fake_env(ScriptFile), Config),
    must_contain(Err, <<"not available">>),
    %% Поток длился бы ~8 с; завершение задолго до него доказывает
    %% проверку статуса во время событий, а не после их исчерпания.
    true = Elapsed < 4500,
    {NoElapsed, {1, _Out2, Err2}} =
        run_split_timed(Driver, scan_args() ++ ["--no-progress"],
                        fake_env(ScriptFile), Config),
    must_contain(Err2, <<"not available">>),
    true = NoElapsed < 4500,
    ok.

%% Терминал: перерисовка строки после находки НЕ сдвигает плановый срок,
%% поэтому контроль статуса остаётся живым и во время непрерывного потока
%% показанных находок. Иначе находки отодвигали бы tick и ожидание росло
%% бы до конца потока.
scan_stream_status_lost_tty(Config) ->
    Script = #{total => 1600, status => {status_after, 1}, steps => [
        {repeat, 1600, open_result(80), 5}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {Elapsed, {1, Raw}} = run_pty_timed(Driver, scan_args(),
                                        fake_env(ScriptFile), Config),
    must_contain(Raw, <<"not available">>),
    %% Поток длился бы ~8 с; завершение задолго до него доказывает, что
    %% находки не отодвигают tick.
    true = Elapsed < 3000,
    ok.

%% --no-progress молчит даже при непрерывном потоке событий, при этом
%% сканирование завершается штатно, а сводка авторитетна.
scan_stream_no_progress(Config) ->
    Script = #{total => 600, status => ok, steps => [
        {repeat, 600, timeout_result({127, 0, 0, 1}), 5},
        {done, summary(600, 600, #{timeout => 600})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, Err} = run_split_env(Driver, scan_args() ++ ["--no-progress"],
                                  fake_env(ScriptFile), Config),
    <<>> = Err,
    must_contain(Out, <<"Завершено: 600 из 600"/utf8>>),
    must_contain(Out, <<"Без ответа (таймаут): 600"/utf8>>),
    ok.

%% Таймауты не перечисляются в тексте по умолчанию: их IP видны только
%% счётчиком в сводке.
scan_timeout_hidden(Config) ->
    Script = #{total => 5, status => ok, steps => [
        {result, open_result(80)},
        {result, timeout_result({127, 0, 0, 2})},
        {result, timeout_result({127, 0, 0, 3})},
        {result, timeout_result({127, 0, 0, 4})},
        {result, timeout_result({127, 0, 0, 5})},
        {done, summary(5, 5, #{open => 1, timeout => 4})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, Err} = run_split_env(Driver, scan_args(), fake_env(ScriptFile),
                                  Config),
    must_contain(Out, <<"127.0.0.1">>),
    must_contain(Out, <<"Без ответа (таймаут): 4"/utf8>>),
    must_not_contain(Out, <<"127.0.0.2">>),
    must_not_contain(Out, <<"127.0.0.3">>),
    must_not_contain(Out, <<"127.0.0.5">>),
    must_not_contain(Err, <<"127.0.0.3">>),
    ok.

%% Открытая находка приходит до завершения сканирования.
scan_stream_pre_finish(Config) ->
    Script = #{total => 1, status => ok, steps => [
        {result, open_result(9001)},
        {sleep, 1500},
        {done, summary(1, 1, #{open => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, _Out, Early} = run_stream_check(Driver, scan_args(),
                                        fake_env(ScriptFile), <<"9001">>),
    true = Early,
    ok.

%% Ошибка выполнения: строка прогресса завершена, диагностика в stderr,
%% код выхода 1, stdout содержит уже найденные открытые порты.
scan_error_finish(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {result, open_result(80)},
        {sleep, 300},
        {error, boom, summary(2, 1, #{open => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {1, Out, Err} = run_split_env(Driver, scan_args(), fake_env(ScriptFile),
                                  Config),
    must_contain(Out, <<"open">>),
    must_contain(Err, <<"Проверено"/utf8>>),
    must_contain(Err, <<"boom">>),
    true = progress_terminated(Err),
    ok.

%% Отмена тоже завершает строку прогресса и возвращает код 1.
scan_cancelled_finish(Config) ->
    Script = #{total => 1, status => ok, steps => [
        {result, open_result(80)},
        {cancelled, summary(1, 1, #{open => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {1, _Out, Err} = run_split_env(Driver, scan_args(), fake_env(ScriptFile),
                                   Config),
    must_contain(Err, <<"cancelled">>),
    true = progress_terminated(Err),
    ok.

%% Ошибка под терминалом: строка прогресса завершена переводом строки,
%% заголовок и находка не повреждены, диагностика на месте, код 1.
scan_error_finish_tty(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {result, open_result(80)},
        {sleep, 300},
        {error, boom, summary(2, 1, #{open => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {1, Raw} = run_pty(Driver, scan_args(), fake_env(ScriptFile), Config),
    must_contain(Raw, <<"boom">>),
    must_contain(Raw, <<"Проверено"/utf8>>),
    must_contain(Raw, <<"\e[KIP">>),
    true = progress_terminated(Raw),
    true = binary:last(Raw) =:= $\n,
    ok.

%% Отмена под терминалом: строка прогресса также корректно завершается.
scan_cancelled_finish_tty(Config) ->
    Script = #{total => 1, status => ok, steps => [
        {result, open_result(80)},
        {cancelled, summary(1, 1, #{open => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {1, Raw} = run_pty(Driver, scan_args(), fake_env(ScriptFile), Config),
    must_contain(Raw, <<"cancelled">>),
    must_contain(Raw, <<"Проверено"/utf8>>),
    true = progress_terminated(Raw),
    true = binary:last(Raw) =:= $\n,
    ok.

%% --verbose показывает неуспешные состояния timeout/unreachable/error
%% строками IP/порт/состояние; по умолчанию они скрыты и видны только
%% авторитетными счётчиками сводки.
scan_verbose_failures(Config) ->
    Script = #{total => 3, status => ok, steps => [
        {result, timeout_result({127, 0, 0, 2})},
        {result, #{ip => {127, 0, 0, 3}, port => 80, state => unreachable,
                   elapsed_ms => 1}},
        {result, #{ip => {127, 0, 0, 4}, port => 80, state => error,
                   elapsed_ms => 1}},
        {done, summary(3, 3, #{timeout => 1, unreachable => 1, error => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, _Err} = run_split_env(Driver, scan_args() ++ ["--verbose"],
                                   fake_env(ScriptFile), Config),
    must_contain(Out, <<"127.0.0.2">>),
    must_contain(Out, <<"timeout">>),
    must_contain(Out, <<"127.0.0.3">>),
    must_contain(Out, <<"unreachable">>),
    must_contain(Out, <<"127.0.0.4">>),
    must_contain(Out, <<"error">>),
    {0, Hidden, _Err2} = run_split_env(Driver, scan_args(),
                                       fake_env(ScriptFile), Config),
    must_not_contain(Hidden, <<"127.0.0.2">>),
    must_not_contain(Hidden, <<"127.0.0.3">>),
    must_not_contain(Hidden, <<"127.0.0.4">>),
    must_contain(Hidden, <<"Открытых портов не найдено"/utf8>>),
    must_contain(Hidden, <<"Без ответа (таймаут): 1"/utf8>>),
    must_contain(Hidden, <<"Недоступно: 1"/utf8>>),
    must_contain(Hidden, <<"Ошибки: 1"/utf8>>),
    ok.

%% По умолчанию перечисляются только открытые порты, а все неуспешные
%% исходы скрыты и представлены счётчиками итоговой сводки.
scan_default_counters(Config) ->
    Script = #{total => 5, status => ok, steps => [
        {result, open_result(8080)},
        {result, #{ip => {127, 0, 0, 2}, port => 80, state => closed,
                   elapsed_ms => 1}},
        {result, timeout_result({127, 0, 0, 3})},
        {result, #{ip => {127, 0, 0, 4}, port => 80, state => unreachable,
                   elapsed_ms => 1}},
        {result, #{ip => {127, 0, 0, 5}, port => 80, state => error,
                   elapsed_ms => 1}},
        {done, summary(5, 5, #{open => 1, closed => 1, timeout => 1,
                                unreachable => 1, error => 1})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Out, _Err} = run_split_env(Driver, scan_args(), fake_env(ScriptFile),
                                   Config),
    must_contain(Out, <<"127.0.0.1">>),
    must_contain(Out, <<"8080">>),
    must_contain(Out, <<"open">>),
    must_contain(Out, <<"Завершено: 5 из 5"/utf8>>),
    must_contain(Out, <<"Открытых портов: 1"/utf8>>),
    must_contain(Out, <<"Закрыто: 1"/utf8>>),
    must_contain(Out, <<"Без ответа (таймаут): 1"/utf8>>),
    must_contain(Out, <<"Недоступно: 1"/utf8>>),
    must_contain(Out, <<"Ошибки: 1"/utf8>>),
    must_not_contain(Out, <<"127.0.0.2">>),
    must_not_contain(Out, <<"127.0.0.3">>),
    must_not_contain(Out, <<"127.0.0.4">>),
    must_not_contain(Out, <<"127.0.0.5">>),
    ok.

%% Потеря статуса во время работы не приводит к зависанию: прогресс
%% завершается, диагностика в stderr, код выхода 1. Проверка статуса
%% идёт и с --no-progress, поэтому ожидание тоже ограничено.
scan_status_lost(Config) ->
    Script = #{total => 1, status => {status_after, 1}, steps => [{sleep, 2400}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {1, _Out, Err} = run_split_env(Driver, scan_args(), fake_env(ScriptFile),
                                   Config),
    must_contain(Err, <<"not available">>),
    true = progress_terminated(Err),
    {1, _Out2, Err2} = run_split_env(Driver, scan_args() ++ ["--no-progress"],
                                     fake_env(ScriptFile), Config),
    must_contain(Err2, <<"not available">>),
    ok.

%% Терминал: прогресс обновляется в одной строке (CR и очистка); заголовок
%% печатается на очищенной строке (не приклеен к прогрессу), обе строки
%% находок целы и содержат IP, порт и состояние, а вывод завершается
%% переводом строки.
scan_tty_line(Config) ->
    Script = #{total => 2, status => ok, steps => [
        {result, open_result(8001)},
        {sleep, 400},
        {result, open_result(8002)},
        {done, summary(2, 2, #{open => 2})}]},
    {Driver, ScriptFile} = fake_driver(Config, Script),
    {0, Raw} = run_pty(Driver, scan_args(), fake_env(ScriptFile), Config),
    must_contain(Raw, <<"\r">>),
    must_contain(Raw, <<"\e[K">>),
    %% Заголовок идёт сразу после очистки строки: \e[KIP.
    must_contain(Raw, <<"\e[KIP">>),
    [Line1] = lines_with(Raw, <<"8001">>),
    must_contain(Line1, <<"127.0.0.1">>),
    must_contain(Line1, <<"open">>),
    [Line2] = lines_with(Raw, <<"8002">>),
    must_contain(Line2, <<"127.0.0.1">>),
    must_contain(Line2, <<"open">>),
    %% Прогресс завершён переводом строки, вывод не обрывается.
    true = binary:last(Raw) =:= $\n,
    ok.

%%% ------------------------------------------------------------------
%%% Запуск реального CLI и локального драйвера
%%% ------------------------------------------------------------------

%% Реальный escript с объединёнными потоками (диагностика + вывод).
run(Args, _Config) ->
    Port = open_port({spawn_executable, executable()},
        [binary, exit_status, use_stdio, stderr_to_stdout, {args, Args}]),
    collect(Port, <<>>, 20000).

%% Реальный escript с раздельными stdout и stderr.
run_split(Args, Config) ->
    run_split_env(executable(), Args, [], Config).

%% Запускает заданный исполняемый файл через shell, раздельно
%% перенаправляя stdout и stderr в уникальные файлы в priv_dir, и
%% возвращает {КодВыхода, Stdout, Stderr}. `Env' — дополнительные
%% переменные окружения для тестового драйвера.
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

%% То же, что run_split_env, но дополнительно возвращает длительность
%% запуска: позволяет отличить завершение по сроку во время потока от
%% завершения после исчерпания всех событий.
run_split_timed(Exe, Args, Env, Config) ->
    Start = erlang:monotonic_time(millisecond),
    Result = run_split_env(Exe, Args, Env, Config),
    {erlang:monotonic_time(millisecond) - Start, Result}.

env_prefix([]) -> "";
env_prefix(Env) ->
    [[Key, $=, shell_quote(Value), $\s] || {Key, Value} <- Env].

%% Читает объединённый вывод по мере поступления и запоминает, когда
%% впервые встретилась искомая строка и когда процесс завершился. Так
%% проверяется, что находка пришла до окончания сканирования.
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

%% Запускает драйвер под псевдотерминалом `script', чтобы stderr стал
%% терминалом; возвращает код выхода и сырой вывод терминала.
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

%% То же, что run_pty, но с длительностью запуска.
run_pty_timed(Exe, Args, Env, Config) ->
    Start = erlang:monotonic_time(millisecond),
    Result = run_pty(Exe, Args, Env, Config),
    {erlang:monotonic_time(millisecond) - Start, Result}.

%%% ------------------------------------------------------------------
%%% Локальный драйвер с тестовым двойником ядра
%%% ------------------------------------------------------------------

%% Собирает драйвер: реальный модуль `trawler_cli' и тестовый модуль
%% `trawler' в одном каталоге кода, плюс минимальное описание приложения.
%% Сценарий событий задаётся файлом, путь к которому передаётся через
%% переменную окружения.
fake_driver(Config, Script) ->
    PrivDir = ?config(priv_dir, Config),
    Unique = integer_to_list(erlang:unique_integer([positive, monotonic])),
    Dir = filename:join(PrivDir, "fake_" ++ Unique),
    Ebin = filename:join(Dir, "ebin"),
    ok = filelib:ensure_dir(filename:join(Ebin, "keep")),
    {ok, _} = file:copy(cli_beam(), filename:join(Ebin, "trawler_cli.beam")),
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
    "%% Тестовый двойник библиотечного ядра: отдаёт заданные события.\n"
    "-module(trawler).\n"
    "-export([start_scan/3, scan/3, status/1, cancel/1]).\n"
    "start_scan(_Targets, _Ports, Options) ->\n"
    "    Script = script(),\n"
    "    Recipient = maps:get(recipient, Options, self()),\n"
    "    Ref = make_ref(),\n"
    "    put({trawler_fake, Ref}, Script),\n"
    "    put({trawler_fake_calls, Ref}, 0),\n"
    "    spawn(fun() -> run(Recipient, Ref, maps:get(steps, Script, [])) end),\n"
    "    {ok, Ref}.\n"
    "scan(_Targets, _Ports, _Options) -> {ok, []}.\n"
    "status(Ref) ->\n"
    "    case get({trawler_fake, Ref}) of\n"
    "        undefined ->\n"
    "            {error, not_found};\n"
    "        Script ->\n"
    "            N = get({trawler_fake_calls, Ref}),\n"
    "            put({trawler_fake_calls, Ref}, N + 1),\n"
    "            case maps:get(status, Script, ok) of\n"
    "                not_found ->\n"
    "                    {error, not_found};\n"
    "                {status_after, Limit} when N >= Limit ->\n"
    "                    {error, not_found};\n"
    "                _ ->\n"
    "                    {ok, #{state => running,\n"
    "                           total => maps:get(total, Script, 0),\n"
    "                           completed => 0,\n"
    "                           counters => zero()}}\n"
    "            end\n"
    "    end.\n"
    "cancel(_Ref) -> ok.\n"
    "script() ->\n"
    "    {ok, [Script]} = file:consult(os:getenv(\"TRAWLER_FAKE_SCRIPT\")),\n"
    "    Script.\n"
    "zero() ->\n"
    "    #{open => 0, closed => 0, timeout => 0, unreachable => 0, error => 0}.\n"
    "run(R, Ref, [{sleep, Ms} | Rest]) ->\n"
    "    timer:sleep(Ms), run(R, Ref, Rest);\n"
    "run(R, Ref, [{result, Value} | Rest]) ->\n"
    "    R ! {trawler, Ref, {result, Value}}, run(R, Ref, Rest);\n"
    "run(R, Ref, [{repeat, Count, Value, Delay} | Rest]) ->\n"
    "    repeat(R, Ref, Count, Value, Delay), run(R, Ref, Rest);\n"
    "run(R, Ref, [{done, S} | _]) ->\n"
    "    R ! {trawler, Ref, {done, S}};\n"
    "run(R, Ref, [{error, Reason, S} | _]) ->\n"
    "    R ! {trawler, Ref, {error, Reason, S}};\n"
    "run(R, Ref, [{cancelled, S} | _]) ->\n"
    "    R ! {trawler, Ref, {cancelled, S}};\n"
    "run(_R, _Ref, []) -> ok.\n"
    "repeat(_R, _Ref, 0, _Value, _Delay) -> ok;\n"
    "repeat(R, Ref, N, Value, Delay) ->\n"
    "    R ! {trawler, Ref, {result, Value}},\n"
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

%% Реальный модуль CLI из сборки escript.
cli_beam() ->
    Default = filename:join([project_root(), "_build", "default", "lib",
                             "trawler", "ebin", "trawler_cli.beam"]),
    case filelib:is_file(Default) of
        true -> Default;
        false -> filename:join([code:lib_dir(trawler), "ebin",
                                "trawler_cli.beam"])
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

open_result(Port) ->
    #{ip => {127, 0, 0, 1}, port => Port, state => open, elapsed_ms => 1}.

timeout_result({A, B, C, D}) ->
    #{ip => {A, B, C, D}, port => 80, state => timeout, elapsed_ms => 100}.

summary(Total, Completed, Partial) ->
    Zero = #{open => 0, closed => 0, timeout => 0, unreachable => 0, error => 0},
    #{total => Total,
      completed => Completed,
      counters => maps:merge(Zero, Partial),
      elapsed_ms => 5}.

%% Аргументы драйвера: сценарий задаёт события, цели и порты формальны.
scan_args() ->
    ["scan", "--targets", "127.0.0.1", "--ports", "80"].

fake_env(ScriptFile) ->
    [{"TRAWLER_FAKE_SCRIPT", ScriptFile}].

%% Строки сырого вывода, содержащие подстроку (для проверки целостности
%% отдельных строк находок под терминалом).
lines_with(Raw, Needle) ->
    [L || L <- binary:split(Raw, <<"\n">>, [global]),
          binary:match(L, Needle) =/= nomatch].

%% Число вхождений подстроки (например, перерисовок строки прогресса).
count_occurrences(Subject, Pattern) ->
    length(binary:matches(Subject, Pattern)).

%% Строка прогресса считается завершённой, если после последнего её
%% вхождения есть перевод строки.
progress_terminated(Err) ->
    case binary:matches(Err, <<"Проверено"/utf8>>) of
        [] ->
            false;
        Matches ->
            {Pos, _Len} = lists:last(Matches),
            Scope = {Pos, byte_size(Err) - Pos},
            binary:match(Err, <<"\n">>, [{scope, Scope}]) =/= nomatch
    end.

progress_lines(Err) ->
    Lines = binary:split(Err, <<"\n">>, [global]),
    length([L || L <- Lines,
                 binary:match(L, <<"Проверено"/utf8>>) =/= nomatch]).

%% Квотирование одного аргумента для POSIX sh одинарными кавычками.
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

must_not_contain(Output, Needle) ->
    case binary:match(Output, Needle) of
        nomatch -> ok;
        _Match -> ct:fail({unexpected_output, Needle, Output})
    end.
