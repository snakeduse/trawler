%%%-------------------------------------------------------------------
%%% @doc Дополнительные проверки найденного IPv4-хоста.
%%%
%%% Модуль проверяет выбранные TCP-порты в общем абсолютном бюджете
%%% адреса и, по запросу, строит приблизительное предположение об ОС по
%%% ограниченным наблюдениям. Публичный контракт состоит из двух
%%% функций: {@link inspect/4} выполняет проверки, {@link classify/1}
%%% остаётся чистой эвристикой для fixture-тестов.
%%%
%%% Сетевые правила:
%%% <ul>
%%%   <li>в каждый момент используется не более одного пассивного
%%%       `gen_tcp'-сокета, соединение закрывается при любом исходе;</li>
%%%   <li>соединение и необязательное чтение баннера делят один
%%%       абсолютный срок попытки, поэтому бюджет адреса не
%%%       продлевается;</li>
%%%   <li>данные не отправляются и логины не выполняются; читается
%%%       только ограниченный корректный SSH identification: завершённая
%%%       печатная строка с непустым softwareversion;</li>
%%%   <li>ошибки сокета отражаются в исходе порта, а не бросаются
%%%       исключением.</li>
%%% </ul>
%%%
%%% Предположение об ОС намеренно приблизительное: открытый SSH или SMB
%%% не доказывает семью, а явные признаки BSD/macOS и конфликты дают
%%% `unknown'. В evidence попадают только собственные безопасные метки,
%%% не произвольные строки удалённого устройства.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_host_inspection).

%% Публичный контракт.
-export([inspect/4, classify/1]).

-export_type([ip4/0, tcp_port/0, port_state/0, port_result/0,
              os_family/0, os_confidence/0, os_map/0, observation/0,
              result/0]).

%% IPv4-адрес в форме кортежа октетов.
-type ip4() :: {0..255, 0..255, 0..255, 0..255}.
%% Номер TCP-порта.
-type tcp_port() :: 1..65535.
%% Исход проверки одного порта.
-type port_state() :: open | closed | timeout | unreachable | error | skipped.
%% Исходы, которые может дать ошибка соединения.
-type connect_state() :: closed | timeout | unreachable | error.
%% Результат проверки явно выбранного порта. `reason' присутствует у
%% `error' и `skipped'.
-type port_result() :: #{port := tcp_port(),
                         state := port_state(),
                         elapsed_ms := non_neg_integer(),
                         reason => term()}.
%% Семья ОС в приблизительной классификации.
-type os_family() :: windows | linux | unknown.
%% Качественная уверенность классификации.
-type os_confidence() :: medium | low | none.
%% Результат классификации: безопасные метки оснований.
-type os_map() :: #{family := os_family(),
                    confidence := os_confidence(),
                    evidence := [binary()]}.
%% Наблюдение одного порта для classify/1. `banner' содержит только
%% ограниченные прочитанные байты и публично не возвращается.
-type observation() :: #{port := tcp_port(), state := atom(), banner => binary()}.
%% Дополнительные поля результата инспектора.
-type result() :: #{port_results => [port_result()],
                    open_ports => [tcp_port()],
                    os => os_map()}.

%% Предел одной попытки соединения вместе с чтением баннера, мс.
-define(MAX_ATTEMPT_MS, 200).
%% Предел прочитанного баннера, байт.
-define(MAX_BANNER_BYTES, 4096).
%% Предел строки SSH identification по RFC 4253, байт.
-define(MAX_IDENTIFICATION_BYTES, 255).
%% Служебные порты, добавляемые при включённой классификации ОС.
-define(OS_PORTS, [22, 135, 139, 445, 3389, 5985, 5986]).
%% Служебные порты — слабый Windows-признак.
-define(WINDOWS_PORTS, [135, 139, 445, 3389, 5985, 5986]).

%%% ------------------------------------------------------------------
%%% inspect
%%% ------------------------------------------------------------------

%% @doc Проверяет выбранные порты и, по запросу, классифицирует ОС.
%%
%% `RequestedPorts' — уже проверенный уникальный список портов либо
%% `undefined'; `os_detection' добавляет служебный набор
%% [22,135,139,445,3389,5985,5986] и чтение SSH identification.
%% `Deadline' — абсолютное монотонное время в миллисекундах; оно может
%% быть в прошлом. Возвращаются только дополнительные поля: при явных
%% портах — `port_results' и `open_ports', при классификации — `os'.
%% Без опций возвращается пустая карта без сетевых операций.
%%
%% В каждый момент открыт не более одного пассивного `gen_tcp'-сокета.
%% Ошибки соединения отражаются в исходе порта; не проверенные из-за
%% исчерпанного бюджета явные порты получают `skipped'.
-spec inspect(ip4(), undefined | [tcp_port()], boolean(), integer()) -> result().
inspect(_IP, undefined, false, _Deadline) ->
    #{};
inspect(IP, RequestedPorts, OSDetection, Deadline) ->
    Requested = case RequestedPorts of
                    undefined -> [];
                    Ports -> Ports
                end,
    Work = work_ports(Requested, OSDetection),
    RequestedSet = maps:from_list([{Port, true} || Port <- Requested]),
    {Rows, Observations} =
        inspect_work(IP, Work, RequestedSet, OSDetection, Deadline,
                     length(Work), [], []),
    Base = port_fields(RequestedPorts, RequestedSet, Rows),
    case OSDetection of
        true -> Base#{os => classify(lists:reverse(Observations))};
        false -> Base
    end.

%% Явно выбранные порты идут первыми и проверяются один раз; служебный
%% набор добавляется только при включённой классификации.
-spec work_ports([tcp_port()], boolean()) -> [tcp_port()].
work_ports(Requested, false) ->
    dedupe(Requested);
work_ports(Requested, true) ->
    dedupe(Requested ++ ?OS_PORTS).

-spec dedupe([tcp_port()]) -> [tcp_port()].
dedupe(Ports) ->
    dedupe(Ports, #{}, []).

-spec dedupe([tcp_port()], map(), [tcp_port()]) -> [tcp_port()].
dedupe([], _Seen, Acc) ->
    lists:reverse(Acc);
dedupe([Port | Rest], Seen, Acc) ->
    case maps:is_key(Port, Seen) of
        true -> dedupe(Rest, Seen, Acc);
        false -> dedupe(Rest, Seen#{Port => true}, [Port | Acc])
    end.

%% Последовательный обход: остаток бюджета делится между текущим и
%% оставшимися портами, но одна попытка не длится дольше 200 мс.
%% `Count' уменьшается вместе со списком, поэтому длина остатка не
%% пересчитывается на каждом шаге.
-spec inspect_work(ip4(), [tcp_port()], map(), boolean(), integer(),
                   non_neg_integer(), [port_result()], [observation()]) ->
          {[port_result()], [observation()]}.
inspect_work(_IP, [], _RequestedSet, _OSDetection, _Deadline, _Count,
             Rows, Observations) ->
    {Rows, Observations};
inspect_work(IP, [Port | Rest], RequestedSet, OSDetection, Deadline, Count,
             Rows, Observations) ->
    Remaining = Deadline - now_ms(),
    case Remaining > 0 of
        false ->
            skip_rest([Port | Rest], RequestedSet, Rows, Observations);
        true ->
            Wait = max(1, min(?MAX_ATTEMPT_MS, Remaining div Count)),
            Now = now_ms(),
            AttemptDeadline = min(Deadline, Now + Wait),
            case AttemptDeadline > Now of
                false ->
                    skip_rest([Port | Rest], RequestedSet, Rows, Observations);
                true ->
                    {Row, Observation} =
                        probe_port(IP, Port, OSDetection,
                                   maps:is_key(Port, RequestedSet),
                                   AttemptDeadline),
                    NewObservations = case Observation of
                                          undefined -> Observations;
                                          _ -> [Observation | Observations]
                                      end,
                    inspect_work(IP, Rest, RequestedSet, OSDetection, Deadline,
                                 Count - 1, [Row | Rows], NewObservations)
            end
    end.

%% Бюджет закончился до начала очередной попытки: явно выбранные
%% оставшиеся порты получают skipped, служебные просто не проверяются.
-spec skip_rest([tcp_port()], map(), [port_result()], [observation()]) ->
          {[port_result()], [observation()]}.
skip_rest(Ports, RequestedSet, Rows, Observations) ->
    Skipped = [skipped_result(Port) || Port <- Ports,
                                       maps:is_key(Port, RequestedSet)],
    {Skipped ++ Rows, Observations}.

%% @doc Проверяет один порт в пределах общей попытки.
%%
%% Соединение пассивное; сокет закрывается в `after' при любом исходе.
%% При включённой классификации читается SSH identification на 22 и
%% явно выбранных открытых портах; остальные служебные порты только
%% подключаются. Данные не отправляются.
-spec probe_port(ip4(), tcp_port(), boolean(), boolean(), integer()) ->
          {port_result(), observation() | undefined}.
probe_port(IP, Port, OSDetection, Explicit, AttemptDeadline) ->
    Start = now_ms(),
    case AttemptDeadline - now_ms() of
        Timeout when Timeout > 0 ->
            case gen_tcp:connect(IP, Port,
                                 [inet, {active, false}, {mode, binary}],
                                 Timeout) of
                {ok, Socket} ->
                    try
                        Banner = case OSDetection andalso
                                      (Port =:= 22 orelse Explicit) of
                                     true ->
                                         read_banner(Socket, AttemptDeadline, <<>>);
                                     false ->
                                         <<>>
                                 end,
                        {#{port => Port, state => open,
                           elapsed_ms => elapsed(Start)},
                         observation(Port, Banner)}
                    after
                        _ = gen_tcp:close(Socket)
                    end;
                {error, Reason} ->
                    {error_result(Port, Reason, Start), undefined}
            end;
        _Expired ->
            {skipped_result(Port), undefined}
    end.

%% Наблюдение для классификатора содержит только ограниченный баннер.
%% Пустые данные не публикуются и не занимают поле карты.
-spec observation(tcp_port(), binary()) ->
          #{port := tcp_port(), state := open}
          | #{port := tcp_port(), state := open,
              banner := <<_:8, _:_*8>>}.
observation(Port, <<>>) ->
    #{port => Port, state => open};
observation(Port, Banner) ->
    #{port => Port, state => open, banner => Banner}.

%% @doc Читает ограниченный SSH identification в пределах попытки.
%%
%% Сокет пассивный, поэтому фрагментация TCP обрабатывается
%% последовательными `recv'. Чтение прекращается на корректной
%% завершённой строке `SSH-2.0-'/`SSH-1.99-', на 4096 байтах, по
%% абсолютному сроку попытки или при закрытии соединения. Произвольные и
%% чрезмерные данные не продлевают ожидание и не попадают в публичный
%% результат.
-spec read_banner(gen_tcp:socket(), integer(), binary()) -> binary().
read_banner(_Socket, _Deadline, Acc) when byte_size(Acc) >= ?MAX_BANNER_BYTES ->
    Acc;
read_banner(Socket, Deadline, Acc) ->
    Remaining = Deadline - now_ms(),
    case Remaining > 0 of
        false ->
            Acc;
        true ->
            case gen_tcp:recv(Socket, 0, Remaining) of
                {ok, Data} ->
                    Allowed = ?MAX_BANNER_BYTES - byte_size(Acc),
                    Chunk = case byte_size(Data) > Allowed of
                                true -> binary:part(Data, 0, Allowed);
                                false -> Data
                            end,
                    Bounded = <<Acc/binary, Chunk/binary>>,
                    case ssh_identification(Bounded) of
                        {ok, _Line} -> Bounded;
                        none -> read_banner(Socket, Deadline, Bounded)
                    end;
                {error, _Reason} ->
                    Acc
            end
    end.

-spec error_result(tcp_port(), atom(), integer()) ->
          #{port := tcp_port(), state := connect_state(),
            elapsed_ms := non_neg_integer(), reason => atom()}.
error_result(Port, Reason, Start) ->
    State = error_state(Reason),
    Base = #{port => Port, state => State, elapsed_ms => elapsed(Start)},
    case State of
        error -> Base#{reason => Reason};
        _ -> Base
    end.

-spec error_state(atom()) -> connect_state().
error_state(econnrefused) -> closed;
error_state(timeout) -> timeout;
error_state(enetunreach) -> unreachable;
error_state(ehostunreach) -> unreachable;
error_state(_Reason) -> error.

-spec skipped_result(tcp_port()) ->
          #{port := tcp_port(), state := skipped, elapsed_ms := 0,
            reason := budget_exhausted}.
skipped_result(Port) ->
    #{port => Port, state => skipped, elapsed_ms => 0,
      reason => budget_exhausted}.

%% `port_results' и `open_ports' публикуются только при явном наборе и
%% содержат только явно выбранные порты, а не добавленные для ОС.
-spec port_fields(undefined | [tcp_port()], map(), [port_result()]) -> result().
port_fields(undefined, _RequestedSet, _Rows) ->
    #{};
port_fields(_Requested, RequestedSet, Rows) ->
    ExplicitRows = [Row || #{port := Port} = Row <- Rows,
                           maps:is_key(Port, RequestedSet)],
    Sorted = lists:sort(fun(A, B) ->
                                maps:get(port, A) =< maps:get(port, B)
                        end, ExplicitRows),
    #{port_results => Sorted,
      open_ports => [Port || #{port := Port, state := open} <- Sorted]}.

-spec now_ms() -> integer().
now_ms() ->
    erlang:monotonic_time(millisecond).

-spec elapsed(integer()) -> non_neg_integer().
elapsed(Start) ->
    max(0, now_ms() - Start).

%%% ------------------------------------------------------------------
%%% classify
%%% ------------------------------------------------------------------

%% @doc Строит приблизительное предположение об ОС по наблюдениям.
%%
%% Учитываются только открытые порты. Явный SSH identification
%% (`SSH-2.0-...' или `SSH-1.99-...') с Windows-признаком даёт
%% `windows/medium', с известным Linux-дистрибутивом — `linux/medium',
%% с BSD/Darwin/macOS — `unknown/none'. Противоречивые явные признаки
%% дают `unknown/none'. Без явного семейного признака открытый 22 —
%% слабый Linux-признак, а 135/139/445/3389/5985/5986 — слабый
%% Windows-признак; одновременные признаки обеих семей дают
%% `unknown/none'. Повреждённые или неполные строки не считаются
%% баннером.
-spec classify([observation()]) -> os_map().
classify(Observations) when is_list(Observations) ->
    Families = lists:usort(
                 lists:append([banner_families(Banner)
                               || #{port := Port, state := open,
                                    banner := Banner} <- Observations,
                                  is_binary(Banner), is_valid_port(Port)])),
    case {lists:member(windows, Families),
          lists:member(linux, Families),
          lists:member(other, Families)} of
        {true, true, _} ->
            conflict(Families);
        {true, false, false} ->
            #{family => windows, confidence => medium,
              evidence => [<<"ssh_banner:windows">>]};
        {false, true, false} ->
            #{family => linux, confidence => medium,
              evidence => [<<"ssh_banner:linux">>]};
        {false, false, true} ->
            #{family => unknown, confidence => none,
              evidence => [<<"ssh_banner:other">>]};
        {false, false, false} ->
            port_classification(Observations);
        {true, false, true} ->
            conflict(Families);
        {false, true, true} ->
            conflict(Families)
    end.

%% Семейные признаки одной строки SSH identification. Неполная строка
%% или строка без префикса SSH-2.0-/SSH-1.99- не даёт признаков.
-spec banner_families(binary()) -> [windows | linux | other].
banner_families(Banner) ->
    case ssh_identification(Banner) of
        {ok, Line} ->
            lists:usort(family_markers(ascii_lower(Line)));
        none ->
            []
    end.

%% Явные семейные маркеры в softwareversion/comment. Generic OpenSSH не
%% содержит ни одного из них и не усиливает предположение.
-spec family_markers(binary()) -> [windows | linux | other].
family_markers(Line) ->
    Markers = [{<<"windows">>, windows},
               {<<"win32-openssh">>, windows},
               {<<"linux">>, linux},
               {<<"ubuntu">>, linux},
               {<<"debian">>, linux},
               {<<"fedora">>, linux},
               {<<"centos">>, linux},
               {<<"rhel">>, linux},
               {<<"redhat">>, linux},
               {<<"red hat">>, linux},
               {<<"alpine">>, linux},
               {<<"suse">>, linux},
               {<<"freebsd">>, other},
               {<<"openbsd">>, other},
               {<<"netbsd">>, other},
               {<<"darwin">>, other},
               {<<"macos">>, other},
               {<<"mac os x">>, other}],
    lists:foldl(fun({Marker, Family}, Acc) ->
                        case binary:match(Line, Marker) of
                            nomatch -> Acc;
                            _ -> [Family | Acc]
                        end
                end, [], Markers).

%% Противоречивые явные признаки: семья не определяется, но основания
%% сохраняются для диагностики.
-spec conflict([windows | linux | other]) ->
          #{family := unknown, confidence := none,
            evidence := [<<_:128, _:_*16>>]}.
conflict(Families) ->
    #{family => unknown, confidence => none,
      evidence => lists:usort([banner_label(Family) || Family <- Families])}.

-spec banner_label(windows | linux | other) -> <<_:128, _:_*16>>.
banner_label(windows) -> <<"ssh_banner:windows">>;
banner_label(linux) -> <<"ssh_banner:linux">>;
banner_label(other) -> <<"ssh_banner:other">>.

%% Слабые признаки по открытым портам. 22 — Linux, служебный набор —
%% Windows; совпадение обеих групп не позволяет выбрать семью.
-spec port_classification([observation()]) -> os_map().
port_classification(Observations) ->
    Open = lists:usort([Port || #{port := Port, state := open} <- Observations,
                                is_valid_port(Port)]),
    Linux = lists:member(22, Open),
    Windows = [Port || Port <- Open, lists:member(Port, ?WINDOWS_PORTS)],
    case {Linux, Windows} of
        {true, []} ->
            #{family => linux, confidence => low,
              evidence => [tcp_open_label(22)]};
        {false, [_ | _]} ->
            #{family => windows, confidence => low,
              evidence => [tcp_open_label(Port) || Port <- Windows]};
        {true, [_ | _]} ->
            #{family => unknown, confidence => none,
              evidence => lists:usort([tcp_open_label(22)
                                       | [tcp_open_label(Port)
                                          || Port <- Windows]])};
        {false, []} ->
            #{family => unknown, confidence => none, evidence => []}
    end.

-spec tcp_open_label(tcp_port()) -> binary().
tcp_open_label(Port) ->
    <<"tcp_open:", (integer_to_binary(Port))/binary>>.

-spec is_valid_port(term()) -> boolean().
is_valid_port(Port) ->
    is_integer(Port) andalso Port >= 1 andalso Port =< 65535.

%% ASCII-понижение регистра: повреждённые байты не должны приводить к
%% исключению функции разбора, поэтому Unicode-преобразование не
%% используется.
-spec ascii_lower(binary()) -> binary().
ascii_lower(Binary) ->
    << <<(lower_byte(Byte))>> || <<Byte>> <= Binary >>.

-spec lower_byte(byte()) -> byte().
lower_byte(Byte) when Byte >= $A, Byte =< $Z -> Byte + 32;
lower_byte(Byte) -> Byte.

%% Первая завершённая строка SSH identification. Предварительные строки
%% допускаются; завершением считается `\n', хвостовой `\r' отбрасывается.
%% Незавершённый хвост не считается баннером: усечённые данные не
%% должны давать семейный признак. Строка проверяется как ограниченная
%% печатная identification с непустым softwareversion; управляющие байты,
%% пустая версия и чрезмерная длина не дают признака.
-spec ssh_identification(binary()) -> {ok, binary()} | none.
ssh_identification(Banner) ->
    case binary:split(Banner, <<"\n">>) of
        [_Incomplete] ->
            none;
        [Line0, Rest] ->
            Line = strip_cr(Line0),
            case valid_ssh_identification(Line) of
                true -> {ok, Line};
                false -> ssh_identification(Rest)
            end
    end.

-spec strip_cr(binary()) -> binary().
strip_cr(Line) ->
    case byte_size(Line) > 0 andalso binary:last(Line) =:= $\r of
        true -> binary:part(Line, 0, byte_size(Line) - 1);
        false -> Line
    end.

%% Допустимая identification: ограниченная длина, протокол 2.0/1.99,
%% непустой печатный softwareversion без пробелов и, если он есть,
%% печатный комментарий. Иначе строка повреждена и пропускается.
-spec valid_ssh_identification(binary()) -> boolean().
valid_ssh_identification(Line) ->
    case byte_size(Line) > 0
         andalso byte_size(Line) =< ?MAX_IDENTIFICATION_BYTES of
        false ->
            false;
        true ->
            case Line of
                <<"SSH-2.0-", Rest/binary>> -> valid_softwareversion(Rest);
                <<"SSH-1.99-", Rest/binary>> -> valid_softwareversion(Rest);
                _Other -> false
            end
    end.

-spec valid_softwareversion(binary()) -> boolean().
valid_softwareversion(Rest) ->
    case binary:match(Rest, <<" ">>) of
        nomatch ->
            printable_softwareversion(Rest);
        {Pos, 1} ->
            Software = binary:part(Rest, 0, Pos),
            Comment = binary:part(Rest, Pos + 1,
                                  byte_size(Rest) - Pos - 1),
            printable_softwareversion(Software) andalso printable_comment(Comment)
    end.

-spec printable_softwareversion(binary()) -> boolean().
printable_softwareversion(<<>>) ->
    false;
printable_softwareversion(Software) ->
    lists:all(fun(Byte) ->
                      Byte >= $! andalso Byte =< $~
              end, binary_to_list(Software)).

-spec printable_comment(binary()) -> boolean().
printable_comment(Comment) ->
    lists:all(fun(Byte) -> Byte >= 16#20 andalso Byte =< 16#7E end,
              binary_to_list(Comment)).
