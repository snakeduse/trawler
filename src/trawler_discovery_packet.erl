%%%-------------------------------------------------------------------
%%% @doc Чистый codec IPv4-, ARP-, ICMP- и TCP-пакетов обнаружения.
%%%
%%% Модуль не создаёт сокетов, процессов и не читает состояние системы:
%%% все функции — чистые преобразования бинарных данных. Он собирает
%%% исходящие пробы и проверяет входящие ответы, чтобы транспортный
%%% уровень ({@link trawler_discovery_probe}) работал только с сокетами.
%%%
%%% Правила проверки ответов намеренно строгие: подтверждением считается
%%% только пакет, совпадающий с адресом и идентификаторами текущей пробы.
%%% ARP принимает единственный Ethernet/IPv4-ответ, ICMP — только echo
%%% или timestamp reply с совпадающими id, sequence и данными, TCP —
%%% только ожидаемый SYN+ACK/RST+ACK или RST с корректным sequence.
%%% Чужие, повреждённые, фрагментированные и усечённые пакеты, а также
%%% ICMP-ошибки (например, `destination unreachable') игнорируются.
%%%
%%% Контрольные суммы считаются по RFC 1071: сумма 16-битных слов в
%%% дополнительном коде с заворачиванием переноса. TCP-сегмент
%%% проверяется вместе с псевдозаголовком IPv4.
%%%
%%% Числа `sockaddr_ll' для Linux сосредоточены в
%%% {@link native_packet_address/3}: `family' = `AF_PACKET' (17),
%%% протокол в сетевом порядке, остальные поля в native-порядке машины.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_packet).

-export([checksum/1,
         arp_request/3,
         arp_reply/4,
         icmp_request/4,
         icmp_reply/6,
         tcp_request/7,
         tcp_reply/8,
         native_packet_address/3]).

-export_type([ip4/0, mac/0, icmp_kind/0, tcp_kind/0]).

%% IPv4-адрес в форме кортежа октетов.
-type ip4() :: {0..255, 0..255, 0..255, 0..255}.
%% MAC-адрес Ethernet: 6 сырых байт.
-type mac() :: <<_:48>>.
%% Вид ICMP-пробы.
-type icmp_kind() :: echo | timestamp.
%% Вид TCP-пробы.
-type tcp_kind() :: syn | ack.

%% Linux ABI: AF_PACKET и ARPHRD_ETHER из linux/socket.h и linux/if_arp.h.
-define(AF_PACKET, 17).
-define(ARPHRD_ETHER, 1).

-define(ETHERTYPE_ARP, 16#0806).
-define(ETHERTYPE_IP, 16#0800).
-define(BROADCAST_MAC, <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF>>).
-define(ZERO_MAC, <<0, 0, 0, 0, 0, 0>>).
%% Минимальный размер Ethernet-кадра без FCS (ETH_ZLEN).
-define(ETH_MIN_FRAME, 60).

-define(ARP_HTYPE_ETHER, 1).
-define(ARP_REQUEST, 1).
-define(ARP_REPLY, 2).

-define(IPPROTO_ICMP, 1).
-define(IPPROTO_TCP, 6).
-define(IPPROTO_MAX, 65535).

-define(ICMP_ECHO_REPLY, 0).
-define(ICMP_ECHO_REQUEST, 8).
-define(ICMP_TIMESTAMP_REQUEST, 13).
-define(ICMP_TIMESTAMP_REPLY, 14).

-define(TCP_SYN, 2).
-define(TCP_RST, 4).
-define(TCP_ACK, 16).
%% Допустимые точные комбинации флагов ответа: SYN+ACK и RST+ACK.
-define(TCP_SYN_ACK, 16#12).
-define(TCP_RST_ACK, 16#14).
-define(TCP_WINDOW, 1024).

%%% ------------------------------------------------------------------
%%% Контрольная сумма
%%% ------------------------------------------------------------------

%% @doc Интернет-контрольная сумма бинарных данных (RFC 1071).
%%
%% Возвращает значение 0..65535, которое помещается в поле контрольной
%% суммы. Нечётный последний байт дополняется нулём справа. Готовый
%% пакет корректен, когда сумма всех его 16-битных слов равна `16#FFFF'.
-spec checksum(binary()) -> 0..65535.
checksum(Bin) when is_binary(Bin) ->
    (bnot ones_complement_sum(Bin)) band 16#FFFF.

ones_complement_sum(Bin) ->
    fold_carry(sum_words(Bin, 0)).

sum_words(<<Word:16, Rest/binary>>, Acc) ->
    sum_words(Rest, Acc + Word);
sum_words(<<Byte:8>>, Acc) ->
    Acc + (Byte bsl 8);
sum_words(<<>>, Acc) ->
    Acc.

fold_carry(Sum) when Sum > 16#FFFF ->
    fold_carry((Sum band 16#FFFF) + (Sum bsr 16));
fold_carry(Sum) ->
    Sum.

%%% ------------------------------------------------------------------
%%% ARP
%%% ------------------------------------------------------------------

%% @doc Собирает Ethernet-кадр ARP-запроса «кто владеет TargetIP».
%%
%% Кадр адресован широковещательному MAC, `sender protocol address' —
%% `SourceIP', `target protocol address' — `TargetIP'. Кадр дополняется
%% нулями до минимального размера Ethernet без FCS (60 байт), поэтому
%% его можно отправлять через `AF_PACKET' как есть.
-spec arp_request(mac(), ip4(), ip4()) -> binary().
arp_request(SourceMac, SourceIP, TargetIP)
  when is_binary(SourceMac), byte_size(SourceMac) =:= 6 ->
    Body = <<?ARP_HTYPE_ETHER:16, ?ETHERTYPE_IP:16, 6:8, 4:8, ?ARP_REQUEST:16,
             SourceMac/binary, (ip_to_bin(SourceIP))/binary,
             ?ZERO_MAC/binary, (ip_to_bin(TargetIP))/binary>>,
    Frame = <<?BROADCAST_MAC/binary, SourceMac/binary, ?ETHERTYPE_ARP:16,
              Body/binary>>,
    pad_frame(Frame).

%% @doc Проверяет Ethernet-кадр ARP-ответа для конкретной пробы.
%%
%% `TargetIP' — адрес, который мы искали: он обязан совпасть с sender
%% protocol address ответа. `SourceIP' и `SourceMac' — наши адрес и MAC:
%% они обязаны совпасть с target protocol address и target hardware
%% address, а `SourceMac' ещё и с адресом назначения кадра. Sender MAC
%% должен совпадать с MAC-источником кадра и быть индивидуальным:
%% нулевой (00:00:00:00:00:00) и групповой (первый бит первого байта)
%% отвергаются. Возвращается подтверждённый MAC отправителя.
-spec arp_reply(binary(), ip4(), ip4(), mac()) -> {ok, mac()} | ignore.
arp_reply(Frame, TargetIP, SourceIP, SourceMac) when is_binary(Frame) ->
    case Frame of
        <<EtherDst:6/binary, EtherSrc:6/binary, ?ETHERTYPE_ARP:16,
          ?ARP_HTYPE_ETHER:16, ?ETHERTYPE_IP:16, 6:8, 4:8, ?ARP_REPLY:16,
          SenderMac:6/binary, SenderIP:4/binary,
          TargetMac:6/binary, TargetIPBin:4/binary, _/binary>> ->
            validate_arp(EtherDst, EtherSrc, SenderMac, SenderIP, TargetMac,
                         TargetIPBin, TargetIP, SourceIP, SourceMac);
        _ ->
            ignore
    end.

validate_arp(EtherDst, EtherSrc, SenderMac, SenderIP, TargetMac, TargetIPBin,
             TargetIP, SourceIP, SourceMac) ->
    Matches = EtherDst =:= SourceMac
        andalso TargetMac =:= SourceMac
        andalso SenderMac =:= EtherSrc
        andalso SenderIP =:= ip_to_bin(TargetIP)
        andalso TargetIPBin =:= ip_to_bin(SourceIP),
    case Matches andalso individual_mac(SenderMac) of
        true -> {ok, SenderMac};
        false -> ignore
    end.

%% Индивидуальный MAC: не нулевой и не групповой (I/G-бит сброшен).
individual_mac(?ZERO_MAC) ->
    false;
individual_mac(<<First:8, _/binary>>) ->
    First band 1 =:= 0.

%%% ------------------------------------------------------------------
%%% ICMP
%%% ------------------------------------------------------------------

%% @doc Собирает ICMP-сообщение пробы без IPv4-заголовка.
%%
%% Для `echo' полезная нагрузка `Payload' — произвольные байты, которые
%% возвращаются в ответе и служат корреляционным маркером. Для
%% `timestamp' `Payload' — четырёхбайтовая метка отправки
%% (бинарной строкой ровно 4 байта или целым 0..4294967295); её же
%% ответ обязан вернуть в поле originate timestamp.
-spec icmp_request(icmp_kind(), 0..65535, 0..65535, binary() | non_neg_integer())
                  -> binary().
icmp_request(echo, Id, Seq, Payload) when is_binary(Payload) ->
    build_icmp(<<?ICMP_ECHO_REQUEST:8, 0:8, 0:16, Id:16, Seq:16, Payload/binary>>);
icmp_request(timestamp, Id, Seq, Payload) ->
    Originate = timestamp_bin(Payload),
    build_icmp(<<?ICMP_TIMESTAMP_REQUEST:8, 0:8, 0:16, Id:16, Seq:16,
                 Originate/binary, 0:32, 0:32>>).

%% @doc Проверяет IPv4-пакет с ICMP-ответом на конкретную пробу.
%%
%% `TargetIP' — адрес назначения пробы (ожидаемый источник ответа),
%% `SourceIP' — наш адрес (ожидаемый получатель). Заголовок IPv4
%% проверяется целиком: версия, IHL, полная длина, отсутствие
%% фрагментации и контрольная сумма. Подтверждаются только echo reply
%% (code 0, совпадают id, sequence и данные) и timestamp reply
%% (code 0, ровно 20 байт: id, sequence, originate/receive/transmit,
%% originate timestamp совпадает с `Payload'). Ответ с ненулевым code
%% или усечённым timestamp-телом не принимается, как и прочие типы,
%% включая ICMP-ошибки маршрутизаторов.
-spec icmp_reply(binary(), ip4(), ip4(), 0..65535, 0..65535,
                 binary() | non_neg_integer()) ->
          {ok, icmp_echo | icmp_timestamp} | ignore.
icmp_reply(Packet, TargetIP, SourceIP, Id, Seq, Payload) ->
    case ipv4_payload(Packet, ?IPPROTO_ICMP, TargetIP, SourceIP) of
        {ok, Icmp} -> validate_icmp(Icmp, Id, Seq, Payload);
        ignore -> ignore
    end.

validate_icmp(Icmp, Id, Seq, Payload) when is_binary(Icmp) ->
    case byte_size(Icmp) >= 8 andalso ones_complement_sum(Icmp) =:= 16#FFFF of
        false -> ignore;
        true -> classify_icmp(Icmp, Id, Seq, Payload)
    end.

classify_icmp(<<?ICMP_ECHO_REPLY:8, 0:8, _Csum:16, ReplyId:16, ReplySeq:16,
                Data/binary>>, Id, Seq, Payload)
  when ReplyId =:= Id, ReplySeq =:= Seq ->
    case Data =:= Payload of
        true -> {ok, icmp_echo};
        false -> ignore
    end;
classify_icmp(<<?ICMP_TIMESTAMP_REPLY:8, 0:8, _Csum:16, ReplyId:16,
                ReplySeq:16, Originate:32, _Receive:32, _Transmit:32>>,
              Id, Seq, Payload)
  when ReplyId =:= Id, ReplySeq =:= Seq ->
    %% Ровно 20 байт: без receive/transmit ответ усечён и не принимается.
    case expected_timestamp(Payload) of
        OriginateBin when OriginateBin =/= undefined ->
            case <<Originate:32>> =:= OriginateBin of
                true -> {ok, icmp_timestamp};
                false -> ignore
            end;
        undefined ->
            ignore
    end;
classify_icmp(_Icmp, _Id, _Seq, _Payload) ->
    ignore.

build_icmp(Plain) ->
    Csum = checksum(Plain),
    <<Head:2/binary, _:16, Tail/binary>> = Plain,
    <<Head/binary, Csum:16, Tail/binary>>.

timestamp_bin(Value) ->
    case expected_timestamp(Value) of
        undefined -> error(badarg);
        Bin -> Bin
    end.

%% Метка времени ICMP: либо целое 0..4294967295, либо ровно 4 байта.
expected_timestamp(Value) when is_integer(Value), Value >= 0,
                               Value =< 4294967295 ->
    <<Value:32>>;
expected_timestamp(Value) when is_binary(Value), byte_size(Value) =:= 4 ->
    Value;
expected_timestamp(_Value) ->
    undefined.

%%% ------------------------------------------------------------------
%%% TCP
%%% ------------------------------------------------------------------

%% @doc Собирает TCP-сегмент пробы без IPv4-заголовка.
%%
%% Возвращается 20-байтовый заголовок без options. Для `syn' выставляется
%% флаг SYN, для `ack' — флаг ACK; sequence и acknowledgement берутся из
%% аргументов. Контрольная сумма считается вместе с IPv4-псевдозаголовком
%% (`SourceIP' и `TargetIP'), поэтому ядро может отправить сегмент через
%% `SOCK_RAW' как есть.
-spec tcp_request(tcp_kind(), ip4(), ip4(), 0..65535, 0..65535,
                  0..4294967295, 0..4294967295) -> binary().
tcp_request(syn, SourceIP, TargetIP, SourcePort, TargetPort, Seq, Ack) ->
    build_tcp(SourceIP, TargetIP, SourcePort, TargetPort, Seq, Ack, ?TCP_SYN);
tcp_request(ack, SourceIP, TargetIP, SourcePort, TargetPort, Seq, Ack) ->
    build_tcp(SourceIP, TargetIP, SourcePort, TargetPort, Seq, Ack, ?TCP_ACK).

%% @doc Проверяет IPv4-пакет с TCP-ответом на конкретную пробу.
%%
%% `TargetIP' и `SourceIP' — адрес пробы и наш адрес, `SourcePort' —
%% локальный порт пробы, `TargetPort' — проверяемый порт. Заголовок IPv4
%% и контрольная сумма TCP (с псевдозаголовком) проверяются полностью.
%% Для пробы `syn' подтверждением считается SYN+ACK или RST+ACK с
%% acknowledgement равным отправленному sequence плюс один; для пробы
%% `ack' — только RST, sequence которого равен отправленному
%% acknowledgement (RFC 793), а не любой RST. Прочие ответы
%% игнорируются.
-spec tcp_reply(binary(), ip4(), ip4(), 0..65535, 0..65535,
                0..4294967295, 0..4294967295, tcp_kind()) ->
          {ok, tcp_syn | tcp_ack} | ignore.
tcp_reply(Packet, TargetIP, SourceIP, SourcePort, TargetPort, Seq, Ack, Kind) ->
    case ipv4_payload(Packet, ?IPPROTO_TCP, TargetIP, SourceIP) of
        {ok, Segment} ->
            Pseudo = tcp_pseudo(TargetIP, SourceIP, Segment),
            validate_tcp(Segment, Pseudo, SourcePort, TargetPort, Seq, Ack, Kind);
        ignore ->
            ignore
    end.

validate_tcp(<<ReplyPort:16, LocalPort:16, _RSeq:32, _RAck:32, DataOffset:4, _:4,
               _Flags:8, _/binary>> = Segment,
             Pseudo, SourcePort, TargetPort, Seq, Ack, Kind)
  when DataOffset >= 5 ->
    HeaderLen = DataOffset * 4,
    case ReplyPort =:= TargetPort andalso LocalPort =:= SourcePort
         andalso HeaderLen =< byte_size(Segment) of
        false ->
            ignore;
        true ->
            match_tcp(Segment, Pseudo, Seq, Ack, Kind)
    end;
validate_tcp(_Segment, _Pseudo, _SourcePort, _TargetPort, _Seq, _Ack, _Kind) ->
    ignore.

match_tcp(Segment, Pseudo, Seq, Ack, Kind) ->
    <<_ReplyPort:16, _LocalPort:16, RSeq:32, RAck:32, _:4, _:4, Flags:8,
      _/binary>> = Segment,
    case ones_complement_sum(<<Pseudo/binary, Segment/binary>>) of
        16#FFFF ->
            case validate_flags(Kind, Flags, RSeq, RAck, Seq, Ack) of
                true -> {ok, tcp_method(Kind)};
                false -> ignore
            end;
        _ ->
            ignore
    end.

tcp_method(syn) -> tcp_syn;
tcp_method(ack) -> tcp_ack.

%% Ответ на SYN-пробу: ровно SYN+ACK либо ровно RST+ACK с acknowledgement
%% равным отправленному sequence плюс один. Ответ на ACK-пробу: ровно
%% RST, sequence которого равен отправленному acknowledgement (RFC 793).
%% Любая лишняя, недостающая или противоречивая комбинация флагов
%% (например, SYN|RST|ACK) отвергается.
validate_flags(syn, ?TCP_SYN_ACK, _RSeq, RAck, Seq, _Ack)
  when RAck =:= (Seq + 1) band 16#FFFFFFFF ->
    true;
validate_flags(syn, ?TCP_RST_ACK, _RSeq, RAck, Seq, _Ack)
  when RAck =:= (Seq + 1) band 16#FFFFFFFF ->
    true;
validate_flags(ack, ?TCP_RST, RSeq, _RAck, _Seq, Ack) ->
    RSeq =:= Ack;
validate_flags(_Kind, _Flags, _RSeq, _RAck, _Seq, _Ack) ->
    false.

build_tcp(SourceIP, TargetIP, SourcePort, TargetPort, Seq, Ack, Flags) ->
    Segment = <<SourcePort:16, TargetPort:16, Seq:32, Ack:32, 5:4, 0:4,
                Flags:8, ?TCP_WINDOW:16, 0:16, 0:16>>,
    Pseudo = tcp_pseudo(SourceIP, TargetIP, Segment),
    Csum = checksum(<<Pseudo/binary, Segment/binary>>),
    <<Head:16/binary, _:16, Tail/binary>> = Segment,
    <<Head/binary, Csum:16, Tail/binary>>.

tcp_pseudo(SourceIP, TargetIP, Segment) ->
    <<(ip_to_bin(SourceIP))/binary, (ip_to_bin(TargetIP))/binary, 0:8,
      ?IPPROTO_TCP:8, (byte_size(Segment)):16>>.

%%% ------------------------------------------------------------------
%%% Привязка AF_PACKET
%%% ------------------------------------------------------------------

%% @doc Строит `socket:sockaddr_native()' для привязки `AF_PACKET'.
%%
%% Linux `struct sockaddr_ll' передаётся OTP без поля `sa_family',
%% поэтому `addr' содержит: протокол кадра (big-endian, например
%% 16#0806 для ARP), ifindex, тип оборудования `ARPHRD_ETHER',
%% pkttype, длину MAC и сам MAC, дополненный нулями до 8 байт.
%% Пустой MAC даёт `halen' = 0 — такое значение используется при
%% привязке «ко всему протоколу интерфейса».
-spec native_packet_address(pos_integer(), 0..65535, binary()) ->
          socket:sockaddr_native().
native_packet_address(Ifindex, Protocol, Mac)
  when is_integer(Ifindex), Ifindex >= 0,
       is_integer(Protocol), Protocol >= 0, Protocol =< ?IPPROTO_MAX,
       is_binary(Mac), byte_size(Mac) =< 8 ->
    #{family => ?AF_PACKET,
      addr => <<Protocol:16/big, Ifindex:32/native, ?ARPHRD_ETHER:16/native,
                0:8, (byte_size(Mac)):8, (pad_mac(Mac))/binary>>}.

%%% ------------------------------------------------------------------
%%% Общие проверки IPv4
%%% ------------------------------------------------------------------

%% Разбор IPv4-заголовка и выделение полезной нагрузки ожидаемого
%% протокола от ожидаемого источника к ожидаемому получателю. Любое
%% расхождение — `ignore', а не исключение.
ipv4_payload(Packet, ExpectedProtocol, ExpectedSrc, ExpectedDst)
  when is_binary(Packet) ->
    case Packet of
        <<4:4, Ihl:4, _Tos:8, TotalLen:16, _Id:16, Flags:3, FragOff:13,
          _Ttl:8, ExpectedProtocol, _Csum:16, Src:32, Dst:32, _/binary>>
          when Ihl >= 5, (Flags band 1) =:= 0, FragOff =:= 0 ->
            validate_ipv4(Packet, Ihl, TotalLen, Src, Dst,
                          ip_to_int(ExpectedSrc), ip_to_int(ExpectedDst));
        _ ->
            ignore
    end.

validate_ipv4(Packet, Ihl, TotalLen, Src, Dst, ExpectedSrc, ExpectedDst) ->
    HeaderLen = Ihl * 4,
    case TotalLen >= HeaderLen andalso TotalLen =< byte_size(Packet) of
        false ->
            ignore;
        true ->
            <<Header:HeaderLen/binary, Rest/binary>> = Packet,
            PayloadLen = TotalLen - HeaderLen,
            <<Payload:PayloadLen/binary, _/binary>> = Rest,
            case {Src, Dst, ones_complement_sum(Header)} of
                {ExpectedSrc, ExpectedDst, 16#FFFF} -> {ok, Payload};
                _ -> ignore
            end
    end.

%%% ------------------------------------------------------------------
%%% Вспомогательные преобразования
%%% ------------------------------------------------------------------

ip_to_bin({A, B, C, D}) ->
    <<A, B, C, D>>.

ip_to_int({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D.

pad_frame(Frame) when byte_size(Frame) >= ?ETH_MIN_FRAME ->
    Frame;
pad_frame(Frame) ->
    Padding = ?ETH_MIN_FRAME - byte_size(Frame),
    <<Frame/binary, (binary:copy(<<0>>, Padding))/binary>>.

pad_mac(Mac) ->
    Padding = 8 - byte_size(Mac),
    <<Mac/binary, (binary:copy(<<0>>, Padding))/binary>>.
