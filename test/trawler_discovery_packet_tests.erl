%%%-------------------------------------------------------------------
%%% @doc EUnit-тесты чистого codec-модуля trawler_discovery_packet.
%%%
%%% Тесты используют независимую реализацию контрольной суммы
%%% (`ref_checksum/1') и собственные построители IPv4/TCP/ARP, чтобы
%%% проверка модуля не опиралась на его код. Часть векторов закреплена
%%% абсолютными значениями, вычисленными вне Erlang.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_packet_tests).

-include_lib("eunit/include/eunit.hrl").

%% Наш MAC: индивидуальный (I/G-бит сброшен).
-define(OUR_MAC, <<2, 3, 4, 5, 6, 7>>).
%% Индивидуальный (I/G-бит сброшен) MAC отвечающего узла.
-define(PEER_MAC, <<16#12, 16#34, 16#56, 16#78, 16#9A, 16#BC>>).
-define(OUR_IP, {10, 0, 0, 5}).
-define(TARGET_IP, {10, 0, 0, 9}).

%%% ------------------------------------------------------------------
%%% Построители и независимая контрольная сумма
%%% ------------------------------------------------------------------

%% Независимая (по структуре) реализация интернет-контрольной суммы.
ref_checksum(Bin) when is_binary(Bin) ->
    Sum = lists:sum(ref_words(binary_to_list(Bin))),
    (16#FFFF - ref_fold(Sum)) band 16#FFFF.

ref_words([]) ->
    [];
ref_words([Byte]) ->
    [Byte bsl 8];
ref_words([High, Low | Rest]) ->
    [(High bsl 8) bor Low | ref_words(Rest)].

ref_fold(Sum) when Sum > 16#FFFF ->
    ref_fold((Sum band 16#FFFF) + (Sum bsr 16));
ref_fold(Sum) ->
    Sum.

%% Готовый пакет корректен, если сумма всех 16-битных слов, включая поле
%% контрольной суммы, равна 0xFFFF.
ref_valid(Bin) ->
    16#FFFF =:= ref_fold(lists:sum(ref_words(binary_to_list(Bin)))).

ip_bin({A, B, C, D}) ->
    <<A, B, C, D>>.

%% Сборка IPv4-пакета. Опции позволяют получать повреждённые,
%% фрагментированные, усечённые и нестандартные пакеты.
ipv4(Proto, Src, Dst, Payload) ->
    ipv4(Proto, Src, Dst, Payload, []).

ipv4(Proto, Src, Dst, Payload, Opts) ->
    Ihl = proplists:get_value(ihl, Opts, 5),
    Flags = proplists:get_value(flags, Opts, 0),
    FragOff = proplists:get_value(fragoff, Opts, 0),
    Options = case Ihl >= 5 of
                  true -> binary:copy(<<0>>, (Ihl - 5) * 4);
                  false -> <<>>
              end,
    TotalLen = proplists:get_value(total_len, Opts, Ihl * 4 + byte_size(Payload)),
    Zero = <<4:4, Ihl:4, 0:8, TotalLen:16, 0:16, Flags:3, FragOff:13,
             64:8, Proto:8, 0:16, (ip_bin(Src))/binary, (ip_bin(Dst))/binary,
             Options/binary>>,
    Csum = case proplists:get_value(csum, Opts, good) of
               good -> ref_checksum(Zero);
               zero -> 0;
               bad -> (ref_checksum(Zero) + 1) band 16#FFFF
           end,
    <<4:4, Ihl:4, 0:8, TotalLen:16, 0:16, Flags:3, FragOff:13,
      64:8, Proto:8, Csum:16, (ip_bin(Src))/binary, (ip_bin(Dst))/binary,
      Options/binary, Payload/binary>>.

%% TCP-сегмент с явным полем контрольной суммы.
tcp_segment(SrcPort, DstPort, Seq, Ack, Flags, Csum) ->
    <<SrcPort:16, DstPort:16, Seq:32, Ack:32, 5:4, 0:4, Flags:8,
      1024:16, Csum:16, 0:16>>.

tcp_pseudo(SrcIP, DstIP, Segment) ->
    <<(ip_bin(SrcIP))/binary, (ip_bin(DstIP))/binary, 0:8, 6:8,
      (byte_size(Segment)):16>>.

tcp_checksum(SrcIP, DstIP, Segment) ->
    ref_checksum(<<(tcp_pseudo(SrcIP, DstIP, Segment))/binary, Segment/binary>>).

set_tcp_checksum(Segment, Csum) ->
    <<Head:16/binary, _:16, Tail/binary>> = Segment,
    <<Head/binary, Csum:16, Tail/binary>>.

%% IPv4/TCP-пакет из готового TCP-сегмента с корректной TCP-суммой.
tcp_packet_from_segment(SrcIP, DstIP, Segment0) ->
    Segment = set_tcp_checksum(Segment0, tcp_checksum(SrcIP, DstIP, Segment0)),
    ipv4(6, SrcIP, DstIP, Segment).

tcp_packet(SrcIP, DstIP, SrcPort, DstPort, Seq, Ack, Flags) ->
    tcp_packet(SrcIP, DstIP, SrcPort, DstPort, Seq, Ack, Flags, []).

tcp_packet(SrcIP, DstIP, SrcPort, DstPort, Seq, Ack, Flags, Opts) ->
    Segment0 = tcp_segment(SrcPort, DstPort, Seq, Ack, Flags, 0),
    Good = tcp_checksum(SrcIP, DstIP, Segment0),
    Csum = case proplists:get_value(csum, Opts, good) of
               good -> Good;
               bad -> (Good + 1) band 16#FFFF
           end,
    Segment = set_tcp_checksum(Segment0, Csum),
    ipv4(6, SrcIP, DstIP, Segment, proplists:get_value(ip_opts, Opts, [])).

flags(Name, Extra) ->
    Base = case Name of
               syn -> 16#02;
               rst -> 16#04;
               ack -> 16#10
           end,
    lists:foldl(fun(F, Acc) -> Acc bor flag(F) end, Base, Extra).

flag(syn) -> 16#02;
flag(ack) -> 16#10;
flag(rst) -> 16#04;
flag(fin) -> 16#01.

ip_value(IP) ->
    ip_bin(IP).

%% Кадр ARP в Ethernet (без выравнивания до минимального размера).
arp_frame(SenderIP, TargetIP, TargetMac, SenderMac, Oper, EthSrc) ->
    arp_frame(SenderIP, TargetIP, TargetMac, SenderMac, Oper, EthSrc, 16#0800).

arp_frame(SenderIP, TargetIP, TargetMac, SenderMac, Oper, EthSrc, PType) ->
    <<TargetMac/binary, EthSrc/binary, 16#0806:16,
      1:16, PType:16, 6:8, 4:8, Oper:16,
      SenderMac/binary, (ip_value(SenderIP))/binary,
      TargetMac/binary, (ip_value(TargetIP))/binary>>.

%% ICMP-сообщение с корректной контрольной суммой.
icmp_message(Type, Id, Seq, Body) ->
    Plain = <<Type:8, 0:8, 0:16, Id:16, Seq:16, Body/binary>>,
    <<Type:8, 0:8, (ref_checksum(Plain)):16, Id:16, Seq:16, Body/binary>>.

%% ICMP-сообщение с явным code: позволяет проверять, что ненулевой code
%% не принимается за ответ.
icmp_message_code(Type, Code, Id, Seq, Body) ->
    Plain = <<Type:8, Code:8, 0:16, Id:16, Seq:16, Body/binary>>,
    <<Type:8, Code:8, (ref_checksum(Plain)):16, Id:16, Seq:16, Body/binary>>.

icmp_echo_reply(Id, Seq, Payload) ->
    icmp_message(0, Id, Seq, Payload).

icmp_timestamp_reply(Id, Seq, Originate, Transmit) ->
    icmp_message(14, Id, Seq, <<Originate:32, Transmit:32, 0:32>>).

icmp_packet(SrcIP, DstIP, Icmp) ->
    icmp_packet(SrcIP, DstIP, Icmp, []).

icmp_packet(SrcIP, DstIP, Icmp, Opts) ->
    ipv4(1, SrcIP, DstIP, Icmp, Opts).

%%% ------------------------------------------------------------------
%%% Контрольная сумма
%%% ------------------------------------------------------------------

checksum_rfc_vector_test() ->
    Header = <<16#45, 16#00, 16#00, 16#73, 16#00, 16#00, 16#40, 16#00,
               16#40, 16#11, 16#00, 16#00, 16#C0, 16#A8, 16#00, 16#01,
               16#C0, 16#A8, 16#00, 16#C7>>,
    ?assertEqual(16#B861, trawler_discovery_packet:checksum(Header)).

checksum_icmp_vector_test() ->
    ?assertEqual(16#6667,
                 trawler_discovery_packet:checksum(<<8, 0, 0, 0, 0, 1, 0, 2,
                                                     "abcdefgh">>)).

checksum_odd_length_test() ->
    ?assertEqual(16#F6F9, trawler_discovery_packet:checksum(<<1, 2, 3, 4, 5>>)).

checksum_empty_test() ->
    ?assertEqual(16#FFFF, trawler_discovery_packet:checksum(<<>>)).

checksum_matches_reference_test() ->
    lists:foreach(
      fun(N) ->
          Bin = list_to_binary([(I * 37 + 11) band 255 || I <- lists:seq(0, N - 1)]),
          ?assertEqual(ref_checksum(Bin), trawler_discovery_packet:checksum(Bin))
      end, lists:seq(0, 64)).

checksum_packet_verifies_test() ->
    Packet = ipv4(17, {10, 0, 0, 5}, {10, 0, 0, 9}, <<"payload">>),
    <<Header:20/binary, _/binary>> = Packet,
    ?assert(ref_valid(Header)).

%%% ------------------------------------------------------------------
%%% ARP
%%% ------------------------------------------------------------------

arp_request_test() ->
    Frame = trawler_discovery_packet:arp_request(?OUR_MAC, ?OUR_IP, ?TARGET_IP),
    ?assertEqual(60, byte_size(Frame)),
    <<Dst:6/binary, Src:6/binary, EtherType:16, HType:16, PType:16,
      HLen:8, PLen:8, Oper:16, Sha:6/binary, Spa:4/binary,
      Tha:6/binary, Tpa:4/binary, Padding/binary>> = Frame,
    ?assertEqual(<<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF>>, Dst),
    ?assertEqual(?OUR_MAC, Src),
    ?assertEqual(16#0806, EtherType),
    ?assertEqual(1, HType),
    ?assertEqual(16#0800, PType),
    ?assertEqual(6, HLen),
    ?assertEqual(4, PLen),
    ?assertEqual(1, Oper),
    ?assertEqual(?OUR_MAC, Sha),
    ?assertEqual(ip_bin(?OUR_IP), Spa),
    ?assertEqual(<<0, 0, 0, 0, 0, 0>>, Tha),
    ?assertEqual(ip_bin(?TARGET_IP), Tpa),
    ?assertEqual(18, byte_size(Padding)).

arp_reply_accepts_matching_test() ->
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, ?PEER_MAC),
    ?assertEqual({ok, ?PEER_MAC},
                 trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP, ?OUR_IP,
                                                    ?OUR_MAC)).

arp_reply_accepts_same_mac_test() ->
    %% Один MAC может отвечать за несколько адресов (proxy ARP).
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, ?OUR_MAC),
    ?assertEqual({ok, ?OUR_MAC},
                 trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP, ?OUR_IP,
                                                    ?OUR_MAC)).

arp_reply_rejects_zero_sender_test() ->
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, <<0, 0, 0, 0, 0, 0>>),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_multicast_sender_test() ->
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, <<1, 2, 3, 4, 5, 6>>),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_broadcast_sender_test() ->
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC,
                            <<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF>>),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_other_ether_dst_test() ->
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, <<7, 7, 7, 7, 7, 7>>,
                            ?PEER_MAC),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_mismatched_eth_src_test() ->
    Frame = arp_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, ?PEER_MAC, 2,
                      <<1, 1, 1, 1, 1, 1>>),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_other_sender_ip_test() ->
    Frame = arp_reply_frame({10, 0, 0, 8}, ?OUR_IP, ?OUR_MAC, ?PEER_MAC),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_other_target_ip_test() ->
    Frame = arp_reply_frame(?TARGET_IP, {10, 0, 0, 4}, ?OUR_MAC, ?PEER_MAC),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_request_test() ->
    Frame = arp_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, ?PEER_MAC, 1,
                      ?PEER_MAC),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_foreign_ethertype_test() ->
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, ?PEER_MAC),
    <<Dst:6/binary, Src:6/binary, _:16, Rest/binary>> = Frame,
    Broken = <<Dst/binary, Src/binary, 16#0800:16, Rest/binary>>,
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Broken, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_foreign_protocol_type_test() ->
    Frame = arp_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, ?PEER_MAC, 2,
                      ?PEER_MAC, 16#86DD),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Frame, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_wrong_hardware_length_test() ->
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, ?PEER_MAC),
    <<Pre:18/binary, _HLen:8, Post/binary>> = Frame,
    Broken = <<Pre/binary, 5:8, Post/binary>>,
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Broken, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_rejects_truncated_test() ->
    Frame = arp_reply_frame(?TARGET_IP, ?OUR_IP, ?OUR_MAC, ?PEER_MAC),
    Truncated = binary:part(Frame, 0, 30),
    ?assertEqual(ignore, trawler_discovery_packet:arp_reply(Truncated, ?TARGET_IP,
                                                            ?OUR_IP, ?OUR_MAC)).

arp_reply_frame(SenderIP, TargetIP, TargetMac, SenderMac) ->
    arp_frame(SenderIP, TargetIP, TargetMac, SenderMac, 2, SenderMac).

%%% ------------------------------------------------------------------
%%% ICMP
%%% ------------------------------------------------------------------

icmp_echo_request_test() ->
    Packet = trawler_discovery_packet:icmp_request(echo, 1, 2, <<"abcdefgh">>),
    ?assertEqual(<<8, 0, 16#66, 16#67, 0, 1, 0, 2, "abcdefgh">>, Packet),
    ?assert(ref_valid(Packet)).

icmp_timestamp_request_binary_test() ->
    Packet = trawler_discovery_packet:icmp_request(timestamp, 7, 9, <<0, 0, 1, 44>>),
    ?assertEqual(20, byte_size(Packet)),
    ?assertMatch(<<13, 0, _:16, 0, 7, 0, 9, _/binary>>, Packet),
    ?assertEqual(<<0, 0, 1, 44>>, binary:part(Packet, 8, 4)),
    ?assertEqual(<<0:64>>, binary:part(Packet, 12, 8)),
    ?assert(ref_valid(Packet)).

icmp_timestamp_request_integer_test() ->
    Packet = trawler_discovery_packet:icmp_request(timestamp, 7, 9, 300),
    ?assertEqual(<<0, 0, 1, 44>>, binary:part(Packet, 8, 4)),
    ?assert(ref_valid(Packet)).

icmp_echo_reply_accepts_test() ->
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_echo_reply(1, 2, <<"abcdefgh">>)),
    ?assertEqual({ok, icmp_echo},
                 trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP, ?OUR_IP,
                                                     1, 2, <<"abcdefgh">>)).

icmp_echo_reply_rejects_wrong_id_test() ->
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_echo_reply(2, 2, <<"abcdefgh">>)),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_echo_reply_rejects_wrong_seq_test() ->
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_echo_reply(1, 3, <<"abcdefgh">>)),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_echo_reply_rejects_wrong_payload_test() ->
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_echo_reply(1, 2, <<"abcdefgi">>)),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_echo_reply_rejects_empty_payload_test() ->
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_echo_reply(1, 2, <<>>)),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_echo_reply_rejects_foreign_source_test() ->
    Packet = icmp_packet({10, 0, 0, 8}, ?OUR_IP, icmp_echo_reply(1, 2, <<"abcdefgh">>)),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_echo_reply_rejects_foreign_destination_test() ->
    Packet = icmp_packet(?TARGET_IP, {10, 0, 0, 4},
                         icmp_echo_reply(1, 2, <<"abcdefgh">>)),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_echo_reply_rejects_bad_icmp_checksum_test() ->
    Reply = icmp_echo_reply(1, 2, <<"abcdefgh">>),
    <<Type:8, Code:8, Csum:16, Rest/binary>> = Reply,
    Broken = <<Type, Code, ((Csum + 1) band 16#FFFF):16, Rest/binary>>,
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Broken),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_bad_ipv4_checksum_test() ->
    Reply = icmp_echo_reply(1, 2, <<"abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Reply, [{csum, bad}]),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_unreachable_test() ->
    %% ICMP type 3 (destination unreachable) не подтверждает целевой хост.
    Unreachable = icmp_message(3, 1, 0, <<0:32, "abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Unreachable),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_redirect_test() ->
    Redirect = icmp_message(5, 1, 0, <<"abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Redirect),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_request_test() ->
    %% Собственный запрос, вернувшийся по ошибке, не ответ.
    Request = icmp_message(8, 1, 2, <<"abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Request),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_fragment_test() ->
    Reply = icmp_echo_reply(1, 2, <<"abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Reply, [{flags, 1}, {fragoff, 64}]),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_truncated_packet_test() ->
    Reply = icmp_echo_reply(1, 2, <<"abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Reply),
    Truncated = binary:part(Packet, 0, byte_size(Packet) - 4),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Truncated, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_bad_total_length_test() ->
    Reply = icmp_echo_reply(1, 2, <<"abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Reply,
                         [{total_len, 20 + byte_size(Reply) + 4}]),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_bad_ihl_test() ->
    Reply = icmp_echo_reply(1, 2, <<"abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Reply, [{ihl, 4}]),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_reply_rejects_wrong_protocol_test() ->
    Reply = icmp_echo_reply(1, 2, <<"abcdefgh">>),
    Packet = ipv4(17, ?TARGET_IP, ?OUR_IP, Reply),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_timestamp_reply_accepts_test() ->
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_timestamp_reply(3, 4, 300, 400)),
    ?assertEqual({ok, icmp_timestamp},
                 trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP, ?OUR_IP,
                                                     3, 4, <<0, 0, 1, 44>>)).

icmp_timestamp_reply_rejects_other_originate_test() ->
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_timestamp_reply(3, 4, 301, 400)),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 3, 4,
                                                             <<0, 0, 1, 44>>)).

icmp_timestamp_probe_accepts_echo_reply_with_same_token_test() ->
    %% Вид ICMP-ответа определяется самим пакетом: echo reply с нашим
    %% корреляционным маркером подтверждает пробу как icmp_echo.
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_echo_reply(3, 4, <<0, 0, 1, 44>>)),
    ?assertEqual({ok, icmp_echo},
                 trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP, ?OUR_IP,
                                                     3, 4, <<0, 0, 1, 44>>)).

icmp_timestamp_probe_rejects_echo_reply_with_other_token_test() ->
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, icmp_echo_reply(3, 4, <<"abcdefgh">>)),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 3, 4,
                                                             <<0, 0, 1, 44>>)).

icmp_echo_reply_rejects_nonzero_code_test() ->
    %% echo reply обязан иметь code 0: иной code не подтверждает хост.
    Reply = icmp_message_code(0, 1, 1, 2, <<"abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Reply),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 1, 2,
                                                             <<"abcdefgh">>)).

icmp_timestamp_reply_rejects_nonzero_code_test() ->
    Reply = icmp_message_code(14, 1, 3, 4, <<300:32, 400:32, 0:32>>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Reply),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 3, 4,
                                                             <<0, 0, 1, 44>>)).

icmp_timestamp_reply_rejects_truncated_body_test() ->
    %% timestamp reply без receive и transmit (12 байт вместо 20).
    Reply = icmp_message(14, 3, 4, <<300:32>>),
    ?assertEqual(12, byte_size(Reply)),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Reply),
    ?assertEqual(ignore, trawler_discovery_packet:icmp_reply(Packet, ?TARGET_IP,
                                                             ?OUR_IP, 3, 4,
                                                             <<0, 0, 1, 44>>)).

%%% ------------------------------------------------------------------
%%% TCP
%%% ------------------------------------------------------------------

tcp_syn_request_vector_test() ->
    Segment = trawler_discovery_packet:tcp_request(syn, {10, 0, 0, 5}, {10, 0, 0, 9},
                                                   40000, 443, 1234567, 0),
    ?assertEqual(20, byte_size(Segment)),
    ?assertEqual(<<16#9C40:16, 16#01BB:16, 1234567:32, 0:32, 5:4, 0:4, 16#02:8,
                   1024:16, 16#2340:16, 0:16>>, Segment).

tcp_ack_request_test() ->
    Segment = trawler_discovery_packet:tcp_request(ack, {10, 0, 0, 5}, {10, 0, 0, 9},
                                                   40001, 80, 100, 200),
    ?assertMatch(<<16#9C41:16, 80:16, 100:32, 200:32, 5:4, 0:4, 16#10:8, _/binary>>,
                 Segment),
    Pseudo = tcp_pseudo({10, 0, 0, 5}, {10, 0, 0, 9}, Segment),
    ?assert(ref_valid(<<Pseudo/binary, Segment/binary>>)).

tcp_request_checksum_binds_addresses_test() ->
    Original = trawler_discovery_packet:tcp_request(syn, {10, 0, 0, 5}, {10, 0, 0, 9},
                                                    40000, 443, 1234567, 0),
    Other = trawler_discovery_packet:tcp_request(syn, {10, 0, 0, 6}, {10, 0, 0, 9},
                                                 40000, 443, 1234567, 0),
    ?assertNotEqual(Original, Other),
    ?assertEqual(binary:part(Original, 0, 16), binary:part(Other, 0, 16)).

tcp_synack_accepts_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 9000, 1234568,
                        flags(syn, [ack])),
    ?assertEqual({ok, tcp_syn},
                 trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP, ?OUR_IP,
                                                    40000, 443, 1234567, 0, syn)).

tcp_syn_rst_ack_accepts_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 0, 1234568,
                        flags(rst, [ack])),
    ?assertEqual({ok, tcp_syn},
                 trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP, ?OUR_IP,
                                                    40000, 443, 1234567, 0, syn)).

tcp_syn_rejects_wrong_ack_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 9000, 1234569,
                        flags(syn, [ack])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_syn_rejects_bare_rst_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 0, 0, flags(rst, [])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_syn_rejects_bare_syn_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 0, 0, flags(syn, [])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_syn_rejects_contradictory_flags_test() ->
    %% SYN|RST|ACK противоречив: недопустимая комбинация флагов ответа.
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 0, 1234568,
                        flags(syn, [rst, ack])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_syn_rejects_syn_ack_extra_fin_test() ->
    %% Лишний флаг FIN к SYN+ACK делает ответ недействительным.
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 9000, 1234568,
                        flags(syn, [ack, fin])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_ack_rst_accepts_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 80, 40001, 555, 0, flags(rst, [])),
    ?assertEqual({ok, tcp_ack},
                 trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP, ?OUR_IP,
                                                    40001, 80, 100, 555, ack)).

tcp_ack_rejects_other_rst_seq_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 80, 40001, 556, 0, flags(rst, [])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40001, 80,
                                                            100, 555, ack)).

tcp_ack_rejects_rst_syn_test() ->
    %% RST|SYN для ACK-пробы недействителен: принимается только чистый RST.
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 80, 40001, 555, 0, flags(rst, [syn])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40001, 80,
                                                            100, 555, ack)).

tcp_ack_rejects_rst_ack_test() ->
    %% RST с выставленным ACK не является ответом на ACK-пробу.
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 80, 40001, 555, 0, flags(rst, [ack])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40001, 80,
                                                            100, 555, ack)).

tcp_ack_rejects_synack_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 80, 40001, 555, 101, flags(syn, [ack])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40001, 80,
                                                            100, 555, ack)).

tcp_ack_rejects_syn_request_reply_test() ->
    %% SYN 443 не подтверждает ACK-пробу 80.
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 9000, 1234568,
                        flags(syn, [ack])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40001, 80,
                                                            100, 555, ack)).

tcp_reply_rejects_wrong_ports_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 444, 40000, 9000, 1234568,
                        flags(syn, [ack])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_reply_rejects_foreign_source_test() ->
    Packet = tcp_packet({10, 0, 0, 8}, ?OUR_IP, 443, 40000, 9000, 1234568,
                        flags(syn, [ack])),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_reply_rejects_bad_checksum_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 9000, 1234568,
                        flags(syn, [ack]), [{csum, bad}]),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_reply_rejects_bad_ipv4_checksum_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 9000, 1234568,
                        flags(syn, [ack]), [{ip_opts, [{csum, bad}]}]),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_reply_rejects_small_data_offset_test() ->
    Segment = tcp_segment(443, 40000, 9000, 1234568, flags(syn, [ack]), 0),
    <<Head:12/binary, _Doff:4, Rest/bits>> = Segment,
    Broken = <<Head/binary, 4:4, Rest/bits>>,
    Packet = tcp_packet_from_segment(?TARGET_IP, ?OUR_IP, Broken),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_reply_rejects_truncated_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 9000, 1234568,
                        flags(syn, [ack])),
    Truncated = binary:part(Packet, 0, 30),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Truncated, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_reply_rejects_fragment_test() ->
    Packet = tcp_packet(?TARGET_IP, ?OUR_IP, 443, 40000, 9000, 1234568,
                        flags(syn, [ack]), [{ip_opts, [{fragoff, 8}]}]),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

tcp_reply_rejects_icmp_unreachable_test() ->
    Unreachable = icmp_message(3, 1, 0, <<0:32, "abcdefgh">>),
    Packet = icmp_packet(?TARGET_IP, ?OUR_IP, Unreachable),
    ?assertEqual(ignore, trawler_discovery_packet:tcp_reply(Packet, ?TARGET_IP,
                                                            ?OUR_IP, 40000, 443,
                                                            1234567, 0, syn)).

%%% ------------------------------------------------------------------
%%% Привязка AF_PACKET
%%% ------------------------------------------------------------------

native_packet_address_matches_verified_bind_test() ->
    %% Значение подтверждено реальной привязкой AF_PACKET в этом окружении.
    ?assertEqual(#{family => 17,
                   addr => <<16#0806:16/big, 2:32/native, 1:16/native,
                             0:8, 0:8, 0:64>>},
                 trawler_discovery_packet:native_packet_address(2, 16#0806, <<>>)).

native_packet_address_with_mac_test() ->
    Mac = <<16#9A, 16#B2, 16#3C, 16#6F, 16#78, 16#DA>>,
    SockAddr = trawler_discovery_packet:native_packet_address(2, 16#0806, Mac),
    ?assertEqual(17, maps:get(family, SockAddr)),
    Addr = maps:get(addr, SockAddr),
    ?assertEqual(18, byte_size(Addr)),
    ?assertEqual(<<16#0806:16/big, 2:32/native, 1:16/native, 0:8, 6:8,
                   Mac/binary, 0:16>>, Addr).

native_packet_address_other_protocol_test() ->
    SockAddr = trawler_discovery_packet:native_packet_address(1, 16#0800, <<>>),
    Addr = maps:get(addr, SockAddr),
    ?assertEqual(<<16#0800:16/big, 1:32/native, 1:16/native, 0:8, 0:8, 0:64>>,
                 Addr).
