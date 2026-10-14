%%%-------------------------------------------------------------------
%%% @doc EUnit-тесты модуля trawler_discovery_route.
%%%
%%% Fixture-тесты собирают сообщения netlink NETLINK_ROUTE вручную
%%% (native-endian заголовки, выравнивание атрибутов) и проверяют
%%% разбор шлюза, on-link, локального адреса и интерфейса без сети.
%%% Реальные проверки ограничены loopback: маршрут 127.0.0.1 и
%%% определение исходного адреса через UDP без отправки данных.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_discovery_route_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LO, {127, 0, 0, 1}).
-define(ETH0_IP, {192, 168, 1, 35}).
-define(ETH0_MAC, <<16#00, 16#11, 16#22, 16#33, 16#44, 16#55>>).

%%% ------------------------------------------------------------------
%%% Построители netlink и интерфейсов
%%% ------------------------------------------------------------------

ip_bin({A, B, C, D}) ->
    <<A, B, C, D>>.

nl_message(Seq, Type, Payload) ->
    Len = 16 + byte_size(Payload),
    <<Len:32/native, Type:16/native, 0:16/native, Seq:32/native, 0:32/native,
      Payload/binary>>.

nl_rtm(RtmOpts) ->
    <<(proplists:get_value(family, RtmOpts, 2)):8,
      (proplists:get_value(dst_len, RtmOpts, 32)):8,
      0:8, 0:8,
      (proplists:get_value(table, RtmOpts, 254)):8,
      0:8, 0:8,
      (proplists:get_value(type, RtmOpts, 1)):8,
      (proplists:get_value(flags, RtmOpts, 0)):32/native>>.

nl_attr(Type, Value) ->
    Pad = case byte_size(Value) rem 4 of
              0 -> <<>>;
              Rem -> binary:copy(<<0>>, 4 - Rem)
          end,
    <<(4 + byte_size(Value)):16/native, Type:16/native, Value/binary, Pad/binary>>.

nl_route(Seq, RtmOpts, Attrs) ->
    Payload = iolist_to_binary([nl_rtm(RtmOpts) | [nl_attr(T, V) || {T, V} <- Attrs]]),
    nl_message(Seq, 24, Payload).

nl_error(Seq, Errno) ->
    ErrU = case Errno < 0 of
               true -> Errno + 16#100000000;
               false -> Errno
           end,
    Request = <<36:32/native, 26:16/native, 1:16/native, Seq:32/native, 0:32/native>>,
    nl_message(Seq, 2, <<ErrU:32/native, Request/binary>>).

%% Атрибуты разобранного маршрута.
attrs(Type, Ifindex, Extra) ->
    maps:merge(#{type => Type,
                 table => 254,
                 dst => undefined,
                 source => undefined,
                 gateway => undefined,
                 ifindex => Ifindex},
               maps:from_list(Extra)).

eth_iface() ->
    #{name => "eth0",
      ifindex => 2,
      addresses => [?ETH0_IP],
      ethernet => true,
      mac => ?ETH0_MAC,
      flags => [up, broadcast, running],
      up => true}.

lo_iface() ->
    #{name => "lo",
      ifindex => 1,
      addresses => [?LO],
      ethernet => false,
      flags => [up, loopback, running],
      up => true}.

vpn_iface() ->
    #{name => "amn0",
      ifindex => 28,
      addresses => [{100, 82, 92, 217}],
      ethernet => false,
      flags => [up, pointopoint],
      up => true}.

%% Фикстура вывода net:getifaddrs/0: записи family=packet и family=inet
%% для loopback и Ethernet-интерфейса и inet6-запись без MAC.
getifaddrs_fixture() ->
    [#{name => "lo", flags => [up, loopback, running],
       addr => #{family => packet, protocol => 0, hatype => loopback,
                 ifindex => 1, pkttype => host, addr => <<0, 0, 0, 0, 0, 0>>}},
     #{name => "eth0", flags => [up, broadcast, running],
       addr => #{family => packet, protocol => 0, hatype => ether,
                 ifindex => 2, pkttype => host, addr => ?ETH0_MAC}},
     #{name => "lo", flags => [up, loopback, running],
       addr => #{family => inet, port => 0, addr => ?LO},
       netmask => #{family => inet, port => 0, addr => {255, 0, 0, 0}}},
     #{name => "eth0", flags => [up, broadcast, running],
       addr => #{family => inet, port => 0, addr => ?ETH0_IP},
       netmask => #{family => inet, port => 0, addr => {255, 255, 255, 0}}},
     %% Интерфейс без link-layer адреса (point-to-point/tun): записи
     %% family=packet для него нет, индекс приходит из net:if_names/0.
     #{name => "amn0", flags => [up, pointopoint, running],
       addr => #{family => inet, port => 0, addr => {100, 82, 92, 217}},
       netmask => #{family => inet, port => 0, addr => {255, 255, 255, 255}},
       dstaddr => #{family => inet, port => 0, addr => {100, 82, 92, 217}}},
     #{name => "eth0", flags => [up, broadcast, running],
       addr => #{family => inet6, port => 0, addr => {0, 0, 0, 0, 0, 0, 0, 1},
                 scope_id => 0, flowinfo => 0}}].

%%% ------------------------------------------------------------------
%%% Кодирование запроса RTM_GETROUTE
%%% ------------------------------------------------------------------

encode_getroute_bytes_test() ->
    Request = trawler_discovery_route:encode_getroute(?LO, 1),
    ?assertEqual(36, byte_size(Request)),
    ?assertEqual(<<36:32/native, 26:16/native, 1:16/native, 1:32/native, 0:32/native,
                   2:8, 32:8, 0:8, 0:8, 0:8, 0:8, 0:8, 0:8, 0:32/native,
                   8:16/native, 1:16/native, 127, 0, 0, 1>>,
                 Request).

encode_getroute_seq_and_address_test() ->
    Request = trawler_discovery_route:encode_getroute({10, 20, 30, 40}, 777),
    <<_:8/binary, Seq:32/native, _/binary>> = Request,
    ?assertEqual(777, Seq),
    ?assertEqual(<<10, 20, 30, 40>>, binary:part(Request, 32, 4)).

%%% ------------------------------------------------------------------
%%% Разбор ответа netlink
%%% ------------------------------------------------------------------

decode_unicast_gateway_test() ->
    Message = nl_route(5, [], [{1, ip_bin({8, 8, 8, 8})},
                               {4, <<2:32/native>>},
                               {5, ip_bin({192, 168, 1, 1})},
                               {7, ip_bin(?ETH0_IP)}]),
    ?assertEqual({ok, attrs(1, 2, [{dst, {8, 8, 8, 8}},
                                   {gateway, {192, 168, 1, 1}},
                                   {source, ?ETH0_IP}])},
                 trawler_discovery_route:decode_message(Message, 5)).

decode_local_route_test() ->
    Message = nl_route(9, [{type, 2}], [{1, ip_bin(?LO)},
                                        {4, <<1:32/native>>},
                                        {7, ip_bin(?LO)}]),
    ?assertEqual({ok, attrs(2, 1, [{dst, ?LO}, {source, ?LO}])},
                 trawler_discovery_route:decode_message(Message, 9)).

decode_attributes_order_and_padding_test() ->
    %% OIF идёт раньше DST; присутствует выровненный атрибут RTA_UID
    %% длиной 4 и атрибут RTA_TABLE; порядок не важен.
    Message = nl_route(3, [{type, 1}, {table, 254}],
                       [{25, <<1000:32/native>>},
                        {4, <<2:32/native>>},
                        {15, <<254:32/native>>},
                        {1, ip_bin({10, 1, 2, 3})},
                        {7, ip_bin(?ETH0_IP)}]),
    ?assertEqual({ok, attrs(1, 2, [{dst, {10, 1, 2, 3}}, {source, ?ETH0_IP}])},
                 trawler_discovery_route:decode_message(Message, 3)).

decode_native_endian_ifindex_test() ->
    %% Если бы индекс читался как big-endian, значение было бы 0x0000001C.
    Message = nl_route(1, [], [{4, <<28:32/native>>}]),
    {ok, Decoded} = trawler_discovery_route:decode_message(Message, 1),
    ?assertEqual(28, maps:get(ifindex, Decoded)).

decode_netlink_error_enetunreach_test() ->
    ?assertEqual({error, enetunreach},
                 trawler_discovery_route:decode_message(nl_error(4, -101), 4)).

decode_netlink_error_unknown_test() ->
    ?assertEqual({error, {netlink_error, -1234}},
                 trawler_discovery_route:decode_message(nl_error(4, -1234), 4)).

decode_netlink_error_eopnotsupp_test() ->
    ?assertEqual({error, eopnotsupp},
                 trawler_discovery_route:decode_message(nl_error(4, -95), 4)).

decode_unexpected_ack_test() ->
    ?assertEqual({error, {netlink, unexpected_ack}},
                 trawler_discovery_route:decode_message(nl_error(4, 0), 4)).

decode_wrong_seq_test() ->
    Message = nl_route(7, [], [{4, <<2:32/native>>}]),
    ?assertEqual({error, {netlink, {unexpected_seq, 7}}},
                 trawler_discovery_route:decode_message(Message, 5)).

decode_unexpected_message_type_test() ->
    Message = nl_message(1, 16, <<>>),
    ?assertEqual({error, {netlink, {unexpected_message, 16}}},
                 trawler_discovery_route:decode_message(Message, 1)).

decode_truncated_header_test() ->
    ?assertEqual({error, {netlink, truncated}},
                 trawler_discovery_route:decode_message(<<16, 0, 0, 0>>, 1)).

decode_truncated_body_test() ->
    %% Заголовок обещает 104 байта, приходит меньше.
    Message = <<104:32/native, 24:16/native, 0:16/native, 1:32/native, 0:32/native,
                2:8, 32:8, 0:8, 0:8>>,
    ?assertEqual({error, {netlink, truncated}},
                 trawler_discovery_route:decode_message(Message, 1)).

decode_missing_rtmsg_test() ->
    Message = nl_message(1, 24, <<2:8, 32:8>>),
    ?assertEqual({error, {netlink, truncated}},
                 trawler_discovery_route:decode_message(Message, 1)).

decode_foreign_family_test() ->
    Message = nl_route(1, [{family, 10}], [{4, <<2:32/native>>}]),
    ?assertEqual({error, {netlink, {unexpected_family, 10}}},
                 trawler_discovery_route:decode_message(Message, 1)).

decode_truncated_attribute_test() ->
    %% Атрибут объявляет 8 байт, но в сообщении только 4.
    Rtm = nl_rtm([]),
    Message = nl_message(1, 24, <<Rtm/binary, 8:16/native, 4:16/native, 0>>),
    ?assertEqual({error, {netlink, truncated}},
                 trawler_discovery_route:decode_message(Message, 1)).

%%% ------------------------------------------------------------------
%%% Сборка маршрута из атрибутов и интерфейсов
%%% ------------------------------------------------------------------

route_gateway_test() ->
    Attrs = attrs(1, 2, [{dst, {8, 8, 8, 8}},
                         {gateway, {192, 168, 1, 1}},
                         {source, ?ETH0_IP}]),
    Route = trawler_discovery_route:route_from_attrs(Attrs, [eth_iface()], {8, 8, 8, 8}),
    ?assertEqual(?ETH0_IP, maps:get(source, Route)),
    ?assertEqual(2, maps:get(ifindex, Route)),
    ?assertEqual("eth0", maps:get(interface, Route)),
    ?assertEqual(false, maps:get(local, Route)),
    ?assertEqual(true, maps:get(ethernet, Route)),
    ?assertEqual(false, maps:get(on_link, Route)),
    ?assertEqual({192, 168, 1, 1}, maps:get(gateway, Route)),
    ?assertEqual(?ETH0_MAC, maps:get(mac, Route)).

route_on_link_test() ->
    Attrs = attrs(1, 2, [{dst, {192, 168, 1, 1}}, {source, ?ETH0_IP}]),
    Route = trawler_discovery_route:route_from_attrs(Attrs, [eth_iface()],
                                                     {192, 168, 1, 1}),
    ?assertEqual(true, maps:get(on_link, Route)),
    ?assertEqual(false, maps:is_key(gateway, Route)),
    ?assertEqual(true, maps:get(ethernet, Route)).

route_local_test() ->
    Attrs = attrs(2, 1, [{dst, ?LO}, {source, ?LO}]),
    Route = trawler_discovery_route:route_from_attrs(Attrs, [lo_iface()], ?LO),
    ?assertEqual(true, maps:get(local, Route)),
    ?assertEqual("lo", maps:get(interface, Route)),
    ?assertEqual(false, maps:get(ethernet, Route)),
    ?assertEqual(false, maps:is_key(mac, Route)).

route_local_by_interface_address_test() ->
    %% Ядро вернуло unicast-маршрут на собственный адрес интерфейса.
    Attrs = attrs(1, 2, [{dst, ?ETH0_IP}, {source, ?ETH0_IP}]),
    Route = trawler_discovery_route:route_from_attrs(Attrs, [eth_iface()], ?ETH0_IP),
    ?assertEqual(true, maps:get(local, Route)).

route_vpn_not_ethernet_test() ->
    Attrs = attrs(1, 28, [{dst, {8, 8, 8, 8}}, {source, {100, 82, 92, 217}}]),
    Route = trawler_discovery_route:route_from_attrs(Attrs, [vpn_iface()],
                                                     {8, 8, 8, 8}),
    ?assertEqual("amn0", maps:get(interface, Route)),
    ?assertEqual(false, maps:get(ethernet, Route)),
    ?assertEqual(false, maps:is_key(mac, Route)),
    ?assertEqual(true, maps:get(on_link, Route)).

route_missing_source_resolved_on_loopback_test() ->
    %% Без RTA_PREFSRC источник берётся через UDP connect+sockname.
    Attrs = attrs(2, 1, [{dst, ?LO}]),
    Route = trawler_discovery_route:route_from_attrs(Attrs, [lo_iface()], ?LO),
    ?assertEqual(?LO, maps:get(source, Route)).

route_unknown_interface_test() ->
    Attrs = attrs(1, 99, [{source, ?ETH0_IP}]),
    ?assertEqual({error, {unknown_interface, 99}},
                 trawler_discovery_route:route_from_attrs(Attrs, [eth_iface()],
                                                          {8, 8, 8, 8})).

route_missing_ifindex_test() ->
    Attrs = attrs(1, undefined, [{source, ?ETH0_IP}]),
    ?assertEqual({error, {no_route, {8, 8, 8, 8}}},
                 trawler_discovery_route:route_from_attrs(Attrs, [eth_iface()],
                                                          {8, 8, 8, 8})).

%%% ------------------------------------------------------------------
%%% Интерфейсы
%%% ------------------------------------------------------------------

interfaces_from_fixture_test() ->
    Names = [{1, "lo"}, {2, "eth0"}, {28, "amn0"}],
    ?assertEqual([#{name => "lo", ifindex => 1, addresses => [?LO],
                    ethernet => false, flags => [up, loopback, running], up => true},
                  #{name => "eth0", ifindex => 2, addresses => [?ETH0_IP],
                    ethernet => true, mac => ?ETH0_MAC,
                    flags => [up, broadcast, running], up => true},
                  #{name => "amn0", ifindex => 28,
                    addresses => [{100, 82, 92, 217}], ethernet => false,
                    flags => [up, pointopoint, running], up => true}],
                 trawler_discovery_route:interfaces_from(Names,
                                                          getifaddrs_fixture())).

interfaces_from_ignores_names_without_addresses_test() ->
    %% Имя, известное только по inet6-записи и отсутствующее в if_names,
    %% не даёт индекс и пропускается.
    Extra = [#{name => "weird", flags => [up],
               addr => #{family => inet6, port => 0, addr => {0, 0, 0, 0, 0, 0, 0, 1},
                         scope_id => 0, flowinfo => 0}}],
    ?assertEqual([], trawler_discovery_route:interfaces_from([], Extra)).

interfaces_from_reports_unknown_index_test() ->
    WithExtra = [#{name => "eth9", flags => [up, running],
                   addr => #{family => inet, port => 0, addr => {10, 9, 9, 9}}}],
    ?assertEqual([#{name => "eth9", ifindex => 7, addresses => [{10, 9, 9, 9}],
                    ethernet => false, flags => [up, running], up => true}],
                 trawler_discovery_route:interfaces_from([{7, "eth9"}], WithExtra)).

interfaces_real_loopback_test() ->
    {ok, Interfaces} = trawler_discovery_route:interfaces(),
    ?assert(lists:all(fun(#{ifindex := Index}) -> is_integer(Index) end, Interfaces)),
    Lo = [I || I <- Interfaces, maps:get(ifindex, I) =:= 1],
    ?assertEqual(1, length(Lo)),
    #{name := Name, addresses := Addresses, ethernet := Ethernet} = hd(Lo),
    ?assertEqual("lo", Name),
    ?assert(lists:member(?LO, Addresses)),
    ?assertEqual(false, Ethernet).

%%% ------------------------------------------------------------------
%%% Реальные проверки loopback
%%% ------------------------------------------------------------------

resolve_source_loopback_test() ->
    ?assertEqual({ok, ?LO}, trawler_discovery_route:resolve_source(?LO)).

resolve_source_releases_socket_test() ->
    %% Ни успешный, ни ошибочный путь не оставляют открытых дескрипторов:
    %% сокет закрывается через after.
    Before = erlang:system_info(port_count),
    ?assertEqual({ok, ?LO}, trawler_discovery_route:resolve_source(?LO)),
    ?assertMatch({error, _},
                 trawler_discovery_route:resolve_source({255, 255, 255, 255})),
    lists:foreach(fun(_) ->
                          ?assertEqual({ok, ?LO},
                                       trawler_discovery_route:resolve_source(?LO))
                  end, lists:seq(1, 25)),
    ?assert(erlang:system_info(port_count) =< Before).

lookup_loopback_test() ->
    {ok, Route} = trawler_discovery_route:lookup(?LO),
    ?assertEqual(?LO, maps:get(source, Route)),
    ?assertEqual(1, maps:get(ifindex, Route)),
    ?assertEqual("lo", maps:get(interface, Route)),
    ?assertEqual(true, maps:get(local, Route)),
    ?assertEqual(false, maps:get(ethernet, Route)),
    ?assertEqual(true, maps:get(on_link, Route)),
    ?assertEqual(false, maps:is_key(gateway, Route)).

lookup_invalid_ip_test() ->
    ?assertMatch({error, _}, trawler_discovery_route:lookup({127, 0, 0})).
