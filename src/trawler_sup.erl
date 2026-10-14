%%%-------------------------------------------------------------------
%%% @doc Корневой supervisor приложения trawler.
%%%
%%% Запускает глобальный планировщик проб, реестры сканирования и
%%% обнаружения и динамические supervisor'ы координаторов. Порядок детей
%%% задаёт порядок запуска: планировщик и реестры доступны до появления
%%% координаторов.
%%% @end
%%%-------------------------------------------------------------------
-module(trawler_sup).
-behaviour(supervisor).

-export([start_link/0, init/1]).

%% @doc Запускает корневой supervisor.
-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% @doc Задаёт стратегию `one_for_one' и постоянных детей.
-spec init([]) -> {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    Flags = #{strategy => one_for_one, intensity => 3, period => 5},
    Children =
        [#{id => trawler_scheduler,
           start => {trawler_scheduler, start_link, []},
           restart => permanent,
           shutdown => 5000,
           type => worker,
           modules => [trawler_scheduler]},
         #{id => trawler_scan_registry,
           start => {trawler_scan_registry, start_link, []},
           restart => permanent,
           shutdown => 5000,
           type => worker,
           modules => [trawler_scan_registry]},
         #{id => trawler_scan_sup,
           start => {trawler_scan_sup, start_link, []},
           restart => permanent,
           shutdown => infinity,
           type => supervisor,
           modules => [trawler_scan_sup]},
         #{id => trawler_discovery_registry,
           start => {trawler_discovery_registry, start_link, []},
           restart => permanent,
           shutdown => 5000,
           type => worker,
           modules => [trawler_discovery_registry]},
         #{id => trawler_discovery_sup,
           start => {trawler_discovery_sup, start_link, []},
           restart => permanent,
           shutdown => infinity,
           type => supervisor,
           modules => [trawler_discovery_sup]}],
    {ok, {Flags, Children}}.
