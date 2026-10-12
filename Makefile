.PHONY: build cli test eunit ct xref dialyzer specs consumer check docs shell hermes

build:
	./scripts/rebar3 compile

cli:
	./scripts/rebar3 escriptize

eunit:
	./scripts/rebar3 eunit

ct: cli
	./scripts/rebar3 ct

test: eunit ct

xref:
	./scripts/rebar3 xref

dialyzer:
	./scripts/rebar3 dialyzer

specs:
	./scripts/openspec validate --all --strict --no-interactive

consumer:
	./scripts/check-consumer

check: build test xref dialyzer specs consumer

docs:
	./scripts/rebar3 edoc

shell:
	./scripts/rebar3 shell

hermes:
	./scripts/hermes chat
