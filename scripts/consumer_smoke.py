#!/usr/bin/env python3
"""Verify trawler as an OTP dependency from a separate temporary application."""

from pathlib import Path
import subprocess
import tempfile


def main() -> None:
    project = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="trawler-consumer-") as directory:
        consumer = Path(directory)
        (consumer / "src").mkdir()
        (consumer / "_checkouts").mkdir()
        (consumer / "_checkouts" / "trawler").symlink_to(project, target_is_directory=True)
        (consumer / "rebar.config").write_text(
            '{erl_opts, [warnings_as_errors]}.\n{deps, [trawler]}.\n', encoding="utf-8"
        )
        (consumer / "src" / "consumer.app.src").write_text(
            '{application, consumer, [{description, "External consumer smoke test"}, '
            '{vsn, "0.0.0"}, {modules, []}, '
            '{applications, [kernel, stdlib, trawler]}]}.\n', encoding="utf-8"
        )
        (consumer / "src" / "consumer.erl").write_text(
            '-module(consumer).\n-export([verify/0]).\n'
            'verify() ->\n'
            '    {ok, Started} = application:ensure_all_started(consumer),\n'
            '    true = lists:member(trawler, Started),\n'
            '    true = is_pid(whereis(trawler_sup)),\n'
            '    ok = application:stop(consumer),\n'
            '    ok = application:stop(trawler),\n'
            '    undefined = whereis(trawler_sup),\n'
            '    ok.\n', encoding="utf-8"
        )
        subprocess.run(["rebar3", "compile"], cwd=consumer, check=True)
        libraries = [str(path) for base in ("lib", "checkouts")
                     for path in (consumer / "_build" / "default" / base).glob("*/ebin")]
        subprocess.run(
            ["erl", "-noshell", "-pa", *libraries, "-eval", "ok = consumer:verify(), halt()."],
            cwd=consumer, check=True
        )
    print("External OTP consumer: passed")


if __name__ == "__main__":
    main()
