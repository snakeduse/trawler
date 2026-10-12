#!/usr/bin/env python3
"""Launch the installed Hermes with project config and an isolated state directory."""

import os
from pathlib import Path
import shlex
import shutil
import sys


def deepseek_key(path: Path) -> str:
    """Read only the DeepSeek credential; never execute or export a whole env file."""
    if not path.is_file():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        assignment = line.strip().removeprefix("export ")
        name, separator, value = assignment.partition("=")
        if separator and name.strip() == "DEEPSEEK_API_KEY":
            words = shlex.split(value, comments=True)
            return words[0] if len(words) == 1 else ""
    return ""


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    runtime = root / ".hermes" / "runtime"
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime.chmod(0o700)
    # PM-managed Hermes installs share their dependency/tool trees across profiles.
    # An arbitrary HERMES_HOME needs these links to find its installed environment.
    # Configuration, sessions and memories remain in the project runtime directory.
    install_home = Path(os.environ.get("TRAWLER_HERMES_INSTALL_HOME", Path.home() / ".hermes"))
    for directory in ("installs", "tools"):
        shared = install_home / directory
        link = runtime / directory
        if shared.is_dir() and not link.exists() and not link.is_symlink():
            link.symlink_to(shared, target_is_directory=True)
    # Hermes doctor expects an env-file marker even when the key is inherited.
    env_file = runtime / ".env"
    if not env_file.exists():
        with env_file.open("x") as output:
            env_file.chmod(0o600)
            output.write("# Optional DEEPSEEK_API_KEY override; launcher also reads process/user credentials.\n")
    configuration = (root / ".hermes" / "config.yaml").read_bytes()
    destination = runtime / "config.yaml"
    if not destination.exists() or destination.read_bytes() != configuration:
        temporary = runtime / f".config-{os.getpid()}.yaml"
        with temporary.open("xb") as output:
            os.chmod(temporary, 0o600)
            output.write(configuration)
        temporary.replace(destination)

    environment = os.environ.copy()
    if not environment.get("DEEPSEEK_API_KEY"):
        for source in (runtime / ".env", Path.home() / ".hermes" / ".env"):
            key = deepseek_key(source)
            if key:
                environment["DEEPSEEK_API_KEY"] = key
                break
    environment["TRAWLER_ROOT"] = str(root)
    environment["HERMES_HOME"] = str(runtime)
    # Only the project profile's configuration and DeepSeek route are selected.
    environment.pop("HERMES_PROFILE", None)
    environment.pop("HERMES_INFERENCE_MODEL", None)
    executable = shutil.which("hermes")
    if executable is None:
        sys.exit("Hermes is not installed or not available in PATH.")
    arguments = sys.argv[1:] or ["chat"]
    os.execve(executable, [executable, *arguments], environment)


if __name__ == "__main__":
    main()
