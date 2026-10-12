#!/usr/bin/env bash
# Source with "otp" for Erlang only, or "all" for Erlang and Node/OpenSpec.

trawler_source_runtime() {
    # Kerl/NVM activation scripts are not compatible with nounset.
    local restore_nounset=false
    [[ $- == *u* ]] && restore_nounset=true
    set +u
    source "$1"
    local status=$?
    if [[ "${restore_nounset}" == true ]]; then
        set -u
    fi
    return "${status}"
}

trawler_env() {
    local mode="${1:-all}"
    TRAWLER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
    export TRAWLER_ROOT
    local otp_root="${TRAWLER_OTP_ROOT:-${HOME}/erlang/27.3.4.18}"
    if [[ -r "${otp_root}/activate" ]]; then
        # Kerl activation changes only this shell's environment.
        trawler_source_runtime "${otp_root}/activate" || return 1
    fi
    if ! command -v erl >/dev/null || ! command -v rebar3 >/dev/null; then
        echo "Erlang/OTP 27 and rebar3 3.27.3 are required. Set TRAWLER_OTP_ROOT to your Kerl installation." >&2
        return 1
    fi
    local otp_release
    otp_release="$(erl -noshell -eval 'io:put_chars(erlang:system_info(otp_release)), halt().')" || return 1
    if [[ "${otp_release}" != "27" ]]; then
        echo "Expected Erlang/OTP 27; found ${otp_release}." >&2
        return 1
    fi
    if [[ "${mode}" == "otp" ]]; then
        return 0
    fi
    if ! command -v node >/dev/null || [[ "$(node --version)" != "v24.15.0" ]]; then
        local nvm_script="${NVM_DIR:-${HOME}/.nvm}/nvm.sh"
        if [[ ! -r "${nvm_script}" ]]; then
            echo "Node.js 24.15.0 is required. Install it or make NVM available." >&2
            return 1
        fi
        trawler_source_runtime "${nvm_script}" || return 1
        nvm use --silent 24.15.0 || return 1
    fi
}

trawler_env "${1:-all}"
