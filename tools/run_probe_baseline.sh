#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROBE="$REPO_DIR/tools/ctaphid_probe.py"
PYTHON="${PYTHON:-python3}"

completed_steps=()

run_step() {
  local name="$1"
  shift

  printf '\n==> %s\n' "$name"
  printf '+'
  printf ' %q' "$@"
  printf '\n'

  if "$@"; then
    completed_steps+=("$name")
    return 0
  fi

  local status=$?
  printf '\nFAILED: %s exited with status %d\n' "$name" "$status" >&2
  printf 'Completed steps before failure:\n' >&2
  if ((${#completed_steps[@]} == 0)); then
    printf '%s\n' '- none' >&2
  else
    printf -- '- %s\n' "${completed_steps[@]}" >&2
  fi
  exit "$status"
}

printf 'ESP32-S3 FIDO lab key baseline probe\n'
printf 'Repo: %s\n' "$REPO_DIR"
printf '\nThis baseline mutates lab state: it creates disposable credentials,\n'
printf 'sets the lab PIN during the PIN smoke probe, and ends with a guarded reset.\n'
printf 'Press BOOT whenever the AMOLED requests user presence or reset confirmation.\n'

run_step "board list" arduino-cli board list
run_step "compile fido-lab" arduino-cli compile --profile fido-lab "$REPO_DIR"
run_step "list FIDO HID devices" "$PYTHON" "$PROBE" --list
run_step "basic CTAPHID and CTAP2 probe" "$PYTHON" "$PROBE"
run_step "CTAP2 register/sign roundtrip" "$PYTHON" "$PROBE" --ctap2-roundtrip
run_step "resident credential roundtrip" "$PYTHON" "$PROBE" --resident-roundtrip
run_step "credential-management smoke" "$PYTHON" "$PROBE" --cred-mgmt-smoke
run_step "silent preflight probe" "$PYTHON" "$PROBE" --preflight-probe
run_step "stateless credential bulk probe" "$PYTHON" "$PROBE" --stateless-bulk 9
run_step "Chrome-like login oracle" "$PYTHON" "$PROBE" --login-verify
run_step "dummy RP getAssertion probe" "$PYTHON" "$PROBE" --dummy-rp-probe
run_step "dummy makeCredential probe" "$PYTHON" "$PROBE" --dummy-makecred-probe
run_step "legacy U2F register probe" "$PYTHON" "$PROBE" --u2f-register
run_step "client PIN smoke" "$PYTHON" "$PROBE" --client-pin-smoke
run_step "guarded cleanup reset" "$PYTHON" "$PROBE" --reset

printf '\nBaseline proof summary:\n'
printf '%s\n' '- compile-ready: arduino-cli compile --profile fido-lab succeeded'
printf '%s\n' '- enumerated: host probe opened the FIDO HID device after --list'
printf '%s\n' '- probe-proven: baseline CTAPHID, CTAP2, PIN, U2F, and browser-compat probes passed'
printf '%s\n' '- cleanup-reset requested: guarded CTAP2 reset completed after BOOT confirmation'
printf '\nBrowser-proven status is separate: run a real browser/WebAuthn.io test manually.\n'
