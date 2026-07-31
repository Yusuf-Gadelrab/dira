#!/usr/bin/env bash
# demo/session.sh — the exact, scripted sequence that gets captured by
# demo/record.sh. Not meant to be run by hand except to preview pacing; it
# expects DEMO_DIR (a throwaway fixture built by setup_fixture.sh) and DIRA_BIN
# (the dira command to invoke) to already be set in the environment.
#
# Timing is tuned to land around 60 seconds end-to-end, including the
# typing animation and the pauses that give a viewer time to actually read the
# output — that reading time is most of the budget, on purpose. Scale
# everything with DIRA_DEMO_SPEED (default 1.0; 0.4 for a quick dry run while
# you check the content, 1 for the real recording).
set -euo pipefail

DEMO_DIR="${DEMO_DIR:?set DEMO_DIR to a fixture built by setup_fixture.sh}"
DIRA_BIN="${DIRA_BIN:-dira}"
SPEED="${DIRA_DEMO_SPEED:-1}"

pause() { sleep "$(awk -v s="$1" -v m="$SPEED" 'BEGIN{print s*m}')"; }

# Clears any stray readline state and gives the recording a clean first frame.
clear 2>/dev/null || true

banner() {
  printf '\n\033[2;37m# %s\033[0m\n' "$1"
  pause "${2:-1.2}"
}

# Types text character-by-character at a natural-looking cadence, then a
# prompt-return pause, WITHOUT executing it — used for the closing CTA line,
# where the point is to show the command, not spend recording time running it.
type_only() {
  printf '\033[1;33m$ \033[0m'
  local text="$1" i
  for (( i=0; i<${#text}; i++ )); do
    printf '%s' "${text:$i:1}"
    pause 0.022
  done
  printf '\n'
}

# Same typing animation, then actually runs the command.
type_and_run() {
  printf '\033[1;33m$ \033[0m'
  local text="$1" i
  for (( i=0; i<${#text}; i++ )); do
    printf '%s' "${text:$i:1}"
    pause 0.022
  done
  pause 0.4
  printf '\n'
  eval "$text"
}

cd "$DEMO_DIR"

banner "DIRA -- one command, zero third-party dependencies" 1.8

type_and_run "$DIRA_BIN scan ."
pause 8

banner "safe, additive fixes it can write for you (dry-run by default)" 1.2

type_and_run "$DIRA_BIN fix ."
pause 6.5

banner "same scan, Markdown format -- paste straight into a PR comment" 1.2

type_and_run "$DIRA_BIN scan . --offline --only secrets,config -f markdown"
pause 5.5

banner "install:" 0.6
type_only 'pipx install "git+https://github.com/Yusuf-Gadelrab/dira@v1.2.0"'
pause 1.3
printf '\n\033[2;37m# github.com/Yusuf-Gadelrab/dira  ·  MIT  ·  yusuf-gadelrab.github.io/dira.html\033[0m\n'
pause 4
