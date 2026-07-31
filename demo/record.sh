#!/usr/bin/env bash
# demo/record.sh — records a ~60-second terminal demo of DIRA to an asciinema
# .cast file. Headless: this captures raw terminal I/O through a pty, the same
# way `script` does. It never opens a Terminal/iTerm window, a browser, or any
# GUI — safe to run from a background shell.
#
# Usage:
#   cd ~/Startups/dira
#   uv sync --extra dev              # only needed once, so `dira` resolves
#   demo/record.sh                   # writes demo/dira-demo.cast
#   DIRA_DEMO_SPEED=0.35 demo/record.sh   # fast dry run to check content/timing
#   asciinema play demo/dira-demo.cast    # preview locally, in-terminal
#
# What this does NOT do, on purpose:
#   - does not upload anywhere (`asciinema upload` is a publish action)
#   - does not touch the live site or any launch post
#   - does not install DIRA globally; it runs the in-repo checkout
#
# Publishing the recording (asciinema.org upload, embedding the .cast or a
# converted GIF on yusuf-gadelrab.github.io/dira.html, or in any launch post)
# is gated exactly like every other "post it publicly" action in
# LAUNCH-PLAYBOOK.md — stage it, don't publish it, until the hold lifts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
OUT="${1:-$HERE/dira-demo.cast}"

if ! command -v asciinema >/dev/null 2>&1; then
  echo "asciinema not found. Install it (free, MIT-licensed, one-time):" >&2
  echo "  brew install asciinema" >&2
  exit 1
fi

# Run the in-repo checkout, not a globally installed dira, so the recording
# always reflects the code sitting in this working tree.
DIRA_BIN="python3 -m dira"
if command -v uv >/dev/null 2>&1; then
  DIRA_BIN="uv run --project $REPO_ROOT python -m dira"
fi

DEMO_DIR="$(mktemp -d -t dira-demo)"
trap 'rm -rf "$DEMO_DIR"' EXIT

bash "$HERE/setup_fixture.sh" "$DEMO_DIR"

echo "Recording to $OUT ..."
DEMO_DIR="$DEMO_DIR" DIRA_BIN="$DIRA_BIN" DIRA_DEMO_SPEED="${DIRA_DEMO_SPEED:-1}" \
  asciinema rec "$OUT" \
    --overwrite \
    --title "DIRA -- one command, zero dependencies" \
    --idle-time-limit 2 \
    --command "bash '$HERE/session.sh'"

echo
echo "Done. Play it back locally:"
echo "  asciinema play $OUT"
echo
echo "To turn it into a GIF for the README/landing page later (local render, no upload):"
echo "  brew install agg && agg $OUT demo/dira-demo.gif"
echo
echo "Do not run 'asciinema upload' or embed this anywhere public until the hold in"
echo "CLAUDE.md / LAUNCH-PLAYBOOK.md lifts."
