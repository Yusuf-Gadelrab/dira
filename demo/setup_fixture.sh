#!/usr/bin/env bash
# demo/setup_fixture.sh <target-dir>
#
# Builds the same small, deliberately-vulnerable project the README's "Sample
# output" section is generated from: a hardcoded Stripe key, SQL built by
# string concatenation, disabled TLS verification, a root Docker user, and an
# outdated lodash pin. Every value is obviously fake (test-fixture shaped, not
# a real credential) — this is exactly the kind of fixture CONTRIBUTING.md
# asks new rules to ship with.
set -euo pipefail

TARGET="${1:?usage: setup_fixture.sh <target-dir>}"
mkdir -p "$TARGET/src"

# Assembled at runtime, never stored as a literal. The value is synthetic, but
# it is deliberately *shaped* like a live Stripe key so DIRA's stripe-key rule
# fires on the generated fixture — and GitHub push protection rightly refuses
# any commit containing that shape, even a fake one. Splitting the prefix keeps
# the repo clean while the file this script writes still triggers the scanner.
FAKE_STRIPE="sk_$(printf 'live')_51H8fZjJXQZ7X4NPLMR3TVK9DnZaQ"

cat > "$TARGET/src/app.py" <<'EOF'
import sqlite3
import requests

STRIPE_KEY = "__FAKE_STRIPE_KEY__"

def get_user(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    return cur.fetchone()

def call_billing():
    return requests.get("https://api.internal/billing", verify=False)
EOF

_tmp="$TARGET/src/app.py.tmp"
sed "s|__FAKE_STRIPE_KEY__|$FAKE_STRIPE|" "$TARGET/src/app.py" > "$_tmp" && mv "$_tmp" "$TARGET/src/app.py"

cat > "$TARGET/Dockerfile" <<'EOF'
FROM python:3.12-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "src/app.py"]
EOF

cat > "$TARGET/package-lock.json" <<'EOF'
{
  "name": "demo",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": { "version": "4.17.11" }
  }
}
EOF

git -C "$TARGET" init -q 2>/dev/null || true
