TITLE:
I wrote a security scanner (secrets/CVEs/misconfig/SBOM) with zero runtime dependencies — some notes on what that costs you

BODY:

Wrote this myself (Yusuf, CS undergrad at SJSU) — flagging that up front per sub rules, this is
self-promotion and I'd rather be transparent about it than not.

DIRA (github.com/Yusuf-Gadelrab/dira) is a security scanner for codebases: hardcoded secrets,
dependency CVEs against OSV.dev, ~38 config/IaC misconfiguration rules, license risk, git-history
leak scanning, and live TLS/header checks against a domain. It's MIT licensed, requires Python
>=3.9, and — the part I actually want feedback on — has zero runtime dependencies. Pure stdlib:
`re`, `urllib`, `json`, `sqlite3`-adjacent caching via plain files, `concurrent.futures` for the
thread pool. No `requests`, no `click`, no `rich`.

Why bother: install friction is a real cost for a security tool specifically, because the people
who most need a fast pre-commit check are the ones least likely to want to manage a virtualenv
with 15 transitive dependencies just to run a linter-adjacent tool. `pipx install` and it just
works, no dependency resolution to go wrong, no supply-chain surface added to a tool whose whole
job is reducing supply-chain surface (feels a little silly to ship `requests` inside a tool that
also flags vulnerable `requests` versions).

What that costs, concretely, since stdlib-only is a real tradeoff not a free lunch:

- HTTP: hand-rolled batching against OSV.dev's API using `urllib.request` instead of `requests` —
  more boilerplate for retries/timeouts, but it's a small, well-defined surface.
- No `click`/`argparse` alternative — just `argparse`, which is fine, but you lose things like
  automatic shell completion generation you'd get from `click` or `typer` for free.
- No `rich` for the terminal report — the box-drawing/coloring is hand-written ANSI, which is more
  code than I'd like to maintain but avoids a dependency that changes its API across majors.
- Packaging: built for PyPI (`dira-scan`) and npm (`npx dira-scan`, a small Node shim that shells
  out to Python) — not published yet, so it's install-from-source or grab the release wheel for
  now.

Performance angle that's more Python-specific: secret detection compiles all 24 provider patterns
into one alternation regex instead of running each pattern separately per file, so it's one read +
one match per file instead of N. There's also an incremental cache keyed on `(size, mtime, ruleset
version)` — 1.56s to 0.05s on a second run over a 117-file repo, though that only covers file
scanning; git-history scanning isn't cached and dominates full runs on repos with deep history.

98 tests pass locally (`pytest`, also stdlib-adjacent — no fixtures-heavy plugin stack). Report
formats: terminal, JSON, SARIF 2.1.0 (for GitHub code scanning), Markdown (for PR comments), plus
CycloneDX 1.5/SPDX 2.3 SBOM output.

Repo: https://github.com/Yusuf-Gadelrab/dira

Genuinely curious whether other people building CLI tools in Python have found the zero-dependency
constraint worth it, or whether I'm just reinventing bad versions of `requests`/`rich`/`click` for
no real user benefit. Also happy to talk through the regex-compilation-into-one-alternation trick
if anyone wants specifics.
