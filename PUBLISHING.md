# Publishing DIRA

The GitHub repo, tag, and release are live. The registries are the only step left, and both
require a browser login that cannot be automated from this machine.

## PyPI — token-free, ~2 minutes

`.github/workflows/publish.yml` uses **Trusted Publishing** (OIDC), so no API token is ever
stored in the repo.

1. Log in at <https://pypi.org/manage/account/publishing/>
2. Add a **pending publisher**:
   - PyPI project name: `dira-scan`
   - Owner: `Yusuf-Gadelrab`
   - Repository: `dira`
   - Workflow name: `publish.yml`
   - Environment name: `release`
3. In the GitHub repo → Settings → Environments → **New environment** → name it `release`.
4. Push a tag and it publishes itself:

   ```bash
   cd ~/Startups/dira
   git tag v1.1.1 && git push origin v1.1.1
   ```

   Or run the workflow manually: Actions → publish → Run workflow.

### Fallback — publish from this machine instead

```bash
# create a token at https://pypi.org/manage/account/token/ (scope: entire account for the
# first upload, then narrow it to the dira-scan project)
cd ~/Startups/dira
uv build
UV_PUBLISH_TOKEN=pypi-xxxxx uv publish
```

## npm — ~3 minutes

The npm package is a thin launcher that shells out to the Python CLI, so publish it **after**
PyPI so `npx dira-scan` resolves on a clean machine.

```bash
npm login                 # opens a browser
cd ~/Startups/dira/npm
npm publish --access public
```

To let CI do it instead: create an **Automation** token at
<https://www.npmjs.com/settings/~/tokens>, add it as the repo secret `NPM_TOKEN`, and set the
repo variable `PUBLISH_NPM` to `true`.

## After both are live

Revert the install docs to the registry commands — they were switched to source installs so the
README would not promise something that 404s:

- `README.md` — Install section and the "Registry status" note
- `action.yml` — `pip install --quiet "dira-scan==1.1.0"`
- `dira/cli.py` — the `WORKFLOW` template's install line
- `~/Yusuf-Gadelrab.github.io/public/dira.html` — install step and the cost FAQ answer

Then bump the version in `pyproject.toml`, `npm/package.json`, `npm/bin/dira.js` (`PKG`), and
`dira/__init__.py`, and tag again.
