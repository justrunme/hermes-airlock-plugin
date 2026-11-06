# airlock-sandbox

I built this Hermes Agent plugin so my terminal, `execute_code`, and file-tool
commands run through [Airlock](https://github.com/justrunme/airlock) instead of
on my host. Airlock's policy engine decides allow or deny. Allowed code runs in
Airlock's disposable Docker sandbox. Every decision comes back with a signed
receipt I can check (RFC 8785 JCS, SHA-256, Ed25519, `prev_hash` chain), surfaced
as **BLOCKED** / **ALLOWED** / **VERIFIED**.

This is a real loadable plugin (`plugin.yaml` + `register(ctx)`), not a prompt
wrapper or skill. It hooks Hermes through the official terminal environment
provider seam: `ctx.register_terminal_environment_provider(...)`.

## Install

```bash
hermes plugins install /path/to/hermes-airlock-plugin
# or from git after I publish a pin:
# hermes plugins install https://github.com/justrunme/hermes-airlock-plugin
hermes plugins enable airlock-sandbox
hermes config set terminal.backend airlock_sandbox
```

Requires Hermes `>=0.21.6` (terminal environment provider API).

## Configure

Settings live under `plugins.entries.airlock-sandbox.settings` (also editable in
the Desktop Plugins form from `config_schema`):

| Key | Default | Purpose |
|-----|---------|---------|
| `base_url` | `https://45-77-141-253.sslip.io` | Airlock HTTPS API base (public demo) |
| `timeout_s` | `60` | HTTP timeout |
| `verify_receipts` | `true` | Fail closed on bad hash/signature |
| `public_key_hex` | `""` | Pin Ed25519 pubkey; empty fetches `/api/pubkey` |
| `language` | `bash` | Arena language (`bash` or `python`) |
| `api_token` (secret) | unset | Optional `AIRLOCK_API_TOKEN` for a private Airlock |

I read the optional token only through `agent.secret_scope.get_secret("AIRLOCK_API_TOKEN")`.
I never open `.env` or Hermes `auth.json` myself.

## How execution is hooked

1. Hermes loads this plugin and calls `register(ctx)`.
2. I register `AirlockSandboxProvider` with
   `ctx.register_terminal_environment_provider`.
3. When I set `terminal.backend: airlock_sandbox`, Hermes routes `terminal`,
   `execute_code`, and file tools through my `AirlockEnvironment.execute()`.
4. Each command is posted to Airlock `POST /api/arena`. On allow, Airlock runs it
   in its sandbox. On deny, nothing starts there.
5. I verify the receipt (canonical JSON → SHA-256 → Ed25519) and print status
   lines: `BLOCKED`, `ALLOWED`, or `VERIFIED`.
6. Hermes dangerous-command approvals stay on (`skip_container_guards = False`).
   Airlock is an extra fail-closed gate, not a bypass.

## Disclosure (catalog rule 13)

- **Network:** HTTPS calls to the configured Airlock base URL only:
  `GET /healthz`, `GET /api/pubkey`, `POST /api/arena`, `GET /api/receipt/{id}`.
  Default base URL is my public demo at `https://45-77-141-253.sslip.io`.
- **Shell:** This plugin does not spawn a host shell. Commands run only inside
  Airlock when policy allows.
- **Credentials:** Optional `AIRLOCK_API_TOKEN` via Hermes `config_schema` secret /
  `requires`-style secret scope. Listed in `strip_env_keys` so model-authored
  commands cannot read it from subprocess environments.
- **No binaries** shipped. Python deps: `httpx`, `cryptography`, `jcs`.

## Fail-closed behaviour

| Case | Result |
|------|--------|
| Airlock down / bad `/healthz` | `BLOCKED`, non-zero exit, nothing on host |
| Policy deny | `BLOCKED` (+ `VERIFIED` if receipt checks out) |
| Tampered / wrong-key receipt | `BLOCKED` / `INVALID RECEIPT`, output discarded |

## Develop / test

```bash
pip install -e .
pip install 'pytest>=8,<9'
pytest
hermes plugins validate . --install-deps
```

Sample catalog entry (SHA placeholder): `catalog/airlock-sandbox.yaml`.

## License

MIT — see `LICENSE`.
