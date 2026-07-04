# ntlm-bridge

A thin HTTP Basic/Digest-to-NTLM bridge. Point clients that can only speak
HTTP Basic or HTTP Digest at the bridge, and it forwards the request to an
NTLM-protected upstream service.

**Design goals**

- One static binary with a small config file.
- No session store required for Basic auth. Each request carries credentials
  used for an upstream NTLM handshake.
- Digest support is explicit: because Digest does not reveal the plaintext
  password, Digest users must be configured locally.
- Installs as a Windows service.

---

## Endpoints

### `GET /health`

Returns `ok`. No auth.

### `/*`

Every other route is proxied to `upstream.base_url` with the same method, path,
query string, headers, and body, except hop-by-hop headers and the incoming
`Authorization` header are stripped.

**Basic request**

```http
GET /protected/report?id=123 HTTP/1.1
Host: localhost:3002
Authorization: Basic <base64(DOMAIN\user:password)>
```

The bridge performs an NTLMv2 handshake with the upstream and returns the
upstream response.

**Digest request**

Digest is advertised only when `[auth].users` contains at least one user.
The bridge verifies the Digest response locally, then uses that user's configured
password for upstream NTLM.

---

## Configuration

Copy `config.example.toml` to `config.toml` and edit. Key sections:

- `[server]` bind address, request timeout, body size cap.
- `[upstream]` NTLM-protected base URL, default domain, workstation name.
- `[auth]` Basic/Digest realm and optional Digest users.
- `[log]` level and request logging.

Config is resolved in this order: `--config`, `NTLM_BRIDGE_CONFIG` env var,
`./config.toml`, `config.toml` next to the binary.

---

## Tooling

This project uses [mise](https://mise.jdx.dev/) for Rust toolchain setup and
all common project tasks. After cloning:

```powershell
mise trust
mise run setup
```

`mise.toml` pins Rust `1.95.0` for normal builds and `nightly` for Miri.

Useful tasks:

| Task | Purpose |
|---|---|
| `mise run setup` | Install toolchains and Rust components. |
| `mise run gate` | Run fmt, check, Clippy, and tests. |
| `mise run miri` | Run tests under Miri. |
| `mise run ci` | CI-shaped local run: setup plus gate. |
| `mise run release:build` | Build the release binary. |
| `mise run version:next` | Print the next `YYYY-MM-DD-N` tag. |
| `mise run version:cut` | Create the next annotated release tag. |
| `mise run version:push` | Push tags to `origin`. |
| `mise run release:package` | Build and zip release artifacts into `dist/`. |
| `mise run release:publish` | Publish `dist/` artifacts to GitHub Releases. |

---

## Build

```powershell
mise run release:build
```

The release binary is at `target/release/ntlm-bridge` (`.exe` on Windows).

---

## Checks

```powershell
mise run gate
mise run miri
```

---

## Versioning

Releases use CalVer tags in the form `YYYY-MM-DD-N`, where `N` is the release
number for that date. The binary reports the CalVer tag when built from an
exact release tag or when `NTLM_BRIDGE_VERSION` is set.

```powershell
mise run version:next
mise run version:cut
mise run version:push
```

For a local test build without creating a tag:

```powershell
$env:NTLM_BRIDGE_VERSION = "$(mise run version:next)"
mise run release:build
.\target\release\ntlm-bridge.exe --version
```

---

## Run

```powershell
# Use defaults: listen on 127.0.0.1:3002, proxy to http://localhost:8080
ntlm-bridge

# Override common settings inline
ntlm-bridge --bind 0.0.0.0:3002 --upstream-url http://intranet.local

# Load config.toml; CLI flags still override any field they define
ntlm-bridge --config ./config.toml --log-requests

# Generate a starter config.toml
ntlm-bridge print-config --output config.toml
```

Full help:

```powershell
ntlm-bridge --help
```

---

## Install as a Windows service

Place `ntlm-bridge.exe` and `config.toml` in a stable location, for example
`C:\Program Files\ntlm-bridge\`. From an elevated PowerShell:

```powershell
cd 'C:\Program Files\ntlm-bridge'
.\ntlm-bridge.exe install --config 'C:\Program Files\ntlm-bridge\config.toml'
sc.exe start ntlm-bridge
```

Uninstall:

```powershell
.\ntlm-bridge.exe uninstall
```

---

## Security notes

- Never expose the bridge to the public Internet. It receives credentials and
  forwards them to an upstream service.
- Use TLS on the listen side for anything off-box. This binary is plain HTTP;
  put it behind a TLS terminator if leaving localhost.
- Prefer Basic over Digest when the bridge should not store passwords. Digest
  requires configured plaintext passwords so the bridge can perform NTLM.
- Digest nonces are stateless and time-bounded, but nonce-count replay tracking
  is intentionally not stored.

---

## License

MIT
