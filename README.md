# MCPBytes Vault

[![CI](https://github.com/MCPBytes/mcpbytes-vault/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MCPBytes/mcpbytes-vault/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MCPBytes/mcpbytes-vault)](https://github.com/MCPBytes/mcpbytes-vault/releases/latest)
[![License: AGPL-3.0-only](https://img.shields.io/github/license/MCPBytes/mcpbytes-vault)](LICENSE)

A local MCP server that lets an AI agent create secrets it never sees.

The agent asks for a secret (1–64 random bytes) under a label; the vault generates it from your
operating system's secure random generator, saves it in your OS credential store or a private file,
and returns only a reference. The bytes never enter the conversation, so they never reach chat
logs or transcripts. You read, delete or enroll secrets yourself, from your own terminal.

- **Local-only by default.** The default build has no network code: it uses your OS generator and
  nothing else.
- **Native storage.** Windows Credential Manager, macOS Keychain, Linux Secret Service, or a private
  file with owner-only permissions. A locked or missing store is an error, never a silent fallback.
- **Two MCP tools.** `get_random_bytes` creates a secret and returns a reference; `list_secrets`
  lists labels and versions. There is no tool that returns a secret's value.
- **Owner commands.** `list`, `reveal`, `delete` and `totp-qr` (an authenticator-app QR code) run
  in an interactive terminal only.

## Install

One command, for Windows x64, macOS on Apple silicon and Linux x64:

```sh
curl -fsSL https://github.com/MCPBytes/mcpbytes-vault/releases/latest/download/install.sh | sh
```

```powershell
irm https://github.com/MCPBytes/mcpbytes-vault/releases/latest/download/install.ps1 | iex
```

The script downloads the latest release for your platform, checks it against the release's
`SHA256SUMS.txt`, and runs `mcpbytes-vault install`. That copies the program into your user folder
(`%LOCALAPPDATA%\MCPBytes\Vault`, `~/Library/Application Support/MCPBytes/Vault` or
`~/.local/share/mcpbytes-vault`), creates a private local-only configuration, and prints the commands
that register it with Claude Code, Codex or any MCP client. Running it again updates the program and
keeps your configuration and secrets. It never edits your MCP client's settings itself.

Your OS credential store is the default. For private files instead (for example on a Linux server
without a desktop keyring): `curl ... | sh -s -- --store file`, or in PowerShell
`$env:MCPBYTES_VAULT_STORE = 'file'` before the `irm` line.

The installer never takes over a folder set up by the [mcpbytes.com](https://mcpbytes.com/docs/random-bytes)
installer (the MCPBytes release, with the optional hardware contribution): it stops, changes nothing and
says so. To keep that release, update it with its own installer. To install this build beside it, choose
another folder: `curl ... | sh -s -- --dir <folder>`, or in PowerShell `$env:MCPBYTES_VAULT_DIR = '<folder>'`
before the `irm` line.

The executable is its own installer, so you can also download an archive from the
[releases](https://github.com/MCPBytes/mcpbytes-vault/releases), compare it with `SHA256SUMS.txt`,
and run `mcpbytes-vault install [--store native|file] [--dir <folder>]` (macOS binaries are unsigned: a
browser download is quarantined, so allow it in System Settings → Privacy & Security, or use the
one-line installer, whose download is not). Or build it from source (the
Rust version is pinned in `rust-toolchain.toml`):

```sh
cargo install --git https://github.com/MCPBytes/mcpbytes-vault --locked
mcpbytes-vault install
```

## Configure

`install` writes `config.json` for you. To write it yourself, copy the example for your store from
`examples/`, replace `YOUR_USER`, and create the state directory (and the key directory for
`private_file`). Paths must be absolute.

```json
{
  "state_dir": "/home/YOUR_USER/.local/state/mcpbytes-vault",
  "store": { "backend": "linux_secret_service" },
  "label_prefix": "agent-",
  "mode": "local_only"
}
```

- `store.backend`: `windows_credential_manager`, `macos_keychain`, `linux_secret_service`, or
  `private_file` with a `directory`.
- `label_prefix`: every label the agent uses must start with it (letters, digits, `_` or `-`).
- `mode`: `local_only` (the only mode of the default build).

On Linux and macOS, the state and key directories must be owned by you with mode `0700`, and
`config.json` must not be writable by others. On Windows, keep them in your profile on an NTFS
volume; private files get an owner-only ACL. The owner commands find `config.json` without
`--config` when it is at `%LOCALAPPDATA%\MCPBytes\Vault\config.json` (Windows),
`~/Library/Application Support/MCPBytes/Vault/config.json` (macOS) or
`${XDG_DATA_HOME:-~/.local/share}/mcpbytes-vault/config.json` (Linux).

## Connect your agent

`install` prints these commands with your paths filled in, and saves the JSON entry in
`mcp-server.json` next to the configuration. Register it as a local stdio MCP server: the command is
the binary, the arguments are `--config` and the absolute path to `config.json`. Your client starts
it; it opens no network port.

```sh
claude mcp add --transport stdio --scope user mcpbytes-vault -- /path/to/mcpbytes-vault --config /path/to/config.json
codex mcp add mcpbytes-vault -- /path/to/mcpbytes-vault --config /path/to/config.json
```

In PowerShell, call the client's executable rather than its npm `.ps1` shim, which swallows `--`:
`& (Get-Command claude -CommandType Application | Select-Object -First 1 -ExpandProperty Source) mcp add ...`.
Other clients take the same command and arguments in their JSON settings:

```json
{ "mcpServers": { "mcpbytes-vault": { "command": "/path/to/mcpbytes-vault", "args": ["--config", "/path/to/config.json"] } } }
```

## Using it

`get_random_bytes` takes `label`, `n` (1–64) and `operation_id`. Its description states your label
prefix, storage and mode, so the agent knows them before its first call; errors name the problem
(`label_prefix_mismatch: label must start with "agent-"`).

- Reuse the same `operation_id` after an uncertain reply: a completed operation returns the same
  receipt without generating again. A new `operation_id` creates the next version of the label;
  existing versions are never overwritten.
- The receipt has `reference`, `label`, `version`, `bytes`, `backend`, `entropy_mode`, `format`
  (`raw`: unencoded bytes) and, on Windows, `store_name` (the Credential Manager entry). Hand the
  reference to the application that uses the secret.
- The native entry is service `mcpbytes-vault`, account `label#version`.

## Owner commands

```sh
mcpbytes-vault install [--store native|file] [--dir <folder>]
mcpbytes-vault list [--json]                         # labels, versions, dates; never values
mcpbytes-vault reveal <label> [--version N] [--hex|--base64|--base32]
mcpbytes-vault delete <label> --version N            # asks you to type the label
mcpbytes-vault totp-qr <label> [--issuer NAME] [--account NAME] [--light-terminal]
```

`reveal`, `delete` and `totp-qr` refuse unless they run in an interactive terminal, so an agent's
shell tool cannot use them by accident. `delete` also updates the vault's records, so a retried
operation reports `secret_deleted` instead of a receipt for a secret that is gone; use it rather than
your OS credential tools. For an authenticator seed, have the agent create 20 bytes, then run
`totp-qr` (seeds under 16 bytes are refused, RFC 4226 §4).

## Security model

- The security baseline is your OS random generator and this helper. Output goes through
  HKDF-SHA256 (RFC 5869) with the label, version and operation in the context.
- Normal MCP replies contain references only. A reference is **not** an isolation boundary: another
  program running as the same OS user can read the same store. If an agent has unrestricted shell
  access, run the vault under a separate OS identity or sandbox.
- Owner commands need a terminal; that is a speed bump against accidental use, not a boundary.
- Zeroization is best effort. Unix core dumps and Linux process dumping are disabled; MCP input
  frames are capped at 16 KiB. The code has not had an independent security audit.

## The optional MCPBytes contribution

With `--features remote`, the vault can also mix an encrypted hardware-generated contribution from
the [MCPBytes](https://mcpbytes.com) API into each secret (`mode` `remote_required` or
`remote_preferred`, with a pinned device key; see `sealed-core/` for the HPKE RFC 9180 protocol).
That service is paid and needs an MCPBytes API key. It adds an independent source; it does not
replace your OS generator, and the default build does not include it.

## Development

```sh
cargo test --locked                      # the default, local-only build
cargo test --locked --features remote    # adds the sealed-protocol tests
python tests/stdio_smoke.py target/debug/mcpbytes-vault
cd sealed-core && cargo test --locked --features json   # RFC 9180 test vectors
```

`native_vault_round_trip` (ignored by default) writes, reads and deletes one synthetic entry in your
real credential store: `cargo test --locked native_vault_round_trip -- --ignored --test-threads=1`.

This repository is published from the MCPBytes source tree; issues and pull requests are welcome here.

## License

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`); see `LICENSE`. Release archives list
the licenses of the third-party crates they contain in `THIRD_PARTY.json`.
