//! Owner commands. `install` and `list` run anywhere; `reveal`, `delete` and `totp-qr` run only in an
//! interactive terminal so an agent's shell tool (piped output) cannot use them by accident.
//! That is a speed bump, not a boundary: another program running as the same user can read the store.
use mcpbytes_random_bytes::{
    app::Vault,
    config::{self, Config},
    install,
};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use zeroize::Zeroizing;

pub const USAGE: &str = "Usage:
  mcpbytes-vault install [--store native|file] [--dir <folder>]
      Install this executable for your user: a local-only configuration (created once, then kept)
      and the settings for your MCP client.
  mcpbytes-vault --config <config.json>
      Run the MCP server (your MCP client starts this).
  mcpbytes-vault list [--json] [--config <path>]
      Labels, versions and dates of your secrets. Never shows values.
  mcpbytes-vault reveal <label> [--version N] [--hex | --base64 | --base32] [--config <path>]
      Print a secret (default: the newest saved version, as hex).
  mcpbytes-vault delete <label> --version N [--config <path>]
      Delete one version permanently, after you type the label to confirm.
  mcpbytes-vault totp-qr <label> [--version N] [--issuer NAME] [--account NAME] [--light-terminal] [--config <path>]
      Show an authenticator-app QR code for a TOTP seed (create it with n = 20).

reveal, delete and totp-qr work only in an interactive terminal. Without --config, the
installer's location is used.";

#[derive(Default)]
struct Args {
    label: Option<String>,
    version: Option<u64>,
    config: Option<String>,
    encoding: Option<&'static str>,
    issuer: Option<String>,
    account: Option<String>,
    json: bool,
    light_terminal: bool,
    store: Option<String>,
    dir: Option<String>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut parsed = Args::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = || rest.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--config" => parsed.config = Some(value()?),
            "--version" => {
                parsed.version = Some(value()?.parse().map_err(|_| "--version must be a number".to_string())?)
            }
            "--issuer" => parsed.issuer = Some(value()?),
            "--account" => parsed.account = Some(value()?),
            "--store" => parsed.store = Some(value()?),
            "--dir" => parsed.dir = Some(value()?),
            "--hex" | "--base64" | "--base32" if parsed.encoding.is_none() => {
                parsed.encoding = Some(match arg.as_str() {
                    "--hex" => "hex",
                    "--base64" => "base64",
                    _ => "base32",
                })
            }
            "--json" => parsed.json = true,
            "--light-terminal" => parsed.light_terminal = true,
            label if !label.starts_with('-') && parsed.label.is_none() => parsed.label = Some(label.into()),
            other => return Err(format!("unexpected argument: {other}")),
        }
    }
    Ok(parsed)
}

/// Runs an owner command and returns the process exit code.
pub fn run(command: &str, args: &[String]) -> i32 {
    let args = match parse(args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("mcpbytes-vault: {message}\n\n{USAGE}");
            return 2;
        }
    };
    if command == "install" {
        return install_command(&args);
    }
    let Some(path) = args.config.clone().map(Into::into).or_else(config::default_path) else {
        eprintln!("mcpbytes-vault: no --config given and no default location on this system");
        return 2;
    };
    let vault = match Config::load(&path).and_then(Vault::new) {
        Ok(vault) => vault,
        Err(code) => {
            eprintln!("mcpbytes-vault: {code} ({})", path.display());
            return 2;
        }
    };
    let result = match command {
        "list" => list(&vault, &args),
        "reveal" => reveal(&vault, &args),
        "delete" => delete(&vault, &args),
        _ => totp_qr(&vault, &args),
    };
    match result {
        Ok(()) => 0,
        Err(Failure::Usage(message)) => {
            eprintln!("mcpbytes-vault: {message}");
            2
        }
        Err(Failure::Vault(code)) => {
            eprintln!("mcpbytes-vault: {code}: {}", vault.hint(code));
            1
        }
    }
}

/// `install`: puts this executable in place and prints how to register it with an MCP client.
fn install_command(args: &Args) -> i32 {
    let file_store = match args.store.as_deref() {
        None | Some("native") => false,
        Some("file") => true,
        Some(other) => {
            eprintln!("mcpbytes-vault: --store is native or file, not {other}");
            return 2;
        }
    };
    let default_root = || config::default_path().and_then(|path| path.parent().map(Path::to_path_buf));
    let Some(root) = args.dir.clone().map(Into::into).or_else(default_root) else {
        eprintln!("mcpbytes-vault: no default install folder on this system; pass --dir <folder>");
        return 2;
    };
    let root = std::path::absolute(&root).unwrap_or(root);
    let done = match install::install(&root, file_store) {
        Ok(done) => done,
        Err(message) => {
            eprintln!("mcpbytes-vault: {message}");
            return 1;
        }
    };
    println!("Installed MCPBytes Vault {} for this user.", env!("CARGO_PKG_VERSION"));
    println!("  Program:       {}", done.binary.display());
    if done.created_config {
        println!("  Configuration: {} (new: local-only, {})", done.config.display(), done.backend);
    } else {
        println!("  Configuration: {} (kept)", done.config.display());
        if args.store.is_some() {
            println!("  --store only applies to a new configuration; the existing one was kept.");
        }
    }
    let (binary, config) = (shell_quote(&done.binary), shell_quote(&done.config));
    // On Windows, call the client's executable: npm's PowerShell shim swallows the `--` separator.
    let client = |name: &str| if cfg!(windows) { format!("& (Get-Command {name} -CommandType Application | Select-Object -First 1 -ExpandProperty Source)") } else { name.into() };
    println!("\nRegister it with your MCP client:");
    println!("  Claude Code:   {} mcp add --transport stdio --scope user mcpbytes-vault -- {binary} --config {config}", client("claude"));
    println!("  Codex:         {} mcp add mcpbytes-vault -- {binary} --config {config}", client("codex"));
    println!("  Other clients: the server entry in {}", done.settings.display());
    if done.backend == "linux_secret_service" {
        println!("\nThe Secret Service needs an unlocked desktop keyring. On a server, install into a new folder with --store file.");
    }
    // PowerShell runs a quoted path only through the call operator. Outside the default folder, owner commands need
    // --config: without it they would read the default one (possibly another install's).
    let config_flag = if config::default_path().as_deref() == Some(done.config.as_path()) { String::new() } else { format!(" --config {config}") };
    println!("\nManage your secrets with: {}{binary} list{config_flag}", if cfg!(windows) { "& " } else { "" });
    0
}

/// A path as a single shell word: PowerShell single quotes on Windows, POSIX single quotes elsewhere.
fn shell_quote(path: &Path) -> String {
    let text = path.display().to_string();
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"/\\:._-".contains(&b)) {
        return text;
    }
    if cfg!(windows) {
        format!("'{}'", text.replace('\'', "''"))
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

enum Failure {
    Usage(String),
    Vault(&'static str),
}
impl From<&'static str> for Failure {
    fn from(code: &'static str) -> Self {
        Self::Vault(code)
    }
}

fn require_terminal(command: &str, action: &str) -> Result<(), Failure> {
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        return Ok(());
    }
    Err(Failure::Usage(format!(
        "{command} {action}, so it runs only in an interactive terminal. Open a terminal and run it there (not through an agent's shell tool)."
    )))
}
fn label(args: &Args) -> Result<&str, Failure> {
    args.label.as_deref().ok_or_else(|| Failure::Usage(format!("a label is required\n\n{USAGE}")))
}

fn list(vault: &Vault, args: &Args) -> Result<(), Failure> {
    let listing = vault.list()?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&listing).map_err(|_| "invalid_state")?);
        return Ok(());
    }
    if listing.secrets.is_empty() {
        println!("No secrets yet. Labels must start with \"{}\".", listing.label_prefix);
        return Ok(());
    }
    let rows: Vec<[String; 6]> = listing
        .secrets
        .iter()
        .map(|s| {
            [
                s.label.clone(),
                s.version.to_string(),
                s.bytes.to_string(),
                s.status.into(),
                s.entropy_mode.clone().unwrap_or_else(|| "-".into()),
                s.created_at.map_or_else(|| "-".into(), utc),
            ]
        })
        .collect();
    let header = ["LABEL", "VERSION", "BYTES", "STATUS", "ENTROPY", "CREATED (UTC)"].map(String::from);
    let widths: Vec<usize> = (0..6)
        .map(|i| rows.iter().chain([&header]).map(|r| r[i].chars().count()).max().unwrap_or(0))
        .collect();
    for row in [&header].into_iter().chain(&rows) {
        let cells: Vec<String> = row.iter().zip(&widths).map(|(cell, w)| format!("{cell:<w$}")).collect();
        println!("{}", cells.join("  ").trim_end());
    }
    Ok(())
}

fn reveal(vault: &Vault, args: &Args) -> Result<(), Failure> {
    require_terminal("reveal", "prints a secret")?;
    let (record, bytes) = vault.reveal(label(args)?, args.version)?;
    let encoded = Zeroizing::new(match args.encoding.unwrap_or("hex") {
        "hex" => hex(&bytes),
        "base64" => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(bytes.as_slice())
        }
        _ => base32(&bytes),
    });
    let mode = record.receipt.as_ref().map_or("-", |r| r.entropy_mode.as_str());
    println!("{} version {} ({} bytes, {mode}):", record.input.label, record.version, bytes.len());
    println!("{}", encoded.as_str());
    Ok(())
}

fn delete(vault: &Vault, args: &Args) -> Result<(), Failure> {
    require_terminal("delete", "deletes a secret permanently")?;
    let label = label(args)?;
    let version = args
        .version
        .ok_or_else(|| Failure::Usage("delete needs --version N (see `mcpbytes-vault list`)".into()))?;
    print!("Delete {label} version {version} permanently? Type the label to confirm: ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer).map_err(|_| Failure::Usage("no confirmation read".into()))?;
    if answer.trim() != label {
        return Err(Failure::Usage("not confirmed; nothing was deleted".into()));
    }
    let (_, existed) = vault.delete(label, version)?;
    if existed {
        println!("Deleted {label} version {version}.");
    } else {
        println!("{label} version {version} was already gone from the store; the vault's records now match.");
    }
    Ok(())
}

fn totp_qr(vault: &Vault, args: &Args) -> Result<(), Failure> {
    use qrcode::render::unicode::Dense1x2;
    require_terminal("totp-qr", "shows a secret as a QR code")?;
    let label = label(args)?;
    let (record, bytes) = vault.reveal(label, args.version)?;
    // RFC 4226 section 4: the shared secret MUST be at least 128 bits (160 recommended).
    if bytes.len() < 16 {
        return Err(Failure::Usage(format!(
            "{label} version {} has {} bytes; a TOTP seed needs at least 16 (create one with n = 20)",
            record.version,
            bytes.len()
        )));
    }
    let secret = Zeroizing::new(base32(&bytes));
    let issuer = args.issuer.as_deref().unwrap_or("MCPBytes Vault");
    let account = args.account.as_deref().unwrap_or(label);
    // Key URI format (Google Authenticator wiki): unpadded base32, issuer both as prefix and parameter.
    let uri = Zeroizing::new(format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        percent(issuer),
        percent(account),
        secret.as_str(),
        percent(issuer)
    ));
    let code = qrcode::QrCode::new(uri.as_bytes()).map_err(|_| Failure::Usage("QR encoding failed".into()))?;
    let mut renderer = code.render::<Dense1x2>();
    renderer.quiet_zone(true);
    if !args.light_terminal {
        // Dense1x2 draws dark modules in the text colour, which is light on a dark terminal.
        renderer.dark_color(Dense1x2::Light).light_color(Dense1x2::Dark);
    }
    let image = Zeroizing::new(renderer.build());
    println!("{}", image.as_str());
    println!("{account} ({issuer}), version {}. Scan with your authenticator app.", record.version);
    println!("If the code does not scan, retry with{} --light-terminal.", if args.light_terminal { "out" } else { "" });
    let grouped = Zeroizing::new(
        secret.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join(" "),
    );
    println!("Manual entry key: {}", grouped.as_str());
    Ok(())
}

/// Written into one pre-sized buffer so no temporary strings hold parts of the secret.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}
/// RFC 4648 base32 without padding, the form authenticator apps expect.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u16, 0);
    for &byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[usize::from((buffer >> bits) & 31)] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[usize::from((buffer << (5 - bits)) & 31)] as char);
    }
    out
}
/// Percent-encodes everything outside RFC 3986 unreserved characters.
fn percent(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
/// `YYYY-MM-DD HH:MM` in UTC from Unix seconds (days-to-civil, H. Hinnant).
fn utc(seconds: u64) -> String {
    let days = (seconds / 86400) as i64 + 719468;
    let era = days.div_euclid(146097);
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let rest = seconds % 86400;
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}", rest / 3600, rest % 3600 / 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encodings_match_their_standards() {
        // RFC 4648 section 10 vectors, unpadded.
        for (input, expected) in [("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"), ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI")] {
            assert_eq!(base32(input.as_bytes()), expected);
        }
        assert_eq!(hex(&[0x0d, 0xff, 0x00]), "0dff00");
        assert_eq!(percent("MCPBytes Vault/é"), "MCPBytes%20Vault%2F%C3%A9");
        assert_eq!(utc(0), "1970-01-01 00:00");
        assert_eq!(utc(1_700_000_000), "2023-11-14 22:13");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00");
    }
    #[test]
    fn arguments_parse_strictly() {
        let args = |v: &[&str]| parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let parsed = args(&["agent-x", "--version", "2", "--base32", "--config", "C:/c.json"]).ok().unwrap();
        assert_eq!(parsed.label.as_deref(), Some("agent-x"));
        assert_eq!(parsed.version, Some(2));
        assert_eq!(parsed.encoding, Some("base32"));
        assert_eq!(parsed.config.as_deref(), Some("C:/c.json"));
        assert!(args(&["agent-x", "--version", "two"]).is_err());
        assert!(args(&["agent-x", "agent-y"]).is_err());
        assert!(args(&["--hex", "--base64"]).is_err());
        assert!(args(&["--version"]).is_err());
    }
}
