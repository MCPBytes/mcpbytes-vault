mod cli;
use mcpbytes_random_bytes::{
    app::{Input, Listing, Saved, Vault, ARGUMENT_ERRORS},
    config::Config,
};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerConfig},
    tool, tool_handler, tool_router, ErrorData, Json, ServerHandler, ServiceExt,
};
use std::{path::Path, sync::Arc};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

/// Bound each incoming stdio frame before the SDK's line buffer can grow without limit.
struct BoundedInput {
    stdin: tokio::io::Stdin,
    line_bytes: usize,
}
impl AsyncRead for BoundedInput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.stdin).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                for byte in &buf.filled()[before..] {
                    self.line_bytes += 1;
                    if self.line_bytes > 16384 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "MCP input exceeds limit",
                        )));
                    }
                    if *byte == b'\n' {
                        self.line_bytes = 0;
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[derive(Clone)]
struct Server {
    vault: Arc<Vault>,
    tool_router: ToolRouter<Self>,
}
#[tool_router]
impl Server {
    fn new(vault: Vault) -> Self {
        let mut tool_router = Self::tool_router();
        // The owner's configuration decides the prefix, cost and failure mode: state them in the
        // tool itself, so an agent does not have to learn them from a failed call.
        if let Some(route) = tool_router.map.get_mut("get_random_bytes") {
            route.attr.description = Some(vault.tool_description().into());
            let mut schema = (*route.attr.input_schema).clone();
            if let Some(properties) = schema.get_mut("properties").and_then(|p| p.as_object_mut()) {
                if let Some(label) = properties.get_mut("label").and_then(|l| l.as_object_mut()) {
                    // The prefix is itself a valid label ([A-Za-z0-9_-]), so it needs no regex escaping.
                    label.insert("pattern".into(), format!("^{}[A-Za-z0-9_-]*$", vault.label_prefix()).into());
                    label.insert("maxLength".into(), 64.into());
                }
                if let Some(operation) = properties.get_mut("operation_id").and_then(|o| o.as_object_mut()) {
                    operation.insert("pattern".into(), "^[A-Za-z0-9_-]{1,128}$".into());
                }
            }
            route.attr.input_schema = Arc::new(schema);
        }
        Self {
            vault: Arc::new(vault),
            tool_router,
        }
    }
    fn error(&self, code: &'static str) -> ErrorData {
        // Fixed hint text only: no upstream diagnostics reach the transcript.
        let message = format!("{code}: {}", self.vault.hint(code));
        if ARGUMENT_ERRORS.contains(&code) {
            ErrorData::invalid_params(message, None)
        } else {
            ErrorData::internal_error(message, None)
        }
    }
    /// Description replaced at startup from the owner's configuration (Server::new).
    #[tool(description = "Generate and save 1–64 random bytes locally. Returns a reference, never the bytes.")]
    async fn get_random_bytes(
        &self,
        Parameters(input): Parameters<Input>,
    ) -> Result<Json<Saved>, ErrorData> {
        self.vault
            .generate(input)
            .await
            .map(Json)
            .map_err(|code| self.error(code))
    }
    #[tool(
        description = "List the secrets this vault has created: label, version, size, status (saved, deleted or incomplete), entropy mode and creation time. Metadata only; never returns secret values.",
        annotations(read_only_hint = true)
    )]
    async fn list_secrets(&self) -> Result<Json<Listing>, ErrorData> {
        self.vault.list().map(Json).map_err(|code| self.error(code))
    }
}
#[tool_handler(router = self.tool_router)]
impl ServerHandler for Server {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(rmcp::model::Implementation::new("mcpbytes-vault", env!("CARGO_PKG_VERSION")).with_title("MCPBytes Vault"))
            .with_instructions(self.vault.instructions())
    }
}

#[tokio::main]
async fn main() {
    // No panic values or upstream diagnostics may reach an MCP transcript.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("mcpbytes-vault: fatal internal error")
    }));
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            eprintln!("mcpbytes-vault: cannot disable core dumps");
            std::process::exit(2);
        }
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        eprintln!("mcpbytes-vault: cannot disable process memory dumps");
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--config") if args.len() == 2 => (),
        Some(command @ ("install" | "list" | "reveal" | "delete" | "totp-qr")) => {
            std::process::exit(cli::run(command, &args[1..]))
        }
        Some("help" | "--help" | "-h") => {
            println!("{}", cli::USAGE);
            return;
        }
        _ => {
            eprintln!("{}", cli::USAGE);
            std::process::exit(2);
        }
    }
    let vault = match Config::load(Path::new(&args[1])).and_then(Vault::new) {
        Ok(vault) => vault,
        Err(code) => {
            eprintln!("mcpbytes-vault: {code}");
            std::process::exit(2);
        }
    };
    let io = (
        BoundedInput {
            stdin: tokio::io::stdin(),
            line_bytes: 0,
        },
        tokio::io::stdout(),
    );
    match Server::new(vault).serve(io).await {
        Ok(service) => {
            if service.waiting().await.is_err() {
                eprintln!("mcpbytes-vault: transport closed");
            }
        }
        Err(_) => {
            eprintln!("mcpbytes-vault: startup failed");
            std::process::exit(1);
        }
    }
}
