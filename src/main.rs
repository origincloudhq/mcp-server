use clap::Parser;
use origincloud_mcp_server::config::{Config, LogFormat};
use origincloud_mcp_server::Server;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match config.log_format {
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_env_filter(filter)
            .init(),
        LogFormat::Text => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
    let server = Server::new(config.clone())?;
    let listener = TcpListener::bind(config.listen).await?;
    let metrics = TcpListener::bind(config.metrics_listen).await?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        listen = %config.listen,
        metrics = %config.metrics_listen,
        resource = %config.canonical_resource(),
        issuer = %config.issuer_id(),
        "serving"
    );
    server.run(listener, metrics, terminated()).await
}

/// Completes on SIGTERM or Ctrl-C.
async fn terminated() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
}
