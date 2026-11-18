use anyhow::Context;
use oxsession_server::{config, routes};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = config::Config::from_env().context("failed to load service configuration")?;
    let bind_address = config.bind_address;
    let dev_login = config.dev_login;

    let listener = TcpListener::bind(bind_address)
        .await
        .with_context(|| format!("failed to bind to {bind_address}"))?;

    println!("oXSession server listening on {bind_address}");
    if dev_login {
        println!(
            "warning: AUTH_DEV_LOGIN is enabled; POST /sessions mints sessions for any subject"
        );
    }

    axum::serve(listener, routes::router(config))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
