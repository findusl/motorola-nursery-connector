// SPDX-License-Identifier: GPL-3.0-or-later
use motorola_receiver::{settings::Settings, supervisor, telemetry};
use std::path::Path;
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().collect();
    let (command, path) = match args.as_slice() {
        [_, flag, path] if flag == "--config" => ("run", path),
        [_, command, flag, path]
            if flag == "--config"
                && ["healthcheck", "status", "check-config"].contains(&command.as_str()) =>
        {
            (command.as_str(), path)
        }
        _ => {
            eprintln!("usage: motorola-receiver [healthcheck|status|check-config] --config PRIVATE_CONFIG_JSON");
            std::process::exit(2);
        }
    };
    let result = async {
        let (s, c) = Settings::load(Path::new(path))?;
        match command {
            "run" => supervisor::supervise(s, c).await,
            "check-config" => Ok(()),
            command => {
                let addr = s
                    .metrics_listen
                    .ok_or_else(|| anyhow::anyhow!("metrics_listener_not_configured"))?;
                let body = telemetry::query(addr, command == "healthcheck").await?;
                if command == "status" {
                    println!("{body}");
                }
                Ok(())
            }
        }
    }
    .await;
    if result.is_err() {
        // Detailed session errors are already classified in retry logs. CLI
        // errors can contain private paths/addresses and are not printed raw.
        eprintln!(
            "{}",
            serde_json::json!({"event":"command_failed","command":command})
        );
        std::process::exit(1);
    }
}
