// SPDX-License-Identifier: GPL-3.0-or-later
//! Isolated, explicit account onboarding experiment. Does not start a camera stream.
use anyhow::{bail, ensure, Result};
use motorola_receiver::{
    account::{self, AccountSession},
    account_transport::{AccountTransport, Limits, TransportError},
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const INITIAL_HOST: &str = "primary.moto.5gencare.com";
const PORT: u16 = 3388;
fn event(name: &str) {
    println!("{}", json!({"event":name}));
}
fn allowed_host(host: &str) -> Result<&str> {
    ensure!(
        host.len() <= 253
            && host.ends_with(".moto.5gencare.com")
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
        "unexpected_account_server"
    );
    Ok(host)
}
struct Client {
    directory: PathBuf,
    socket: AccountTransport,
}
impl Client {
    async fn connect(host: &str, directory: &Path) -> Result<Self> {
        let limits = Limits {
            read_timeout: Duration::from_secs(1),
            ..Limits::default()
        };
        let socket = AccountTransport::connect(allowed_host(host)?, PORT, limits).await?;
        event("tls_connected");
        Ok(Self {
            socket,
            directory: directory.into(),
        })
    }
    async fn send(&mut self, message: &str) -> Result<()> {
        self.socket.send(message).await?;
        Ok(())
    }
    async fn next(&mut self) -> Result<Option<Vec<String>>> {
        match self.socket.read_line().await {
            Ok(Some(line)) => {
                let tokens = line
                    .as_str()
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                if tokens.first().is_some_and(|t| t == "ping") {
                    self.send("pong").await?;
                    return Ok(None);
                }
                Ok(Some(tokens))
            }
            Ok(None) => bail!("account_connection_closed"),
            Err(TransportError::ReadTimeout) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    async fn wait(&mut self, command: &str) -> Result<Vec<String>> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Some(reply) = self.next().await? {
                if reply.first().is_some_and(|t| t == command) {
                    return Ok(reply);
                }
                event("unsolicited_reply_saved");
            }
        }
        bail!("account_reply_timeout")
    }
    async fn cameras(&mut self) -> Result<()> {
        self.send("v3_dlist").await?;
        let reply = self.wait("v3_dlist").await?;
        let refs: Vec<_> = reply.iter().map(String::as_str).collect();
        let cameras = account::parse_camera_list(&refs)?;
        account::write_private(&self.directory.join("cameras.json"), &cameras)?;
        println!(
            "{}",
            json!({"event":"camera_list_saved","count":cameras.len()})
        );
        Ok(())
    }
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&account::read_private(path)?)
        .map_err(|_| anyhow::anyhow!("invalid_private_json"))
}
fn reject_negative(tokens: &[String]) -> Result<()> {
    let n: i64 = tokens
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("missing_reply_status"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid_reply_status"))?;
    if n < 0 {
        println!("{}", json!({"event":"account_rejected","code":n}));
        bail!("account_rejected");
    }
    Ok(())
}
async fn resume(directory: &Path, mut session: AccountSession, master: bool) -> Result<Client> {
    let mut request = session.resume_request(master)?;
    let mut master_attempted = master;
    let mut host = session.hostname.clone();
    for _ in 0..3 {
        let mut client = Client::connect(&host, directory).await?;
        client.send(&request).await?;
        let reply = client.wait("v3_session").await?;
        if reply.get(1).is_some_and(|t| t == "-6") {
            host = allowed_host(
                reply
                    .get(2)
                    .ok_or_else(|| anyhow::anyhow!("missing_redirect"))?,
            )?
            .into();
            event("session_redirect");
            continue;
        }
        if reply.get(1).is_some_and(|t| t == "-9") && !master_attempted {
            request = session.resume_request(true)?;
            master_attempted = true;
            event("session_master_fallback");
            continue;
        }
        reject_negative(&reply)?;
        let returned_host = allowed_host(
            reply
                .get(4)
                .ok_or_else(|| anyhow::anyhow!("missing_session_server"))?,
        )?;
        if returned_host != host {
            host = returned_host.into();
            session.hostname = host.clone();
            request = session.resume_request(true)?;
            master_attempted = true;
            event("session_server_changed");
            continue;
        }
        let refs: Vec<_> = reply.iter().map(String::as_str).collect();
        session.apply_resume(&refs)?;
        allowed_host(&session.hostname)?;
        account::write_private(&directory.join("session.json"), &session)?;
        event("session_resumed");
        return Ok(client);
    }
    bail!("too_many_account_redirects")
}
async fn login(
    directory: &Path,
    email_file: &Path,
    code_file: &Path,
    interactive: bool,
) -> Result<()> {
    ensure!(
        !directory.join("session.json").exists(),
        "account_already_initialized"
    );
    ensure!(!code_file.exists(), "stale_code_file");
    let address: Value = read_json(email_file)?;
    let email = account::email(
        address
            .get("email")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("email_required"))?,
    )?;
    let identity_path = directory.join("identity.json");
    let identity: String = if identity_path.exists() {
        read_json(&identity_path)?
    } else {
        let i = account::device_identity()?;
        account::write_private(&identity_path, &i)?;
        i
    };
    let request = account::otp_request(&identity, email)?;
    let mut host = INITIAL_HOST.to_owned();
    let mut pending = None;
    for _ in 0..3 {
        let mut client = Client::connect(&host, directory).await?;
        client.send(&request).await?;
        let reply = client.wait("v3_otp").await?;
        if reply.get(1).is_some_and(|t| t == "-6") {
            host = allowed_host(
                reply
                    .get(2)
                    .ok_or_else(|| anyhow::anyhow!("missing_redirect"))?,
            )?
            .into();
            event("otp_redirect");
            continue;
        }
        reject_negative(&reply)?;
        let user_id = reply[1].parse::<i64>()?;
        pending = Some((client, user_id));
        break;
    }
    let (mut client, user_id) =
        pending.ok_or_else(|| anyhow::anyhow!("too_many_account_redirects"))?;
    event("otp_requested_waiting_for_code");
    let input = if interactive {
        eprintln!("Enter the six-digit email code (terminal input is visible):");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(prompt("Code: "));
        });
        Some(rx)
    } else {
        None
    };
    let deadline = Instant::now() + Duration::from_secs(600);
    let code = loop {
        ensure!(Instant::now() < deadline, "otp_wait_timeout");
        if let Some(rx) = &input {
            match rx.try_recv() {
                Ok(result) => {
                    let code = result?;
                    account::login_request(user_id, &identity, email, &code)?;
                    break code;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => bail!("terminal_input_failed"),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        if !interactive && code_file.exists() {
            let bytes = account::read_private(code_file)?;
            let code = std::str::from_utf8(&bytes)?.trim().to_owned();
            let _ = account::login_request(user_id, &identity, email, &code)?;
            std::fs::remove_file(code_file)?;
            break code;
        }
        if client.next().await?.is_some() {
            event("unsolicited_reply_saved");
        }
    };
    client
        .send(&account::login_request(user_id, &identity, email, &code)?)
        .await?;
    let reply = client.wait("v3_loginset").await?;
    reject_negative(&reply)?;
    let refs: Vec<_> = reply.iter().map(String::as_str).collect();
    let session = AccountSession::from_login(&identity, &refs)?;
    allowed_host(&session.hostname)?;
    let changed_server = session.hostname != host;
    account::write_private(&directory.join("session.json"), &session)?;
    event("login_succeeded_session_saved");
    if changed_server {
        client = resume(directory, session, true).await?;
    }
    client.cameras().await?;
    event("login_complete");
    Ok(())
}
fn prompt(label: &str) -> Result<String> {
    use std::io::{BufRead, Read, Write};
    eprint!("{label}");
    std::io::stderr().flush()?;
    let mut input = String::new();
    let count = std::io::stdin().lock().take(4097).read_line(&mut input)?;
    ensure!(count > 0 && count <= 4096, "terminal_input_failed");
    Ok(input.trim().to_owned())
}
fn select_index(text: &str, count: usize) -> Result<usize> {
    let n: usize = text
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid_camera_selection"))?;
    ensure!(n > 0 && n <= count, "invalid_camera_selection");
    Ok(n - 1)
}
async fn setup(directory: &Path) -> Result<()> {
    use std::io::IsTerminal;
    ensure!(
        std::io::stdin().is_terminal(),
        "interactive_terminal_required"
    );
    ensure!(
        !directory.join("camera.json").exists() && !directory.join("config.json").exists(),
        "setup_output_exists"
    );
    if directory.join("session.json").exists() {
        let mut client = resume(
            directory,
            read_json(&directory.join("session.json"))?,
            false,
        )
        .await?;
        client.cameras().await?;
    } else {
        let email = prompt("Motorola account email: ")?;
        account::email(&email)?;
        let path = directory.join("email.json");
        account::write_private(&path, &json!({"email":email}))?;
        let result = login(directory, &path, &directory.join("otp"), true).await;
        let _ = std::fs::remove_file(path);
        result?;
    }
    let cameras: Vec<account::AccountCamera> = read_json(&directory.join("cameras.json"))?;
    ensure!(!cameras.is_empty(), "camera_not_found");
    for (i, c) in cameras.iter().enumerate() {
        let safe = |s: &str| {
            s.chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .take(160)
                .collect::<String>()
        };
        eprintln!("{}. {} ({})", i + 1, safe(&c.encoded_name), safe(&c.model));
    }
    let index = if cameras.len() == 1 {
        0
    } else {
        select_index(&prompt("Select camera number: ")?, cameras.len())?
    };
    let ip: std::net::Ipv4Addr = prompt("Selected camera's LAN IPv4 address (from your router): ")?
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid_camera_address"))?;
    ensure!(
        !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() && !ip.is_broadcast(),
        "invalid_camera_address"
    );
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|_| anyhow::anyhow!("identity_random_failed"))?;
    let letters: Vec<char> = random.iter().map(|b| (b'A' + b % 26) as char).collect();
    let token = [
        &letters[0..8],
        &letters[8..12],
        &letters[12..16],
        &letters[16..20],
        &letters[20..32],
    ]
    .iter()
    .map(|s| s.iter().collect::<String>())
    .collect::<Vec<_>>()
    .join("-");
    let config = json!({"credentials":"/etc/connector/camera.json","camera_ip":ip.to_string(),"listen":"0.0.0.0:8554","allow_nonloopback_listen":true,"client_token":token,"seconds":0,"metrics_listen":"0.0.0.0:9091","media_timeout_seconds":20,"repair_interleaved_response":true});
    let parsed: motorola_receiver::settings::Settings = serde_json::from_value(config.clone())?;
    parsed.validate()?;
    account::export_camera(
        &cameras,
        Some(cameras[index].device_id),
        &directory.join("camera.json"),
    )?;
    if let Err(error) = account::write_private(&directory.join("config.json"), &config) {
        // Export created this file exclusively; leave setup retryable if settings fail.
        let _ = std::fs::remove_file(directory.join("camera.json"));
        return Err(error);
    }
    event("setup_complete");
    eprintln!("Private camera.json and config.json saved. Start the service with docker compose up -d receiver.");
    Ok(())
}
#[tokio::main]
async fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let result = async {
        let command = arguments.get(1).ok_or_else(|| anyhow::anyhow!("usage"))?;
        ensure!(
            [
                "setup",
                "probe",
                "login",
                "resume",
                "resume-master",
                "export-camera"
            ]
            .contains(&command.as_str()),
            "usage"
        );
        let mut flags = std::collections::HashMap::new();
        for pair in arguments[2..].chunks(2) {
            ensure!(pair.len() == 2, "usage");
            ensure!(
                [
                    "--state-dir",
                    "--email-file",
                    "--code-file",
                    "--camera-id",
                    "--output"
                ]
                .contains(&pair[0].as_str()),
                "usage"
            );
            ensure!(
                flags.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
                "usage"
            );
        }
        let directory = Path::new(
            *flags
                .get("--state-dir")
                .ok_or_else(|| anyhow::anyhow!("usage"))?,
        );
        if command == "export-camera" {
            account::require_private_dir(directory)?;
        } else {
            account::private_dir(directory)?;
        }
        match command.as_str() {
            "setup" => setup(directory).await?,
            "export-camera" => {
                ensure!(
                    !flags.contains_key("--email-file") && !flags.contains_key("--code-file"),
                    "usage"
                );
                let selected = flags
                    .get("--camera-id")
                    .map(|value| {
                        ensure!(
                            !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
                            "invalid_camera_id"
                        );
                        let id = value
                            .parse::<i64>()
                            .map_err(|_| anyhow::anyhow!("invalid_camera_id"))?;
                        ensure!(id > 0, "invalid_camera_id");
                        Ok::<i64, anyhow::Error>(id)
                    })
                    .transpose()?;
                let output = Path::new(
                    *flags
                        .get("--output")
                        .ok_or_else(|| anyhow::anyhow!("usage"))?,
                );
                let cameras: Vec<account::AccountCamera> =
                    read_json(&directory.join("cameras.json"))?;
                account::export_camera(&cameras, selected, output)?;
                event("credentials_exported");
            }
            "probe" => {
                let _ = Client::connect(INITIAL_HOST, directory).await?;
                event("tls_probe_passed");
            }
            "login" => {
                login(
                    directory,
                    Path::new(
                        *flags
                            .get("--email-file")
                            .ok_or_else(|| anyhow::anyhow!("usage"))?,
                    ),
                    Path::new(
                        *flags
                            .get("--code-file")
                            .ok_or_else(|| anyhow::anyhow!("usage"))?,
                    ),
                    false,
                )
                .await?
            }
            _ => {
                let session = read_json(&directory.join("session.json"))?;
                let mut client = resume(directory, session, command == "resume-master").await?;
                client.cameras().await?;
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        // Only locally defined fixed error strings escape; never print an arbitrary IO/JSON error.
        let message = error.to_string();
        let safe = if let Some(transport) = error.downcast_ref::<TransportError>() {
            transport.to_string()
        } else {
            match message.as_str() {
                "usage"
                | "terminal_input_failed"
                | "interactive_terminal_required"
                | "setup_output_exists"
                | "invalid_camera_selection"
                | "invalid_camera_address"
                | "unexpected_account_server"
                | "account_connection_closed"
                | "account_reply_timeout"
                | "invalid_private_json"
                | "missing_reply_status"
                | "invalid_reply_status"
                | "account_rejected"
                | "missing_redirect"
                | "missing_session_server"
                | "too_many_account_redirects"
                | "account_already_initialized"
                | "stale_code_file"
                | "email_required"
                | "otp_wait_timeout"
                | "invalid_protocol_atom"
                | "invalid_email"
                | "invalid_otp_format"
                | "invalid_login_reply"
                | "login_rejected"
                | "invalid_session_reply"
                | "session_rejected"
                | "invalid_camera_list"
                | "invalid_camera_list_count"
                | "invalid_camera_id"
                | "camera_not_found"
                | "ambiguous_camera_selection"
                | "camera_selection_required"
                | "output_parent_required"
                | "export_output_exists"
                | "export_write_failed"
                | "private_directory_required"
                | "private_file_required"
                | "private_state_write_failed" => message,
                _ => "account_operation_failed".to_owned(),
            }
        };
        eprintln!(
            "{}",
            json!({"event":"account_operation_failed","reason":safe})
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod setup_tests {
    use super::*;
    #[test]
    fn selection_is_bounded_and_one_based() {
        assert_eq!(select_index("2", 3).unwrap(), 1);
        for v in ["0", "4", "-1", "text", "18446744073709551616"] {
            assert!(select_index(v, 3).is_err());
        }
        assert!(select_index("1", 0).is_err());
    }
}
