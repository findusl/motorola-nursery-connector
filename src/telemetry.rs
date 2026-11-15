// SPDX-License-Identifier: GPL-3.0-or-later
//! Operational telemetry only: no camera identifiers, request contents or secrets.
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};

/// A successfully parsed PLAY starts a fresh grace period. Only validated video
/// RTP advances this clock; heartbeats, RTCP and audio cannot hide video stalls.
pub(crate) struct Playback {
    started: Instant,
    video: Option<Instant>,
}
impl Playback {
    pub(crate) fn new() -> Self {
        Self {
            started: Instant::now(),
            video: None,
        }
    }
    pub(crate) fn video(&mut self) {
        self.video = Some(Instant::now());
    }
    pub(crate) fn age(&self) -> Option<f64> {
        self.video.map(|at| at.elapsed().as_secs_f64())
    }
    pub(crate) fn deadline(&self, limit: Duration) -> Instant {
        self.video.unwrap_or(self.started) + limit
    }
    pub(crate) fn stalled(&self, limit: Duration) -> bool {
        self.stalled_at(Instant::now(), limit)
    }
    fn stalled_at(&self, now: Instant, limit: Duration) -> bool {
        now >= self.deadline(limit)
    }
}

#[derive(Serialize)]
pub struct Status {
    pub ready: bool,
    pub status_age_seconds: f64,
    pub state: &'static str,
    pub attempt: u64,
    pub session_age_seconds: Option<f64>,
    pub heartbeat_age_seconds: Option<f64>,
    pub active_streams: usize,
    pub media_age_seconds: Option<f64>,
    pub media_healthy: bool,
    pub last_failure: Option<&'static str>,
    pub retry_delay_seconds: Option<f64>,
}
struct State {
    updated: Instant,
    ready: bool,
    phase: &'static str,
    attempt: u64,
    since: Option<Instant>,
    heartbeat: Option<Instant>,
    active: usize,
    media: Option<Instant>,
    media_stalled: bool,
    failure: Option<&'static str>,
    delay: Option<f64>,
    failed_at: Option<Instant>,
    recovery: Option<f64>,
    counters: BTreeMap<&'static str, u64>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            updated: Instant::now(),
            ready: false,
            phase: "starting",
            attempt: 0,
            since: None,
            heartbeat: None,
            active: 0,
            media: None,
            media_stalled: false,
            failure: None,
            delay: None,
            failed_at: None,
            recovery: None,
            counters: [
                "attempt_started",
                "retry_started",
                "session_failed",
                "timeout",
                "forwarding_failed",
                "session_ready",
                "media_resumed",
            ]
            .into_iter()
            .map(|k| (k, 0))
            .collect(),
        }
    }
}
#[derive(Default)]
pub struct Diagnostics {
    state: Mutex<State>,
}
impl Diagnostics {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub(crate) fn event(&self, event: &str, fields: &Value) {
        let mut s = self.state();
        s.updated = Instant::now();
        match event {
            "supervisor_attempt_start" => {
                s.ready = false;
                s.phase = "connecting";
                s.attempt = fields["attempt_number"].as_u64().unwrap_or(0);
                s.since = None;
                s.heartbeat = None;
                s.active = 0;
                s.media = None;
                s.media_stalled = false;
                s.delay = None;
                *s.counters.get_mut("attempt_started").unwrap() += 1;
                if s.attempt > 1 {
                    *s.counters.get_mut("retry_started").unwrap() += 1;
                }
            }
            "local_network_wait" => {
                s.ready = false;
                s.phase = "waiting_network";
                s.delay = None;
            }
            "local_network_restored" => {
                s.phase = "connecting";
            }
            "supervisor_authenticated" => {
                s.ready = true;
                s.phase = "ready";
                s.since = Some(Instant::now());
                s.delay = None;
                s.recovery = s.failed_at.take().map(|t| t.elapsed().as_secs_f64());
                *s.counters.get_mut("session_ready").unwrap() += 1;
            }
            "retry_scheduled" => {
                s.ready = false;
                s.phase = "retrying";
                s.active = 0;
                s.media = None;
                s.media_stalled = false;
                s.delay = fields["delay_ms"].as_f64().map(|v| v / 1000.0);
                s.failed_at.get_or_insert_with(Instant::now);
                *s.counters.get_mut("session_failed").unwrap() += 1;
                if fields["retry_reason"]
                    .as_str()
                    .is_some_and(|s| s.ends_with("timeout"))
                {
                    *s.counters.get_mut("timeout").unwrap() += 1;
                }
            }
            "supervisor_shutdown" | "bounded_duration_complete" => {
                s.ready = false;
                s.phase = "stopped";
                s.active = 0;
            }
            _ => (),
        }
    }
    pub(crate) fn failure(&self, reason: &'static str) {
        self.state().failure = Some(reason);
    }
    pub(crate) fn incoming(&self) {
        self.state().heartbeat = Some(Instant::now());
    }
    pub(crate) fn forwarding_failure(&self) {
        *self.state().counters.get_mut("forwarding_failed").unwrap() += 1;
    }
    pub(crate) fn playback(&self, active: usize, media_age: Option<f64>, stalled: bool) {
        let mut s = self.state();
        if media_age.is_some() && (s.media.is_none() || s.media_stalled) {
            *s.counters.get_mut("media_resumed").unwrap() += 1;
        }
        s.updated = Instant::now();
        s.active = active;
        s.media = media_age.map(|age| Instant::now() - Duration::from_secs_f64(age));
        s.media_stalled = stalled;
    }
    pub fn status(&self) -> Status {
        let s = self.state();
        Status {
            ready: s.ready,
            status_age_seconds: s.updated.elapsed().as_secs_f64(),
            state: s.phase,
            attempt: s.attempt,
            session_age_seconds: s.since.map(|t| t.elapsed().as_secs_f64()),
            heartbeat_age_seconds: s.heartbeat.map(|t| t.elapsed().as_secs_f64()),
            active_streams: s.active,
            media_age_seconds: s.media.map(|t| t.elapsed().as_secs_f64()),
            media_healthy: s.ready && s.active > 0 && s.media.is_some() && !s.media_stalled,
            last_failure: s.failure,
            retry_delay_seconds: s.delay,
        }
    }
    pub fn metrics(&self) -> String {
        let status = self.status();
        let s = self.state();
        let optional = |v: Option<f64>| v.map_or_else(|| "NaN".into(), |n| format!("{n:.3}"));
        let mut out=format!("motorola_connector_ready {}\nmotorola_connector_status_age_seconds {:.3}\nmotorola_connector_session_age_seconds {}\nmotorola_connector_heartbeat_age_seconds {}\nmotorola_connector_active_streams {}\nmotorola_connector_media_age_seconds {}\nmotorola_connector_media_healthy {}\nmotorola_connector_last_recovery_seconds {}\n",u8::from(status.ready),status.status_age_seconds,optional(status.session_age_seconds),optional(status.heartbeat_age_seconds),status.active_streams,optional(status.media_age_seconds),u8::from(status.media_healthy),optional(s.recovery));
        for (event, count) in &s.counters {
            out.push_str(&format!(
                "motorola_connector_events_total{{event=\"{event}\"}} {count}\n"
            ));
        }
        out
    }
}
async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    diagnostics: Arc<Diagnostics>,
) -> Result<()> {
    let mut request = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            bail!("http_truncated_request");
        }
        request.extend_from_slice(&chunk[..count]);
        if request.len() > 4096 {
            bail!("http_request_limit");
        }
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let first = request.split(|b| *b == b'\n').next().unwrap_or_default();
    let (status, content_type, body) = match first {
        b"GET /metrics HTTP/1.1\r" | b"GET /metrics HTTP/1.0\r" => {
            ("200 OK", "text/plain; version=0.0.4", diagnostics.metrics())
        }
        b"GET /status HTTP/1.1\r" | b"GET /status HTTP/1.0\r" => (
            "200 OK",
            "application/json",
            serde_json::to_string(&diagnostics.status())?,
        ),
        b"GET /healthz HTTP/1.1\r" | b"GET /healthz HTTP/1.0\r" => {
            let s = diagnostics.status();
            if s.ready
                && s.status_age_seconds < 30.0
                && s.heartbeat_age_seconds.is_none_or(|age| age < 45.0)
                && (s.active_streams == 0 || s.media_healthy)
            {
                ("200 OK", "text/plain", "ready\n".into())
            } else {
                (
                    "503 Service Unavailable",
                    "text/plain",
                    "not ready\n".into(),
                )
            }
        }
        _ => ("404 Not Found", "text/plain", "not found\n".into()),
    };
    let reply=format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
    stream.write_all(reply.as_bytes()).await?;
    Ok(())
}
/// Bounded, read-only local diagnostics. The deployment exposes this only to its
/// monitoring network. It never proxies camera traffic or returns credentials.
pub async fn serve(listener: TcpListener, diagnostics: Arc<Diagnostics>) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            result=listener.accept()=> { let (stream,_)=result.context("metrics_listener_failed")?; if tasks.len()<16 { let diagnostics=diagnostics.clone(); tasks.spawn(async move { let _=timeout(Duration::from_secs(2),respond(stream,diagnostics)).await; }); } },
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
}
pub async fn query(addr: SocketAddr, healthcheck: bool) -> Result<String> {
    let result = timeout(Duration::from_secs(3), async {
        let local = SocketAddr::new(
            if addr.ip().is_unspecified() {
                if addr.is_ipv4() {
                    "127.0.0.1".parse().unwrap()
                } else {
                    "::1".parse().unwrap()
                }
            } else {
                addr.ip()
            },
            addr.port(),
        );
        let mut stream = TcpStream::connect(local).await?;
        let path = if healthcheck { "/healthz" } else { "/status" };
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        stream.take(16384).read_to_end(&mut response).await?;
        let response = String::from_utf8(response).context("invalid_status_response")?;
        if !response.starts_with("HTTP/1.1 200 ") {
            bail!("receiver_not_ready");
        }
        Ok(response
            .split_once("\r\n\r\n")
            .context("invalid_status_response")?
            .1
            .to_owned())
    })
    .await
    .context("status_timeout")?;
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn video_watchdog_has_play_grace_and_requires_video_progress() {
        let now = Instant::now();
        let limit = Duration::from_secs(60);
        let mut playback = Playback {
            started: now,
            video: None,
        };
        assert!(!playback.stalled_at(now + Duration::from_secs(59), limit));
        assert!(playback.stalled_at(now + limit, limit));
        playback.video = Some(now + Duration::from_secs(50));
        assert!(!playback.stalled_at(now + Duration::from_secs(90), limit));
        assert!(playback.stalled_at(now + Duration::from_secs(110), limit));
    }
    #[test]
    fn video_progress_and_new_play_replace_deadline() {
        let start = Instant::now();
        let limit = Duration::from_secs(20);
        let mut playback = Playback {
            started: start,
            video: None,
        };
        assert_eq!(playback.deadline(limit), start + limit);
        playback.video = Some(start + Duration::from_secs(12));
        assert_eq!(playback.deadline(limit), start + Duration::from_secs(32));
        let resumed = Playback {
            started: start + Duration::from_secs(40),
            video: None,
        };
        assert_eq!(resumed.deadline(limit), start + Duration::from_secs(60));
    }
    #[test]
    fn local_network_wait_is_unready_without_failed_attempts() {
        let d = Diagnostics::default();
        d.event("supervisor_attempt_start", &json!({"attempt_number":1}));
        d.event("local_network_wait", &json!({}));
        assert_eq!(d.status().state, "waiting_network");
        assert!(!d.status().ready);
        assert!(d.metrics().contains("event=\"session_failed\"} 0"));
        d.event("local_network_restored", &json!({}));
        assert_eq!(d.status().state, "connecting");
        assert!(!d.status().ready);
    }
    #[test]
    fn retries_clear_ready_and_do_not_invent_media() {
        let d = Diagnostics::default();
        d.event("supervisor_attempt_start", &json!({"attempt_number":1}));
        d.event("supervisor_authenticated", &json!({}));
        assert!(d.status().ready);
        assert!(d.status().media_age_seconds.is_none());
        d.playback(1, None, true);
        assert!(!d.status().media_healthy);
        d.event(
            "retry_scheduled",
            &json!({"delay_ms":2000,"retry_reason":"media_timeout"}),
        );
        assert!(!d.status().ready);
        assert_eq!(d.status().active_streams, 0);
        assert!(d.metrics().contains("event=\"timeout\"} 1"));
        assert!(d.metrics().contains("media_age_seconds NaN"));
    }
    async fn request(d: Arc<Diagnostics>, path: &str) -> String {
        let (mut client, server) = tokio::io::duplex(16384);
        let worker = tokio::spawn(respond(server, d));
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        worker.await.unwrap().unwrap();
        response
    }
    #[tokio::test]
    async fn health_status_and_metrics_have_distinct_readiness() {
        let d = Arc::new(Diagnostics::default());
        assert!(request(d.clone(), "/healthz")
            .await
            .starts_with("HTTP/1.1 503"));
        assert!(request(d.clone(), "/status")
            .await
            .contains("\"ready\":false"));
        d.event("supervisor_authenticated", &json!({}));
        assert!(request(d.clone(), "/healthz")
            .await
            .starts_with("HTTP/1.1 200"));
        assert!(!d.status().media_healthy); // authenticated with no consumer is not video evidence
        d.playback(1, None, true);
        assert!(request(d.clone(), "/healthz")
            .await
            .starts_with("HTTP/1.1 503"));
        d.playback(1, Some(0.0), false);
        assert!(request(d.clone(), "/metrics")
            .await
            .contains("motorola_connector_media_healthy 1"));
        assert!(request(d, "/private").await.starts_with("HTTP/1.1 404"));
    }
    #[tokio::test]
    async fn oversized_headers_are_bounded_and_never_echoed() {
        let (mut client, server) = tokio::io::duplex(8192);
        let worker = tokio::spawn(respond(server, Arc::new(Diagnostics::default())));
        client.write_all(&vec![b'X'; 4608]).await.unwrap();
        let error = worker.await.unwrap().unwrap_err();
        assert_eq!(error.to_string(), "http_request_limit");
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.is_empty());
    }
}
