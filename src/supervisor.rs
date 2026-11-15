// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded retry supervisor. Each attempt owns its sockets and child tasks;
//! dropping its future on shutdown/deadline tears those resources down.
use crate::telemetry::Diagnostics;
use crate::{
    session,
    settings::{Credentials, Settings},
    CodecError,
};
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::{future::Future, sync::Arc};
use tokio::{
    sync::watch,
    time::{sleep, sleep_until, Duration, Instant},
};

#[derive(Clone, Copy)]
struct RetryPolicy {
    initial: Duration,
    maximum: Duration,
    stable: Duration,
}
impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(2),
            maximum: Duration::from_secs(30),
            stable: Duration::from_secs(60),
        }
    }
}

/// Return the delay for this failure and the following failure. Keeping this
/// calculation pure lets tests verify the cap/reset without scheduler timing.
fn backoff_step(current: Duration, stable: bool, policy: RetryPolicy) -> (Duration, Duration) {
    let delay = if stable { policy.initial } else { current }.min(policy.maximum);
    (delay, delay.saturating_mul(2).min(policy.maximum))
}

fn log(diagnostics: &Diagnostics, start: Instant, event: &str, detail: Value) {
    diagnostics.event(event, &detail);
    eprintln!(
        "{}",
        json!({"event": event, "elapsed_ms": start.elapsed().as_millis(), "detail": detail})
    );
}

/// Emit known error classifications, never arbitrary peer/library error text.
/// Unknown errors remain retryable but cannot expose payloads through this log.
pub(crate) fn retry_reason(error: &anyhow::Error) -> &'static str {
    for cause in error.chain() {
        let text = cause.to_string();
        for known in [
            "setup_timeout",
            "media_timeout",
            "session_returned_unexpectedly",
            "key_request_timeout",
            "candidate_timeout",
            "auth_timeout",
            "auth_rejected",
            "heartbeat_timeout",
            "write_timeout",
            "frame_limit",
            "bootstrap_connect",
            "direct_control_connect",
            "frame_reader_closed",
            "discovery_request_failed",
            "discovery_body_read",
            "discovery_body_limit",
            "discovery_rejected",
            "discovery_invalid_json",
            "auth_invalid_json",
            "auth_length",
            "channel_header_mismatch",
            "sequence_exhausted",
            "channel_id_exhausted",
            "local_event_channel_closed",
            "random_failed",
            "worker_task_failed",
            "listener_failed",
            "key_request_length",
            "key_request_missing",
            "unexpected_pre_key_command",
            "direct_mode_not_supported",
            "discovery_missing_tatip",
            "discovery_invalid_tatip",
            "discovery_missing_relayip",
            "discovery_invalid_relayip",
            "bootstrap_rejected_command_105",
            "bootstrap_rejected_command_109",
            "bootstrap_rejected_command_123",
        ] {
            if text == known {
                return known;
            }
        }
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        return match error.kind() {
            std::io::ErrorKind::UnexpectedEof => "peer_eof",
            std::io::ErrorKind::ConnectionReset => "connection_reset",
            std::io::ErrorKind::ConnectionRefused => "connection_refused",
            std::io::ErrorKind::ConnectionAborted => "connection_aborted",
            std::io::ErrorKind::BrokenPipe => "broken_pipe",
            std::io::ErrorKind::TimedOut => "io_timeout",
            std::io::ErrorKind::AddrInUse => "address_in_use",
            _ => "io_failure",
        };
    }
    if error.downcast_ref::<CodecError>().is_some() {
        return "codec_failure";
    }
    if let Some(error) = error.downcast_ref::<crate::crypto::CryptoError>() {
        return match error {
            crate::crypto::CryptoError::InvalidHandshake => "invalid_key_handshake",
            crate::crypto::CryptoError::InvalidParameters => "unsupported_key_parameters",
            crate::crypto::CryptoError::RandomUnavailable => "random_failed",
            crate::crypto::CryptoError::InvalidCiphertext => "invalid_ciphertext",
            crate::crypto::CryptoError::CipherFailure => "cipher_failure",
            crate::crypto::CryptoError::Codec(_) => "codec_failure",
        };
    }
    if error
        .downcast_ref::<crate::signaling::SignalingError>()
        .is_some()
    {
        return "signaling_failure";
    }
    "attempt_failed"
}

async fn shutdown_signal() -> Result<&'static str> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("sigterm_handler_registration")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => { result.context("sigint_handler")?; Ok("sigint") },
        result = terminate.recv() => { result.context("sigterm_handler_closed")?; Ok("sigterm") },
    }
}

/// Local interface availability only: UDP bind/route selection sends no packet.
/// This intentionally says nothing about internet or camera reachability.
fn local_network_available(settings: &Settings) -> bool {
    settings
        .source_ip()
        .ok()
        .is_some_and(|ip| std::net::UdpSocket::bind(std::net::SocketAddr::new(ip, 0)).is_ok())
}

/// Waiting remains inside the attempt future, so the outer deadline and signal
/// handler cancel it. Missing local interfaces do not become failed cloud
/// attempts, and therefore cannot grow the ordinary retry backoff.
async fn wait_for_local_network<Check, Emit>(
    mut available: Check,
    mut emit: Emit,
    interval: Duration,
) where
    Check: FnMut() -> bool,
    Emit: FnMut(&'static str, Duration),
{
    if available() {
        return;
    }
    let start = Instant::now();
    emit("local_network_wait", Duration::ZERO);
    loop {
        sleep(interval).await;
        if available() {
            emit("local_network_restored", start.elapsed());
            return;
        }
    }
}

/// The configured duration covers setup, active attempts and retry delays.
/// Completion means a currently authenticated session, not proof of video flow.
/// User-requested shutdown is a successful orderly exit regardless of readiness.
pub async fn supervise(s: Settings, c: Credentials) -> Result<()> {
    let duration = Duration::from_secs(s.seconds);
    let diagnostics = Arc::new(Diagnostics::default());
    let listener = match s.metrics_listen {
        Some(addr) => Some(
            tokio::net::TcpListener::bind(addr)
                .await
                .context("metrics_listener_bind")?,
        ),
        None => None,
    };
    let attempt_diagnostics = diagnostics.clone();
    let driver = supervise_with_monitor(
        duration,
        RetryPolicy::default(),
        move |ready| {
            let settings = s.clone();
            let credentials = c.clone();
            let diagnostics = attempt_diagnostics.clone();
            async move {
                let start = Instant::now();
                wait_for_local_network(
                    || local_network_available(&settings),
                    |event, elapsed| {
                        log(
                            &diagnostics,
                            start,
                            event,
                            json!({"wait_elapsed_ms":elapsed.as_millis(),"poll_interval_ms":1000}),
                        )
                    },
                    Duration::from_secs(1),
                )
                .await;
                session::run_monitored(settings, credentials, ready, diagnostics).await
            }
        },
        shutdown_signal(),
        diagnostics.clone(),
    );
    if let Some(listener) = listener {
        tokio::select! {
            result = driver => result,
            result = crate::telemetry::serve(listener, diagnostics) => { result?; Err(anyhow!("metrics_server_stopped")) },
        }
    } else {
        driver.await
    }
}

/// Injectable driver keeps retry/cancellation tests independent of real signals,
/// credentials, clocks with second-long waits, and camera/network connections.
#[cfg(test)]
async fn supervise_with<F, Attempt, Shutdown>(
    duration: Duration,
    policy: RetryPolicy,
    run_attempt: F,
    shutdown: Shutdown,
) -> Result<()>
where
    F: FnMut(watch::Sender<bool>) -> Attempt,
    Attempt: Future<Output = Result<()>>,
    Shutdown: Future<Output = Result<&'static str>>,
{
    supervise_with_monitor(
        duration,
        policy,
        run_attempt,
        shutdown,
        Arc::new(Diagnostics::default()),
    )
    .await
}

async fn supervise_with_monitor<F, Attempt, Shutdown>(
    duration: Duration,
    policy: RetryPolicy,
    mut run_attempt: F,
    shutdown: Shutdown,
    diagnostics: Arc<Diagnostics>,
) -> Result<()>
where
    F: FnMut(watch::Sender<bool>) -> Attempt,
    Attempt: Future<Output = Result<()>>,
    Shutdown: Future<Output = Result<&'static str>>,
{
    let start = Instant::now();
    let end = async {
        if duration.is_zero() {
            std::future::pending::<()>().await;
        } else {
            sleep_until(start + duration).await;
        }
    };
    tokio::pin!(end);
    tokio::pin!(shutdown);
    let mut number = 0u64;
    let mut next_delay = policy.initial;
    loop {
        number = number.checked_add(1).context("attempt_number_exhausted")?;
        let (ready_tx, mut ready_rx) = watch::channel(false);
        let mut ready_open = true;
        let mut ready_since = None;
        log(
            &diagnostics,
            start,
            "supervisor_attempt_start",
            json!({"attempt_number":number}),
        );
        // Scope is intentional: timeout/shutdown/error drops the attempt before
        // sleeping or starting another connection, including all RAII resources.
        let failure = {
            let attempt = run_attempt(ready_tx);
            tokio::pin!(attempt);
            loop {
                tokio::select! {
                    biased;
                    stop = &mut shutdown => {
                        let signal = stop?;
                        log(&diagnostics, start, "supervisor_shutdown", json!({"attempt_number":number,"signal":signal,"authenticated":*ready_rx.borrow()}));
                        return Ok(());
                    },
                    change = ready_rx.changed(), if ready_open => {
                        if change.is_err() { ready_open = false; }
                        else if *ready_rx.borrow_and_update() {
                            if ready_since.is_none() { ready_since = Some(Instant::now()); }
                            log(&diagnostics, start, "supervisor_authenticated", json!({"attempt_number":number}));
                        } else { ready_since = None; }
                    },
                    result = &mut attempt => {
                        match result {
                            Ok(()) => {
                                if duration.is_zero() { break anyhow!("session_returned_unexpectedly"); }
                                let ready = *ready_rx.borrow();
                                log(&diagnostics, start, "bounded_duration_complete", json!({"attempt_number":number,"authenticated":ready,"phase":"attempt_returned"}));
                                return if ready { Ok(()) } else { Err(anyhow!("attempt_completed_without_authentication")) };
                            },
                            Err(error) => break error,
                        }
                    },
                    // An already-ready attempt failure wins over the deadline:
                    // a stale true readiness flag must not hide a known error.
                    _ = &mut end => {
                        let ready = *ready_rx.borrow();
                        log(&diagnostics, start, "bounded_duration_complete", json!({"attempt_number":number,"authenticated":ready,"phase":"attempt"}));
                        return if ready { Ok(()) } else { Err(anyhow!("test_ended_without_live_authenticated_session")) };
                    },
                }
            }
        };
        let stable = ready_since.is_some_and(|since| since.elapsed() >= policy.stable);
        let (delay, following_delay) = backoff_step(next_delay, stable, policy);
        let reason = retry_reason(&failure);
        diagnostics.failure(reason);
        let remaining = if duration.is_zero() {
            delay
        } else {
            duration.saturating_sub(start.elapsed())
        };
        let actual_delay = delay.min(remaining);
        log(
            &diagnostics,
            start,
            "retry_scheduled",
            json!({"attempt_number":number,"retry_reason":reason,"delay_ms":actual_delay.as_millis(),"backoff_ms":delay.as_millis(),"stable_reset":stable}),
        );
        // Failed attempts are never considered authenticated during backoff,
        // even if a previous attempt had been healthy for some time.
        tokio::select! {
            biased;
            stop = &mut shutdown => {
                let signal = stop?;
                log(&diagnostics, start, "supervisor_shutdown", json!({"attempt_number":number,"signal":signal,"authenticated":false,"phase":"backoff"}));
                return Ok(());
            },
            _ = &mut end => {
                log(&diagnostics, start, "bounded_duration_complete", json!({"attempt_number":number,"authenticated":false,"phase":"backoff"}));
                return Err(anyhow!("test_ended_without_live_authenticated_session"));
            },
            _ = sleep(actual_delay) => {},
        }
        next_delay = following_delay;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::pending,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    fn fast() -> RetryPolicy {
        RetryPolicy {
            initial: Duration::from_millis(5),
            maximum: Duration::from_millis(20),
            stable: Duration::from_millis(20),
        }
    }
    fn no_signal() -> impl Future<Output = Result<&'static str>> {
        pending()
    }
    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn healthy_deadline_succeeds_and_drops_attempt() {
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        supervise_with(
            Duration::from_millis(20),
            fast(),
            move |ready| {
                let flag = flag.clone();
                async move {
                    let _guard = DropFlag(flag);
                    ready.send(true).unwrap();
                    pending::<Result<()>>().await
                }
            },
            no_signal(),
        )
        .await
        .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn unready_deadline_is_failure() {
        let result = supervise_with(
            Duration::from_millis(10),
            fast(),
            |_ready| pending::<Result<()>>(),
            no_signal(),
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "test_ended_without_live_authenticated_session"
        );
    }

    #[tokio::test]
    async fn past_authentication_does_not_turn_failed_backoff_into_success() {
        let result = supervise_with(
            Duration::from_millis(15),
            RetryPolicy {
                initial: Duration::from_secs(1),
                ..fast()
            },
            |ready| async move {
                ready.send(true).unwrap();
                sleep(Duration::from_millis(3)).await;
                Err(anyhow!("connection_reset"))
            },
            no_signal(),
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "test_ended_without_live_authenticated_session"
        );
    }

    #[tokio::test]
    async fn exponential_backoff_is_capped() {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let times = starts.clone();
        let result = supervise_with(
            Duration::from_secs(2),
            fast(),
            move |ready| {
                let index = {
                    let mut starts = times.lock().unwrap();
                    starts.push(Instant::now());
                    starts.len()
                };
                async move {
                    if index == 6 {
                        ready.send(true).unwrap();
                        Ok(())
                    } else {
                        Err(anyhow!("synthetic_failure"))
                    }
                }
            },
            no_signal(),
        )
        .await;
        result.unwrap();
        let starts = starts.lock().unwrap();
        for (pair, millis) in starts.windows(2).zip([5, 10, 20, 20, 20]) {
            assert!(pair[1].duration_since(pair[0]) >= Duration::from_millis(millis));
        }
    }

    #[tokio::test]
    async fn stable_authenticated_attempt_resets_backoff() {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let failed_at = Arc::new(Mutex::new(None));
        let times = starts.clone();
        let failed = failed_at.clone();
        supervise_with(
            Duration::from_secs(2),
            fast(),
            move |ready| {
                let index = {
                    let mut starts = times.lock().unwrap();
                    starts.push(Instant::now());
                    starts.len()
                };
                let failed = failed.clone();
                async move {
                    if index == 3 {
                        ready.send(true).unwrap();
                        sleep(Duration::from_millis(35)).await;
                        *failed.lock().unwrap() = Some(Instant::now());
                    }
                    if index == 4 {
                        ready.send(true).unwrap();
                        Ok(())
                    } else {
                        Err(anyhow!("synthetic_failure"))
                    }
                }
            },
            no_signal(),
        )
        .await
        .unwrap();
        let delay = starts.lock().unwrap()[3].duration_since(failed_at.lock().unwrap().unwrap());
        assert!(delay >= Duration::from_millis(5));
    }

    #[tokio::test]
    async fn shutdown_cancels_active_attempt_and_prevents_retry() {
        let dropped = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));
        let flag = dropped.clone();
        let calls = count.clone();
        supervise_with(
            Duration::from_secs(2),
            fast(),
            move |_ready| {
                calls.fetch_add(1, Ordering::SeqCst);
                let flag = flag.clone();
                async move {
                    let _guard = DropFlag(flag);
                    pending::<Result<()>>().await
                }
            },
            async {
                sleep(Duration::from_millis(10)).await;
                Ok("synthetic_sigterm")
            },
        )
        .await
        .unwrap();
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_interrupts_backoff() {
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        supervise_with(
            Duration::from_secs(2),
            RetryPolicy {
                initial: Duration::from_secs(1),
                ..fast()
            },
            move |_ready| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err(anyhow!("synthetic_failure")) }
            },
            async {
                sleep(Duration::from_millis(10)).await;
                Ok("synthetic_sigint")
            },
        )
        .await
        .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fresh_attempt_cannot_inherit_previous_authentication() {
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        let result = supervise_with(
            Duration::from_millis(30),
            fast(),
            move |ready| {
                let index = calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if index == 0 {
                        ready.send(true).unwrap();
                        Err(anyhow!("synthetic_failure"))
                    } else {
                        pending::<Result<()>>().await
                    }
                }
            },
            no_signal(),
        )
        .await;
        assert!(count.load(Ordering::SeqCst) >= 2);
        assert_eq!(
            result.unwrap_err().to_string(),
            "test_ended_without_live_authenticated_session"
        );
    }

    #[tokio::test]
    async fn successful_return_still_requires_authentication() {
        let error = supervise_with(
            Duration::from_secs(1),
            fast(),
            |_ready| async { Ok(()) },
            no_signal(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "attempt_completed_without_authentication"
        );
    }

    #[test]
    fn exact_backoff_sequence_cap_and_stability_reset() {
        let policy = RetryPolicy::default();
        let mut current = policy.initial;
        for expected in [2, 4, 8, 16, 30, 30] {
            let (delay, next) = backoff_step(current, false, policy);
            assert_eq!(delay, Duration::from_secs(expected));
            current = next;
        }
        let (delay, next) = backoff_step(current, true, policy);
        assert_eq!(delay, Duration::from_secs(2));
        assert_eq!(next, Duration::from_secs(4));
    }

    #[test]
    fn retry_reason_never_echoes_unknown_error_text() {
        assert_eq!(
            retry_reason(&anyhow!("sensitive-token=abcdef")),
            "attempt_failed"
        );
        assert_eq!(retry_reason(&anyhow!("auth_rejected")), "auth_rejected");
        assert_eq!(
            retry_reason(&std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()),
            "peer_eof"
        );
    }
    #[tokio::test]
    async fn indefinite_mode_retries_until_signal_and_drops_active_attempt() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = dropped.clone();
        supervise_with(
            Duration::ZERO,
            fast(),
            move |ready| {
                let index = calls.fetch_add(1, Ordering::SeqCst);
                let flag = flag.clone();
                async move {
                    if index == 0 {
                        Err(anyhow!("heartbeat_timeout"))
                    } else {
                        let _guard = DropFlag(flag);
                        ready.send(true).unwrap();
                        pending::<Result<()>>().await
                    }
                }
            },
            async {
                sleep(Duration::from_millis(30)).await;
                Ok("synthetic_sigterm")
            },
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(dropped.load(Ordering::SeqCst));
    }
    #[tokio::test]
    async fn indefinite_mode_treats_unexpected_success_as_retryable() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        supervise_with(
            Duration::ZERO,
            fast(),
            move |ready| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    ready.send(true).unwrap();
                    Ok(())
                }
            },
            async {
                sleep(Duration::from_millis(30)).await;
                Ok("synthetic_sigterm")
            },
        )
        .await
        .unwrap();
        assert!(attempts.load(Ordering::SeqCst) >= 2);
    }
    #[tokio::test]
    async fn missing_interface_emits_one_wait_and_one_restore_before_proceeding() {
        let mut probes = 0;
        let mut events = Vec::new();
        wait_for_local_network(
            || {
                probes += 1;
                probes >= 4
            },
            |event, elapsed| events.push((event, elapsed)),
            Duration::from_millis(2),
        )
        .await;
        assert_eq!(probes, 4);
        assert_eq!(
            events.iter().map(|e| e.0).collect::<Vec<_>>(),
            ["local_network_wait", "local_network_restored"]
        );
        assert!(events[1].1 >= Duration::from_millis(6));
    }
    #[tokio::test]
    async fn available_interface_proceeds_without_transition_logs() {
        let mut events = Vec::new();
        wait_for_local_network(
            || true,
            |event, _| events.push(event),
            Duration::from_secs(1),
        )
        .await;
        assert!(events.is_empty());
    }
    #[tokio::test]
    async fn network_wait_is_cancelled_by_supervisor_without_retries_or_cloud_work() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let calls = attempts.clone();
        let cloud = Arc::new(AtomicBool::new(false));
        let cloud_called = cloud.clone();
        let d = Arc::new(Diagnostics::default());
        let monitor = d.clone();
        supervise_with_monitor(
            Duration::ZERO,
            fast(),
            move |_ready| {
                calls.fetch_add(1, Ordering::SeqCst);
                let d = monitor.clone();
                let cloud = cloud_called.clone();
                async move {
                    wait_for_local_network(
                        || false,
                        |event, _| d.event(event, &json!({})),
                        Duration::from_millis(2),
                    )
                    .await;
                    cloud.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
            async {
                sleep(Duration::from_millis(15)).await;
                Ok("synthetic_sigterm")
            },
            d.clone(),
        )
        .await
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!cloud.load(Ordering::SeqCst));
        assert_eq!(d.status().state, "stopped");
        assert!(d.metrics().contains("event=\"session_failed\"} 0"));
    }
}
