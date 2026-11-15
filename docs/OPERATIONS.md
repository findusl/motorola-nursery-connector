# Receiver configuration and operations

For installation and interactive onboarding, start with the [README](../README.md).
The receiver forwards encoded media; recording, decoding and motion detection
belong to FFmpeg, go2rtc, Frigate or another downstream consumer.

## Configuration

Run `motorola-receiver --config /absolute/path/to/private-settings.json`.
Settings and credentials must be regular files without group/world access
(mode `0600`); keep their parent directories private (mode `0700`).

Example settings use documentation addresses and a synthetic identity:

```json
{
  "credentials": "/run/secrets/camera.json",
  "camera_ip": "192.0.2.10",
  "bind_ip": "192.0.2.20",
  "listen": "127.0.0.1:28554",
  "client_token": "ABCDEFGH-IJKL-MNOP-QRST-UVWXYZABCDEF",
  "seconds": 900,
  "metrics_listen": "127.0.0.1:9091",
  "repair_interleaved_response": false,
  "media_timeout_seconds": 60,
  "video_rtp_channel": 0
}
```

- `camera_ip`: the selected camera's IPv4 address. IP discovery is not implemented.
- `bind_ip`: optional source address for a particular interface. Omitting it uses
  the kernel's route selection without sending a probe packet.
- `listen`: local RTSP endpoint. A non-loopback listener requires
  `allow_nonloopback_listen: true`. Keep it on a private network.
- `client_token`: persistent, independently generated uppercase identity with
  group lengths 8-4-4-4-12. The setup wizard generates it. Do not reuse the example.
- `seconds`: zero runs indefinitely; a positive duration includes setup and retries.
- `metrics_listen`: optional operational HTTP listener. Keep it private too.
- `media_timeout_seconds`: video watchdog timeout, between 10 and 600 seconds.
  The receiver default is 60; the setup wizard configures 20.
- `repair_interleaved_response`: enables the observed camera framing repair,
  described below. Default false; the setup wizard enables it.
- `video_rtp_channel`: negotiated video interleaved channel, default zero.

For a service, the wizard uses `listen: "0.0.0.0:8554"`,
`allow_nonloopback_listen: true`, `metrics_listen: "0.0.0.0:9091"` and `seconds: 0`.
The auxiliary camera authentication listener stays on loopback, using the RTSP
port plus one. Reserve both ports before starting another instance.

Credential fields are `session_id`, `rendezvous`, `transport_user` and
`transport_password`; `sid`/`rdz_host` aliases are also accepted. Account login
exports these privately. The camera SID differs from the account session ID.
Use the legitimate rendezvous DNS hostname for verified HTTPS, rather than a
cached IP. The inspected app uses `rdz.orbwebsys.com`; other regions are unverified.

The RTSP path is `/blinkhd`; use TCP/interleaved RTP. Camera RTSP authentication
is separate from transport credentials; see the README's tested defaults.
The receiver does not automatically request email codes or renew account tokens.
See [account login](ACCOUNT-LOGIN.txt) for session restoration and advanced commands.

## Health and retries

Logs are JSON lines on stderr, containing retry attempts, classified failures,
heartbeat misses, counters and timings. Normal logs omit keys, passwords,
signaling identifiers and video payloads. Configure Docker log rotation for
long-running deployments.

Retry delays start at 2 seconds, double to 30 seconds, and reset after 60 seconds
of authenticated operation. A missing configured source address enters
`waiting_network`, polled every second, without increasing cloud backoff. This
checks local address availability, not remote reachability. It does not shorten
an already scheduled retry. SIGINT/SIGTERM close the receiver's sockets and tasks;
they do not reset or reconfigure the camera.

When `metrics_listen` is enabled:

| Endpoint | Purpose |
| --- | --- |
| `/metrics` | Prometheus metrics |
| `/status` | Readiness, session/media age, retry and failure state |
| `/healthz` | HTTP 200 when authenticated and operational; otherwise 503 |

CLI helpers accept the same `--config` argument: `check-config` validates without
connecting, `status` prints operational JSON, and `healthcheck` reports health
through its exit status. HTTP requests are bounded to 4 KiB and 2 seconds with
at most 16 workers. These endpoints return no credentials or media.

`ready` means authenticated. `media_healthy` additionally requires an active PLAY
and advancing video RTP. No active consumer means the media watchdog is disabled.
PLAY starts a grace period; PAUSE/TEARDOWN or channel closure ends it. Audio,
heartbeats, RTSP replies, duplicate RTP and out-of-order RTP do not reset the video
watchdog. A timeout triggers reconnect/backoff. A bounded tunnel write can defer
handling by up to its 10-second timeout. RTP progress does not prove decoding,
image changes or successful downstream recording. Missing ages are JSON null or
Prometheus NaN.

The optional framing repair handles an observed complete RTSP response inserted
between an interleaved frame header and its RTP payload. It forwards validated,
reordered bytes; ambiguous data closes that local channel without silently
falling back to raw forwarding. The watchdog observes repaired video when enabled.

## Private diagnostics and recovery experiments

Keep a known-working configuration and image for rollback. Avoid concurrent
phone/new receiver sessions during tests: previous sessions interfered. Bound
experiments, restore the original service afterward, and verify downstream video
and recording. See [recovery results](RECOVERY-CHAOS.txt).

Optional `capture_dir` must point to an existing private directory (mode `0700`)
mounted writable at that path. Capture is disabled by default. It deliberately
records session keys and encrypted/decrypted video around parser failures.
Never commit or upload these captures to external analysis services.

Capture files use mode `0600`. Limits are two attempts per session, four files
and 32 MiB per directory across retries, with a 2 MiB/32-packet memory ring.
A crash can leave `.capture.lock`; inspect the directory before removing that
empty lock. Capture failure does not stop media forwarding. Snapshot writes use
separate tasks, and ordinary logs contain only bounded diagnostic metadata.

Test fixtures use synthetic inputs; their provenance records which outputs were
measured using the original SDK offline. The proprietary oracle/runtime is not
a build dependency. See [crypto provenance](../tests/fixtures/CRYPTO-PROVENANCE.txt)
for dependency and cipher limitations. Legacy cryptography is implemented for
compatibility, not recommended for new designs.
