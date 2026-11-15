Independent Motorola PIP1610 receiver — experimental

This Rust application implements the recovered Orbweb direct TCP transport.
The runtime contains no Motorola/Orbweb binary, Android runtime or emulator.
It uses cloud-assisted discovery and rendezvous, then restricts media peer
connections to the configured owned-camera IP. It does not prove or prevent
independent camera uploads to the cloud.

The code supports IPv4 direct mode, existing legitimate camera credentials,
bounded experiments and an indefinitely supervised service (seconds=0).
A standalone Docker Compose deployment is documented in README.md.
Relay/STUN fallback and automatic credential renewal are not implemented.
Independent email-code login and saved-session resume are available through
the separate motorola-account helper; see docs/ACCOUNT-LOGIN.txt.
The parent monitor is not modified. Successful local reception does not establish
that independent uploads have stopped or that credentials will remain valid.

Build and offline tests:
  cargo test --locked
  cargo build --locked --release
  docker build -t local/motorola-receiver:experiment .
The Docker build context allowlist excludes inputs, secrets and recordings.
All test vectors are synthetic. Tests/fixtures document which expected bytes
were actually measured against the original SDK in a network-disabled oracle.
The oracle and proprietary binary are private research inputs, not build deps.

Configuration: pass --config /absolute/path/to/private-settings.json.
Both settings and credentials must be regular files without group/world access
(chmod600), and their parent directories should be private (chmod700).
Settings schema (these addresses are documentation examples, not usable defaults):
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
Omitting bind_ip selects the kernel route's source address without sending a
probe packet. An explicit bind_ip is supported for a chosen Docker interface.
For the service, set seconds=0, listen="0.0.0.0:8554",
allow_nonloopback_listen=true and metrics_listen="0.0.0.0:9091". Expose those
ports only to the existing internal Docker/monitoring networks, not the internet.
The authentication listener always stays on 127.0.0.1 at the RTSP port plus one.
Generate and retain your own random uppercase identity with group lengths
8-4-4-4-12; the sample above is for tests/documentation only. This identity is
separate from account authentication and is not a camera MAC address.
Credentials schema: session_id, rendezvous, transport_user, transport_password.
Existing connector credential files use these fields. sid/rdz_host aliases are
also accepted. Do not publish or paste credential values into logs/CLI flags.
Use the legitimate RDZ DNS hostname, not a cached IP: TLS hostname verification
is enabled. The supplied APK's global deployment uses rdz.orbwebsys.com.
Do not blindly replace region-specific credentials/endpoints from other builds.

RTSP becomes available at rtsp://127.0.0.1:28554/blinkhd after stream_ready.
The following loopback port (28555 in this example) is reserved for the initial
camera authentication channel. RTSP credentials, if required by the camera,
are separate from transport_user/transport_password; retain them privately in
your existing FFmpeg/go2rtc configuration. Force RTSP-over-TCP/interleaved RTP.
The application forwards encoded media; it does not transcode, record or detect
motion. FFmpeg/go2rtc/Frigate remain responsible for these downstream functions.

Diagnostics are JSON lines on stderr: attempt numbers, bootstrap commands and
lengths, capability mode, candidates without IP/identity strings, key-exchange
stage, channel opens/closes, counters, heartbeat misses, retries and deadlines.
No keys, account passwords, signaling identifiers or video payloads are logged.
Retry delays start at2seconds, double to30seconds, and reset after60seconds of
authenticated operation. Before each attempt, the receiver checks that its local
source address can be bound (UDP bind/route selection; no probe packet). Missing
interfaces enter waiting_network and are checked once a second, with one wait
and one restored log per transition. This wait is cancellable and does not grow
cloud-failure backoff. It does not test actual internet/camera reachability or
shorten a retry delay already scheduled before interface loss.
A nonzero run duration includes setup and retry delay;
zero has no deadline. SIGINT or
SIGTERM cancels owned sockets/tasks; this does not reset/reconfigure the camera.

Read-only operational endpoints (enabled only when metrics_listen is configured):
  GET /metrics   Prometheus gauges and event counters (existing connector names)
  GET /status    JSON readiness, attempt, ages, retry/failure state
  GET /healthz   200 when authenticated and operational, otherwise503
CLI helpers, each followed by --config PRIVATE_CONFIG_JSON:
  check-config  validates private configuration/credentials without connecting
  status        prints operational JSON from the metrics listener
  healthcheck   exits0 only when /healthz succeeds; emits no private data
HTTP requests are limited to4KiB and2seconds with at most16workers. No endpoint
returns camera identifiers, credentials, media or diagnostic capture contents.
JSON logs remain on stderr for the deployment's rotating Docker log driver.

Ready means authenticated; media_healthy additionally requires an active PLAY
and observed valid video RTP. Missing age measurements are JSON null/Prometheus
NaN. With no active consumers the media watchdog is disabled. Parsed PLAY starts
a fresh grace period; PAUSE/TEARDOWN and closing channels stop that expectation.
After media_timeout_seconds without advancing valid video RTP, the attempt
fails with media_timeout and reconnects through the bounded backoff. Heartbeats,
RTSP replies, audio, RTCP, duplicate and out-of-order RTP do not reset that clock.
The default video interleaved channel0 is observed for this camera; change it
only if the downstream client negotiates a different video channel. An explicit timer wakes the actor at the earliest active video deadline, even
when neither packets nor heartbeats arrive. An already-running bounded tunnel
write can defer handling by up to its10second write timeout. RTP progress proves
reception, not codec decoding, image changes or Frigate storage. For recovery
experiments media_timeout_seconds may be reduced (minimum10seconds); the default
remains60seconds until false-positive behavior has been measured.

Optional repair_interleaved_response (defaultfalse) repairs the observed camera
quirk of a complete RTSP response inserted between an interleaved frame header
and its RTP payload. It preserves raw passive evidence and forwards validated
reordered bytes. Ambiguous/invalid repair closes only that local channel with a
static reason, never a midstream raw fallback. The watchdog observes the repaired
stream when enabled; normal raw-observer failure remains separately visible.

Operational testing:
- Reserve local ports before contacting the camera.
- Avoid concurrent original/new camera sessions; prior sessions interfered.
- Keep the original container, configuration, secrets and immutable image ID.
- Use a separate experiment image and an independent bounded rollback runner.
- Stop the test and start the unchanged original container to restore service.
- Verify original container health and downstream video after restoration.
No host/router firewall change or camera firmware operation is needed.

Publication remains a separate review. This directory has publish=false; no
public repository has been created. Dependency licenses and cipher limitations
are documented in tests/fixtures/CRYPTO-PROVENANCE.txt. The legacy protocol's
crypto is implemented for compatibility, not recommended for new designs.

Optional private failure investigation:
Set capture_dir only to a private existing directory (mode700), mounted writable
at that same path inside the experimental container. Default is disabled.
This deliberately captures session keys plus encrypted/decrypted video around a
passive parser failure. Treat captures as highly private, exclude the directory
from Git and backups intended for publication, and never upload it to analysis
services. Capture files are created mode600; limits are2attempts/session,
4files and32MiB/directory across retries, with a2MiB/32packet memory ring.
A crash can leave .capture.lock; capture fails closed until the owner checks and
removes that empty lock. Failure to capture never stops media forwarding.
Snapshot writes run in separately tracked tasks; ordinary event logs include
only success/failure, request method names and sequence discontinuity counts.

Independent email-code onboarding (experimental):
A separate Rust helper, motorola-account, implements the app's email OTP flow,
private session persistence, session/master-token resume and camera enumeration.
Its offline export-camera command writes a new receiver credentials file and
refuses overwrites. See docs/ACCOUNT-LOGIN.txt for the tested protocol, private
file workflow and current limitations. Build its isolated container with
Dockerfile.account. The normal receiver's startup behavior is unchanged: it loads
its configured camera credentials; it does not automatically request email codes.
