# Independent Motorola camera receiver

An experimental Rust service that exposes a Motorola camera's live stream to
FFmpeg, go2rtc or Frigate through a local RTSP endpoint. Includes independent
email-code login and camera selection. No Motorola/Orbweb SDK, Android runtime,
or emulator is required to build or run it.

**All project-specific code and documentation, including this README, are
AI-written. AI agents also write commit messages, create commits, and push them
to GitHub under the maintainer's direction and authorization. It works for me;
it has not had a comprehensive human review or independent security audit.** See
[AI disclosure](AI_DISCLOSURE.md) for scope and validation limits.

## Compatibility and privacy

Tested with one Motorola PIP1610 HD CONNECT, hardware H91-V1.3, firmware V1.6.54,
and the protocol recovered from Motorola Nursery 2.2.18 (4350). Other cameras,
accounts and regions are unverified. This is an unofficial interoperability
project, unaffiliated with Motorola or Orbweb.

Account login and stream establishment still use cloud services. Video transport
is restricted to the camera IPv4 address you configure; relay fallback is not
implemented. Receiving video locally does **not** prevent the camera from making
independent uploads. No firmware, pairing, router rules or parent-monitor settings
are modified. The implementation is designed to preserve the dedicated parent monitor;
check its operation in your own setup.
The service forwards media; Frigate or another downstream tool records it and
performs motion detection.

## Install on a Linux server

Prerequisites: Docker Engine with Compose v2, access to your Motorola account's
email, and a network route from the Docker host to the camera. Obtain the camera's
LAN IPv4 address from your router; automatic discovery of that address is not
implemented. The camera can be on a separate VLAN, as in the maintainer's tested
setup, provided routing and firewall rules allow the receiver to reach it.
Run all commands below from this repository's root after cloning/downloading it.
Use an account that already owns the paired camera. Close the phone's live view
during initial testing: simultaneous phone/receiver sessions have interfered.

```sh
umask 077
mkdir -p state
chmod 700 state
export LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)"
docker compose --profile setup build
docker compose --profile setup run --rm account
```

The wizard asks for your email, requests one code, lists account cameras, asks
which camera to use if there is more than one, then asks for its LAN IP address.
Names may appear percent-encoded. The code is entered in your terminal; **input
is visible**, so do not record/share the terminal session. The helper services
server heartbeats while waiting for the code and saves private files mode 0600.
The state directory must be owned by the UID/GID passed above.

It generates `state/camera.json` (camera transport credentials) and
`state/config.json` (service settings). Start and inspect the service:

```sh
docker compose up -d receiver
docker compose logs --tail 50 receiver
docker compose exec receiver motorola-receiver status --config /etc/connector/config.json
```

The listener is published only on the host loopback address, port 8554. It has no
additional access-control layer: keep it private. A host-installed consumer can
use the RTSP URL below with TCP transport. The tested app supplies this shared
RTSP authentication pair; it is a protocol default, **not** the maintainer's
account password or the account-specific camera token:

```text
rtsp://Pascal:5GenCare.com@127.0.0.1:8554/blinkhd
```

These app constants are referenced at CameraModel._startM2M AOT addresses
0x764e90/0x764e98 in the supplied app version. The legacy branch has different
defaults; compatibility with it is untested. Never assume these defaults secure
an exposed listener. For go2rtc, add the URL as a stream source with TCP transport.
For containerized Frigate, attach receiver and Frigate to a private shared Docker
network and use `receiver:8554` instead of `127.0.0.1:8554` in the URL. Inside a
container, loopback refers to that container, not the host. Do not publish the
port on all interfaces to work around this.

The stock Compose example permits outbound connections. It installs no custom
host firewall rules. Account operations use verified TLS on TCP 3388; stream
setup uses HTTPS/binary rendezvous on TCP 443 and negotiated camera TCP ports.

## Session reuse and multiple cameras

Restarts of the receiver use saved camera credentials and need no phone or OTP.
Account session and master-token restoration worked in fresh containers, but
long-term expiry/revocation behavior is unknown. Account refresh is not a daemon.
Refresh the account's saved camera list explicitly:

```sh
docker compose --profile setup run --rm account resume --state-dir /state
```

`setup` resumes an existing saved session instead of requesting another code.
It refuses to overwrite existing `camera.json` or `config.json`. To redo setup,
stop the receiver, move those two files into a private backup directory, and run
setup again. If account tokens are revoked, retain a private backup and use a new
empty state directory for a fresh OTP login. Do not blindly resend email codes.

The wizard selects one camera per service instance. The underlying exporter
already supports explicit camera-ID selection. Multiple account entries and
selection are tested synthetically; simultaneous physical cameras have not been
tested. Additional instances need separate private configuration, transport
identity, Compose project and host port. Do not share one credentials file across
unrelated cameras. See [account protocol and advanced commands](docs/ACCOUNT-LOGIN.txt).

## Secrets and excluded material

Never commit `state/` or share its contents: email, OTP, account session/master
tokens and IDs, client identity, camera IDs/tokens/SIDs, and private stream URLs.
Camera names, MAC addresses, LAN details and captures also belong in private
support material. The repository contains no maintainer account or device
credentials. Its examples use documentation addresses and synthetic test values.
`.gitignore` is a guardrail, not a substitute for checking staged files.

APKs, vendor libraries, Android runtime files, decompilation, packet captures,
video and diagnostic key/media captures stay outside this repository. Diagnostic
capture is disabled by default; enabling it produces highly sensitive files.

## Development and validation

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
```

The earlier file-based login was tested end to end: fresh identity, emailed code,
account resume, camera export, then 20 seconds of decoded live video. On
2026-11-15, the published interactive Compose setup at commit `dd1ca50` was also
tested with empty account state: fresh email code, camera listing, LAN IP entry,
credential generation, and deployment of a receiver built from that GitHub
checkout. Frigate received video and wrote fresh recordings. Only one physical
camera was available; multiple-camera selection has automated coverage only.
Recovery tests of the receiver are documented in
[the recovery report](docs/RECOVERY-CHAOS.txt). These observations are not a
promise of reliability or support for other models. The [technical runbook](docs/OPERATIONS.md)
documents settings, watchdogs and metrics.

## Acknowledgments

Thanks to [REA — Reverse Engineer Anything](https://github.com/morluto/rea)
and its `reverse-engineer-anything` skill. Its tools and investigation workflow
helped the AI agents inspect the app and native library, trace protocol behavior,
and distinguish code-derived findings from runtime observations. REA was used
for research; it is not a dependency of the published receiver.

## License

Project-specific code is licensed under **GPL-3.0-or-later**, without warranty.
See [LICENSE](LICENSE). Upstream components retain their own licenses; see
[third-party notices](THIRD_PARTY_NOTICES.md). Distribute corresponding source
alongside binary/container releases as required by the applicable licenses.
The included notices cover Cargo dependencies; Debian image packages retain
license/copyright information under `/usr/share/doc` in the image.
