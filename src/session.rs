// SPDX-License-Identifier: GPL-3.0-or-later
//! Direct-only, bounded experimental receiver. No device-setting or firmware APIs.
use crate::{
    channel::{ChannelAction, ChannelDirection, ChannelHeader, OpenChannel},
    crypto::{respond_key_exchange, CipherMode, TunnelCipher},
    frame::Frame,
    settings::{Credentials, Settings},
    signaling as sig,
    wire_io::{read_frame, write_frame, MAX_FRAME},
};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Instant,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{tcp::OwnedWriteHalf, TcpListener, TcpSocket, TcpStream},
    sync::mpsc,
    task::JoinSet,
    time::{interval_at, timeout, Duration, Instant as TokioInstant},
};
const SETUP_TIMEOUT: Duration = Duration::from_secs(45);
const PEER_TIMEOUT: Duration = Duration::from_secs(10);
fn event(start: Instant, name: &str, fields: Value) {
    eprintln!(
        "{}",
        json!({"event":name,"elapsed_ms":start.elapsed().as_millis(),"detail":fields})
    );
}
fn reader(
    stream: tokio::net::tcp::OwnedReadHalf,
    tasks: &mut JoinSet<()>,
) -> mpsc::Receiver<Result<Frame>> {
    let (tx, rx) = mpsc::channel(32);
    tasks.spawn(async move {
        let mut r = stream;
        loop {
            let f = read_frame(&mut r).await;
            let stop = f.is_err();
            if tx.send(f).await.is_err() || stop {
                break;
            }
        }
    });
    rx
}
async fn next_frame(rx: &mut mpsc::Receiver<Result<Frame>>) -> Result<Frame> {
    rx.recv().await.context("frame_reader_closed")?
}
async fn wait_command(stream: &mut TcpStream, command: i32, start: Instant) -> Result<Frame> {
    loop {
        let f = read_frame(stream).await?;
        event(
            start,
            "bootstrap_receive",
            json!({"command":f.command,"bytes":f.payload.len()}),
        );
        if [105, 109, 123].contains(&f.command) {
            bail!("bootstrap_rejected_command_{}", f.command)
        }
        if f.command == command {
            return Ok(f);
        }
    }
}
async fn peer(mut stream: TcpStream) -> Result<(TcpStream, Frame)> {
    stream.set_nodelay(true)?;
    let request = timeout(PEER_TIMEOUT, async {
        for _ in 0..8 {
            let f = read_frame(&mut stream).await?;
            if f.command == 3 {
                ensure!(f.payload.len() == 24, "key_request_length");
                return Ok(f);
            }
            ensure!(f.command == 1, "unexpected_pre_key_command");
        }
        bail!("key_request_missing")
    })
    .await
    .context("key_request_timeout")??;
    Ok((stream, request))
}
struct Established {
    socket: TcpStream,
    cipher: TunnelCipher,
    id: String,
    control_tasks: JoinSet<()>,
    control_rx: mpsc::Receiver<Result<Frame>>,
    control_write: OwnedWriteHalf,
    control_open: bool,
}
fn parse_discovery(v: &Value) -> Result<(IpAddr, IpAddr)> {
    ensure!(v["errno"] == "0" || v["errno"] == 0, "discovery_rejected");
    let tat = v["tatip"]
        .as_str()
        .context("discovery_missing_tatip")?
        .parse()
        .context("discovery_invalid_tatip")?;
    let relay = v["relayip"]
        .as_str()
        .context("discovery_missing_relayip")?
        .parse()
        .context("discovery_invalid_relayip")?;
    Ok((tat, relay))
}
/// Awaiting no consumer has no timer. Rebuilt each actor iteration so PLAY,
/// progress, PAUSE and channel closure immediately change the watched deadline.
async fn media_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(TokioInstant::from_std(deadline)).await,
        None => std::future::pending::<()>().await,
    }
}

async fn establish(s: &Settings, c: &Credentials, start: Instant) -> Result<Established> {
    let bind_ip = s.source_ip()?;
    let url = sig::discovery_url(&c.rendezvous)?;
    event(start, "discovery_start", json!({"timeout_seconds":15}));
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = http
        .post(url)
        .json(&json!({"role":"client","id":c.session_id,"token":""}))
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("discovery_request_failed"))?;
    ensure!(
        response.status().is_success(),
        "discovery_http_status_{}",
        response.status().as_u16()
    );
    ensure!(
        response.content_length().unwrap_or(0) <= 65536,
        "discovery_body_limit"
    );
    let mut response = response;
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow::anyhow!("discovery_body_read"))?
    {
        ensure!(bytes.len() + chunk.len() <= 65536, "discovery_body_limit");
        bytes.extend_from_slice(&chunk);
    }
    let v: Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("discovery_invalid_json"))?;
    let (tat, relay) = parse_discovery(&v)?;
    let relay = relay.to_string();
    let mut nonce = [0u8; 2];
    getrandom::getrandom(&mut nonce).map_err(|_| anyhow::anyhow!("random_failed"))?;
    let id = sig::generated_id(
        &c.session_id,
        &s.client_token,
        u16::from_le_bytes(nonce) % 1000,
    )?;
    let mut bootstrap = TcpStream::connect(SocketAddr::new(tat, 443))
        .await
        .context("bootstrap_connect")?;
    bootstrap.set_nodelay(true)?;
    write_frame(&mut bootstrap, &sig::register103(&id)?).await?;
    event(start, "bootstrap_registered", json!({"command":103}));
    let fields = wait_command(&mut bootstrap, 104, start).await?;
    sig::parse104(&fields.payload)?;
    write_frame(
        &mut bootstrap,
        &sig::host_nic119(&c.session_id, &id, 1, 1, 25000)?,
    )
    .await?;
    let cap = wait_command(&mut bootstrap, 120, start).await?;
    let cap = sig::parse120(&cap.payload)?;
    event(
        start,
        "host_capabilities",
        json!({"version":cap.version,"cipher_flag":cap.cipher_flag,"host_mode":cap.host_mode,"host_nic_count":cap.host_nic_count}),
    );
    ensure!(cap.host_mode & 1 != 0, "direct_mode_not_supported");
    write_frame(
        &mut bootstrap,
        &sig::connect106(&c.session_id, &id, &s.client_token, &relay)?,
    )
    .await?;
    let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0)).await?;
    let advertised = listener.local_addr()?;
    let mut direct = TcpStream::connect(SocketAddr::new(tat, 443))
        .await
        .context("direct_control_connect")?;
    write_frame(&mut direct, &sig::listen200(&id, &[advertised])?).await?;
    event(
        start,
        "direct_listen_registered",
        json!({"command":200,"listener_port":advertised.port()}),
    );
    let mut io_tasks = JoinSet::new();
    let (br, mut bw) = bootstrap.into_split();
    let (dr, _dw) = direct.into_split();
    let mut brx = reader(br, &mut io_tasks);
    let mut direct_tasks = JoinSet::new();
    let mut drx = reader(dr, &mut direct_tasks);
    let mut direct_open = true;
    let mut bootstrap_open = true;
    let mut peers: JoinSet<Result<(TcpStream, Frame)>> = JoinSet::new();
    let mut attempted = HashSet::new();
    loop {
        tokio::select! {
         f=next_frame(&mut brx),if bootstrap_open=>{match f{
          Ok(f)=>{event(start,"bootstrap_receive",json!({"command":f.command,"bytes":f.payload.len()}));match f.command{
           108=>{write_frame(&mut bw,&sig::success115(&id)?).await?;event(start,"bootstrap_deregister",json!({"command":115}));},
           105|109|123=>bail!("bootstrap_rejected_command_{}",f.command),_=>{}}},
          Err(_)=>{bootstrap_open=false;event(start,"bootstrap_closed",json!({}));}
         }},
         f=next_frame(&mut drx),if direct_open=>{let f=match f {Ok(f)=>f,Err(_)=>{direct_open=false;event(start,"direct_control_closed",json!({"pending_candidates":peers.len()}));continue}};event(start,"direct_control_receive",json!({"command":f.command,"bytes":f.payload.len()}));if f.command==204{
          let prefix=f.payload.iter().position(|b|*b==0).unwrap_or(f.payload.len());event(start,"candidate_payload_shape",json!({"first_nul":prefix,"total_bytes":f.payload.len(),"field_lengths":f.payload[..prefix].split(|b|*b==b';').map(|s|s.len()).collect::<Vec<_>>()}));let candidates=sig::parse204(&f.payload)?;
          for addr in candidates.candidates{if addr.ip()!=s.camera_ip {event(start,"candidate_ignored",json!({"reason":"outside_owned_camera_address"}));continue;}
           if attempted.len()>=16||!attempted.insert(addr){continue;}
           let bind=bind_ip;event(start,"candidate_connect_start",json!({"port":addr.port(),"timeout_seconds":10}));
           peers.spawn(async move {tokio::time::sleep(Duration::from_secs(1)).await;timeout(PEER_TIMEOUT,async{let sock=TcpSocket::new_v4()?;sock.bind(SocketAddr::new(bind,0))?;peer(sock.connect(addr).await?).await}).await.context("candidate_timeout")?});
          }
         }},
         incoming=listener.accept()=>{let(socket,addr)=incoming?;if addr.ip()==s.camera_ip&&peers.len()<16{event(start,"candidate_accepted",json!({"port":addr.port()}));peers.spawn(peer(socket));}else{event(start,"incoming_ignored",json!({"reason":"outside_camera_or_limit"}));}},
         result=peers.join_next(),if !peers.is_empty()=>{match result.context("peer_tasks_empty")?{
          Ok(Ok((mut socket,request)))=>{let(response,cipher)=respond_key_exchange(&request.payload,CipherMode::from_capability(cap.cipher_flag),MAX_FRAME-16)?;
           write_frame(&mut socket,&Frame{command:3,payload:response.to_vec()}).await?;
           event(start,"tunnel_established",json!({"transport":"direct_tcp","cipher_flag":cap.cipher_flag}));
           // Drop cancels losing candidates/readers; no production resources are owned.
           return Ok(Established{socket,cipher,id,control_tasks:io_tasks,control_rx:brx,control_write:bw,control_open:bootstrap_open});
          },Ok(Err(e))=>event(start,"candidate_failed",json!({"reason":crate::supervisor::retry_reason(&e),"pending_candidates":peers.len(),"inbound_listener":true,"retry":"remaining_candidates_or_inbound"})),Err(_)=>event(start,"candidate_failed",json!({"reason":"task_failed","pending_candidates":peers.len(),"inbound_listener":true}))
         }}
        }
    }
}
#[derive(Debug)]
enum Local {
    Accepted(TcpStream, u16, u16),
    Data(i32, Vec<u8>),
    Closed(i32, LocalCloseReason),
    Auth(Result<()>),
    ListenerFailed(u16, std::io::Error),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalCloseReason {
    ReadEof,
    ReadError,
    WriteError,
    WriteTimeout,
}
impl LocalCloseReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadEof => "read_eof",
            Self::ReadError => "read_error",
            Self::WriteError => "local_write_error",
            Self::WriteTimeout => "local_write_timeout",
        }
    }
}
fn classify_local_read(
    result: std::io::Result<usize>,
) -> std::result::Result<usize, LocalCloseReason> {
    match result {
        Ok(0) => Err(LocalCloseReason::ReadEof),
        Ok(n) => Ok(n),
        Err(_) => Err(LocalCloseReason::ReadError),
    }
}
fn classify_local_write(
    result: std::result::Result<std::io::Result<()>, tokio::time::error::Elapsed>,
) -> Option<LocalCloseReason> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(_)) => Some(LocalCloseReason::WriteError),
        Err(_) => Some(LocalCloseReason::WriteTimeout),
    }
}

// Accept failures must reach the session owner: otherwise a dead local
// listener can leave an authenticated, heartbeating tunnel looking healthy.
async fn listener_worker<F, Accept>(
    mut accept: F,
    tx: mpsc::Sender<Local>,
    local_port: u16,
    remote_port: u16,
) where
    F: FnMut() -> Accept,
    Accept: std::future::Future<Output = std::io::Result<(TcpStream, SocketAddr)>>,
{
    loop {
        let message = match accept().await {
            Ok((socket, _)) => Local::Accepted(socket, local_port, remote_port),
            Err(error) => {
                let _ = tx.send(Local::ListenerFailed(local_port, error)).await;
                return;
            }
        };
        if tx.send(message).await.is_err() {
            return;
        }
    }
}

fn check_worker_result(result: std::result::Result<(), tokio::task::JoinError>) -> Result<()> {
    result.map_err(|_| anyhow::anyhow!("worker_task_failed"))
}

struct Channel {
    playback: Option<crate::telemetry::Playback>,
    local: u16,
    remote: u16,
    sequence: i32,
    tx: mpsc::Sender<Vec<u8>>,
    closing: Option<Instant>,
    observer: Option<crate::media_observer::MediaObserver>,
    last_incoming_sequence: Option<i32>,
    requests: crate::request_observer::RequestObserver,
    repair: Option<crate::rtsp_repair::RtspRepair>,
    repaired_observer: Option<crate::media_observer::MediaObserver>,
}
// When repair is enabled only the validated post-repair stream is progress.
// A disabled/failed observer cannot silently substitute tunnel byte activity.
fn channel_video_packets(channel: &Channel, rtp_channel: u8) -> u64 {
    let observer = if channel.repair.is_some() {
        channel.repaired_observer.as_ref()
    } else {
        channel.observer.as_ref()
    };
    observer
        .and_then(|o| {
            o.snapshot().streams.get(&rtp_channel).map(|c| {
                c.rtp_packets
                    .saturating_sub(c.duplicates)
                    .saturating_sub(c.out_of_order)
            })
        })
        .unwrap_or(0)
}
/// Successful output is the only data eligible for local delivery. A repair
/// error has no raw fallback; the caller must close that channel.
struct PreparedDelivery {
    bytes: Vec<u8>,
    repair_delta: u64,
    repair_count: u64,
}
fn prepare_delivery(
    repair: &mut Option<crate::rtsp_repair::RtspRepair>,
    body: Vec<u8>,
) -> std::result::Result<PreparedDelivery, crate::rtsp_repair::RepairError> {
    match repair {
        Some(repair) => {
            let previous = repair.repairs();
            let bytes = repair.feed(&body)?;
            Ok(PreparedDelivery {
                bytes,
                repair_delta: repair.repairs() - previous,
                repair_count: repair.repairs(),
            })
        }
        None => Ok(PreparedDelivery {
            bytes: body,
            repair_delta: 0,
            repair_count: 0,
        }),
    }
}

async fn send_channel(
    w: &mut OwnedWriteHalf,
    cipher: &TunnelCipher,
    id: i32,
    ch: &Channel,
    seq: i32,
    body: &[u8],
) -> Result<()> {
    let header = ChannelHeader {
        request_id: id,
        sequence: seq,
        direction: ChannelDirection::Initiator,
        local_port: ch.local,
        peer_port: ch.remote,
        reserved: 0,
    };
    let mut payload = header.encode().to_vec();
    payload.extend_from_slice(&cipher.encrypt(body)?);
    write_frame(
        w,
        &Frame {
            command: 0,
            payload,
        },
    )
    .await
}
async fn authenticate(addr: SocketAddr, c: &Credentials, id: &str) -> Result<()> {
    let mut s = TcpStream::connect(addr).await?;
    let mut body = serde_json::to_vec(
        &json!({"CMD_ID":"P2P_USER_PASSWORD_REQ","P2PSERVERID":id,"NAME":c.transport_user,"PASSWORD":c.transport_password}),
    )?;
    body.push(0);
    s.write_all(&1u32.to_le_bytes()).await?;
    s.write_all(&(body.len() as u32).to_le_bytes()).await?;
    s.write_all(&body).await?;
    let mut h = [0; 8];
    s.read_exact(&mut h).await?;
    let n = u32::from_le_bytes(h[4..].try_into().unwrap()) as usize;
    ensure!((1..=65536).contains(&n), "auth_length");
    let mut b = vec![0; n];
    s.read_exact(&mut b).await?;
    let end = b.iter().position(|x| *x == 0).unwrap_or(n);
    let v: Value =
        serde_json::from_slice(&b[..end]).map_err(|_| anyhow::anyhow!("auth_invalid_json"))?;
    ensure!(v["STATUS"] == 0 || v["STATUS"] == "0", "auth_rejected");
    Ok(())
}
pub async fn run(s: Settings, c: Credentials) -> Result<()> {
    let (ready, _) = tokio::sync::watch::channel(false);
    run_observed(s, c, ready).await
}
pub async fn run_observed(
    s: Settings,
    c: Credentials,
    ready: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    run_monitored(
        s,
        c,
        ready,
        std::sync::Arc::new(crate::telemetry::Diagnostics::default()),
    )
    .await
}
pub async fn run_monitored(
    s: Settings,
    c: Credentials,
    ready: tokio::sync::watch::Sender<bool>,
    diagnostics: std::sync::Arc<crate::telemetry::Diagnostics>,
) -> Result<()> {
    let start = Instant::now();
    event(
        start,
        "attempt_start",
        json!({"setup_timeout_seconds":45,"duration_seconds":s.seconds,"direct_only":true,"repair_interleaved_response":s.repair_interleaved_response}),
    );
    // Reserve local ports before opening any camera session.
    let authaddr = SocketAddr::from(([127, 0, 0, 1], s.listen.port() + 1));
    let listeners = [
        (TcpListener::bind(s.listen).await?, 6667u16),
        (TcpListener::bind(authaddr).await?, 9001u16),
    ];
    let mut capture = s
        .capture_dir
        .as_deref()
        .map(crate::diagnostic_capture::FailureCapture::new)
        .transpose()?;
    let established = timeout(SETUP_TIMEOUT, establish(&s, &c, start))
        .await
        .context("setup_timeout")??;
    let Established {
        socket,
        cipher,
        id,
        control_tasks: mut tasks,
        control_rx: mut control,
        mut control_write,
        mut control_open,
    } = established;
    let (r, mut w) = socket.into_split();
    let mut frames = reader(r, &mut tasks);
    let (tx, mut local) = mpsc::channel(64);
    for (l, remote) in listeners {
        let addr = l.local_addr()?;
        let tx = tx.clone();
        tasks.spawn(async move {
            let listener = &l;
            listener_worker(|| listener.accept(), tx, addr.port(), remote).await;
        });
    }
    let auth_tx = tx.clone();
    let auth_id = id.clone();
    tasks.spawn(async move {
        let result = timeout(
            Duration::from_secs(15),
            authenticate(authaddr, &c, &auth_id),
        )
        .await
        .context("auth_timeout")
        .and_then(|r| r);
        let _ = auth_tx.send(Local::Auth(result)).await;
    });
    let mut channels: HashMap<i32, Channel> = HashMap::new();
    let mut next_id = 1i32;
    let mut heartbeat = interval_at(
        TokioInstant::now() + Duration::from_secs(2),
        Duration::from_secs(8),
    );
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut stats = interval_at(
        TokioInstant::now() + Duration::from_secs(30),
        Duration::from_secs(30),
    );
    let end = async {
        if s.seconds == 0 {
            std::future::pending::<()>().await;
        } else {
            tokio::time::sleep(Duration::from_secs(s.seconds)).await;
        }
    };
    tokio::pin!(end);
    let mut misses = 0u8;
    let mut rxbytes = 0u64;
    let mut txbytes = 0u64;
    let mut authenticated = false;
    loop {
        let active = channels
            .values()
            .filter(|ch| ch.closing.is_none())
            .filter_map(|ch| ch.playback.as_ref())
            .collect::<Vec<_>>();
        let media_age = active.iter().filter_map(|p| p.age()).reduce(f64::min);
        let deadline = active
            .iter()
            .map(|p| p.deadline(Duration::from_secs(s.media_timeout_seconds)))
            .min();
        let stalled = active
            .iter()
            .any(|p| p.stalled(Duration::from_secs(s.media_timeout_seconds)));
        diagnostics.playback(active.len(), media_age, stalled);
        if stalled {
            event(
                start,
                "media_timeout",
                json!({"timeout_seconds":s.media_timeout_seconds,"active_streams":active.len(),"video_rtp_channel":s.video_rtp_channel,"last_video_age_seconds":media_age,"last_any_rx_age_seconds":diagnostics.status().heartbeat_age_seconds}),
            );
            bail!("media_timeout");
        }
        tokio::select! {
                         // Re-enter the shared timeout check; no heartbeat or
                         // incoming packet is required to notice stalled media.
                         _=media_deadline(deadline)=>continue,
                         Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Err(error)=check_worker_result(result){event(start,"worker_task_failed",json!({}));return Err(error);}},
                         _=&mut end=>{ensure!(authenticated,"ended_without_authentication");event(start,"test_duration_complete",json!({"received_bytes":rxbytes,"sent_bytes":txbytes}));return Ok(())},
                         _=stats.tick()=>event(start,"tunnel_stats",json!({"received_bytes":rxbytes,"sent_bytes":txbytes,"channels":channels.len(),"missed_heartbeats":misses,"media":channels.iter().filter_map(|(id,ch)|ch.observer.as_ref().map(|o|(*id,o.snapshot()))).collect::<Vec<_>>(),"repaired_media":channels.iter().filter_map(|(id,ch)|ch.repaired_observer.as_ref().map(|o|(*id,o.snapshot()))).collect::<Vec<_>>(),"repair_counts":channels.iter().filter_map(|(id,ch)|ch.repair.as_ref().map(|r|(*id,r.repairs()))).collect::<Vec<_>>()})),
                         _=heartbeat.tick()=>{channels.retain(|id,ch|{let keep=ch.closing.is_none_or(|t|t.elapsed()<Duration::from_secs(10));if !keep{event(start,"channel_close_timeout",json!({"channel":id,"timeout_seconds":10}));}keep});write_frame(&mut w,&Frame{command:1,payload:vec![]}).await?;event(start,"heartbeat_sent",json!({"missed_before_send":misses,"interval_seconds":8}));ensure!(misses<=4,"heartbeat_timeout");misses+=1;},
                         f=next_frame(&mut control),if control_open=>{match f{Ok(f)=>{event(start,"bootstrap_receive",json!({"command":f.command,"bytes":f.payload.len()}));if f.command==108{write_frame(&mut control_write,&sig::success115(&id)?).await?;event(start,"bootstrap_deregister",json!({"command":115}));}else if [105,109,123].contains(&f.command){bail!("bootstrap_rejected_command_{}",f.command)}},Err(_)=>{control_open=false;event(start,"bootstrap_closed",json!({}));}}},
                        f=next_frame(&mut frames)=>{let f=f?;match f.command{
                          0=>{misses=0;diagnostics.incoming();let(h,encrypted)=ChannelHeader::split(&f.payload)?;let body=if encrypted.is_empty(){vec![]}else{cipher.decrypt(encrypted)?};
                           if let Some(ch)=channels.get_mut(&h.request_id){if h.sequence>=0{if let Some(previous)=ch.last_incoming_sequence{if h.sequence!=previous.wrapping_add(1){event(start,"tunnel_sequence_discontinuity",json!({"channel":h.request_id,"previous":previous,"current":h.sequence}));}}ch.last_incoming_sequence=Some(h.sequence);}
                            ensure!(h.direction==ChannelDirection::Rejected||(h.direction==ChannelDirection::Target&&h.local_port==ch.remote&&h.peer_port==ch.local),"channel_header_mismatch");
        if ch.remote==6667{if let Some(capture)=capture.as_mut(){capture.remember(h.request_id,h.sequence,h.encode(),encrypted,&body);}}

                            match h.action(){
                             ChannelAction::Forward=>{let video_before=channel_video_packets(ch,s.video_rtp_channel);rxbytes+=body.len()as u64;if let Some(o)=ch.observer.as_mut(){if o.feed(&body).is_err(){if let Some(capture)=capture.as_mut(){let dump=capture.dump(&cipher);tasks.spawn(async move{match dump.await{Ok(written)=>event(start,"private_failure_capture",json!({"written":written})),Err(_)=>event(start,"private_failure_capture_failed",json!({}))}});}event(start,"media_observer_disabled",json!({"channel":h.request_id,"snapshot":o.snapshot()}));ch.observer=None;}}
                if ch.closing.is_some(){continue;}
                let delivery=match prepare_delivery(&mut ch.repair,body){Ok(delivery)=>delivery,Err(error)=>{diagnostics.forwarding_failure();event(start,"rtsp_repair_failed",json!({"channel":h.request_id,"reason":error.to_string(),"action":"close_channel"}));send_channel(&mut w,&cipher,h.request_id,ch,-4,&[]).await?;ch.closing=Some(Instant::now());let(dead,_)=mpsc::channel(1);ch.tx=dead;continue;}};
                if delivery.repair_delta>0{event(start,"rtsp_response_reordered",json!({"channel":h.request_id,"delta":delivery.repair_delta,"count":delivery.repair_count}));}
                if let Some(o)=ch.repaired_observer.as_mut(){if o.feed(&delivery.bytes).is_err(){event(start,"postrepair_observer_disabled",json!({"channel":h.request_id,"snapshot":o.snapshot()}));ch.repaired_observer=None;}}
                if channel_video_packets(ch,s.video_rtp_channel)>video_before { if let Some(playback)=ch.playback.as_mut(){playback.video();} }
                if !delivery.bytes.is_empty() && ch.tx.try_send(delivery.bytes).is_err(){diagnostics.forwarding_failure();event(start,"channel_backpressure",json!({"channel":h.request_id}));send_channel(&mut w,&cipher,h.request_id,ch,-4,&[]).await?;ch.closing=Some(Instant::now());let(dead,_)=mpsc::channel(1);ch.tx=dead;}},
                             ChannelAction::ReplyAndClose{sequence}=>{if let Some(repair)=ch.repair.as_mut(){if let Err(error)=repair.finish(){event(start,"rtsp_repair_failed",json!({"channel":h.request_id,"reason":error.to_string(),"action":"peer_already_closing"}));}}send_channel(&mut w,&cipher,h.request_id,ch,sequence,&[]).await?;ch.closing=Some(Instant::now());let(dead,_)=mpsc::channel(1);ch.tx=dead;},
                             ChannelAction::ReplyAndRemove{sequence}=>{send_channel(&mut w,&cipher,h.request_id,ch,sequence,&[]).await?;channels.remove(&h.request_id);},
                             ChannelAction::Remove=>{channels.remove(&h.request_id);}
                            }
                           }else{event(start,"unknown_channel",json!({"channel":h.request_id}));}
                          },
                          1=>{misses=0;diagnostics.incoming();},
                          7=>{event(start,"unsolicited_open_ignored",json!({}));},
                          other=>event(start,"unexpected_tunnel_command",json!({"command":other}))
                         }},
                         msg=local.recv()=>{match msg.context("local_event_channel_closed")?{
                          Local::Accepted(socket,localport,remote)=>{if remote==6667&&!authenticated{event(start,"client_before_authentication",json!({}));continue;}
                if channels.len()>=16{event(start,"channel_limit",json!({}));continue;}let id=next_id;next_id=next_id.checked_add(1).context("channel_id_exhausted")?;
                           let repair=if remote==6667&&s.repair_interleaved_response{Some(crate::rtsp_repair::RtspRepair::new(MAX_FRAME)?)}else{None};let repaired_observer=repair.as_ref().map(|_|crate::media_observer::MediaObserver::default());
                           let open=OpenChannel{local_port:localport,remote_port:remote,request_id:id};write_frame(&mut w,&open.frame()).await?;
                           let (output,input)=mpsc::channel::<Vec<u8>>(8);channels.insert(id,Channel{playback:None,local:localport,remote,sequence:0,tx:output,closing:None,last_incoming_sequence:None,requests:crate::request_observer::RequestObserver::default(),repair,repaired_observer,observer:if remote==6667{Some(crate::media_observer::MediaObserver::default())}else{None}});
                           let events=tx.clone();tasks.spawn(async move{let(mut r,mut w)=socket.into_split();let mut input=input;let mut buf=[0;16384];let reason=loop{tokio::select!{
                            read=r.read(&mut buf)=>{match classify_local_read(read){Ok(n)=>{if events.send(Local::Data(id,buf[..n].to_vec())).await.is_err(){return}},Err(reason)=>break reason}},
                            data=input.recv()=>{match data{Some(data)=>{if let Some(reason)=classify_local_write(timeout(Duration::from_secs(10),w.write_all(&data)).await){break reason}},None=>return}}
                           }};let _=events.send(Local::Closed(id,reason)).await;});event(start,"channel_open",json!({"channel":id,"remote_port":remote}));
                          },
                          Local::Data(id,data)=>{if let Some(ch)=channels.get_mut(&id){if ch.closing.is_none(){if ch.remote==6667{let report=ch.requests.feed(&data);for request in report.requests{match request.method{"PLAY"=>ch.playback=Some(crate::telemetry::Playback::new()),"PAUSE"|"TEARDOWN"=>ch.playback=None,_=>()};event(start,"rtsp_request",json!({"channel":id,"method":request.method,"request_index":request.index}));}if report.disabled.is_some(){event(start,"request_observer_disabled",json!({"channel":id}));}}send_channel(&mut w,&cipher,id,ch,ch.sequence,&data).await?;ch.sequence=ch.sequence.checked_add(1).context("sequence_exhausted")?;txbytes+=data.len()as u64;}}},
                          Local::Closed(id,reason)=>{event(start,"local_channel_io_closed",json!({"channel":id,"reason":reason.as_str(),"write_timeout_seconds":if reason==LocalCloseReason::WriteTimeout{Some(10)}else{None}}));if let Some(ch)=channels.get_mut(&id){if ch.closing.is_none(){send_channel(&mut w,&cipher,id,ch,-4,&[]).await?;ch.closing=Some(Instant::now());event(start,"channel_close",json!({"channel":id,"media":ch.observer.as_ref().map(|o|o.snapshot())}));}}},
                          Local::ListenerFailed(port,error)=>{event(start,"listener_failed",json!({"listen_port":port,"kind":format!("{:?}",error.kind())}));return Err(error).context("listener_failed");},
                          Local::Auth(result)=>{result?;authenticated=true;let _=ready.send(true);event(start,"stream_ready",json!({"listen_port":s.listen.port(),"path":"/blinkhd","authentication":"accepted"}));}
                         }}
                        }
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    #[test]
    fn accepts_observed_errno_schema() {
        for e in [json!("0"), json!(0)] {
            let v = json!({"errno":e,"tatip":"192.0.2.1","relayip":"192.0.2.2"});
            assert_eq!(
                parse_discovery(&v).unwrap().0,
                "192.0.2.1".parse::<IpAddr>().unwrap()
            );
        }
    }
    #[test]
    fn rejects_failure_and_missing_real_status() {
        for v in [
            json!({"errno":"1"}),
            json!({"status":"0","tatip":"192.0.2.1","relayip":"192.0.2.2"}),
            json!({"errno":"0","tatip":"https://example.com","relayip":"192.0.2.2"}),
        ] {
            assert!(parse_discovery(&v).is_err());
        }
    }
}

#[cfg(test)]
mod worker_tests {
    use super::*;

    #[tokio::test]
    async fn injected_accept_error_reaches_session_event_queue() {
        let (tx, mut rx) = mpsc::channel(1);
        listener_worker(
            || std::future::ready(Err(std::io::Error::from(std::io::ErrorKind::Other))),
            tx,
            18554,
            6667,
        )
        .await;
        match rx.recv().await.unwrap() {
            Local::ListenerFailed(port, error) => {
                assert_eq!(port, 18554);
                assert_eq!(error.kind(), std::io::ErrorKind::Other);
            }
            _ => panic!("accept failure must be reported, not silently swallowed"),
        }
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn worker_panic_is_fatal_without_copying_panic_payload() {
        let result = tokio::spawn(async { panic!("synthetic-worker-panic") }).await;
        let error = check_worker_result(result).unwrap_err();
        assert_eq!(error.to_string(), "worker_task_failed");
    }

    #[test]
    fn normal_worker_completion_is_not_failure() {
        check_worker_result(Ok(())).unwrap();
    }

    #[test]
    fn local_read_classifies_eof_and_error_without_error_text() {
        assert_eq!(classify_local_read(Ok(12)), Ok(12));
        assert_eq!(classify_local_read(Ok(0)), Err(LocalCloseReason::ReadEof));
        let reason =
            classify_local_read(Err(std::io::Error::other("synthetic-error-body"))).unwrap_err();
        assert_eq!(reason.as_str(), "read_error");
        assert_eq!(LocalCloseReason::ReadEof.as_str(), "read_eof");
    }

    #[tokio::test]
    async fn local_write_classifies_error_and_deadline_without_error_text() {
        assert_eq!(classify_local_write(Ok(Ok(()))), None);
        let reason =
            classify_local_write(Ok(Err(std::io::Error::other("synthetic-error-body")))).unwrap();
        assert_eq!(reason.as_str(), "local_write_error");
        let expired = timeout(
            Duration::ZERO,
            std::future::pending::<std::io::Result<()>>(),
        )
        .await;
        let reason = classify_local_write(expired).unwrap();
        assert_eq!(reason.as_str(), "local_write_timeout");
    }
}

#[cfg(test)]
mod repair_delivery_tests {
    use super::*;

    fn inserted_response_fixture() -> (Vec<u8>, Vec<u8>) {
        let response = b"RTSP/1.0 200 OK\r\nCSeq: 9\r\n\r\n";
        let rtp = [0x80, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0x65, 1, 2, 3];
        let header = [b'$', 0, 0, rtp.len() as u8];
        let raw = [header.as_slice(), response, &rtp].concat();
        let repaired = [response.as_slice(), &header, &rtp].concat();
        (raw, repaired)
    }

    #[test]
    fn default_disabled_delivery_preserves_raw_bytes_exactly() {
        let (raw, _) = inserted_response_fixture();
        let mut disabled = None;
        let delivery = prepare_delivery(&mut disabled, raw.clone()).unwrap();
        assert_eq!(delivery.bytes, raw);
        assert_eq!(delivery.repair_count, 0);
    }

    #[test]
    fn repair_delivery_preserves_raw_evidence_and_yields_valid_output() {
        let (raw, expected) = inserted_response_fixture();
        let raw_evidence = raw.clone();
        let mut raw_observer = crate::media_observer::MediaObserver::default();
        assert!(raw_observer.feed(&raw).is_err());
        let mut repair = Some(crate::rtsp_repair::RtspRepair::new(MAX_FRAME).unwrap());
        let mut output = Vec::new();
        let mut delta = 0;
        for chunk in raw.chunks(3) {
            let delivery = prepare_delivery(&mut repair, chunk.to_vec()).unwrap();
            delta += delivery.repair_delta;
            output.extend(delivery.bytes);
        }
        assert_eq!(raw_evidence, raw);
        assert_eq!(output, expected);
        assert_eq!(delta, 1);
        assert_eq!(repair.as_ref().unwrap().repairs(), 1);
        let mut post_observer = crate::media_observer::MediaObserver::default();
        post_observer.feed(&output).unwrap();
        assert_eq!(post_observer.snapshot().streams[&0].rtp_packets, 1);
    }

    #[test]
    fn failed_repair_never_yields_raw_fallback_and_stays_failed() {
        let mut repair = Some(crate::rtsp_repair::RtspRepair::new(MAX_FRAME).unwrap());
        assert!(prepare_delivery(&mut repair, b"invalid framing".to_vec()).is_err());
        let (_, valid) = inserted_response_fixture();
        assert!(prepare_delivery(&mut repair, valid).is_err());
    }
}

#[cfg(test)]
mod media_deadline_tests {
    use super::*;

    #[tokio::test]
    async fn stalled_media_wakes_without_heartbeat_or_socket_activity() {
        let deadline = Instant::now() + Duration::from_millis(15);
        timeout(Duration::from_millis(250), media_deadline(Some(deadline)))
            .await
            .expect("independent timer must wake the actor");
        assert!(Instant::now() >= deadline);
    }

    #[tokio::test]
    async fn no_playing_consumer_has_no_deadline() {
        assert!(timeout(Duration::from_millis(15), media_deadline(None))
            .await
            .is_err());
    }
}
