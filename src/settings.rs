// SPDX-License-Identifier: GPL-3.0-or-later
use anyhow::{ensure, Result};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub credentials: PathBuf,
    pub camera_ip: IpAddr,
    #[serde(default)]
    pub bind_ip: Option<IpAddr>,
    pub listen: SocketAddr,
    pub client_token: String,
    /// Zero runs indefinitely; nonzero values bound the entire supervised run.
    pub seconds: u64,
    #[serde(default)]
    pub allow_nonloopback_listen: bool,
    #[serde(default)]
    pub metrics_listen: Option<SocketAddr>,
    #[serde(default = "default_media_timeout")]
    pub media_timeout_seconds: u64,
    #[serde(default)]
    pub video_rtp_channel: u8,
    #[serde(default)]
    pub capture_dir: Option<PathBuf>,
    #[serde(default)]
    pub repair_interleaved_response: bool,
}
#[derive(Clone, Deserialize)]
pub struct Credentials {
    #[serde(alias = "sid")]
    pub session_id: String,
    #[serde(alias = "rdz_host")]
    pub rendezvous: String,
    pub transport_user: String,
    pub transport_password: String,
}
fn default_media_timeout() -> u64 {
    60
}

fn private_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let f = std::fs::File::open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.permissions().mode() & 0o077 == 0,
        "private_config_permissions"
    );
    ensure!(m.len() <= 16384, "config_size");
    serde_json::from_reader(f).map_err(|_| anyhow::anyhow!("invalid_config_json"))
}
impl Settings {
    /// Ask the kernel which source address routes to this camera. UDP connect
    /// selects a route but sends no datagram; explicit source binding still wins.
    pub fn source_ip(&self) -> Result<IpAddr> {
        if let Some(ip) = self.bind_ip {
            return Ok(ip);
        }
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(SocketAddr::new(self.camera_ip, 9))?;
        let ip = socket.local_addr()?.ip();
        ensure!(!ip.is_unspecified(), "camera_route_source_unavailable");
        Ok(ip)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.camera_ip.is_ipv4() && self.bind_ip.is_none_or(|ip| ip.is_ipv4()),
            "ipv4_required_for_initial_client"
        );
        ensure!(
            !self.camera_ip.is_unspecified() && !self.camera_ip.is_multicast(),
            "invalid_camera_address"
        );
        ensure!(
            self.bind_ip
                .is_none_or(|ip| !ip.is_unspecified() && !ip.is_multicast()),
            "explicit_bind_address_required"
        );
        ensure!(
            (self.listen.ip().is_loopback() || self.allow_nonloopback_listen)
                && !self.listen.ip().is_multicast()
                && self.listen.port() > 1023
                && self.listen.port() < 65535,
            "loopback_listener_required"
        );
        ensure!(
            self.seconds == 0 || (10..=14400).contains(&self.seconds),
            "invalid_test_duration"
        );
        ensure!(
            (10..=600).contains(&self.media_timeout_seconds),
            "invalid_media_timeout"
        );
        if let Some(metrics) = self.metrics_listen {
            ensure!(
                !metrics.ip().is_multicast()
                    && metrics.port() > 1023
                    && metrics.port() != self.listen.port()
                    && metrics.port() != self.listen.port() + 1,
                "invalid_metrics_listener"
            );
        }
        ensure!(
            self.client_token.len() == 36
                && self.client_token.bytes().enumerate().all(|(i, b)| {
                    if [8, 13, 18, 23].contains(&i) {
                        b == b'-'
                    } else {
                        b.is_ascii_uppercase()
                    }
                }),
            "invalid_client_identity"
        );
        Ok(())
    }
    pub fn load(path: &Path) -> Result<(Self, Credentials)> {
        let s: Self = private_json(path)?;
        s.validate()?;
        let c: Credentials = private_json(&s.credentials)?;
        for v in [
            &c.session_id,
            &c.rendezvous,
            &c.transport_user,
            &c.transport_password,
        ] {
            ensure!(
                !v.is_empty() && v.len() <= 4096 && !v.as_bytes().contains(&0),
                "invalid_credential_field"
            );
        }
        Ok((s, c))
    }
}

#[cfg(test)]
mod repair_setting_tests {
    use super::*;
    fn config() -> serde_json::Value {
        serde_json::json!({"credentials":"synthetic.json","camera_ip":"192.0.2.1","bind_ip":"192.0.2.2","listen":"127.0.0.1:18554","client_token":"AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA","seconds":60})
    }
    #[test]
    fn repair_is_opt_in_and_requires_boolean() {
        let mut value = config();
        let settings: Settings = serde_json::from_value(value.clone()).unwrap();
        assert!(!settings.repair_interleaved_response);
        value["repair_interleaved_response"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<Settings>(value.clone())
                .unwrap()
                .repair_interleaved_response
        );
        value["repair_interleaved_response"] = serde_json::json!("true");
        assert!(serde_json::from_value::<Settings>(value).is_err());
    }
    #[test]
    fn production_settings_require_explicit_network_exposure() {
        let mut value = config();
        value["seconds"] = serde_json::json!(0);
        value["listen"] = serde_json::json!("0.0.0.0:8554");
        value.as_object_mut().unwrap().remove("bind_ip");
        let s: Settings = serde_json::from_value(value.clone()).unwrap();
        assert!(s.bind_ip.is_none());
        assert!(s.validate().is_err());
        value["allow_nonloopback_listen"] = serde_json::json!(true);
        value["metrics_listen"] = serde_json::json!("0.0.0.0:9091");
        let mut s: Settings = serde_json::from_value(value).unwrap();
        s.validate().unwrap();
        assert_eq!(s.media_timeout_seconds, 60);
        assert_eq!(s.video_rtp_channel, 0);
        s.metrics_listen = Some("127.0.0.1:8555".parse().unwrap());
        assert!(s.validate().is_err());
        s.metrics_listen = None;
        s.media_timeout_seconds = 0;
        assert!(s.validate().is_err());
    }
}
