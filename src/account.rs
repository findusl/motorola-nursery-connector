// SPDX-License-Identifier: GPL-3.0-or-later
//! FEPE account messages recovered from Motorola Nursery 2.2.18/4350.
//! No vendor code or user credentials are embedded.
//! Credential export is offline and never overwrites an existing destination.
use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub fn atom(value: &str) -> Result<&str> {
    ensure!(
        !value.is_empty() && value.len() <= 4096 && value.bytes().all(|b| b.is_ascii_graphic()),
        "invalid_protocol_atom"
    );
    Ok(value)
}
pub fn email(value: &str) -> Result<&str> {
    atom(value)?;
    ensure!(value.len() <= 254 && value.contains('@'), "invalid_email");
    Ok(value)
}
pub fn device_identity() -> Result<String> {
    let mut random = [0u8; 14];
    getrandom::getrandom(&mut random).map_err(|_| anyhow::anyhow!("identity_random_failed"))?;
    Ok(format!(
        "MOAN{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ))
}
pub fn otp_request(identity: &str, address: &str) -> Result<String> {
    Ok(format!(
        "v3_otp {} email {} 6",
        atom(identity)?,
        email(address)?
    ))
}
pub fn login_request(user_id: i64, identity: &str, address: &str, code: &str) -> Result<String> {
    ensure!(user_id >= 0, "invalid_user_id");
    ensure!(
        code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
        "invalid_otp_format"
    );
    Ok(format!(
        "v3_loginset {user_id} {} email {} {code}",
        atom(identity)?,
        email(address)?
    ))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSession {
    pub device_identity: String,
    pub user_id: i64,
    pub session_token: String,
    pub master_token: String,
    pub session_id: String,
    pub hostname: String,
}
impl AccountSession {
    pub fn from_login(identity: &str, tokens: &[&str]) -> Result<Self> {
        ensure!(
            tokens.len() >= 6 && tokens[0] == "v3_loginset",
            "invalid_login_reply"
        );
        let user_id: i64 = tokens[1]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid_login_reply"))?;
        ensure!(user_id >= 0, "login_rejected");
        Ok(Self {
            device_identity: atom(identity)?.into(),
            user_id,
            session_token: atom(tokens[2])?.into(),
            master_token: atom(tokens[3])?.into(),
            session_id: atom(tokens[4])?.into(),
            hostname: atom(tokens[5])?.into(),
        })
    }
    pub fn resume_request(&self, use_master: bool) -> Result<String> {
        ensure!(self.user_id >= 0, "invalid_user_id");
        Ok(format!(
            "v3_session {} {} {}",
            self.user_id,
            atom(if use_master {
                &self.master_token
            } else {
                &self.session_token
            })?,
            atom(&self.session_id)?
        ))
    }
    pub fn apply_resume(&mut self, tokens: &[&str]) -> Result<()> {
        ensure!(
            tokens.len() >= 5 && tokens[0] == "v3_session",
            "invalid_session_reply"
        );
        let user_id: i64 = tokens[1]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid_session_reply"))?;
        ensure!(user_id > 0 && user_id == self.user_id, "session_rejected");
        self.session_token = atom(tokens[2])?.into();
        self.hostname = atom(tokens[4])?.into();
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
pub struct AccountCamera {
    pub device_id: i64,
    pub udid: String,
    pub model: String,
    pub encoded_name: String,
    pub device_token: String,
    pub device_sid: String,
    pub country_code: String,
}
pub fn parse_camera_list(tokens: &[&str]) -> Result<Vec<AccountCamera>> {
    ensure!(
        tokens.len() >= 2 && tokens[0] == "v3_dlist",
        "invalid_camera_list"
    );
    let count: usize = tokens[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid_camera_list"))?;
    ensure!(
        count <= 1024 && tokens.len() == 2 + count * 7,
        "invalid_camera_list_count"
    );
    tokens[2..]
        .chunks_exact(7)
        .map(|c| {
            let id: i64 = c[0]
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid_camera_id"))?;
            ensure!(id > 0, "invalid_camera_id");
            for token in c {
                atom(token)?;
            }
            Ok(AccountCamera {
                device_id: id,
                udid: c[1].into(),
                model: c[2].into(),
                encoded_name: c[3].into(),
                device_token: c[4].into(),
                device_sid: c[5].into(),
                country_code: if c[6] == "undefined" {
                    String::new()
                } else {
                    c[6].into()
                },
            })
        })
        .collect()
}
/// Export exactly one saved camera to the receiver's independent credentials
/// schema. No account/camera network operation or production credential read.
pub fn export_camera(
    cameras: &[AccountCamera],
    selected: Option<i64>,
    output: &Path,
) -> Result<()> {
    ensure!(cameras.len() <= 1024, "invalid_camera_list_count");
    let camera = match selected {
        Some(id) => {
            ensure!(id > 0, "invalid_camera_id");
            let mut matches = cameras.iter().filter(|camera| camera.device_id == id);
            let camera = matches
                .next()
                .ok_or_else(|| anyhow::anyhow!("camera_not_found"))?;
            ensure!(matches.next().is_none(), "ambiguous_camera_selection");
            camera
        }
        None => {
            ensure!(!cameras.is_empty(), "camera_not_found");
            ensure!(cameras.len() == 1, "camera_selection_required");
            &cameras[0]
        }
    };
    ensure!(camera.device_id > 0, "invalid_camera_id");
    let credentials = serde_json::json!({
        "session_id": atom(&camera.device_sid)?,
        "transport_password": atom(&camera.device_token)?,
        "transport_user": "orbweb_user",
        "rendezvous": "rdz.orbwebsys.com",
    });
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("output_parent_required"))?;
    require_private_dir(parent)?;
    // create_new is the no-overwrite check, including existing symlinks and
    // paths created concurrently after validation. Never rename over output.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)
        .map_err(|error| {
            anyhow::anyhow!(if error.kind() == std::io::ErrorKind::AlreadyExists {
                "export_output_exists"
            } else {
                "export_write_failed"
            })
        })?;
    let result = (|| -> Result<()> {
        serde_json::to_writer(&mut file, &credentials)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(output);
        bail!("export_write_failed");
    }
    Ok(())
}
pub fn require_private_dir(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| anyhow::anyhow!("private_directory_required"))?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
        "private_directory_required"
    );
    Ok(())
}

pub fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir(path).map_err(|_| anyhow::anyhow!("state_directory_create_failed"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.permissions().mode() & 0o077 == 0,
        "private_directory_required"
    );
    Ok(())
}
pub fn read_private(path: &Path) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.permissions().mode() & 0o077 == 0,
        "private_file_required"
    );
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "private_file_too_large");
    Ok(bytes)
}
pub fn write_private<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output_parent_required"))?;
    private_dir(parent)?;
    if let Ok(m) = fs::symlink_metadata(path) {
        ensure!(
            m.is_file() && m.permissions().mode() & 0o077 == 0,
            "private_file_required"
        );
    }
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut created = false;
    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        created = true;
        serde_json::to_writer(&mut f, value)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        if created {
            let _ = fs::remove_file(&temporary);
        }
        bail!("private_state_write_failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_grammar_and_injection_rejection() {
        assert_eq!(
            otp_request("MOANtest", "test@example.invalid").unwrap(),
            "v3_otp MOANtest email test@example.invalid 6"
        );
        assert_eq!(
            login_request(42, "MOANtest", "test@example.invalid", "123456").unwrap(),
            "v3_loginset 42 MOANtest email test@example.invalid 123456"
        );
        for bad in ["a b", "a\nb", "a\rb", "", "a\0b"] {
            assert!(otp_request(bad, "test@example.invalid").is_err());
        }
        assert!(login_request(42, "MOANtest", "test@example.invalid", "123456\n").is_err());
        assert!(login_request(-1, "MOANtest", "test@example.invalid", "123456").is_err());
    }
    #[test]
    fn restore_rotates_only_session_token() {
        let mut s = AccountSession::from_login(
            "MOANtest",
            &[
                "v3_loginset",
                "42",
                "session",
                "master",
                "sid",
                "example.invalid",
            ],
        )
        .unwrap();
        assert_eq!(
            s.resume_request(false).unwrap(),
            "v3_session 42 session sid"
        );
        assert_eq!(s.resume_request(true).unwrap(), "v3_session 42 master sid");
        s.apply_resume(&["v3_session", "42", "next", "unused", "next.example.invalid"])
            .unwrap();
        assert_eq!(s.session_token, "next");
        assert_eq!(s.master_token, "master");
        assert_eq!(s.session_id, "sid");
        assert!(s
            .apply_resume(&["v3_session", "43", "bad", "unused", "example.invalid"])
            .is_err());
        assert_eq!(s.session_token, "next");
    }
    #[test]
    fn malformed_camera_count_and_fields_fail() {
        let c = [
            "v3_dlist",
            "1",
            "1",
            "device",
            "PIP1610HDCONNECT",
            "Test%20camera",
            "token",
            "sid",
            "undefined",
        ];
        let parsed = parse_camera_list(&c).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].country_code, "");
        assert!(parse_camera_list(&c[..8]).is_err());
        assert!(parse_camera_list(&["v3_dlist", "18446744073709551615"]).is_err());
        assert!(parse_camera_list(&["v3_dlist", "0", "unexpected"]).is_err());
    }
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("motorola-export-{}", device_identity().unwrap()));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn camera(id: i64) -> AccountCamera {
        AccountCamera {
            device_id: id,
            udid: "synthetic-device".into(),
            model: "synthetic-model".into(),
            encoded_name: "synthetic-name".into(),
            device_token: "synthetic-token".into(),
            device_sid: "synthetic-sid".into(),
            country_code: String::new(),
        }
    }
    #[test]
    fn export_maps_exact_receiver_schema_and_refuses_any_existing_output() {
        let dir = TempDir::new();
        let output = dir.0.join("camera.json");
        export_camera(&[camera(1)], None, &output).unwrap();
        let bytes = read_private(&output).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"session_id":"synthetic-sid","transport_password":"synthetic-token","transport_user":"orbweb_user","rendezvous":"rdz.orbwebsys.com"})
        );
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(export_camera(&[camera(2)], None, &output).is_err());
        assert_eq!(fs::read(&output).unwrap(), bytes);
        let link = dir.0.join("link.json");
        std::os::unix::fs::symlink(&output, &link).unwrap();
        assert!(export_camera(&[camera(1)], None, &link).is_err());
        assert_eq!(fs::read(&output).unwrap(), bytes);
    }
    #[test]
    fn export_requires_one_unambiguous_positive_selection() {
        let dir = TempDir::new();
        let output = dir.0.join("camera.json");
        for (cameras, selected) in [
            (vec![], None),
            (vec![camera(1), camera(2)], None),
            (vec![camera(1)], Some(2)),
            (vec![camera(1), camera(1)], Some(1)),
            (vec![camera(1)], Some(0)),
            (vec![camera(-1)], None),
        ] {
            assert!(export_camera(&cameras, selected, &output).is_err());
            assert!(!output.exists());
        }
        export_camera(&[camera(1), camera(2)], Some(2), &output).unwrap();
    }
    #[test]
    fn export_rejects_malformed_secrets_and_missing_or_public_parent() {
        let dir = TempDir::new();
        let output = dir.0.join("camera.json");
        for malformed in ["", "contains space", "line\nsecond", "nul\0value"] {
            let mut c = camera(1);
            c.device_token = malformed.into();
            assert!(export_camera(&[c], None, &output).is_err());
            let mut c = camera(1);
            c.device_sid = malformed.into();
            assert!(export_camera(&[c], None, &output).is_err());
        }
        assert!(!output.exists());
        assert!(export_camera(&[camera(1)], None, &dir.0.join("missing/camera.json")).is_err());
        assert!(!dir.0.join("missing").exists());
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(export_camera(&[camera(1)], None, &output).is_err());
        assert!(!output.exists());
    }
}
