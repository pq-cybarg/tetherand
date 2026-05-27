//! Minimal parser for the WireGuard config text format.

use std::net::SocketAddr;
use std::str::FromStr;

use base64::Engine;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct WgPeerConfig {
    pub private_key: [u8; 32],
    pub address_cidr: String,
    pub dns: Vec<String>,
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<String>,
    pub endpoint: SocketAddr,
    pub persistent_keepalive_secs: Option<u16>,
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("invalid base64 key for {0}")]
    BadBase64(&'static str),
    #[error("key {0} must decode to 32 bytes, got {1}")]
    KeyLength(&'static str, usize),
    #[error("invalid endpoint: {0}")]
    BadEndpoint(String),
    #[error("invalid number for {0}: {1}")]
    BadNumber(&'static str, String),
    #[error("unknown section: [{0}]")]
    UnknownSection(String),
}

impl WgPeerConfig {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut section: Option<&str> = None;
        let mut interface = std::collections::HashMap::<String, String>::new();
        let mut peer = std::collections::HashMap::<String, String>::new();

        for line in input.lines() {
            let l = line.split('#').next().unwrap().trim();
            if l.is_empty() { continue; }
            if let Some(rest) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                match rest {
                    "Interface" | "Peer" => section = Some(rest),
                    other => return Err(ParseError::UnknownSection(other.into())),
                }
                continue;
            }
            let (k, v) = match l.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            let k = k.trim().to_string();
            let v = v.trim().to_string();
            match section {
                Some("Interface") => { interface.insert(k, v); }
                Some("Peer")      => { peer.insert(k, v); }
                _ => {}
            }
        }

        fn key32(
            b64: &base64::engine::general_purpose::GeneralPurpose,
            src: &str,
            field: &'static str,
        ) -> Result<[u8; 32], ParseError> {
            let bytes = b64.decode(src).map_err(|_| ParseError::BadBase64(field))?;
            if bytes.len() != 32 {
                return Err(ParseError::KeyLength(field, bytes.len()));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(out)
        }

        let private_key = key32(
            &b64,
            interface
                .get("PrivateKey")
                .ok_or(ParseError::Missing("Interface.PrivateKey"))?,
            "Interface.PrivateKey",
        )?;
        let address_cidr = interface
            .get("Address")
            .cloned()
            .ok_or(ParseError::Missing("Interface.Address"))?;
        let dns = interface
            .get("DNS")
            .map(|s| s.split(',').map(|p| p.trim().to_owned()).collect())
            .unwrap_or_default();

        let peer_public_key = key32(
            &b64,
            peer.get("PublicKey")
                .ok_or(ParseError::Missing("Peer.PublicKey"))?,
            "Peer.PublicKey",
        )?;
        let preshared_key = peer
            .get("PresharedKey")
            .map(|s| key32(&b64, s, "Peer.PresharedKey"))
            .transpose()?;
        let allowed_ips = peer
            .get("AllowedIPs")
            .map(|s| s.split(',').map(|p| p.trim().to_owned()).collect())
            .unwrap_or_else(|| vec!["0.0.0.0/0".into()]);
        let endpoint_str = peer
            .get("Endpoint")
            .ok_or(ParseError::Missing("Peer.Endpoint"))?;
        let endpoint = SocketAddr::from_str(endpoint_str)
            .map_err(|e| ParseError::BadEndpoint(format!("{endpoint_str}: {e}")))?;
        let persistent_keepalive_secs = peer
            .get("PersistentKeepalive")
            .map(|s| {
                s.parse::<u16>()
                    .map_err(|e| ParseError::BadNumber("PersistentKeepalive", e.to_string()))
            })
            .transpose()?;

        Ok(Self {
            private_key,
            address_cidr,
            dns,
            peer_public_key,
            preshared_key,
            allowed_ips,
            endpoint,
            persistent_keepalive_secs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[Interface]
PrivateKey = QFlzM1Nb1OFGdQpC7vY9X+Fy2vSC5IqI9bWcQz/aFmI=
Address    = 10.66.0.2/32
DNS        = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey  = OvUKpBPB+RHj4XPYbq2WJv8MNoTQDXq1g6gXBVPXVlw=
AllowedIPs = 0.0.0.0/0
Endpoint   = 198.51.100.7:51820
PersistentKeepalive = 25
"#;

    #[test]
    fn parses_minimal_config() {
        let c = WgPeerConfig::parse(SAMPLE).unwrap();
        assert_eq!(c.address_cidr, "10.66.0.2/32");
        assert_eq!(c.dns, vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()]);
        assert_eq!(c.allowed_ips, vec!["0.0.0.0/0".to_string()]);
        assert_eq!(c.endpoint.to_string(), "198.51.100.7:51820");
        assert_eq!(c.persistent_keepalive_secs, Some(25));
        assert!(c.preshared_key.is_none());
    }

    #[test]
    fn missing_private_key_rejected() {
        let bad = SAMPLE.replace("PrivateKey = QFlzM1Nb1OFGdQpC7vY9X+Fy2vSC5IqI9bWcQz/aFmI=", "");
        let err = WgPeerConfig::parse(&bad).unwrap_err();
        assert_eq!(err, ParseError::Missing("Interface.PrivateKey"));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let with_noise = format!("# header comment\n\n{SAMPLE}\n# trailer\n");
        assert!(WgPeerConfig::parse(&with_noise).is_ok());
    }

    #[test]
    fn psk_parsed() {
        let with_psk = SAMPLE.replace(
            "AllowedIPs",
            "PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs",
        );
        let c = WgPeerConfig::parse(&with_psk).unwrap();
        assert!(c.preshared_key.is_some());
        assert_eq!(c.preshared_key.unwrap(), [0u8; 32]);
    }
}
