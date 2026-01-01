use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;

/// A parsed BridgeDB-format bridge line.
///
/// - vanilla:  `Bridge 1.2.3.4:443 0102...14`
/// - PT:       `Bridge obfs4 1.2.3.4:443 0102...14 cert=... iat-mode=0`
#[derive(Debug, Clone)]
pub struct Bridge {
    pub transport: Option<String>,        // None for vanilla, Some("obfs4") etc for PT
    pub addr: SocketAddr,
    pub fingerprint: String,              // 40-hex; may be empty for some PT bridges
    pub args: HashMap<String, String>,    // PT-specific (cert=..., iat-mode=..., url=...)
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("invalid bridge line: {0}")] InvalidLine(String),
    #[error("invalid socket addr: {0}")] InvalidAddr(String),
    #[error("invalid fingerprint: {0}")] InvalidFingerprint(String),
}

impl Bridge {
    /// Parse a single BridgeDB-format line. Leading "Bridge " is optional.
    pub fn parse(line: &str) -> Result<Bridge, BridgeError> {
        let s = line.trim();
        let s = s.strip_prefix("Bridge ").unwrap_or(s);
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.is_empty() {
            return Err(BridgeError::InvalidLine(line.to_string()));
        }

        // Heuristic: if the first token contains a colon it's an addr
        // (vanilla bridge), else it's a PT name.
        let (transport, idx) = if parts[0].contains(':') {
            (None, 0)
        } else {
            (Some(parts[0].to_string()), 1)
        };
        if parts.len() <= idx {
            return Err(BridgeError::InvalidLine(line.to_string()));
        }
        let addr = SocketAddr::from_str(parts[idx])
            .map_err(|_| BridgeError::InvalidAddr(parts[idx].to_string()))?;

        // Fingerprint is mandatory in vanilla and conventionally present
        // (though not always-validated) in PT bridge lines.
        let mut fp = String::new();
        let mut args = HashMap::new();
        for p in &parts[(idx + 1)..] {
            if p.len() == 40 && p.chars().all(|c| c.is_ascii_hexdigit()) {
                fp = p.to_string();
            } else if let Some((k, v)) = p.split_once('=') {
                args.insert(k.to_string(), v.to_string());
            }
        }
        if fp.is_empty() && transport.is_none() {
            return Err(BridgeError::InvalidFingerprint("missing".into()));
        }

        Ok(Bridge { transport, addr, fingerprint: fp, args })
    }

    /// Format suitable for arti's bridge-config TOML.
    pub fn to_arti_toml(&self) -> String {
        let mut s = String::new();
        if let Some(t) = &self.transport { s.push_str(t); s.push(' '); }
        s.push_str(&self.addr.to_string());
        if !self.fingerprint.is_empty() { s.push(' '); s.push_str(&self.fingerprint); }
        for (k, v) in &self.args { s.push(' '); s.push_str(k); s.push('='); s.push_str(v); }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn parses_vanilla() {
        let b = Bridge::parse("Bridge 1.2.3.4:443 0102030405060708090A0B0C0D0E0F1011121314").unwrap();
        assert!(b.transport.is_none());
        assert_eq!(b.fingerprint, "0102030405060708090A0B0C0D0E0F1011121314");
    }

    #[test] fn parses_obfs4_with_args() {
        let line = "Bridge obfs4 1.2.3.4:443 0102030405060708090A0B0C0D0E0F1011121314 cert=ABC iat-mode=0";
        let b = Bridge::parse(line).unwrap();
        assert_eq!(b.transport.as_deref(), Some("obfs4"));
        assert_eq!(b.args.get("cert"), Some(&"ABC".to_string()));
    }

    #[test] fn rejects_invalid_addr() {
        assert!(Bridge::parse("Bridge not-an-addr 0102030405060708090A0B0C0D0E0F1011121314").is_err());
    }
}
