use std::fmt;
use std::str::FromStr;

use thiserror::Error;

/// Errors that can occur when parsing firewall port tokens
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FwPortParseError {
    /// Invalid token (not a port number, range, keyword, or "*")
    #[error("invalid firewall port token: {0}")]
    Token(String),
    /// Invalid range start port
    #[error("invalid range start port: {0}")]
    RangeStart(String),
    /// Invalid range end port
    #[error("invalid range end port: {0}")]
    RangeEnd(String),
    /// Range start port is greater than end port
    #[error("port range start {start} is greater than end {end}")]
    RangeOrder {
        /// Starting port number of the range
        start: u16,
        /// Ending port number of the range
        end: u16,
    },
}

/// Enum representing firewall port keywords and values
/// Theses token can be uses uniquely in `local_ports` properties of firewall rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FwPortKeyword {
    /// "RPC" - the port(s) used by the RPC service, which can vary dynamically and are determined at runtime. The firewall will automatically allow the necessary ports for RPC communication when this keyword is used.
    Rpc,
    /// "RPC-EPMap" - the port used by the RPC Endpoint Mapper service, which is typically TCP port 135. This service is responsible for mapping RPC services to their dynamically assigned ports.
    RpcEpmap,
    /// "IPHTTPS" - the port used by the IP-HTTPS tunneling protocol, which is typically TCP port 443. This protocol allows IPv6 connectivity over an IPv4 network by encapsulating IPv6 packets within HTTPS.
    IpHttps,
    /// "`Ply2Disc`" - the port used by the Play-to-Disc (`Ply2Disc`) service, which is typically TCP port 1900. This service is used for media streaming and discovery in Windows.
    Ply2Disc,
    /// "Teredo" - the port used by the Teredo tunneling protocol, which is typically UDP port 3544. Teredo allows IPv6 connectivity over an IPv4 network by encapsulating IPv6 packets within UDP.
    Teredo,
}

impl fmt::Display for FwPortKeyword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Rpc => "RPC",
            Self::RpcEpmap => "RPC-EPMap",
            Self::IpHttps => "IPHTTPS",
            Self::Ply2Disc => "Ply2Disc",
            Self::Teredo => "Teredo",
        };
        f.write_str(s)
    }
}

impl FromStr for FwPortKeyword {
    type Err = FwPortParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("rpc") {
            return Ok(Self::Rpc);
        } else if s.eq_ignore_ascii_case("rpc-epmap") {
            return Ok(Self::RpcEpmap);
        } else if s.eq_ignore_ascii_case("iphttps") {
            return Ok(Self::IpHttps);
        } else if s.eq_ignore_ascii_case("ply2disc") {
            return Ok(Self::Ply2Disc);
        } else if s.eq_ignore_ascii_case("teredo") {
            return Ok(Self::Teredo);
        }

        Err(FwPortParseError::Token(s.into()))
    }
}

/// Struct representing a port range for firewall rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FwPortRange {
    /// Starting port number of the range
    pub start: u16,
    /// Ending port number of the range
    pub end: u16,
}

impl fmt::Display for FwPortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl FwPortRange {
    /// Creates a new `FwPortRange` ensuring that the start port is not greater than the end port.
    /// # Errors
    /// Returns `FwPortParseError::RangeOrder` if the start port is greater than the end port.
    pub fn new(start: u16, end: u16) -> Result<Self, FwPortParseError> {
        if start > end {
            return Err(FwPortParseError::RangeOrder { start, end });
        }

        Ok(Self { start, end })
    }
}

/// Firewall port token
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FwPort {
    /// "*" — any port
    Any,
    /// Keywords
    Keyword(FwPortKeyword),
    /// Single port
    Port(u16),
    /// Port range
    Range(FwPortRange),
}

impl fmt::Display for FwPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "*"),
            Self::Keyword(k) => k.fmt(f),
            Self::Port(p) => write!(f, "{p}"),
            Self::Range(range) => range.fmt(f),
        }
    }
}

impl From<u16> for FwPort {
    fn from(value: u16) -> Self {
        Self::Port(value)
    }
}

impl From<FwPortKeyword> for FwPort {
    fn from(value: FwPortKeyword) -> Self {
        Self::Keyword(value)
    }
}

impl From<FwPortRange> for FwPort {
    fn from(range: FwPortRange) -> Self {
        Self::Range(range)
    }
}

impl FromStr for FwPort {
    type Err = FwPortParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.is_empty() {
            return Err(FwPortParseError::Token(s.into()));
        }

        // Any port
        if s == "*" {
            return Ok(Self::Any);
        }

        // Keywords
        if let Ok(keyword) = FwPortKeyword::from_str(s) {
            return Ok(Self::Keyword(keyword));
        }

        // Port range: start-end
        if let Some((start, end)) = s.split_once('-') {
            let start = start
                .parse()
                .map_err(|_| FwPortParseError::RangeStart(start.into()))?;

            let end = end
                .parse()
                .map_err(|_| FwPortParseError::RangeEnd(end.into()))?;

            let range = FwPortRange::new(start, end)?;

            return Ok(Self::Range(range));
        }

        // Single port
        if let Ok(port) = s.parse() {
            return Ok(Self::Port(port));
        }

        Err(FwPortParseError::Token(s.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_any_port() {
        let parsed = FwPort::from_str("*").unwrap();
        assert_eq!(parsed, FwPort::Any);
    }

    /* ---------- From ---------- */

    #[test]
    fn parse_from_u16() {
        let port = 80;
        assert_eq!(FwPort::from(port), FwPort::Port(port));
    }

    #[test]
    fn parse_from_fw_port_range() {
        let range = FwPortRange::new(1000, 2000).unwrap();
        assert_eq!(FwPort::from(range), FwPort::Range(range));
    }

    #[test]
    fn parse_from_fw_port_keyword() {
        assert_eq!(
            FwPort::from(FwPortKeyword::Teredo),
            FwPort::Keyword(FwPortKeyword::Teredo)
        );
    }

    /* ---------- Keywords ---------- */

    #[test]
    fn parse_keywords_case_insensitive() {
        assert_eq!(FwPort::from_str("*").unwrap(), FwPort::Any);
        assert_eq!(
            FwPort::from_str("RPC").unwrap(),
            FwPort::Keyword(FwPortKeyword::Rpc)
        );
        assert_eq!(
            FwPort::from_str("rpc").unwrap(),
            FwPort::Keyword(FwPortKeyword::Rpc)
        );
    }

    #[test]
    fn parse_keywords_with_whitespace() {
        assert_eq!(FwPort::from_str(" * ").unwrap(), FwPort::Any);
        assert_eq!(
            FwPort::from_str(" rpc ").unwrap(),
            FwPort::Keyword(FwPortKeyword::Rpc)
        );
    }

    /* ---------- Single port ---------- */

    #[test]
    fn parse_single_port() {
        let parsed = FwPort::from_str("80").unwrap();
        assert_eq!(parsed, FwPort::Port(80));

        let parsed = FwPort::from_str("0").unwrap();
        assert_eq!(parsed, FwPort::Port(0));

        let parsed = FwPort::from_str("65535").unwrap();
        assert_eq!(parsed, FwPort::Port(65535));
    }

    /* ---------- Port range ---------- */

    #[test]
    fn parse_port_range() {
        let parsed = FwPort::from_str("1000-2000").unwrap();
        assert_eq!(parsed, FwPort::Range(FwPortRange::new(1000, 2000).unwrap()));

        let parsed = FwPort::from_str("0-65535").unwrap();
        assert_eq!(parsed, FwPort::Range(FwPortRange::new(0, 65535).unwrap()));
    }

    #[test]
    fn reject_invalid_range_start() {
        let err = FwPort::from_str("abc-100").unwrap_err();

        assert!(matches!(err, FwPortParseError::RangeStart(_)));
    }

    #[test]
    fn reject_invalid_range_end() {
        let err = FwPort::from_str("100-xyz").unwrap_err();

        assert!(matches!(err, FwPortParseError::RangeEnd(_)));
    }

    #[test]
    fn reject_range_start_greater_than_end() {
        let err = FwPort::from_str("2000-1000").unwrap_err();

        assert!(matches!(err, FwPortParseError::RangeOrder { .. }));
    }

    /* ---------- Display roundtrip ---------- */

    #[test]
    fn display_roundtrip_keyword() {
        let parsed = FwPort::from_str("*").unwrap();
        assert_eq!(parsed.to_string(), "*");

        let parsed = FwPort::from_str("RPC").unwrap();
        assert_eq!(parsed.to_string(), "RPC");
    }

    #[test]
    fn display_roundtrip_port() {
        let port = FwPort::Port(8080);
        let s = port.to_string();
        let parsed = FwPort::from_str(&s).unwrap();
        assert_eq!(port, parsed);
    }

    #[test]
    fn display_roundtrip_range() {
        let range = FwPort::Range(FwPortRange::new(1000, 2000).unwrap());
        let s = range.to_string();
        let parsed = FwPort::from_str(&s).unwrap();
        assert_eq!(range, parsed);
    }

    /* ---------- Invalid inputs ---------- */

    #[test]
    fn reject_invalid_port_number() {
        assert!(FwPort::from_str("70000").is_err());
        assert!(FwPort::from_str("-1").is_err());
        assert!(FwPort::from_str("abc").is_err());
    }

    #[test]
    fn reject_garbage() {
        assert!(FwPort::from_str("not a port").is_err());
        assert!(FwPort::from_str("123-abc").is_err());
        assert!(FwPort::from_str("abc-123").is_err());
    }

    #[test]
    fn parse_empty_string() {
        let err = FwPort::from_str("").unwrap_err();
        assert!(matches!(err, FwPortParseError::Token(_)));
    }
}
