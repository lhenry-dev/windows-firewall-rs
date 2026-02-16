use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::{IpNet, ip_mask_to_prefix};

use thiserror::Error;

/// Errors that can occur when parsing firewall address tokens
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AddressParseError {
    /// Invalid token (not an IP, CIDR, range, keyword, or "*")
    #[error("invalid firewall address token: {0}")]
    Token(String),
    /// Invalid range start address
    #[error("invalid range start address: {0}")]
    RangeStart(String),
    /// Invalid range end address
    #[error("invalid range end address: {0}")]
    RangeEnd(String),
    /// Range start address is greater than end address
    #[error("address range start {start} is greater than end {end}")]
    RangeOrder {
        /// Starting IP address of the range
        start: IpAddr,
        /// Ending IP address of the range
        end: IpAddr,
    },
}

/// Enum representing firewall address tokens
/// Theses token can be uses uniquely in `remote_addresses` properties of firewall rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKeyword {
    /// "`DefaultGateway`" — the address(es) of the default gateway(s) assigned to the machine
    DefaultGateway,
    /// "Dhcp" — the address assigned by DHCP
    Dhcp,
    /// "Dns" — the address of the DNS server(s) assigned to the machine
    Dns,
    /// "Wins" — the address of the WINS server(s) assigned to the machine
    Wins,
    /// "`LocalSubnet`" — the addresses on the local subnet(s) of the machine
    LocalSubnet,
}

impl fmt::Display for AddressKeyword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DefaultGateway => "DefaultGateway",
            Self::Dhcp => "DHCP",
            Self::Dns => "DNS",
            Self::Wins => "WINS",
            Self::LocalSubnet => "LocalSubnet",
        };
        f.write_str(s)
    }
}

impl FromStr for AddressKeyword {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("defaultgateway") {
            return Ok(Self::DefaultGateway);
        } else if s.eq_ignore_ascii_case("dhcp") {
            return Ok(Self::Dhcp);
        } else if s.eq_ignore_ascii_case("dns") {
            return Ok(Self::Dns);
        } else if s.eq_ignore_ascii_case("wins") {
            return Ok(Self::Wins);
        } else if s.eq_ignore_ascii_case("localsubnet") {
            return Ok(Self::LocalSubnet);
        }

        Err(AddressParseError::Token(s.into()))
    }
}

/// Struct representing an IP address range for firewall rules
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressRange {
    /// Starting IP address of the range
    pub start: IpAddr,
    /// Ending IP address of the range
    pub end: IpAddr,
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl AddressRange {
    /// Creates a new `AddressRange` ensuring that the start address is not greater than the end address.
    /// # Errors
    /// Returns `AddressParseError::RangeOrder` if the start address is greater than the end address.
    pub fn new(start: IpAddr, end: IpAddr) -> Result<Self, AddressParseError> {
        if start > end {
            return Err(AddressParseError::RangeOrder { start, end });
        }

        Ok(Self { start, end })
    }
}

/// Firewall address tokenS
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    /// "*" — any address
    Any,
    /// Keywords
    Keyword(AddressKeyword),
    /// Single IPv4 or IPv6 address
    Ip(IpAddr),
    /// CIDR or subnet (IPv4 or IPv6)
    Cidr(IpNet),
    /// IP range (IPv4 or IPv6)
    Range(AddressRange),
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => write!(f, "*"),
            Self::Keyword(kw) => kw.fmt(f),
            Self::Ip(ip) => ip.fmt(f),
            Self::Cidr(net) => net.fmt(f),
            Self::Range(range) => range.fmt(f),
        }
    }
}

impl From<IpAddr> for Address {
    fn from(value: IpAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<IpNet> for Address {
    fn from(value: IpNet) -> Self {
        Self::Cidr(value)
    }
}

impl From<AddressKeyword> for Address {
    fn from(value: AddressKeyword) -> Self {
        Self::Keyword(value)
    }
}

impl From<AddressRange> for Address {
    fn from(value: AddressRange) -> Self {
        Self::Range(value)
    }
}

impl FromStr for Address {
    type Err = AddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();

        if s.is_empty() {
            return Err(AddressParseError::Token(s.into()));
        }

        // Any address
        if s == "*" {
            return Ok(Self::Any);
        }

        // Keywords
        if let Ok(keyword) = AddressKeyword::from_str(s) {
            return Ok(Self::Keyword(keyword));
        }

        // Single IP
        if let Ok(ip) = IpAddr::from_str(s) {
            return Ok(Self::Ip(ip));
        }

        // CIDR or subnet, including format with decimal mask
        if let Some((ip_part, mask_part)) = s.split_once('/') {
            if let Ok(net) = IpNet::from_str(s) {
                return Ok(normalize_net(net));
            }

            let ip: IpAddr = ip_part
                .parse()
                .map_err(|_| AddressParseError::Token(s.into()))?;

            let mask: IpAddr = mask_part
                .parse()
                .map_err(|_| AddressParseError::Token(s.into()))?;

            let prefix = ip_mask_to_prefix(mask).map_err(|_| AddressParseError::Token(s.into()))?;

            let net = IpNet::new(ip, prefix).map_err(|_| AddressParseError::Token(s.into()))?;

            return Ok(normalize_net(net));
        }

        // IP range: start-end
        if let Some((start, end)) = s.split_once('-') {
            let start =
                IpAddr::from_str(start).map_err(|_| AddressParseError::RangeStart(start.into()))?;
            let end = IpAddr::from_str(end).map_err(|_| AddressParseError::RangeEnd(end.into()))?;

            let range = AddressRange::new(start, end)?;

            return Ok(Self::Range(range));
        }

        Err(AddressParseError::Token(s.into()))
    }
}

fn normalize_net(net: IpNet) -> Address {
    if net.prefix_len() == net.max_prefix_len() {
        Address::Ip(net.addr())
    } else {
        Address::Cidr(net)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn parse_any_address() {
        let parsed = Address::from_str("*").unwrap();
        assert_eq!(parsed, Address::Any);
    }

    /* ---------- From ---------- */

    #[test]
    fn parse_from_ip_addr() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Address::from(ip), Address::Ip(ip));
    }

    #[test]
    fn parse_from_ip_net() {
        let net = IpNet::from_str("192.168.0.0/24").unwrap();
        assert_eq!(Address::from(net), Address::Cidr(net));
    }

    #[test]
    fn parse_from_fw_address_keyword() {
        assert_eq!(
            Address::from(AddressKeyword::DefaultGateway),
            Address::Keyword(AddressKeyword::DefaultGateway)
        );
    }

    #[test]
    fn parse_from_fw_address_range() {
        let start = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let end = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let range = AddressRange::new(start, end).unwrap();
        assert_eq!(Address::from(range), Address::Range(range));
    }

    /* ---------- Keywords ---------- */
    #[test]
    fn parse_keywords_case_insensitive() {
        assert_eq!(Address::from_str("*").unwrap(), Address::Any);
        assert_eq!(
            Address::from_str("DEFAULTGATEWAY").unwrap(),
            Address::Keyword(AddressKeyword::DefaultGateway)
        );
        assert_eq!(
            Address::from_str("dhcp").unwrap(),
            Address::Keyword(AddressKeyword::Dhcp)
        );
        assert_eq!(
            Address::from_str("Dns").unwrap(),
            Address::Keyword(AddressKeyword::Dns)
        );
        assert_eq!(
            Address::from_str("wins").unwrap(),
            Address::Keyword(AddressKeyword::Wins)
        );
        assert_eq!(
            Address::from_str("LocalSubnet").unwrap(),
            Address::Keyword(AddressKeyword::LocalSubnet)
        );
    }

    #[test]
    fn parse_keywords_with_whitespace() {
        assert_eq!(
            Address::from_str("  dhcp ").unwrap(),
            Address::Keyword(AddressKeyword::Dhcp)
        );
        assert_eq!(Address::from_str(" * ").unwrap(), Address::Any);
    }

    /* ---------- Single IP ---------- */

    #[test]
    fn parse_single_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Address::from_str("192.168.1.1").unwrap(), Address::Ip(ip));
    }

    #[test]
    fn parse_single_ipv6() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(Address::from_str("::1").unwrap(), Address::Ip(ip));
    }

    /* ---------- CIDR ---------- */

    #[test]
    fn parse_ipv4_cidr() {
        let net = IpNet::from_str("192.168.0.0/24").unwrap();
        assert_eq!(
            Address::from_str("192.168.0.0/24").unwrap(),
            Address::Cidr(net)
        );
    }

    #[test]
    fn parse_ipv6_cidr() {
        let net = IpNet::from_str("2001:db8::/32").unwrap();
        assert_eq!(
            Address::from_str("2001:db8::/32").unwrap(),
            Address::Cidr(net)
        );
    }

    #[test]
    fn parse_ipv4_cidr_32_becomes_ip() {
        let parsed = Address::from_str("192.168.0.1/32").unwrap();
        assert_eq!(parsed, Address::Ip("192.168.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6_cidr_128_becomes_ip() {
        let parsed = Address::from_str("::1/128").unwrap();
        assert_eq!(parsed, Address::Ip("::1".parse().unwrap()));
    }

    /* ---------- Decimal mask ---------- */

    #[test]
    fn parse_ipv4_decimal_mask() {
        let net = IpNet::from_str("192.168.1.0/24").unwrap();
        let parsed = Address::from_str("192.168.1.0/255.255.255.0").unwrap();
        assert_eq!(parsed, Address::Cidr(net));
    }

    #[test]
    fn parse_ipv6_decimal_mask() {
        let expected = IpNet::from_str("2001:db8::/32").unwrap();
        let parsed = Address::from_str("2001:db8::/ffff:ffff::").unwrap();

        assert_eq!(parsed, Address::Cidr(expected));
    }

    /* ---------- IP range ---------- */

    #[test]
    fn parse_ipv4_range() {
        let start = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let end = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));

        assert_eq!(
            Address::from_str("10.0.0.1-10.0.0.10").unwrap(),
            Address::Range(AddressRange { start, end })
        );
    }

    #[test]
    fn parse_ipv6_range() {
        let start = IpAddr::V6("2001:db8::1".parse().unwrap());
        let end = IpAddr::V6("2001:db8::ffff".parse().unwrap());

        assert_eq!(
            Address::from_str("2001:db8::1-2001:db8::ffff").unwrap(),
            Address::Range(AddressRange { start, end })
        );
    }

    #[test]
    fn invalid_range_start() {
        let err = Address::from_str("foo-192.168.0.1").unwrap_err();
        assert!(matches!(err, AddressParseError::RangeStart(_)));
    }

    #[test]
    fn invalid_range_end() {
        let err = Address::from_str("192.168.0.1-bar").unwrap_err();
        assert!(matches!(err, AddressParseError::RangeEnd(_)));
    }

    #[test]
    fn reject_range_start_greater_than_end() {
        let err = Address::from_str("192.168.0.1-192.168.0.0").unwrap_err();

        assert!(matches!(err, AddressParseError::RangeOrder { .. }));
    }

    /* ---------- Display roundtrip ---------- */

    #[test]
    fn display_roundtrip_ip() {
        let original = Address::Ip("8.8.8.8".parse().unwrap());
        let s = original.to_string();
        let parsed = Address::from_str(&s).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn display_roundtrip_cidr() {
        let original = Address::Cidr("10.0.0.0/8".parse().unwrap());
        let s = original.to_string();
        let parsed = Address::from_str(&s).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn display_roundtrip_range() {
        let original = Address::Range(AddressRange {
            start: "192.168.1.1".parse().unwrap(),
            end: "192.168.1.100".parse().unwrap(),
        });
        let s = original.to_string();
        let parsed = Address::from_str(&s).unwrap();
        assert_eq!(original, parsed);
    }

    /* ---------- Invalid inputs ---------- */

    #[test]
    fn reject_invalid_address() {
        assert!(Address::from_str("70000").is_err());
        assert!(Address::from_str("-1").is_err());
        assert!(Address::from_str("abc").is_err());
    }

    #[test]
    fn reject_garbage() {
        assert!(Address::from_str("not-an-ip").is_err());
        assert!(Address::from_str("192.168.1.1/999").is_err());
        assert!(Address::from_str("192.168.1.1/255.0").is_err());
        assert!(Address::from_str("192.168.1.1-").is_err());
    }

    #[test]
    fn parse_empty_string() {
        let err = Address::from_str("").unwrap_err();
        assert!(matches!(err, AddressParseError::Token(_)));
    }
}
