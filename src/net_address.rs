use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// Represents either a single IP address or a CIDR subnet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NetAddress {
    /// A single IPv4 or IPv6 address.
    Ip(IpAddr),
    /// A CIDR subnet (IPv4 or IPv6).
    Cidr(IpNet),
}

impl fmt::Display for NetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetAddress::Ip(ip) => write!(f, "{}", ip),
            NetAddress::Cidr(net) => write!(f, "{}", net),
        }
    }
}

impl From<IpAddr> for NetAddress {
    fn from(value: IpAddr) -> Self {
        NetAddress::Ip(value)
    }
}

impl From<IpNet> for NetAddress {
    fn from(value: IpNet) -> Self {
        NetAddress::Cidr(value)
    }
}

impl FromStr for NetAddress {
    type Err = ipnet::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IpNet::from_str(s)
            .map(NetAddress::Cidr)
            .or_else(|cidr_err| IpAddr::from_str(s).map(NetAddress::Ip).map_err(|_| cidr_err))
    }
}
