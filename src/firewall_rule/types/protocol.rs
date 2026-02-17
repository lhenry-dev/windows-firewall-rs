use windows::Win32::NetworkManagement::WindowsFirewall::{
    NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP,
};

use crate::firewall_rule::types::InvalidRuleProperty;

/// Represents the possible firewall protocols in Windows
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
    /// `ICMPv4` protocol
    Icmpv4,
    /// `ICMPv6` protocol
    Icmpv6,
    /// IGMP protocol
    Igmp,
    /// IPv4 protocol
    Ipv4,
    /// IPv6 protocol
    Ipv6,
    /// GRE protocol
    Gre,
    /// ESP protocol
    Esp,
    /// AH protocol
    Ah,
    /// SCTP protocol
    Sctp,
    /// Any protocol (wildcard)
    Any,
}

impl Protocol {
    /// Helper method to check if the protocol is ICMP (either v4 or v6)
    pub(crate) fn is_icmp(self) -> bool {
        matches!(self, Self::Icmpv4 | Self::Icmpv6)
    }

    /// Helper method to check if the protocol is TCP or UDP
    pub(crate) fn is_tcp_or_udp(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp)
    }
}

/// Implements conversion from `i32` to `Protocol`
impl TryFrom<i32> for Protocol {
    type Error = InvalidRuleProperty;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            x if x == NET_FW_IP_PROTOCOL_TCP.0 => Ok(Self::Tcp),
            x if x == NET_FW_IP_PROTOCOL_UDP.0 => Ok(Self::Udp),
            1 => Ok(Self::Icmpv4),
            58 => Ok(Self::Icmpv6),
            2 => Ok(Self::Igmp),
            4 => Ok(Self::Ipv4),
            41 => Ok(Self::Ipv6),
            47 => Ok(Self::Gre),
            50 => Ok(Self::Esp),
            51 => Ok(Self::Ah),
            132 => Ok(Self::Sctp),
            x if x == NET_FW_IP_PROTOCOL_ANY.0 => Ok(Self::Any),
            _ => Err(InvalidRuleProperty::NetFwIpProtocol),
        }
    }
}

/// Implements conversion from `Protocol` to `i32`
impl From<Protocol> for i32 {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Tcp => NET_FW_IP_PROTOCOL_TCP.0,
            Protocol::Udp => NET_FW_IP_PROTOCOL_UDP.0,
            Protocol::Icmpv4 => 1,
            Protocol::Icmpv6 => 58,
            Protocol::Igmp => 2,
            Protocol::Ipv4 => 4,
            Protocol::Ipv6 => 41,
            Protocol::Gre => 47,
            Protocol::Esp => 50,
            Protocol::Ah => 51,
            Protocol::Sctp => 132,
            Protocol::Any => NET_FW_IP_PROTOCOL_ANY.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Protocol, firewall_rule::types::InvalidRuleProperty};

    #[test]
    fn test_try_from_invalid_net_fw_protocol() {
        let invalid_value = 999;

        let result = Protocol::try_from(invalid_value);

        assert!(matches!(result, Err(InvalidRuleProperty::NetFwIpProtocol)));
    }
}
