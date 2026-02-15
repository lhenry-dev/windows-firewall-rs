use std::{fmt, str::FromStr};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    NET_FW_ACTION, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_ACTION_MAX,
    NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_PROFILE_CURRENT,
    NET_FW_PROFILE_DOMAIN, NET_FW_PROFILE_STANDARD, NET_FW_PROFILE_TYPE_MAX, NET_FW_PROFILE2_ALL,
    NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN,
    NET_FW_RULE_DIR_MAX, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIRECTION,
};

use crate::errors::InvalidRuleValue;

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

/// Implements conversion from `i32` to `Firewall`
impl TryFrom<i32> for Protocol {
    type Error = InvalidRuleValue;

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
            _ => Err(InvalidRuleValue::NetFwIpProtocol),
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

/// Represents the possible firewall rule directions in Windows
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Direction {
    /// Incoming direction
    In,
    /// Outgoing direction
    Out,
    /// Maximum possible value (not typically used directly)
    Max,
}

/// Implements conversion from `NET_FW_RULE_DIRECTION` to `Direction`
impl TryFrom<NET_FW_RULE_DIRECTION> for Direction {
    type Error = InvalidRuleValue;

    fn try_from(value: NET_FW_RULE_DIRECTION) -> Result<Self, Self::Error> {
        match value {
            NET_FW_RULE_DIR_IN => Ok(Self::In),
            NET_FW_RULE_DIR_OUT => Ok(Self::Out),
            NET_FW_RULE_DIR_MAX => Ok(Self::Max),
            _ => Err(InvalidRuleValue::NetFwRuleDirection),
        }
    }
}

/// Implements conversion from `Direction` to `NET_FW_RULE_DIRECTION`
impl From<Direction> for NET_FW_RULE_DIRECTION {
    fn from(direction: Direction) -> Self {
        match direction {
            Direction::In => NET_FW_RULE_DIR_IN,
            Direction::Out => NET_FW_RULE_DIR_OUT,
            Direction::Max => NET_FW_RULE_DIR_MAX,
        }
    }
}

/// Represents the various Windows Firewall profiles.
///
/// This enum includes both legacy (v1) and modern (v2) profile types.
/// Prefer using the `V2` variants unless you're targeting legacy Windows versions (pre-Vista).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Profile {
    /// Modern: Domain profile.
    Domain,
    /// Modern: Private profile (used on trusted networks like home/work).
    Private,
    /// Modern: Public profile (used on untrusted networks like public Wi-Fi).
    Public,
    /// Modern: All profiles combined (bitflag: DOMAIN | PRIVATE | PUBLIC).
    All,

    /// Legacy: Domain profile (Windows XP/2003).
    LegacyDomain,
    /// Legacy: Standard profile (aka Private/Public in older systems).
    LegacyStandard,
    /// Legacy: Current profile (represents the currently active profile).
    LegacyCurrent,
    /// Legacy: Max profile value (internal use only).
    LegacyMax,
}

/// Implements conversion from `i32` to `Profile`
impl TryFrom<i32> for Profile {
    type Error = InvalidRuleValue;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            x if x == NET_FW_PROFILE2_DOMAIN.0 => Ok(Self::Domain),
            x if x == NET_FW_PROFILE2_PRIVATE.0 => Ok(Self::Private),
            x if x == NET_FW_PROFILE2_PUBLIC.0 => Ok(Self::Public),
            x if x == NET_FW_PROFILE2_ALL.0 => Ok(Self::All),

            x if x == NET_FW_PROFILE_DOMAIN.0 => Ok(Self::LegacyDomain),
            x if x == NET_FW_PROFILE_STANDARD.0 => Ok(Self::LegacyStandard),
            x if x == NET_FW_PROFILE_CURRENT.0 => Ok(Self::LegacyCurrent),
            x if x == NET_FW_PROFILE_TYPE_MAX.0 => Ok(Self::LegacyMax),
            _ => Err(InvalidRuleValue::NetFwProfile),
        }
    }
}

/// Implements conversion from [`Profile`] to `i32`
impl From<Profile> for i32 {
    fn from(profile: Profile) -> Self {
        match profile {
            Profile::Domain => NET_FW_PROFILE2_DOMAIN.0,
            Profile::Private => NET_FW_PROFILE2_PRIVATE.0,
            Profile::Public => NET_FW_PROFILE2_PUBLIC.0,
            Profile::All => NET_FW_PROFILE2_ALL.0,

            Profile::LegacyDomain => NET_FW_PROFILE_DOMAIN.0,
            Profile::LegacyStandard => NET_FW_PROFILE_STANDARD.0,
            Profile::LegacyCurrent => NET_FW_PROFILE_CURRENT.0,
            Profile::LegacyMax => NET_FW_PROFILE_TYPE_MAX.0,
        }
    }
}

/// Represents the possible firewall actions in Windows
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Action {
    /// Block network traffic
    Block,
    /// Allow network traffic
    Allow,
    /// Maximum possible value (not typically used directly)
    Max,
}

/// Implements conversion from `NET_FW_ACTION` to `Action`
impl TryFrom<NET_FW_ACTION> for Action {
    type Error = InvalidRuleValue;

    fn try_from(action: NET_FW_ACTION) -> Result<Self, Self::Error> {
        match action {
            NET_FW_ACTION_BLOCK => Ok(Self::Block),
            NET_FW_ACTION_ALLOW => Ok(Self::Allow),
            NET_FW_ACTION_MAX => Ok(Self::Max),
            _ => Err(InvalidRuleValue::NetFwAction),
        }
    }
}

/// Implements conversion from `Action` to `NET_FW_ACTION`
impl From<Action> for NET_FW_ACTION {
    fn from(action: Action) -> Self {
        match action {
            Action::Block => NET_FW_ACTION_BLOCK,
            Action::Allow => NET_FW_ACTION_ALLOW,
            Action::Max => NET_FW_ACTION_MAX,
        }
    }
}

/// Enum representing different types of network interfaces.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum InterfaceType {
    /// Wireless interface
    Wireless,
    /// LAN interface
    Lan,
    /// Remote Access interface
    RemoteAccess,
    /// Applies to all interfaces
    All,
}

impl FromStr for InterfaceType {
    type Err = InvalidRuleValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Wireless" => Ok(Self::Wireless),
            "Lan" => Ok(Self::Lan),
            "RemoteAccess" => Ok(Self::RemoteAccess),
            "All" => Ok(Self::All),
            _ => Err(InvalidRuleValue::InterfaceType),
        }
    }
}

impl fmt::Display for InterfaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Wireless => "Wireless",
            Self::Lan => "Lan",
            Self::RemoteAccess => "RemoteAccess",
            Self::All => "All",
        };
        write!(f, "{s}")
    }
}
