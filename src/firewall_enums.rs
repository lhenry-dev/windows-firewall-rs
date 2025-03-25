use std::{fmt, str::FromStr};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    NET_FW_ACTION, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_ACTION_MAX,
    NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP, NET_FW_IP_PROTOCOL_UDP, NET_FW_PROFILE_CURRENT,
    NET_FW_PROFILE_DOMAIN, NET_FW_PROFILE_STANDARD, NET_FW_PROFILE_TYPE_MAX, NET_FW_PROFILE2_ALL,
    NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_MAX, NET_FW_RULE_DIR_OUT,
    NET_FW_RULE_DIRECTION,
};

use crate::errors::WindowsFirewallError;

/// Represents the possible firewall protocols in Windows
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ProtocolFirewallWindows {
    /// TCP protocol
    Tcp = NET_FW_IP_PROTOCOL_TCP.0 as isize,
    /// UDP protocol
    Udp = NET_FW_IP_PROTOCOL_UDP.0 as isize,
    /// ICMPv4 protocol
    Icmpv4 = 1i32 as isize,
    /// ICMPv6 protocol
    Icmpv6 = 58i32 as isize,
    /// IGMP protocol
    Igmp = 2i32 as isize,
    /// IPv4 protocol
    Ipv4 = 4i32 as isize,
    /// IPv6 protocol
    Ipv6 = 41i32 as isize,
    /// GRE protocol
    Gre = 47i32 as isize,
    /// ESP protocol
    Esp = 50i32 as isize,
    /// AH protocol
    Ah = 51i32 as isize,
    /// SCTP protocol
    Sctp = 132i32 as isize,
    /// Any protocol (wildcard)
    Any = NET_FW_IP_PROTOCOL_ANY.0 as isize,
}

/// Implements conversion from `i32` to `ProtocolFirewallWindows`
impl TryFrom<i32> for ProtocolFirewallWindows {
    type Error = WindowsFirewallError;

    fn try_from(value: i32) -> Result<Self, WindowsFirewallError> {
        match value {
            x if x == NET_FW_IP_PROTOCOL_TCP.0 => Ok(ProtocolFirewallWindows::Tcp),
            x if x == NET_FW_IP_PROTOCOL_UDP.0 => Ok(ProtocolFirewallWindows::Udp),
            1 => Ok(ProtocolFirewallWindows::Icmpv4),
            58 => Ok(ProtocolFirewallWindows::Icmpv6),
            2 => Ok(ProtocolFirewallWindows::Igmp),
            4 => Ok(ProtocolFirewallWindows::Ipv4),
            41 => Ok(ProtocolFirewallWindows::Ipv6),
            47 => Ok(ProtocolFirewallWindows::Gre),
            50 => Ok(ProtocolFirewallWindows::Esp),
            51 => Ok(ProtocolFirewallWindows::Ah),
            132 => Ok(ProtocolFirewallWindows::Sctp),
            x if x == NET_FW_IP_PROTOCOL_ANY.0 => Ok(ProtocolFirewallWindows::Any),
            _ => Err(WindowsFirewallError::InvalidNetFwIpProtocol),
        }
    }
}

/// Implements conversion from `ProtocolFirewallWindows` to `i32`
impl From<ProtocolFirewallWindows> for i32 {
    fn from(protocol: ProtocolFirewallWindows) -> Self {
        protocol as i32
    }
}

/// Represents the possible firewall rule directions in Windows
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DirectionFirewallWindows {
    /// Incoming direction
    In = NET_FW_RULE_DIR_IN.0 as isize,
    /// Outgoing direction
    Out = NET_FW_RULE_DIR_OUT.0 as isize,
    /// Maximum possible value (not typically used directly)
    Max = NET_FW_RULE_DIR_MAX.0 as isize,
}

/// Implements conversion from `NET_FW_RULE_DIRECTION` to `DirectionFirewallWindows`
impl TryFrom<NET_FW_RULE_DIRECTION> for DirectionFirewallWindows {
    type Error = WindowsFirewallError;

    fn try_from(value: NET_FW_RULE_DIRECTION) -> Result<Self, WindowsFirewallError> {
        match value {
            // Convert rule direction value to the corresponding enum variant
            NET_FW_RULE_DIR_IN => Ok(DirectionFirewallWindows::In),
            NET_FW_RULE_DIR_OUT => Ok(DirectionFirewallWindows::Out),
            NET_FW_RULE_DIR_MAX => Ok(DirectionFirewallWindows::Max),
            // Return an error if the value is not recognized
            _ => Err(WindowsFirewallError::InvalidNetFwRuleDirection),
        }
    }
}

/// Implements conversion from `DirectionFirewallWindows` to `NET_FW_RULE_DIRECTION`
impl From<DirectionFirewallWindows> for NET_FW_RULE_DIRECTION {
    fn from(direction: DirectionFirewallWindows) -> Self {
        match direction {
            // Convert each enum variant to its corresponding `NET_FW_RULE_DIRECTION` value
            DirectionFirewallWindows::In => NET_FW_RULE_DIR_IN,
            DirectionFirewallWindows::Out => NET_FW_RULE_DIR_OUT,
            DirectionFirewallWindows::Max => NET_FW_RULE_DIR_MAX,
        }
    }
}

/// Represents the possible firewall profiles in Windows
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ProfileFirewallWindows {
    /// Domain profile
    Domain = NET_FW_PROFILE_DOMAIN.0 as isize,
    /// Standard profile
    Standard = NET_FW_PROFILE_STANDARD.0 as isize,
    /// Current active profile
    Current = NET_FW_PROFILE_CURRENT.0 as isize,
    /// Maximum profile value (not typically used directly)
    Max = NET_FW_PROFILE_TYPE_MAX.0 as isize,
    /// Public profile
    Public = NET_FW_PROFILE2_PUBLIC.0 as isize,
    /// All profiles
    All = NET_FW_PROFILE2_ALL.0 as isize,
}

/// Implements conversion from `i32` to `ProfileFirewallWindows`
impl TryFrom<i32> for ProfileFirewallWindows {
    type Error = WindowsFirewallError;

    fn try_from(value: i32) -> Result<Self, WindowsFirewallError> {
        match value {
            // Convert integer value to the corresponding enum variant
            x if x == NET_FW_PROFILE_DOMAIN.0 => Ok(ProfileFirewallWindows::Domain),
            x if x == NET_FW_PROFILE_STANDARD.0 => Ok(ProfileFirewallWindows::Standard),
            x if x == NET_FW_PROFILE_CURRENT.0 => Ok(ProfileFirewallWindows::Current),
            x if x == NET_FW_PROFILE_TYPE_MAX.0 => Ok(ProfileFirewallWindows::Max),
            x if x == NET_FW_PROFILE2_PUBLIC.0 => Ok(ProfileFirewallWindows::Public),
            x if x == NET_FW_PROFILE2_ALL.0 => Ok(ProfileFirewallWindows::All),
            // Return an error if the value is not recognized
            _ => Err(WindowsFirewallError::InvalidNetFwProfile),
        }
    }
}

/// Implements conversion from `ProfileFirewallWindows` to `i32`
impl From<ProfileFirewallWindows> for i32 {
    fn from(profile: ProfileFirewallWindows) -> Self {
        match profile {
            // Convert each enum variant to its corresponding integer value
            ProfileFirewallWindows::Domain => NET_FW_PROFILE_DOMAIN.0,
            ProfileFirewallWindows::Standard => NET_FW_PROFILE_STANDARD.0,
            ProfileFirewallWindows::Current => NET_FW_PROFILE_CURRENT.0,
            ProfileFirewallWindows::Max => NET_FW_PROFILE_TYPE_MAX.0,
            ProfileFirewallWindows::Public => NET_FW_PROFILE2_PUBLIC.0,
            ProfileFirewallWindows::All => NET_FW_PROFILE2_ALL.0,
        }
    }
}

/// Represents the possible firewall actions in Windows
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ActionFirewallWindows {
    /// Block network traffic
    Block = windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION_BLOCK.0 as isize,
    /// Allow network traffic
    Allow = windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION_ALLOW.0 as isize,
    /// Maximum possible value (not typically used directly)
    Max = windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION_MAX.0 as isize,
}

/// Implements conversion from `NET_FW_ACTION` to `ActionFirewallWindows`
impl TryFrom<NET_FW_ACTION> for ActionFirewallWindows {
    type Error = WindowsFirewallError;

    fn try_from(action: NET_FW_ACTION) -> Result<Self, WindowsFirewallError> {
        match action {
            // Convert action value to the corresponding enum variant
            NET_FW_ACTION_BLOCK => Ok(ActionFirewallWindows::Block),
            NET_FW_ACTION_ALLOW => Ok(ActionFirewallWindows::Allow),
            NET_FW_ACTION_MAX => Ok(ActionFirewallWindows::Max),
            // Return an error if the value is not recognized
            _ => Err(WindowsFirewallError::InvalidNetFwAction),
        }
    }
}

/// Implements conversion from `ActionFirewallWindows` to `NET_FW_ACTION`
impl From<ActionFirewallWindows> for NET_FW_ACTION {
    fn from(action: ActionFirewallWindows) -> Self {
        match action {
            // Convert each enum variant to its corresponding `NET_FW_ACTION` value
            ActionFirewallWindows::Block => NET_FW_ACTION_BLOCK,
            ActionFirewallWindows::Allow => NET_FW_ACTION_ALLOW,
            ActionFirewallWindows::Max => NET_FW_ACTION_MAX,
        }
    }
}

/// Enum representing different types of network interfaces.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum InterfaceTypes {
    /// Wireless interface
    Wireless,
    /// LAN interface
    Lan,
    /// Remote Access interface
    RemoteAccess,
    /// Applies to all interfaces
    All,
}

impl FromStr for InterfaceTypes {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Wireless" => Ok(InterfaceTypes::Wireless),
            "Lan" => Ok(InterfaceTypes::Lan),
            "RemoteAccess" => Ok(InterfaceTypes::RemoteAccess),
            "All" => Ok(InterfaceTypes::All),
            _ => Err(format!("Invalid interface type: {}", s)),
        }
    }
}

impl fmt::Display for InterfaceTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            InterfaceTypes::Wireless => "Wireless",
            InterfaceTypes::Lan => "Lan",
            InterfaceTypes::RemoteAccess => "RemoteAccess",
            InterfaceTypes::All => "All",
        };
        write!(f, "{}", s)
    }
}
