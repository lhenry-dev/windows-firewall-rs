use std::{fmt, str::FromStr};

use crate::firewall_rule::types::InvalidRuleProperty;

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
    type Err = InvalidRuleProperty;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Wireless" => Ok(Self::Wireless),
            "Lan" => Ok(Self::Lan),
            "RemoteAccess" => Ok(Self::RemoteAccess),
            "All" => Ok(Self::All),
            _ => Err(InvalidRuleProperty::InterfaceType),
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{InterfaceType, firewall_rule::types::InvalidRuleProperty};

    #[test]
    fn test_try_from_invalid_net_fw_interface_type() {
        let invalid_value = "Invalid";

        let result = InterfaceType::from_str(invalid_value);

        assert!(matches!(result, Err(InvalidRuleProperty::InterfaceType)));
    }
}
