use windows::Win32::NetworkManagement::WindowsFirewall::{
    NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_MAX, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIRECTION,
};

use crate::firewall_rule::types::InvalidRuleProperty;

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
    type Error = InvalidRuleProperty;

    fn try_from(value: NET_FW_RULE_DIRECTION) -> Result<Self, Self::Error> {
        match value {
            NET_FW_RULE_DIR_IN => Ok(Self::In),
            NET_FW_RULE_DIR_OUT => Ok(Self::Out),
            NET_FW_RULE_DIR_MAX => Ok(Self::Max),
            _ => Err(InvalidRuleProperty::NetFwRuleDirection),
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

#[cfg(test)]
mod tests {
    use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIRECTION;

    use crate::{Direction, firewall_rule::types::InvalidRuleProperty};

    #[test]
    fn test_try_from_invalid_net_fw_direction() {
        let invalid_value = 999;

        let result = Direction::try_from(NET_FW_RULE_DIRECTION(invalid_value));

        assert!(matches!(
            result,
            Err(InvalidRuleProperty::NetFwRuleDirection)
        ));
    }
}
