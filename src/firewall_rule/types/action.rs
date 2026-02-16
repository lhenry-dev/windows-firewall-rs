use windows::Win32::NetworkManagement::WindowsFirewall::{
    NET_FW_ACTION, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK, NET_FW_ACTION_MAX,
};

use crate::firewall_rule::types::InvalidRuleType;

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
    type Error = InvalidRuleType;

    fn try_from(action: NET_FW_ACTION) -> Result<Self, Self::Error> {
        match action {
            NET_FW_ACTION_BLOCK => Ok(Self::Block),
            NET_FW_ACTION_ALLOW => Ok(Self::Allow),
            NET_FW_ACTION_MAX => Ok(Self::Max),
            _ => Err(InvalidRuleType::NetFwAction),
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

#[cfg(test)]
mod tests {
    use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION;

    use crate::{Action, firewall_rule::types::InvalidRuleType};

    #[test]
    fn test_try_from_invalid_net_fw_action() {
        let invalid_value = 999;

        let result = Action::try_from(NET_FW_ACTION(invalid_value));

        assert!(matches!(result, Err(InvalidRuleType::NetFwAction)));
    }
}
