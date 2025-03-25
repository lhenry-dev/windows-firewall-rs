use thiserror::Error;

/// Deriving common traits to automatically implement error handling functionality.
#[derive(Error, Debug, PartialEq)]
pub enum WindowsFirewallError {
    #[error("CoInitializeEx failed: {0}")]
    CoInitializeExFailed(String),
    #[error(transparent)]
    WindowsError(#[from] windows_result::Error),
    #[error("The firewall rule already exists")]
    RuleAlreadyExists,
    #[error("Invalid NET_FW_ACTION value")]
    InvalidNetFwAction,
    #[error("Invalid NET_FW_PROFILE value")]
    InvalidNetFwProfile,
    #[error("Invalid NET_FW_RULE_DIRECTION value")]
    InvalidNetFwRuleDirection,
    #[error("Invalid NET_FW_IP_PROTOCOL value")]
    InvalidNetFwIpProtocol,
    #[error("Empty or None HashSet")]
    EmptyHashSet,
}
