use thiserror::Error;

/// Deriving common traits to automatically implement error handling functionality.
#[derive(Error, Debug, PartialEq)]
pub enum WindowsFirewallError {
    /// Error returned when CoInitializeEx fails during COM initialization.
    #[error("CoInitializeEx failed: {0}")]
    CoInitializeExFailed(String),
    /// A general Windows API error wrapped from the windows_result crate.
    #[error(transparent)]
    WindowsError(#[from] windows_result::Error),
    /// Indicates that the specified firewall rule already exists.
    #[error("The firewall rule already exists")]
    RuleAlreadyExists,
    /// Indicates that an invalid value was used for NET_FW_ACTION.
    #[error("Invalid NET_FW_ACTION value")]
    InvalidNetFwAction,
    /// Indicates that an invalid value was used for NET_FW_PROFILE.
    #[error("Invalid NET_FW_PROFILE value")]
    InvalidNetFwProfile,
    /// Indicates that an invalid value was used for NET_FW_RULE_DIRECTION.
    #[error("Invalid NET_FW_RULE_DIRECTION value")]
    InvalidNetFwRuleDirection,
    /// Indicates that an invalid value was used for NET_FW_IP_PROTOCOL.
    #[error("Invalid NET_FW_IP_PROTOCOL value")]
    InvalidNetFwIpProtocol,
    /// Indicates that a required HashSet is either empty or None.
    #[error("Empty or None HashSet")]
    EmptyHashSet,
}
