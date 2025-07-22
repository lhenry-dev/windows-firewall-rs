use thiserror::Error;

/// Deriving common traits to automatically implement error handling functionality.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum WindowsFirewallError {
    /// Error returned when `CoInitializeEx` fails during COM initialization.
    #[error("CoInitializeEx failed: {0}")]
    CoInitializeExFailed(String),
    /// A general Windows API error wrapped from the `windows_result` crate.
    #[error(transparent)]
    WindowsError(#[from] windows_result::Error),
    /// Error returned when setting a firewall rule property fails.
    #[error(transparent)]
    SetRuleError(#[from] SetRuleError),
    /// Indicates that the specified firewall rule already exists.
    #[error("The firewall rule already exists")]
    RuleAlreadyExists,
    /// Indicates that an invalid value was used for `NET_FW_ACTION`.
    #[error("Invalid NET_FW_ACTION value")]
    InvalidNetFwAction,
    /// Indicates that an invalid value was used for `NET_FW_PROFILE`.
    #[error("Invalid NET_FW_PROFILE value")]
    InvalidNetFwProfile,
    /// Indicates that an invalid value was used for `NET_FW_RULE_DIRECTION`.
    #[error("Invalid NET_FW_RULE_DIRECTION value")]
    InvalidNetFwRuleDirection,
    /// Indicates that an invalid value was used for `NET_FW_IP_PROTOCOL`.
    #[error("Invalid NET_FW_IP_PROTOCOL value")]
    InvalidNetFwIpProtocol,
    /// Indicates that a required `HashSet` is either empty or None.
    #[error("Empty or None HashSet")]
    EmptyHashSet,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SetRuleError {
    #[error("Failed to set name: {0}")]
    Name(#[source] windows_result::Error),
    #[error("Failed to set direction: {0}")]
    Direction(#[source] windows_result::Error),
    #[error("Failed to set enabled: {0}")]
    Enabled(#[source] windows_result::Error),
    #[error("Failed to set action: {0}")]
    Action(#[source] windows_result::Error),
    #[error("Failed to set description: {0}")]
    Description(#[source] windows_result::Error),
    #[error("Failed to set application name: {0}")]
    ApplicationName(#[source] windows_result::Error),
    #[error("Failed to set service name: {0}")]
    ServiceName(#[source] windows_result::Error),
    #[error("Failed to set protocol: {0}")]
    Protocol(#[source] windows_result::Error),
    #[error("Failed to set local ports: {0}")]
    LocalPorts(#[source] windows_result::Error),
    #[error("Failed to set remote ports: {0}")]
    RemotePorts(#[source] windows_result::Error),
    #[error("Failed to set local addresses: {0}")]
    LocalAddresses(#[source] windows_result::Error),
    #[error("Failed to set remote addresses: {0}")]
    RemoteAddresses(#[source] windows_result::Error),
    #[error("Failed to set ICMP types and codes: {0}")]
    IcmpTypesAndCodes(#[source] windows_result::Error),
    #[error("Failed to set edge traversal: {0}")]
    EdgeTraversal(#[source] windows_result::Error),
    #[error("Failed to set grouping: {0}")]
    Grouping(#[source] windows_result::Error),
    #[error("Failed to set interfaces: {0}")]
    Interfaces(#[source] windows_result::Error),
    #[error("Failed to set interface types: {0}")]
    InterfaceTypes(#[source] windows_result::Error),
    #[error("Failed to set profiles: {0}")]
    Profiles(#[source] windows_result::Error),
}
