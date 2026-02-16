use thiserror::Error;

use crate::firewall_rule::types::InvalidRuleType;

/// Deriving common traits to automatically implement error handling functionality.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum WindowsFirewallError {
    /// Error returned when `CoInitializeEx` fails during COM initialization.
    #[error("CoInitializeEx failed: {0}")]
    CoInitializeExFailed(String),
    /// A general Windows API error wrapped from the `windows_result` crate.
    #[error(transparent)]
    WindowsError(#[from] windows::core::Error),
    /// Error returned when setting a firewall rule property fails.
    #[error(transparent)]
    SetRuleError(#[from] SetRuleError),
    /// Error returned when an invalid rule type is encountered while setting a firewall rule property.
    #[error(transparent)]
    RuleTypeError(#[from] InvalidRuleType),
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SetRuleError {
    #[error("Failed to set name: {0}")]
    Name(#[source] windows::core::Error),
    #[error("Failed to set direction: {0}")]
    Direction(#[source] windows::core::Error),
    #[error("Failed to set enabled: {0}")]
    Enabled(#[source] windows::core::Error),
    #[error("Failed to set action: {0}")]
    Action(#[source] windows::core::Error),
    #[error("Failed to set description: {0}")]
    Description(#[source] windows::core::Error),
    #[error("Failed to set application name: {0}")]
    ApplicationName(#[source] windows::core::Error),
    #[error("Failed to set service name: {0}")]
    ServiceName(#[source] windows::core::Error),
    #[error("Failed to set protocol: {0}")]
    Protocol(#[source] windows::core::Error),
    #[error("Failed to set local ports: {0}")]
    LocalPorts(#[source] windows::core::Error),
    #[error("Failed to set remote ports: {0}")]
    RemotePorts(#[source] windows::core::Error),
    #[error("Failed to set local addresses: {0}")]
    LocalAddresses(#[source] windows::core::Error),
    #[error("Failed to set remote addresses: {0}")]
    RemoteAddresses(#[source] windows::core::Error),
    #[error("Failed to set ICMP types and codes: {0}")]
    IcmpTypesAndCodes(#[source] windows::core::Error),
    #[error("Failed to set edge traversal: {0}")]
    EdgeTraversal(#[source] windows::core::Error),
    #[error("Failed to set grouping: {0}")]
    Grouping(#[source] windows::core::Error),
    #[error("Failed to set interfaces: {0}")]
    Interfaces(#[source] windows::core::Error),
    #[error("Failed to set interface types: {0}")]
    InterfaceType(#[source] windows::core::Error),
    #[error("Failed to set profiles: {0}")]
    Profiles(#[source] windows::core::Error),
}
