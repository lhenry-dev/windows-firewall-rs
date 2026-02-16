use thiserror::Error;

pub use self::action::Action;
pub use self::address::Address;
pub use self::direction::Direction;
pub use self::interface_type::InterfaceType;
pub use self::port::Port;
pub use self::profile::Profile;
pub use self::protocol::Protocol;

pub mod action;
pub mod address;
pub mod direction;
pub mod interface_type;
pub mod port;
pub mod profile;
pub mod protocol;

/// Errors related to setting firewall rule properties, with specific variants for each property.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum InvalidRuleType {
    /// Indicates that an invalid value was used for `NET_FW_ACTION`.
    #[error("Invalid NET_FW_ACTION value")]
    NetFwAction,
    /// Indicates that an invalid value was used for `NET_FW_PROFILE`.
    #[error("Invalid NET_FW_PROFILE value")]
    NetFwProfile,
    /// Indicates that an invalid value was used for `NET_FW_RULE_DIRECTION`.
    #[error("Invalid NET_FW_RULE_DIRECTION value")]
    NetFwRuleDirection,
    /// Indicates that an invalid value was used for `NET_FW_IP_PROTOCOL`.
    #[error("Invalid NET_FW_IP_PROTOCOL value")]
    NetFwIpProtocol,
    /// Indicates that an invalid value was used for `InterfaceType`.
    #[error("Invalid InterfaceType value")]
    InterfaceType,
}
