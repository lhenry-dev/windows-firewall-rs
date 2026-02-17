#![crate_type = "lib"]
#![forbid(missing_debug_implementations)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg(target_os = "windows")]

mod constants;
mod errors;
mod firewall_rule;
mod profile;
mod rule_ops;
mod rules_list;
mod utils;

pub use errors::WindowsFirewallError;
pub use firewall_rule::types::address::{Address, AddressKeyword, AddressRange};
pub use firewall_rule::types::port::{Port, PortKeyword, PortRange};
pub use firewall_rule::{
    Action, Direction, FirewallRule, FirewallRuleUpdate, InterfaceType, Profile, Protocol,
};
pub use profile::{get_active_profile, get_firewall_state, set_firewall_state};
pub use rule_ops::{
    add_rule, add_rule_if_not_exists, add_rule_or_update, enable_rule, get_rule, remove_rule,
    rule_exists, update_rule,
};
pub use rules_list::{count_rules, list_incoming_rules, list_outgoing_rules, list_rules};
