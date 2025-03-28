#![crate_type = "lib"]
#![forbid(missing_debug_implementations)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg(target_os = "windows")]

mod constants;
mod errors;
mod firewall_enums;
mod firewall_rule;
mod utils;
mod windows_firewall;

pub use firewall_enums::{
    ActionFirewallWindows, DirectionFirewallWindows, InterfaceTypes, ProfileFirewallWindows,
    ProtocolFirewallWindows,
};
pub use firewall_rule::{WindowsFirewallRule, WindowsFirewallRuleSettings};
pub use windows_firewall::{
    add_rule, add_rule_if_not_exists, disable_rule, enable_rule, get_active_profile,
    get_firewall_state, get_rule, list_incoming_rules, list_outgoing_rules, list_rules,
    remove_rule, rule_exists, set_firewall_state, update_rule,
};
