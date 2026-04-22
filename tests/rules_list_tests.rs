use scopeguard::guard;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows_firewall::count_rules;
use windows_firewall::{list_incoming_rules, list_outgoing_rules, list_rules};

use helpers::build::build_tcp_full_rule;
use helpers::constants::RULE_NAME;

use crate::helpers::auto_remove_firewall_rule::AutoRemoveFirewallRule;
use crate::helpers::utils::assert_firewall_rule_eq;

mod helpers;

#[test]
fn test_list_rules() {
    let rule_name = format!("{RULE_NAME}_list_rules");
    let rule = build_tcp_full_rule(&rule_name);
    let _guard = AutoRemoveFirewallRule::add(&rule).unwrap();

    let count = count_rules().expect("Failed to count rules");
    let rules = list_rules().expect("Failed to list outgoing rules");

    assert_eq!(
        count as usize,
        rules.len(),
        "Count of rules should match the length of the rules list"
    );

    let fetched = rules
        .iter()
        .find(|r| *r.name() == rule_name)
        .unwrap_or_else(|| {
            panic!(
                "Firewall rule '{}' not found in list_rules() output",
                rule_name
            )
        });

    assert_firewall_rule_eq(fetched, &rule);
}

#[test]
fn test_list_incoming_rules() {
    let rules = list_incoming_rules();
    assert!(rules.is_ok(), "Failed to list incoming rules");
}

#[test]
fn test_list_outgoing_rules() {
    let rules = list_outgoing_rules();
    assert!(rules.is_ok(), "Failed to list outgoing rules");
}

#[test]
fn test_firewall_rules_conversion() {
    let firewall_rules = list_rules().expect("Failed to retrieve firewall rules");

    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).unwrap();
    }

    let _com_cleanup = guard((), |()| unsafe { CoUninitialize() });

    let inetfw_rules = firewall_rules
        .iter()
        .map(|rule| INetFwRule::try_from(rule).expect("Failed to convert to INetFwRule"));

    assert_eq!(
        firewall_rules.len(),
        inetfw_rules.len(),
        "Conversion changed the number of rules!"
    );
}
