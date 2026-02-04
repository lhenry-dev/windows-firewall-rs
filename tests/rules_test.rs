use std::collections::HashSet;

use ipconfig::get_adapters;
use scopeguard::guard;
use serial_test::serial;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows_firewall::WindowsFirewallRuleSettings;
use windows_firewall::{DirectionFirewallWindows, ProtocolFirewallWindows};
use windows_firewall::{get_rule, list_incoming_rules, list_outgoing_rules, list_rules};

use helpers::build::{
    build_full_rule_for_protocol, build_icmp_full_rule, build_rule_for_interface,
    build_tcp_full_rule,
};
use helpers::constants::RULE_NAME;

use crate::helpers::auto_remove_firewall_rule::AutoRemoveFirewallRule;
use crate::helpers::build::build_base_rule;
use crate::helpers::utils::assert_firewall_rule_eq;

mod helpers;

#[test]
#[serial]
fn test_list_rules() {
    let rule = build_tcp_full_rule(RULE_NAME);
    let _guard = AutoRemoveFirewallRule::add(&rule).unwrap();

    let rules = list_rules();
    assert!(rules.is_ok(), "Failed to list outgoing rules");

    let rules = rules.unwrap();

    let found = rules.iter().any(|r| r.name() == RULE_NAME);
    assert!(
        found,
        "Firewall rule '{}' not found in list_rules() output",
        RULE_NAME
    );
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
#[serial]
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

#[test]
#[serial]
fn test_add_rule_if_not_exists() {
    let rule = build_tcp_full_rule(RULE_NAME);

    let auto_remove_rule_result = AutoRemoveFirewallRule::add_if_not_exists(&rule).unwrap();
    assert!(auto_remove_rule_result.added_or_changed);
    let auto_remove_rule_result = AutoRemoveFirewallRule::add_if_not_exists(&rule).unwrap();
    assert!(!auto_remove_rule_result.added_or_changed);
}

#[test]
#[serial]
fn test_add_or_update() {
    let rule = build_tcp_full_rule(RULE_NAME);

    let auto_remove_rule_result = AutoRemoveFirewallRule::add_or_update(&rule)
        .expect("Failed to add or update full parameter firewall rule");
    assert!(
        auto_remove_rule_result.added_or_changed,
        "Rule should be added"
    );

    let updated_settings = build_icmp_full_rule(RULE_NAME);
    let auto_remove_rule_result = AutoRemoveFirewallRule::add_or_update(&updated_settings)
        .expect("Failed to add or update full parameter firewall rule");
    assert!(
        !auto_remove_rule_result.added_or_changed,
        "Rule should be updated"
    );

    let updated_rule = get_rule(RULE_NAME).expect("Failed to get updated firewall rule");
    assert_firewall_rule_eq(&updated_rule, &updated_settings);
}

#[test]
#[serial]
fn test_enable_rule() {
    let mut rule = build_tcp_full_rule(RULE_NAME);

    let _guard = AutoRemoveFirewallRule::add(&rule).unwrap();

    rule.enable(false).unwrap();
    assert!(!rule.enabled());

    rule.enable(true).unwrap();
    assert!(rule.enabled());
}

#[test]
fn test_all_protocol_transitions() {
    let protocols = [
        (ProtocolFirewallWindows::Tcp, "Tcp"),
        (ProtocolFirewallWindows::Udp, "Udp"),
        (ProtocolFirewallWindows::Icmpv4, "Icmpv4"),
        (ProtocolFirewallWindows::Icmpv6, "Icmpv6"),
        (ProtocolFirewallWindows::Igmp, "Igmp"),
        (ProtocolFirewallWindows::Ipv4, "Ipv4"),
        (ProtocolFirewallWindows::Ipv6, "Ipv6"),
        (ProtocolFirewallWindows::Gre, "Gre"),
        (ProtocolFirewallWindows::Esp, "Esp"),
        (ProtocolFirewallWindows::Ah, "Ah"),
        (ProtocolFirewallWindows::Sctp, "Sctp"),
        (ProtocolFirewallWindows::Any, "Any"),
    ];

    for (proto_from, label_from) in &protocols {
        for (proto_to, label_to) in &protocols {
            let rule_name = format!("{RULE_NAME}_transition_{label_from}_to_{label_to}");

            let mut rule = build_full_rule_for_protocol(&rule_name, *proto_from);
            let _guard = AutoRemoveFirewallRule::add(&rule).unwrap();

            let fetched = get_rule(&rule_name).unwrap();
            assert_eq!(*fetched.protocol(), Some(proto_from).copied());

            let new_settings = WindowsFirewallRuleSettings::from(build_full_rule_for_protocol(
                &rule_name, *proto_to,
            ));

            rule.update(&new_settings).expect("Failed to update rule");
            assert!(
                rule.exists().unwrap(),
                "Rule should exist after being updated"
            );
            let fetched_updated = get_rule(&rule_name).unwrap();
            assert_eq!(*fetched_updated.protocol(), Some(proto_to).copied());
        }
    }
}

#[test]
#[serial]
fn test_add_rule_per_network_interface() {
    let adapters = get_adapters().expect("Failed to retrieve network interfaces");

    for adapter in adapters {
        let interface_name = adapter.friendly_name();
        let rule_name = format!("{RULE_NAME}_{interface_name}");

        let rule = build_rule_for_interface(&rule_name, interface_name);
        let _guard = AutoRemoveFirewallRule::add(&rule).unwrap();

        let fetched_rule = get_rule(&rule_name).expect("Failed to retrieve the rule");

        assert_firewall_rule_eq(&fetched_rule, &rule);
    }
}

#[test]
#[serial]
fn test_update_rule_per_network_interface() {
    let adapters = get_adapters().expect("Failed to retrieve network interfaces");

    for adapter in adapters {
        let interface_name = adapter.friendly_name();
        let rule_name = format!("{RULE_NAME}_{interface_name}");

        let mut rule = build_base_rule(&rule_name);
        let _guard = AutoRemoveFirewallRule::add(&rule).unwrap();

        let updated_settings = WindowsFirewallRuleSettings::builder()
            .interfaces([interface_name])
            .build();

        println!("Updating rule for interface: {interface_name}");

        rule.update(&updated_settings.clone())
            .expect("Failed to update rule");

        let updated_rule = get_rule(&rule_name).expect("Failed to get updated firewall rule");

        rule.set_interfaces(Some(HashSet::from([interface_name.to_string()])));
        assert_firewall_rule_eq(&updated_rule, &rule);
    }
}

#[test]
#[serial]
fn test_direction_and_edge_traversal_transitions() {
    let states = [
        (DirectionFirewallWindows::In, true, "In_EdgeTrue"),
        (DirectionFirewallWindows::Out, false, "Out_EdgeFalse"),
    ];

    for (dir_from, edge_from, label_from) in &states {
        for (dir_to, edge_to, label_to) in &states {
            let rule_name = format!("{RULE_NAME}_transition_{label_from}_to_{label_to}");

            let mut rule = build_tcp_full_rule(&rule_name);
            rule.set_direction(*dir_from);
            rule.set_edge_traversal(Some(*edge_from));

            let _guard = AutoRemoveFirewallRule::add(&rule).unwrap();

            let fetched = get_rule(&rule_name).unwrap();
            assert_firewall_rule_eq(&fetched, &rule);

            let new_settings = WindowsFirewallRuleSettings::builder()
                .direction(*dir_to)
                .edge_traversal(*edge_to)
                .build();

            rule.update(&new_settings).expect("Failed to update rule");

            let fetched_updated = get_rule(&rule_name).unwrap();

            rule.set_direction(*dir_to);
            rule.set_edge_traversal(Some(*edge_to));
            assert_firewall_rule_eq(&fetched_updated, &rule);
        }
    }
}
