use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use ipconfig::get_adapters;
use ipnet::IpNet;
use scopeguard::guard;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows_firewall::{
    DirectionFirewallWindows, FwAddress, FwAddressKeyword, FwAddressRange, FwPortKeyword,
    FwPortRange, ProtocolFirewallWindows, count_rules,
};
use windows_firewall::{FwPort, WindowsFirewallRuleSettings};
use windows_firewall::{get_rule, list_incoming_rules, list_outgoing_rules, list_rules};

use helpers::build::{
    build_full_rule_for_protocol, build_icmp_full_rule, build_rule_for_interface,
    build_tcp_full_rule,
};
use helpers::constants::RULE_NAME;

use crate::helpers::auto_remove_firewall_rule::AutoRemoveFirewallRule;
use crate::helpers::build::{build_base_rule, build_rule_for_address, build_rule_for_port};
use crate::helpers::utils::assert_firewall_rule_eq;
use serial_test::{parallel, serial};

mod helpers;

#[test]
#[serial]
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

#[test]
#[parallel]
fn test_add_rule_if_not_exists() {
    let rule_name = format!("{RULE_NAME}_add_if_not_exists");
    let rule = build_tcp_full_rule(&rule_name);

    let auto_remove_rule_result = AutoRemoveFirewallRule::add_if_not_exists(&rule).unwrap();
    assert!(auto_remove_rule_result.added_or_changed);
    let auto_remove_rule_result = AutoRemoveFirewallRule::add_if_not_exists(&rule).unwrap();
    assert!(!auto_remove_rule_result.added_or_changed);
}

#[test]
#[parallel]
fn test_add_or_update() {
    let rule_name = format!("{RULE_NAME}_add_or_update");
    let rule = build_tcp_full_rule(&rule_name);

    let auto_remove_rule_result = AutoRemoveFirewallRule::add_or_update(&rule)
        .expect("Failed to add or update full parameter firewall rule");
    assert!(
        auto_remove_rule_result.added_or_changed,
        "Rule should be added"
    );

    let updated_settings = build_icmp_full_rule(&rule_name);
    let auto_remove_rule_result = AutoRemoveFirewallRule::add_or_update(&updated_settings)
        .expect("Failed to add or update full parameter firewall rule");
    assert!(
        !auto_remove_rule_result.added_or_changed,
        "Rule should be updated"
    );

    let updated_rule = get_rule(&rule_name).expect("Failed to get updated firewall rule");
    assert_firewall_rule_eq(&updated_rule, &updated_settings);
}

#[test]
#[parallel]
fn test_enable_rule() {
    let rule_name = format!("{RULE_NAME}_enable_rule");
    let mut rule = build_tcp_full_rule(&rule_name);

    let _guard = AutoRemoveFirewallRule::add(&rule).unwrap();

    rule.enable(false).unwrap();
    assert!(!rule.enabled());

    rule.enable(true).unwrap();
    assert!(rule.enabled());
}

#[test]
#[parallel]
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
            let _guard = AutoRemoveFirewallRule::add(&rule);

            if let Err(e) = &_guard {
                panic!("Failed to add rule with protocol {:?}: {}", proto_from, e);
            }

            let fetched = get_rule(&rule_name).unwrap();
            assert_firewall_rule_eq(&fetched, &rule);

            let new_settings = WindowsFirewallRuleSettings::from(build_full_rule_for_protocol(
                &rule_name, *proto_to,
            ));

            let rule_update = rule.update(&new_settings);

            if let Err(e) = &rule_update {
                panic!("Failed to update rule to protocol {:?}: {}", proto_to, e);
            }

            let fetched_updated = get_rule(&rule_name).unwrap();

            assert_firewall_rule_eq(&fetched_updated, &rule);
        }
    }
}

#[test]
#[parallel]
fn test_add_rule_per_network_interface() {
    let adapters = get_adapters().expect("Failed to retrieve network interfaces");

    for adapter in adapters {
        let interface_name = adapter.friendly_name();
        let rule_name = format!("{RULE_NAME}_add_{interface_name}");

        let rule = build_rule_for_interface(&rule_name, interface_name);
        let _guard = AutoRemoveFirewallRule::add(&rule);

        if let Err(e) = &_guard {
            panic!(
                "Failed to add rule for interface '{}': {}",
                interface_name, e
            );
        }

        let fetched_rule = get_rule(&rule_name).expect("Failed to retrieve the rule");

        assert_firewall_rule_eq(&fetched_rule, &rule);
    }
}

#[test]
#[parallel]
fn test_update_rule_per_network_interface() {
    let adapters = get_adapters().expect("Failed to retrieve network interfaces");

    for adapter in adapters {
        let interface_name = adapter.friendly_name();
        let rule_name = format!("{RULE_NAME}_update_{interface_name}");

        let mut rule = build_base_rule(&rule_name);
        let _guard = AutoRemoveFirewallRule::add(&rule);

        if let Err(e) = &_guard {
            panic!(
                "Failed to add rule for interface '{}': {}",
                interface_name, e
            );
        }

        let updated_settings = WindowsFirewallRuleSettings::builder()
            .interfaces([interface_name])
            .build();

        println!("Updating rule for interface: {interface_name}");

        let update_result = rule.update(&updated_settings.clone());

        if let Err(e) = &update_result {
            panic!(
                "Failed to update rule for interface '{}': {}",
                interface_name, e
            );
        }

        let updated_rule = get_rule(&rule_name).expect("Failed to get updated firewall rule");

        rule.set_interfaces(Some(HashSet::from([interface_name.to_string()])));
        assert_firewall_rule_eq(&updated_rule, &rule);
    }
}

#[test]
#[parallel]
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

            let _guard = AutoRemoveFirewallRule::add(&rule);

            if let Err(e) = &_guard {
                panic!(
                    "Failed to add rule with direction {:?} and edge traversal {:?}: {}",
                    dir_from, edge_from, e
                );
            }

            let fetched = get_rule(&rule_name).unwrap();
            assert_firewall_rule_eq(&fetched, &rule);

            let new_settings = WindowsFirewallRuleSettings::builder()
                .direction(*dir_to)
                .edge_traversal(*edge_to)
                .build();

            let update_result = rule.update(&new_settings);

            if let Err(e) = &update_result {
                panic!(
                    "Failed to update rule to direction {:?} and edge traversal {:?}: {}",
                    dir_to, edge_to, e
                );
            }

            let fetched_updated = get_rule(&rule_name).unwrap();

            rule.set_direction(*dir_to);
            rule.set_edge_traversal(Some(*edge_to));
            assert_firewall_rule_eq(&fetched_updated, &rule);
        }
    }
}

#[test]
#[parallel]
fn test_add_rules_for_all_fwport_variants() {
    let fwports = [
        FwPort::Any,
        FwPort::Keyword(FwPortKeyword::Rpc),
        FwPort::Keyword(FwPortKeyword::RpcEpmap),
        // FwPort::Keyword(FwPortKeyword::IpHttps),
        // FwPort::Keyword(FwPortKeyword::Ply2Disc),
        FwPort::Keyword(FwPortKeyword::Teredo),
        FwPort::Port(80),
        FwPort::Port(443),
        FwPort::Range(FwPortRange {
            start: 1000,
            end: 2000,
        }),
    ];

    for (i, port) in fwports.iter().enumerate() {
        let rule_name = format!("TEST_FWPORT_RULE_{}", i);

        let rule = build_rule_for_port(&rule_name, port);
        let _guard = AutoRemoveFirewallRule::add(&rule);

        if let Err(e) = &_guard {
            panic!("Failed to add rule for port {:?}: {}", port, e);
        }

        let fetched = get_rule(&rule_name).expect("Failed to fetch the rule");
        assert_firewall_rule_eq(&fetched, &rule);
    }
}

#[test]
#[parallel]
fn test_add_rules_for_all_fwaddress_variants() {
    let fwaddresses = [
        FwAddress::Any,
        FwAddress::Keyword(FwAddressKeyword::DefaultGateway),
        FwAddress::Keyword(FwAddressKeyword::Dhcp),
        FwAddress::Keyword(FwAddressKeyword::Dns),
        FwAddress::Keyword(FwAddressKeyword::Wins),
        FwAddress::Keyword(FwAddressKeyword::LocalSubnet),
        FwAddress::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        FwAddress::Cidr(IpNet::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24).unwrap()),
        FwAddress::Range(
            FwAddressRange::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(192, 168, 0, 255)),
            )
            .unwrap(),
        ),
    ];

    for (i, address) in fwaddresses.iter().enumerate() {
        let rule_name = format!("TEST_FWADDRESS_RULE_{}", i);

        let rule = build_rule_for_address(&rule_name, address);
        let _guard = AutoRemoveFirewallRule::add(&rule);

        if let Err(e) = &_guard {
            panic!("Failed to add rule for address {:?}: {}", address, e);
        }

        let fetched = get_rule(&rule_name).expect("Failed to fetch the rule");
        assert_firewall_rule_eq(&fetched, &rule);
    }
}
