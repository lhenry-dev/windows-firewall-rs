use scopeguard::guard;
use serial_test::serial;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};
use windows_firewall::{
    ActionFirewallWindows, DirectionFirewallWindows, InterfaceTypes::Lan, InterfaceTypes::Wireless,
    ProfileFirewallWindows, ProtocolFirewallWindows,
};
use windows_firewall::{WindowsFirewallRule, WindowsFirewallRuleSettings};
use windows_firewall::{
    add_rule, get_active_profile, get_firewall_state, get_rule, list_incoming_rules,
    list_outgoing_rules, list_rules, remove_rule, rule_exists, update_rule,
};

const RULE_NAME: &str = "aaaWindowsFirewallRsTestRule";

#[allow(dead_code)]
fn to_string_hashset_option<T, I>(items: I) -> Option<HashSet<String>>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    Some(items.into_iter().map(Into::into).collect())
}

#[allow(dead_code)]
fn to_hashset_option<T, I>(items: I) -> Option<HashSet<T>>
where
    I: IntoIterator<Item = T>,
    T: Eq + std::hash::Hash,
{
    Some(items.into_iter().collect())
}

#[test]
fn test_get_active_profile() {
    let profile = get_active_profile();
    assert!(profile.is_ok(), "Failed to retrieve the active profile");
}

#[test]
fn test_get_firewall_state() {
    use ProfileFirewallWindows::*;
    let profiles = [Standard, Current, Public];

    for profile in profiles.iter() {
        let state = get_firewall_state(*profile);
        assert!(
            state.is_ok(),
            "Failed to retrieve the firewall state for profile {:?}",
            profile
        );
    }
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

        let _com_cleanup = guard((), |_| CoUninitialize());

        let inetfw_rules: Vec<INetFwRule> = firewall_rules
            .clone()
            .into_iter()
            .map(|rule| rule.try_into().expect("Failed to convert to INetFwRule"))
            .collect();

        assert_eq!(
            firewall_rules.len(),
            inetfw_rules.len(),
            "Conversion changed the number of rules!"
        );
    }
}

#[test]
#[serial]
fn test_firewall_rule_delete() {
    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound HTTP traffic")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([80, 65535])
        .build();

    add_rule(rule.clone()).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    rule.remove().expect("Failed to delete firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_firewall_rule_operations() {
    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound HTTP traffic")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([80, 65535])
        .build();

    add_rule(rule).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    remove_rule(RULE_NAME).expect("Failed to remove firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_firewall_rule_operations_2() {
    let mut rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound HTTP traffic")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([80, 65535])
        .build();

    add_rule(rule.clone()).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    rule.disable(true).expect("Failed to disable firewall rule");
    assert!(!rule.enabled(), "The rule should be disabled");

    rule.disable(false).expect("Failed to enable firewall rule");
    assert!(rule.enabled(), "The rule should be enabled");

    remove_rule(RULE_NAME).expect("Failed to remove firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_firewall_rule_update() {
    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound HTTP traffic")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([80, 65535])
        .build();

    add_rule(rule).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    let new_rule_name = "aaaaaaaUPDATE";

    update_rule(
        RULE_NAME,
        WindowsFirewallRuleSettings::builder()
            .name(new_rule_name)
            .build(),
    )
    .expect("Failed to update firewall rule");

    let res_exist = rule_exists(new_rule_name).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being updated");

    remove_rule(new_rule_name).expect("Failed to remove firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(!res_exist, "The rule should not exist after being removed");

    let res_exist = rule_exists(new_rule_name).expect("Failed to check if rule exists");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_firewall_rule_update_2() {
    let mut rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound HTTP traffic")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([80, 65535])
        .build();

    add_rule(rule.clone()).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    let new_rule_name = "aaaaaaaUPDATE";

    let settings = WindowsFirewallRuleSettings::builder()
        .name(new_rule_name)
        .build();

    rule.update(&settings)
        .expect("Failed to update firewall rule");

    let res_exist = rule_exists(new_rule_name).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being updated");

    remove_rule(new_rule_name).expect("Failed to remove firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(!res_exist, "The rule should not exist after being removed");

    let res_exist = rule_exists(new_rule_name).expect("Failed to check if rule exists");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_tcp_windows_firewall_rule_conversion() {
    let rule_action = ActionFirewallWindows::Allow;
    let rule_direction = DirectionFirewallWindows::In;
    let rule_enabled = true;
    let rule_description = "Allow inbound HTTP traffic";
    let rule_application_name = "C:\\Program Files\\MyApp\\app.exe";
    let rule_service_name = "MyService";
    let rule_protocol = ProtocolFirewallWindows::Tcp;
    let rule_local_ports = [80, 65535];
    let rule_remote_ports = [8080, 443];
    let rule_local_addresses = [
        IpAddr::from_str("192.168.1.1").unwrap(),
        IpAddr::from_str("192.168.1.2").unwrap(),
    ];
    let rule_remote_addresses = [
        IpAddr::from_str("10.0.0.1").unwrap(),
        IpAddr::from_str("10.0.0.2").unwrap(),
    ];
    // // it causes a panic if the interface doesn't exist
    // let rule_interfaces = ["Wi-Fi"];
    let rule_interface_types = [Wireless, Lan];
    let rule_grouping = "Group A";
    let rule_profiles = ProfileFirewallWindows::Standard;
    let rule_edge_traversal = false;

    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(rule_action)
        .direction(rule_direction)
        .enabled(rule_enabled)
        .description(rule_description)
        .application_name(rule_application_name)
        .service_name(rule_service_name)
        .protocol(rule_protocol)
        .local_ports(rule_local_ports)
        .remote_ports(rule_remote_ports)
        .local_addresses(rule_local_addresses)
        .remote_addresses(rule_remote_addresses)
        // // it causes a panic if the interface doesn't exist
        // .interfaces(rule_interfaces)
        .interface_types(rule_interface_types)
        .grouping(rule_grouping)
        .profiles(rule_profiles)
        .edge_traversal(rule_edge_traversal)
        .build();

    add_rule(rule).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    let result = get_rule(RULE_NAME).expect("Failed to retrieve the rule");

    assert_eq!(result.name(), RULE_NAME);
    assert_eq!(*result.action(), rule_action);
    assert_eq!(*result.direction(), rule_direction);
    assert_eq!(result.enabled(), rule_enabled);
    assert_eq!(result.description(), Some(&rule_description.to_string()));
    assert_eq!(
        result.application_name(),
        Some(&rule_application_name.to_string())
    );
    assert_eq!(result.service_name(), Some(&rule_service_name.to_string()));
    assert_eq!(result.protocol(), Some(rule_protocol).as_ref());
    assert_eq!(
        result.local_ports(),
        to_hashset_option(rule_local_ports).as_ref()
    );
    assert_eq!(
        result.remote_ports(),
        to_hashset_option(rule_remote_ports).as_ref()
    );
    assert_eq!(
        result.local_addresses(),
        to_hashset_option(rule_local_addresses).as_ref()
    );
    assert_eq!(
        result.remote_addresses(),
        to_hashset_option(rule_remote_addresses).as_ref()
    );
    // // it causes a panic if the interface doesn't exist
    // assert_eq!(
    //     result.interfaces(),
    //     to_string_hashset_option(rule_interfaces).as_ref()
    // );
    assert_eq!(
        result.interface_types(),
        to_hashset_option(rule_interface_types).as_ref()
    );
    assert_eq!(result.grouping(), Some(&rule_grouping.to_string()));
    assert_eq!(result.profiles(), Some(rule_profiles).as_ref());
    assert_eq!(result.edge_traversal(), Some(rule_edge_traversal));

    remove_rule(RULE_NAME).expect("Failed to remove firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists after removal");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_icmpv4_firewall_rule_conversion() {
    let rule_action = ActionFirewallWindows::Allow;
    let rule_direction = DirectionFirewallWindows::In;
    let rule_enabled = true;
    let rule_description = "Allow inbound ICMPv4 traffic";
    let rule_application_name = "C:\\Program Files\\MyApp\\app.exe";
    let rule_service_name = "MyService";
    let rule_protocol = ProtocolFirewallWindows::Icmpv4;
    let rule_local_addresses = [
        IpAddr::from_str("192.168.1.1").unwrap(),
        IpAddr::from_str("192.168.1.2").unwrap(),
    ];
    let rule_remote_addresses = [
        IpAddr::from_str("10.0.0.1").unwrap(),
        IpAddr::from_str("10.0.0.2").unwrap(),
    ];
    let rule_icmp_types_and_codes = "8:0";
    // // it causes a panic if the interface doesn't exist
    // let rule_interfaces = ["Wi-Fi"];
    let rule_interface_types = [Wireless, Lan];
    let rule_grouping = "Group A";
    let rule_profiles = ProfileFirewallWindows::Standard;
    let rule_edge_traversal = false;

    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(rule_action)
        .direction(rule_direction)
        .enabled(rule_enabled)
        .description(rule_description)
        .application_name(rule_application_name)
        .service_name(rule_service_name)
        .protocol(rule_protocol)
        .local_addresses(rule_local_addresses)
        .remote_addresses(rule_remote_addresses)
        .icmp_types_and_codes(rule_icmp_types_and_codes)
        // // it causes a panic if the interface doesn't exist
        // .interfaces(rule_interfaces) // it causes a panic if the interface doesn't exist
        .interface_types(rule_interface_types)
        .grouping(rule_grouping)
        .profiles(rule_profiles)
        .edge_traversal(rule_edge_traversal)
        .build();

    add_rule(rule).expect("Failed to add ICMPv4 firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    let result = get_rule(RULE_NAME).expect("Failed to retrieve the rule");

    assert_eq!(result.name(), RULE_NAME);
    assert_eq!(*result.action(), rule_action);
    assert_eq!(*result.direction(), rule_direction);
    assert_eq!(result.enabled(), rule_enabled);
    assert_eq!(result.description(), Some(&rule_description.to_string()));
    assert_eq!(
        result.application_name(),
        Some(&rule_application_name.to_string())
    );
    assert_eq!(result.service_name(), Some(&rule_service_name.to_string()));
    assert_eq!(result.protocol(), Some(rule_protocol).as_ref());
    assert_eq!(
        result.local_addresses(),
        to_hashset_option(rule_local_addresses).as_ref()
    );
    assert_eq!(
        result.remote_addresses(),
        to_hashset_option(rule_remote_addresses).as_ref()
    );
    assert_eq!(
        result.icmp_types_and_codes(),
        Some(&rule_icmp_types_and_codes.to_string())
    );
    // // it causes a panic if the interface doesn't exist
    // assert_eq!(
    //     result.interfaces(),
    //     to_string_hashset_option(rule_interfaces).as_ref()
    // );
    assert_eq!(
        result.interface_types(),
        to_hashset_option(rule_interface_types).as_ref()
    );
    assert_eq!(result.grouping(), Some(&rule_grouping.to_string()));
    assert_eq!(result.profiles(), Some(rule_profiles).as_ref());
    assert_eq!(result.edge_traversal(), Some(rule_edge_traversal));

    remove_rule(RULE_NAME).expect("Failed to remove ICMPv4 firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists after removal");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_tcp_to_icmp_rule_conversion() {
    let rule_action = ActionFirewallWindows::Allow;
    let rule_direction = DirectionFirewallWindows::In;
    let rule_enabled = true;
    let rule_description = "Allow inbound TCP traffic";
    let rule_protocol = ProtocolFirewallWindows::Tcp;
    let rule_local_ports = [80, 443];
    let rule_remote_ports = [1000, 2000];
    let rule_local_addresses = [IpAddr::from_str("192.168.1.1").unwrap()];
    let rule_remote_addresses = [IpAddr::from_str("10.0.0.1").unwrap()];

    let tcp_rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(rule_action)
        .direction(rule_direction)
        .enabled(rule_enabled)
        .description(rule_description)
        .protocol(rule_protocol)
        .local_ports(rule_local_ports)
        .remote_ports(rule_remote_ports)
        .local_addresses(rule_local_addresses)
        .remote_addresses(rule_remote_addresses)
        .build();

    add_rule(tcp_rule).expect("Failed to add TCP firewall rule");
    assert!(rule_exists(RULE_NAME).expect("Failed to check if TCP rule exists"));

    let rule_protocol_icmp = ProtocolFirewallWindows::Icmpv4;
    let rule_icmp_types_and_codes = "8:0";

    let icmp_settings = WindowsFirewallRuleSettings::builder()
        .protocol(rule_protocol_icmp)
        .icmp_types_and_codes(rule_icmp_types_and_codes)
        .build();

    update_rule(RULE_NAME, icmp_settings).expect("Failed to update ICMP firewall rule");
    assert!(rule_exists(RULE_NAME).expect("Failed to check if ICMP rule exists"));

    let result = get_rule(RULE_NAME).expect("Failed to retrieve ICMP rule");

    assert_eq!(result.name(), RULE_NAME);
    assert_eq!(result.protocol(), Some(rule_protocol_icmp).as_ref());
    assert_eq!(
        result.icmp_types_and_codes(),
        Some(&rule_icmp_types_and_codes.to_string())
    );
    assert_eq!(
        result.local_addresses(),
        to_hashset_option(rule_local_addresses).as_ref()
    );
    assert_eq!(
        result.remote_addresses(),
        to_hashset_option(rule_remote_addresses).as_ref()
    );

    remove_rule(RULE_NAME).expect("Failed to remove ICMPv4 firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists after removal");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_tcp_to_icmp_rule_conversion_2() {
    let rule_action = ActionFirewallWindows::Allow;
    let rule_direction = DirectionFirewallWindows::In;
    let rule_enabled = true;
    let rule_description = "Allow inbound TCP traffic";
    let rule_protocol = &ProtocolFirewallWindows::Tcp;
    let rule_local_ports = [80, 443];
    let rule_remote_ports = [1000, 2000];
    let rule_local_addresses = [IpAddr::from_str("192.168.1.1").unwrap()];
    let rule_remote_addresses = [IpAddr::from_str("10.0.0.1").unwrap()];

    let mut tcp_rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(rule_action)
        .direction(rule_direction)
        .enabled(rule_enabled)
        .description(rule_description)
        .protocol(*rule_protocol)
        .local_ports(rule_local_ports)
        .remote_ports(rule_remote_ports)
        .local_addresses(rule_local_addresses)
        .remote_addresses(rule_remote_addresses)
        .build();

    add_rule(tcp_rule.clone()).expect("Failed to add TCP firewall rule");
    assert!(rule_exists(RULE_NAME).expect("Failed to check if TCP rule exists"));

    let rule_protocol_icmp = ProtocolFirewallWindows::Icmpv4;
    let rule_icmp_types_and_codes = "8:0";

    let icmp_settings = WindowsFirewallRuleSettings::builder()
        .protocol(rule_protocol_icmp)
        .icmp_types_and_codes(rule_icmp_types_and_codes)
        .build();

    tcp_rule
        .update(&icmp_settings)
        .expect("Failed to update ICMP firewall rule");

    assert!(rule_exists(RULE_NAME).expect("Failed to check if ICMP rule exists"));

    let result = get_rule(RULE_NAME).expect("Failed to retrieve ICMP rule");

    assert_eq!(result.name(), RULE_NAME);
    assert_eq!(result.protocol(), Some(rule_protocol_icmp).as_ref());
    assert_eq!(
        result.icmp_types_and_codes(),
        Some(&rule_icmp_types_and_codes.to_string())
    );
    assert_eq!(
        result.local_addresses(),
        to_hashset_option(rule_local_addresses).as_ref()
    );
    assert_eq!(
        result.remote_addresses(),
        to_hashset_option(rule_remote_addresses).as_ref()
    );

    remove_rule(RULE_NAME).expect("Failed to remove ICMP firewall rule");
    assert!(!rule_exists(RULE_NAME).expect("Failed to check if ICMP rule was removed"));
}

#[test]
#[serial]
fn test_update_firewall_rule() {
    let rule_action = ActionFirewallWindows::Block;
    let rule_direction = DirectionFirewallWindows::Out;
    let rule_enabled = true;
    let rule_description = "Block outbound UDP traffic";
    let rule_protocol = &ProtocolFirewallWindows::Udp;
    let rule_local_ports = [53, 123];
    let rule_remote_ports = [500, 4500];
    let rule_local_addresses = [IpAddr::from_str("192.168.2.1").unwrap()];
    let rule_remote_addresses = [
        IpAddr::from_str("8.8.8.8").unwrap(),
        IpAddr::from_str("8.8.4.4").unwrap(),
    ];

    let mut udp_rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(rule_action)
        .direction(rule_direction)
        .enabled(rule_enabled)
        .description(rule_description)
        .protocol(*rule_protocol)
        .local_ports(rule_local_ports)
        .remote_ports(rule_remote_ports)
        .local_addresses(rule_local_addresses)
        .remote_addresses(rule_remote_addresses)
        .build();

    add_rule(udp_rule.clone()).expect("Failed to add UDP firewall rule");
    assert!(rule_exists(RULE_NAME).expect("Failed to check if UDP rule exists"));

    let new_rule_action = ActionFirewallWindows::Allow;
    let new_rule_protocol = ProtocolFirewallWindows::Icmpv6;
    let new_icmp_types_and_codes = "128:0";
    let new_rule_description = "Allow ICMPv6 Echo Requests";
    let new_rule_enabled = false;

    let updated_settings = WindowsFirewallRuleSettings::builder()
        .action(new_rule_action)
        .protocol(new_rule_protocol)
        .icmp_types_and_codes(new_icmp_types_and_codes)
        .description(new_rule_description)
        .enabled(new_rule_enabled)
        .build();

    udp_rule
        .update(&updated_settings)
        .expect("Failed to update firewall rule");
    assert!(rule_exists(RULE_NAME).expect("Failed to check if updated rule exists"));

    let result = get_rule(RULE_NAME).expect("Failed to retrieve updated rule");

    assert_eq!(result.name(), RULE_NAME);
    assert_eq!(result.action(), &new_rule_action);
    assert_eq!(result.protocol(), Some(new_rule_protocol).as_ref());
    assert_eq!(
        result.icmp_types_and_codes(),
        Some(&new_icmp_types_and_codes.to_string())
    );
    assert_eq!(
        result.description(),
        Some(&new_rule_description.to_string())
    );
    assert_eq!(result.enabled(), new_rule_enabled);
    assert_eq!(
        result.local_addresses(),
        to_hashset_option(rule_local_addresses).as_ref()
    );
    assert_eq!(
        result.remote_addresses(),
        to_hashset_option(rule_remote_addresses).as_ref()
    );

    remove_rule(RULE_NAME).expect("Failed to remove updated firewall rule");
    assert!(!rule_exists(RULE_NAME).expect("Failed to check if updated rule was removed"));
}
