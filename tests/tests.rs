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
    add_rule, add_rule_if_not_exists, get_active_profile, get_firewall_state, get_rule,
    list_incoming_rules, list_outgoing_rules, list_rules, remove_rule, rule_exists,
    set_firewall_state, update_rule,
};

const RULE_NAME: &str = "aaaWindowsFirewallRsTestRule";

fn to_string_hashset<T, I>(items: I) -> HashSet<String>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    items.into_iter().map(Into::into).collect()
}

fn to_hashset<T, I>(items: I) -> HashSet<T>
where
    I: IntoIterator<Item = T>,
    T: Eq + std::hash::Hash,
{
    items.into_iter().collect()
}

#[test]
fn test_get_active_profile() {
    let profile = get_active_profile();
    assert!(profile.is_ok(), "Failed to retrieve the active profile");
}

#[test]
fn test_get_firewall_state() {
    use ProfileFirewallWindows::*;
    let profiles = [Private, Domain, Public];

    for profile in &profiles {
        let state = get_firewall_state(*profile);
        assert!(
            state.is_ok(),
            "Failed to retrieve the firewall state for profile {profile:?}",
        );
    }
}

#[test]
fn test_set_firewall_state() {
    use ProfileFirewallWindows::*;
    let profiles = [Private, Domain, Public];

    for profile in &profiles {
        let state = get_firewall_state(*profile);
        assert!(
            state.is_ok(),
            "Failed to retrieve the firewall state for profile {profile:?}"
        );

        let current_state = state.unwrap();
        set_firewall_state(*profile, current_state).expect("Failed to set the firewall state");

        let new_state = get_firewall_state(*profile)
            .expect("Failed to retrieve the firewall state after setting");
        assert_eq!(
            new_state, current_state,
            "The firewall state should remain the same for profile {profile:?}"
        );
    }
}

#[test]
#[serial]
fn test_list_rules() {
    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound HTTP traffic")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([80, 65535])
        .build();

    add_rule(&rule).expect("Failed to add firewall rule");

    let rules = list_rules();
    assert!(rules.is_ok(), "Failed to list outgoing rules");

    let rules = rules.unwrap();

    let found = rules.iter().any(|r| r.name() == RULE_NAME);
    assert!(
        found,
        "Firewall rule '{}' not found in list_rules() output",
        RULE_NAME
    );

    remove_rule(RULE_NAME).expect("Failed to remove firewall rule");
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

    add_rule(&rule).expect("Failed to add firewall rule");

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

    add_rule(&rule).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    remove_rule(RULE_NAME).expect("Failed to remove firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(!res_exist, "The rule should not exist after being removed");
}

#[test]
#[serial]
fn test_add_rule_if_not_exists() {
    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound HTTP traffic")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([80])
        .build();

    let _ = remove_rule(RULE_NAME);

    let added = add_rule_if_not_exists(&rule).expect("Failed to add rule if not exists");
    assert!(added, "Rule should be added because it did not exist");

    let added_again = add_rule_if_not_exists(&rule).expect("Failed to call add_rule_if_not_exists");
    assert!(
        !added_again,
        "Rule should not be added again if it already exists"
    );

    remove_rule(RULE_NAME).expect("Failed to remove rule after test");
}

#[test]
#[serial]
fn test_add_rule_if_not_exists_2() {
    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound HTTP traffic")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([80])
        .build();

    let _ = rule.clone().remove();

    let added = rule
        .add_if_not_exists()
        .expect("Failed to add rule if not exists");
    assert!(added, "Rule should be added because it did not exist");

    let added_again = rule
        .add_if_not_exists()
        .expect("Failed to call add_rule_if_not_exists");
    assert!(
        !added_again,
        "Rule should not be added again if it already exists"
    );

    remove_rule(RULE_NAME).expect("Failed to remove rule after test");
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

    add_rule(&rule).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    rule.enable(false).expect("Failed to disable firewall rule");
    assert!(!rule.enabled(), "The rule should be disabled");

    rule.enable(true).expect("Failed to enable firewall rule");
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

    add_rule(&rule).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    let new_rule_name = "aaaaaaaUPDATE";

    update_rule(
        RULE_NAME,
        &WindowsFirewallRuleSettings::builder()
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

    rule.add().expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    let new_rule_name = "aaaaaaaUPDATE";

    let settings = WindowsFirewallRuleSettings::builder()
        .name(new_rule_name)
        .build();

    rule.update(&settings)
        .expect("Failed to update firewall rule");

    let res_exist = rule.exists().expect("Failed to check if rule exists");
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
    let rule_profiles = ProfileFirewallWindows::Private;
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

    add_rule(&rule).expect("Failed to add firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    let result = get_rule(RULE_NAME).expect("Failed to retrieve the rule");

    assert_eq!(result.name(), RULE_NAME);
    assert_eq!(*result.action(), rule_action);
    assert_eq!(*result.direction(), rule_direction);
    assert_eq!(*result.enabled(), rule_enabled);
    assert_eq!(*result.description(), Some(rule_description.to_string()));
    assert_eq!(
        *result.application_name(),
        Some(rule_application_name.to_string())
    );
    assert_eq!(*result.service_name(), Some(rule_service_name.to_string()));
    assert_eq!(*result.protocol(), Some(rule_protocol));
    assert_eq!(*result.local_ports(), Some(to_hashset(rule_local_ports)));
    assert_eq!(*result.remote_ports(), Some(to_hashset(rule_remote_ports)));
    assert_eq!(
        *result.local_addresses(),
        Some(to_hashset(rule_local_addresses))
    );
    assert_eq!(
        *result.remote_addresses(),
        Some(to_hashset(rule_remote_addresses))
    );
    // // it causes a panic if the interface doesn't exist
    // assert_eq!(
    //     result.interfaces(),
    //     to_string_hashset_option(rule_interfaces).as_ref()
    // );
    assert_eq!(
        *result.interface_types(),
        Some(to_hashset(rule_interface_types))
    );
    assert_eq!(*result.grouping(), Some(rule_grouping.to_string()));
    assert_eq!(*result.profiles(), Some(rule_profiles));
    assert_eq!(*result.edge_traversal(), Some(rule_edge_traversal));

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
    let rule_profiles = ProfileFirewallWindows::Private;
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

    add_rule(&rule).expect("Failed to add ICMPv4 firewall rule");

    let res_exist = rule_exists(RULE_NAME).expect("Failed to check if rule exists");
    assert!(res_exist, "The rule should exist after being added");

    let result = get_rule(RULE_NAME).expect("Failed to retrieve the rule");

    assert_eq!(result.name(), RULE_NAME);
    assert_eq!(*result.action(), rule_action);
    assert_eq!(*result.direction(), rule_direction);
    assert_eq!(*result.enabled(), rule_enabled);
    assert_eq!(*result.description(), Some(rule_description.to_string()));
    assert_eq!(
        *result.application_name(),
        Some(rule_application_name.to_string())
    );
    assert_eq!(*result.service_name(), Some(rule_service_name.to_string()));
    assert_eq!(*result.protocol(), Some(rule_protocol));
    assert_eq!(
        *result.local_addresses(),
        Some(to_hashset(rule_local_addresses))
    );
    assert_eq!(
        *result.remote_addresses(),
        Some(to_hashset(rule_remote_addresses))
    );
    assert_eq!(
        *result.icmp_types_and_codes(),
        Some(rule_icmp_types_and_codes.to_string())
    );
    // // it causes a panic if the interface doesn't exist
    // assert_eq!(
    //     result.interfaces(),
    //     to_string_hashset_option(rule_interfaces).as_ref()
    // );
    assert_eq!(
        *result.interface_types(),
        Some(to_hashset(rule_interface_types))
    );
    assert_eq!(*result.grouping(), Some(rule_grouping.to_string()));
    assert_eq!(*result.profiles(), Some(rule_profiles));
    assert_eq!(*result.edge_traversal(), Some(rule_edge_traversal));

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

    add_rule(&tcp_rule).expect("Failed to add TCP firewall rule");
    assert!(rule_exists(RULE_NAME).expect("Failed to check if TCP rule exists"));

    let rule_protocol_icmp = ProtocolFirewallWindows::Icmpv4;
    let rule_icmp_types_and_codes = "8:0";

    let icmp_settings = WindowsFirewallRuleSettings::builder()
        .protocol(rule_protocol_icmp)
        .icmp_types_and_codes(rule_icmp_types_and_codes)
        .build();

    update_rule(RULE_NAME, &icmp_settings).expect("Failed to update ICMP firewall rule");
    assert!(rule_exists(RULE_NAME).expect("Failed to check if ICMP rule exists"));

    let result = get_rule(RULE_NAME).expect("Failed to retrieve ICMP rule");

    assert_eq!(result.name(), RULE_NAME);
    assert_eq!(*result.protocol(), Some(rule_protocol_icmp));
    assert_eq!(
        *result.icmp_types_and_codes(),
        Some(rule_icmp_types_and_codes.to_string())
    );
    assert_eq!(
        *result.local_addresses(),
        Some(to_hashset(rule_local_addresses))
    );
    assert_eq!(
        *result.remote_addresses(),
        Some(to_hashset(rule_remote_addresses))
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

    add_rule(&tcp_rule).expect("Failed to add TCP firewall rule");
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
    assert_eq!(*result.protocol(), Some(rule_protocol_icmp));
    assert_eq!(
        *result.icmp_types_and_codes(),
        Some(rule_icmp_types_and_codes.to_string())
    );
    assert_eq!(
        *result.local_addresses(),
        Some(to_hashset(rule_local_addresses))
    );
    assert_eq!(
        *result.remote_addresses(),
        Some(to_hashset(rule_remote_addresses))
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

    add_rule(&udp_rule).expect("Failed to add UDP firewall rule");
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
    assert_eq!(*result.protocol(), Some(new_rule_protocol));
    assert_eq!(
        *result.icmp_types_and_codes(),
        Some(new_icmp_types_and_codes.to_string())
    );
    assert_eq!(
        *result.description(),
        Some(new_rule_description.to_string())
    );
    assert_eq!(*result.enabled(), new_rule_enabled);
    assert_eq!(
        *result.local_addresses(),
        Some(to_hashset(rule_local_addresses))
    );
    assert_eq!(
        *result.remote_addresses(),
        Some(to_hashset(rule_remote_addresses))
    );

    remove_rule(RULE_NAME).expect("Failed to remove updated firewall rule");
    assert!(!rule_exists(RULE_NAME).expect("Failed to check if updated rule was removed"));
}

#[test]
#[serial]
fn test_update_firewall_rule_with_all_parameters() {
    let mut rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound ICMPv4 traffic")
        .application_name("C:\\Program Files\\MyApp\\app.exe")
        .service_name("MyService")
        .protocol(ProtocolFirewallWindows::Icmpv4)
        .local_addresses([
            IpAddr::from_str("192.168.1.1").unwrap(),
            IpAddr::from_str("192.168.1.2").unwrap(),
        ])
        .remote_addresses([
            IpAddr::from_str("10.0.0.1").unwrap(),
            IpAddr::from_str("10.0.0.2").unwrap(),
        ])
        .icmp_types_and_codes("8:0")
        .interface_types([Wireless, Lan])
        .grouping("Group A")
        .profiles(ProfileFirewallWindows::Private)
        .edge_traversal(false)
        .build();

    add_rule(&rule).expect("Failed to add full parameter firewall rule");
    assert!(rule_exists(RULE_NAME).expect("Failed to check rule existence"));

    let updated_settings = WindowsFirewallRuleSettings::builder()
        .action(ActionFirewallWindows::Block)
        .direction(DirectionFirewallWindows::In)
        .enabled(false)
        .description("Block outbound TCP traffic")
        .application_name("C:\\Program Files\\NewApp\\new_app.exe")
        .service_name("NewService")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([443, 8443])
        .remote_ports([80, 8080])
        .local_addresses([IpAddr::from_str("172.16.0.1").unwrap()])
        .remote_addresses([IpAddr::from_str("1.1.1.1").unwrap()])
        .interface_types([Lan])
        .grouping("Group B")
        .profiles(ProfileFirewallWindows::Public)
        .edge_traversal(true)
        .build();

    rule.update(&updated_settings)
        .expect("Failed to update full parameter firewall rule");

    let updated_rule = get_rule(RULE_NAME).expect("Failed to get updated firewall rule");

    assert_eq!(updated_rule.name(), RULE_NAME);
    assert_eq!(updated_rule.action(), &ActionFirewallWindows::Block);
    assert_eq!(updated_rule.direction(), &DirectionFirewallWindows::In);
    assert!(!updated_rule.enabled());
    assert_eq!(
        *updated_rule.description(),
        Some("Block outbound TCP traffic".to_string())
    );
    assert_eq!(
        *updated_rule.application_name(),
        Some("C:\\Program Files\\NewApp\\new_app.exe".to_string())
    );
    assert_eq!(*updated_rule.service_name(), Some("NewService".to_string()));
    assert_eq!(*updated_rule.protocol(), Some(ProtocolFirewallWindows::Tcp));
    assert_eq!(*updated_rule.local_ports(), Some(to_hashset([443, 8443])));
    assert_eq!(*updated_rule.remote_ports(), Some(to_hashset([80, 8080])));
    assert_eq!(
        *updated_rule.local_addresses(),
        Some(to_hashset([IpAddr::from_str("172.16.0.1").unwrap()]))
    );
    assert_eq!(
        *updated_rule.remote_addresses(),
        Some(to_hashset([IpAddr::from_str("1.1.1.1").unwrap()]))
    );
    assert_eq!(*updated_rule.icmp_types_and_codes(), None);
    assert_eq!(*updated_rule.interface_types(), Some(to_hashset([Lan])));
    assert_eq!(*updated_rule.grouping(), Some("Group B".to_string()));
    assert_eq!(
        *updated_rule.profiles(),
        Some(ProfileFirewallWindows::Public)
    );
    assert_eq!(*updated_rule.edge_traversal(), Some(true));

    remove_rule(RULE_NAME).expect("Failed to remove updated rule");
    assert!(!rule_exists(RULE_NAME).expect("Failed to check if rule was removed"));
}

#[test]
#[serial]
fn test_add_or_update_with_all_parameters() {
    let rule = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("Allow inbound ICMPv4 traffic")
        .application_name("C:\\Program Files\\MyApp\\app.exe")
        .service_name("MyService")
        .protocol(ProtocolFirewallWindows::Icmpv4)
        .local_addresses([
            IpAddr::from_str("192.168.1.1").unwrap(),
            IpAddr::from_str("192.168.1.2").unwrap(),
        ])
        .remote_addresses([
            IpAddr::from_str("10.0.0.1").unwrap(),
            IpAddr::from_str("10.0.0.2").unwrap(),
        ])
        .icmp_types_and_codes("8:0")
        .interface_types([Wireless, Lan])
        .grouping("Group A")
        .profiles(ProfileFirewallWindows::Private)
        .edge_traversal(false)
        .build();

    let add_or_update = rule
        .add_or_update()
        .expect("Failed to add or update full parameter firewall rule");

    assert!(add_or_update, "Rule should be added");
    assert!(rule_exists(RULE_NAME).expect("Failed to check rule existence"));

    let updated_settings = WindowsFirewallRule::builder()
        .name(RULE_NAME)
        .action(ActionFirewallWindows::Block)
        .direction(DirectionFirewallWindows::In)
        .enabled(false)
        .description("Block outbound TCP traffic")
        .application_name("C:\\Program Files\\NewApp\\new_app.exe")
        .service_name("NewService")
        .protocol(ProtocolFirewallWindows::Tcp)
        .local_ports([443, 8443])
        .remote_ports([80, 8080])
        .local_addresses([IpAddr::from_str("172.16.0.1").unwrap()])
        .remote_addresses([IpAddr::from_str("1.1.1.1").unwrap()])
        .interface_types([Lan])
        .grouping("Group B")
        .profiles(ProfileFirewallWindows::Public)
        .edge_traversal(true)
        .build();

    let add_or_update = updated_settings
        .add_or_update()
        .expect("Failed to add or update full parameter firewall rule");
    assert!(!add_or_update, "Rule should be updated");

    let updated_rule = get_rule(RULE_NAME).expect("Failed to get updated firewall rule");

    assert_eq!(updated_rule.name(), RULE_NAME);
    assert_eq!(updated_rule.action(), &ActionFirewallWindows::Block);
    assert_eq!(updated_rule.direction(), &DirectionFirewallWindows::In);
    assert!(!updated_rule.enabled());
    assert_eq!(
        *updated_rule.description(),
        Some("Block outbound TCP traffic".to_string())
    );
    assert_eq!(
        *updated_rule.application_name(),
        Some("C:\\Program Files\\NewApp\\new_app.exe".to_string())
    );
    assert_eq!(*updated_rule.service_name(), Some("NewService".to_string()));
    assert_eq!(*updated_rule.protocol(), Some(ProtocolFirewallWindows::Tcp));
    assert_eq!(*updated_rule.local_ports(), Some(to_hashset([443, 8443])));
    assert_eq!(*updated_rule.remote_ports(), Some(to_hashset([80, 8080])));
    assert_eq!(
        *updated_rule.local_addresses(),
        Some(to_hashset([IpAddr::from_str("172.16.0.1").unwrap()]))
    );
    assert_eq!(
        *updated_rule.remote_addresses(),
        Some(to_hashset([IpAddr::from_str("1.1.1.1").unwrap()]))
    );
    assert_eq!(*updated_rule.icmp_types_and_codes(), None);
    assert_eq!(*updated_rule.interface_types(), Some(to_hashset([Lan])));
    assert_eq!(*updated_rule.grouping(), Some("Group B".to_string()));
    assert_eq!(
        *updated_rule.profiles(),
        Some(ProfileFirewallWindows::Public)
    );
    assert_eq!(*updated_rule.edge_traversal(), Some(true));

    remove_rule(RULE_NAME).expect("Failed to remove updated rule");
    assert!(!rule_exists(RULE_NAME).expect("Failed to check if rule was removed"));
}

#[test]
fn test_all_protocol_transitions() {
    use windows_firewall::{
        ActionFirewallWindows, DirectionFirewallWindows, ProtocolFirewallWindows,
        WindowsFirewallRule, remove_rule, rule_exists,
    };

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

            let base_builder = WindowsFirewallRule::builder()
                .name(&rule_name)
                .action(ActionFirewallWindows::Allow)
                .direction(DirectionFirewallWindows::In)
                .enabled(true)
                .description(format!("Transition from {} to {}", label_from, label_to))
                .application_name("test")
                .protocol(*proto_from);

            let rule = match proto_from {
                ProtocolFirewallWindows::Tcp | ProtocolFirewallWindows::Udp => base_builder
                    .local_ports([1234])
                    .remote_ports([4321])
                    .build(),
                ProtocolFirewallWindows::Icmpv4 | ProtocolFirewallWindows::Icmpv6 => {
                    base_builder.icmp_types_and_codes("8:0").build()
                }
                _ => base_builder.build(),
            };

            let result = rule.add_or_update();
            assert!(
                result.is_ok(),
                "Failed to add rule for protocol {}",
                label_from
            );
            assert!(rule_exists(&rule_name).unwrap(), "Rule not created (from)");
            let updated_rule = get_rule(&rule_name).expect("Failed to get updated firewall rule");
            assert_eq!(*updated_rule.protocol(), Some(proto_from).copied());

            let base_builder = WindowsFirewallRule::builder()
                .name(&rule_name)
                .action(ActionFirewallWindows::Allow)
                .direction(DirectionFirewallWindows::In)
                .enabled(true)
                .description(format!("Transition from {} to {}", label_from, label_to))
                .application_name("test")
                .protocol(*proto_to);

            let updated_rule = match proto_to {
                ProtocolFirewallWindows::Tcp | ProtocolFirewallWindows::Udp => base_builder
                    .local_ports([2345])
                    .remote_ports([5432])
                    .build(),
                ProtocolFirewallWindows::Icmpv4 | ProtocolFirewallWindows::Icmpv6 => {
                    base_builder.icmp_types_and_codes("0:0").build()
                }
                _ => base_builder.build(),
            };

            let update_result = updated_rule.add_or_update();
            assert!(
                update_result.is_ok(),
                "Failed to update rule from {} to {}",
                label_from,
                label_to
            );

            assert!(
                rule_exists(&rule_name).unwrap(),
                "Rule disappeared after update"
            );
            let updated_rule = get_rule(&rule_name).expect("Failed to get updated firewall rule");
            assert_eq!(*updated_rule.protocol(), Some(proto_to).copied());

            remove_rule(&rule_name).expect("Failed to remove test rule");
            assert!(!rule_exists(&rule_name).unwrap(), "Rule was not removed");
        }
    }
}

#[test]
#[serial]
fn test_windows_firewall_rule_per_network_interface() {
    use ipconfig::get_adapters;

    let adapters = get_adapters().expect("Failed to retrieve network interfaces");

    for adapter in adapters {
        let interface_name = adapter.friendly_name();
        let rule_name = format!("{RULE_NAME}_{interface_name}");

        let rule = WindowsFirewallRule::builder()
            .name(&rule_name)
            .action(ActionFirewallWindows::Allow)
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .interfaces([interface_name])
            .build();

        println!("Adding rule for interface: {interface_name}");

        rule.add().expect("Failed to add rule");

        assert!(rule.exists().unwrap());

        let result = get_rule(&rule_name).expect("Failed to retrieve the rule");
        assert_eq!(result.name(), &rule_name);
        assert_eq!(
            *result.interfaces(),
            Some(to_string_hashset([interface_name]))
        );

        remove_rule(&rule_name).expect("Failed to remove rule");
        assert!(!rule_exists(&rule_name).unwrap());
    }
}

#[test]
#[serial]
fn test_windows_firewall_rule_update_per_network_interface() {
    use ipconfig::get_adapters;

    let adapters = get_adapters().expect("Failed to retrieve network interfaces");

    for adapter in adapters {
        let interface_name = adapter.friendly_name();
        let rule_name = format!("{RULE_NAME}_{interface_name}");

        let mut rule = WindowsFirewallRule::builder()
            .name(&rule_name)
            .action(ActionFirewallWindows::Allow)
            .direction(DirectionFirewallWindows::In)
            .enabled(true)
            .build();

        rule.add().expect("Failed to add rule");

        assert!(rule.exists().unwrap());

        let updated_settings = WindowsFirewallRuleSettings::builder()
            .interfaces([interface_name])
            .build();

        println!("Updating rule for interface: {interface_name}");

        rule.update(&updated_settings)
            .expect("Failed to update rule");

        let updated_rule = get_rule(&rule_name).expect("Failed to get updated firewall rule");

        assert_eq!(updated_rule.name(), &rule_name);
        assert_eq!(
            *updated_rule.interfaces(),
            Some(to_string_hashset([interface_name]))
        );

        remove_rule(&rule_name).expect("Failed to remove rule");
        assert!(!rule_exists(&rule_name).unwrap());
    }
}
