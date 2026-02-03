use windows_firewall::WindowsFirewallRule;

pub fn assert_firewall_rule_eq(actual: &WindowsFirewallRule, expected: &WindowsFirewallRule) {
    assert_eq!(actual.name(), expected.name(), "Rule name mismatch");
    assert_eq!(
        actual.direction(),
        expected.direction(),
        "Direction mismatch"
    );
    assert_eq!(
        actual.enabled(),
        expected.enabled(),
        "Enabled flag mismatch"
    );
    assert_eq!(actual.action(), expected.action(), "Action mismatch");

    if let Some(desc) = expected.description() {
        assert_eq!(
            actual.description(),
            &Some(desc.clone()),
            "Description mismatch"
        );
    }
    if let Some(app) = expected.application_name() {
        assert_eq!(
            actual.application_name(),
            &Some(app.clone()),
            "Application name mismatch"
        );
    }
    if let Some(service) = expected.service_name() {
        assert_eq!(
            actual.service_name(),
            &Some(service.clone()),
            "Service name mismatch"
        );
    }
    if let Some(protocol) = expected.protocol() {
        assert_eq!(actual.protocol(), &Some(*protocol), "Protocol mismatch");
    }
    if let Some(local_ports) = expected.local_ports() {
        assert_eq!(
            actual.local_ports(),
            &Some(local_ports.clone()),
            "Local ports mismatch"
        );
    }
    if let Some(remote_ports) = expected.remote_ports() {
        assert_eq!(
            actual.remote_ports(),
            &Some(remote_ports.clone()),
            "Remote ports mismatch"
        );
    }
    if let Some(local_addrs) = expected.local_addresses() {
        assert_eq!(
            actual.local_addresses(),
            &Some(local_addrs.clone()),
            "Local addresses mismatch"
        );
    }
    if let Some(remote_addrs) = expected.remote_addresses() {
        assert_eq!(
            actual.remote_addresses(),
            &Some(remote_addrs.clone()),
            "Remote addresses mismatch"
        );
    }
    if let Some(icmp) = expected.icmp_types_and_codes() {
        assert_eq!(
            actual.icmp_types_and_codes(),
            &Some(icmp.clone()),
            "ICMP types and codes mismatch"
        );
    }
    if let Some(interface_types) = expected.interface_types() {
        assert_eq!(
            actual.interface_types(),
            &Some(interface_types.clone()),
            "Interface types mismatch"
        );
    }
    if let Some(grouping) = expected.grouping() {
        assert_eq!(
            actual.grouping(),
            &Some(grouping.clone()),
            "Grouping mismatch"
        );
    }
    if let Some(profiles) = expected.profiles() {
        assert_eq!(actual.profiles(), &Some(*profiles), "Profiles mismatch");
    }
    if let Some(edge) = expected.edge_traversal() {
        assert_eq!(
            actual.edge_traversal(),
            &Some(*edge),
            "Edge traversal mismatch"
        );
    }
}
