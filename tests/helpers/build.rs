use std::net::IpAddr;
use std::str::FromStr;
use windows_firewall::WindowsFirewallRule;
use windows_firewall::{
    ActionFirewallWindows, DirectionFirewallWindows, InterfaceTypes::Lan, InterfaceTypes::Wireless,
    ProfileFirewallWindows, ProtocolFirewallWindows,
};

pub fn build_base_rule(name: &str) -> WindowsFirewallRule {
    WindowsFirewallRule::builder()
        .name(name)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .build()
}

pub fn build_tcp_full_rule(name: &str) -> WindowsFirewallRule {
    WindowsFirewallRule::builder()
        .name(name)
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
        .build()
}

pub fn build_icmp_full_rule(name: &str) -> WindowsFirewallRule {
    WindowsFirewallRule::builder()
        .name(name)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::Out)
        .enabled(true)
        .description("Allow outbound ICMPv4 traffic")
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
        .build()
}

pub fn build_full_rule_for_protocol(
    name: &str,
    proto: ProtocolFirewallWindows,
) -> WindowsFirewallRule {
    let builder = WindowsFirewallRule::builder()
        .name(name)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .description("rule for specific protocol")
        .application_name("C:\\Program Files\\MyApp\\app.exe")
        .service_name("MyService")
        .protocol(proto)
        .local_addresses([
            IpAddr::from_str("192.168.1.1").unwrap(),
            IpAddr::from_str("192.168.1.2").unwrap(),
        ])
        .remote_addresses([
            IpAddr::from_str("10.0.0.1").unwrap(),
            IpAddr::from_str("10.0.0.2").unwrap(),
        ])
        .interface_types([Wireless, Lan])
        .grouping("Group A")
        .profiles(ProfileFirewallWindows::Private)
        .edge_traversal(false);

    match proto {
        ProtocolFirewallWindows::Tcp | ProtocolFirewallWindows::Udp => {
            builder.local_ports([1234]).remote_ports([4321]).build()
        }
        ProtocolFirewallWindows::Icmpv4 | ProtocolFirewallWindows::Icmpv6 => {
            builder.icmp_types_and_codes("8:0").build()
        }
        _ => builder.build(),
    }
}

pub fn build_rule_for_interface(name: &str, interface_name: &str) -> WindowsFirewallRule {
    WindowsFirewallRule::builder()
        .name(name)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true)
        .interfaces([interface_name])
        .build()
}
