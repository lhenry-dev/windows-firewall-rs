use std::net::IpAddr;
use std::str::FromStr;
use windows_firewall::{
    ActionFirewallWindows, DirectionFirewallWindows, InterfaceTypes::Lan,
    InterfaceTypes::RemoteAccess, InterfaceTypes::Wireless, ProfileFirewallWindows,
    ProtocolFirewallWindows,
};
use windows_firewall::{FwAddress, FwPort, FwPortKeyword, WindowsFirewallRule};

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
        .interface_types([Wireless, Lan, RemoteAccess])
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

pub fn build_rule_for_port(name: &str, port: &FwPort) -> WindowsFirewallRule {
    let rule_builder = WindowsFirewallRule::builder()
        .name(name)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true);

    if let FwPort::Keyword(k) = port {
        let rule_builder = match k {
            FwPortKeyword::Teredo => rule_builder.protocol(ProtocolFirewallWindows::Udp),
            _ => rule_builder.protocol(ProtocolFirewallWindows::Tcp),
        };
        rule_builder.local_ports([FwPort::from(*k)]).build()
    } else {
        rule_builder
            .protocol(ProtocolFirewallWindows::Udp)
            .local_ports([port.clone()])
            .remote_ports([port.clone()])
            .build()
    }
}

pub fn build_rule_for_address(name: &str, address: &FwAddress) -> WindowsFirewallRule {
    let rule_builder = WindowsFirewallRule::builder()
        .name(name)
        .action(ActionFirewallWindows::Allow)
        .direction(DirectionFirewallWindows::In)
        .enabled(true);

    if let FwAddress::Keyword(k) = address {
        rule_builder.remote_addresses([FwAddress::from(*k)]).build()
    } else if let FwAddress::Ip(ip) = address {
        rule_builder
            .local_addresses([FwAddress::from(*ip)])
            .remote_addresses([FwAddress::from(*ip)])
            .build()
    } else if let FwAddress::Cidr(cidr) = address {
        rule_builder
            .local_addresses([FwAddress::from(*cidr)])
            .remote_addresses([FwAddress::from(*cidr)])
            .build()
    } else {
        rule_builder
            .local_addresses([address.clone()])
            .remote_addresses([address.clone()])
            .build()
    }
}
