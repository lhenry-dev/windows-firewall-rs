use std::net::IpAddr;
use std::str::FromStr;
use windows_firewall::{
    Action, Direction, InterfaceType::Lan, InterfaceType::RemoteAccess, InterfaceType::Wireless,
    Profile, Protocol,
};
use windows_firewall::{Address, FirewallRule, Port, PortKeyword};

pub fn build_base_rule(name: &str) -> FirewallRule {
    FirewallRule::builder()
        .name(name)
        .action(Action::Allow)
        .direction(Direction::In)
        .enabled(true)
        .build()
}

pub fn build_tcp_full_rule(name: &str) -> FirewallRule {
    FirewallRule::builder()
        .name(name)
        .action(Action::Block)
        .direction(Direction::In)
        .enabled(false)
        .description("Block outbound TCP traffic")
        .application_name("C:\\Program Files\\NewApp\\new_app.exe")
        .service_name("NewService")
        .protocol(Protocol::Tcp)
        .local_ports([443, 8443])
        .remote_ports([80, 8080])
        .local_addresses([IpAddr::from_str("172.16.0.1").unwrap()])
        .remote_addresses([IpAddr::from_str("1.1.1.1").unwrap()])
        .interface_types([Lan])
        .grouping("Group B")
        .profiles(Profile::Public)
        .edge_traversal(true)
        .build()
}

pub fn build_icmp_full_rule(name: &str) -> FirewallRule {
    FirewallRule::builder()
        .name(name)
        .action(Action::Allow)
        .direction(Direction::Out)
        .enabled(true)
        .description("Allow outbound ICMPv4 traffic")
        .application_name("C:\\Program Files\\MyApp\\app.exe")
        .service_name("MyService")
        .protocol(Protocol::Icmpv4)
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
        .profiles(Profile::Private)
        .edge_traversal(false)
        .build()
}

pub fn build_full_rule_for_protocol(name: &str, proto: Protocol) -> FirewallRule {
    let builder = FirewallRule::builder()
        .name(name)
        .action(Action::Allow)
        .direction(Direction::In)
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
        .profiles(Profile::Private)
        .edge_traversal(false);

    match proto {
        Protocol::Tcp | Protocol::Udp => builder.local_ports([1234]).remote_ports([4321]).build(),
        Protocol::Icmpv4 | Protocol::Icmpv6 => builder.icmp_types_and_codes("8:0").build(),
        _ => builder.build(),
    }
}

pub fn build_rule_for_interface(name: &str, interface_name: &str) -> FirewallRule {
    FirewallRule::builder()
        .name(name)
        .action(Action::Allow)
        .direction(Direction::In)
        .enabled(true)
        .interfaces([interface_name])
        .build()
}

pub fn build_rule_for_port(name: &str, port: &Port) -> FirewallRule {
    let rule_builder = FirewallRule::builder()
        .name(name)
        .action(Action::Allow)
        .direction(Direction::In)
        .enabled(true);

    if let Port::Keyword(k) = port {
        let rule_builder = match k {
            PortKeyword::Teredo => rule_builder.protocol(Protocol::Udp),
            _ => rule_builder.protocol(Protocol::Tcp),
        };
        rule_builder.local_ports([Port::from(*k)]).build()
    } else {
        rule_builder
            .protocol(Protocol::Udp)
            .local_ports([port.clone()])
            .remote_ports([port.clone()])
            .build()
    }
}

pub fn build_rule_for_address(name: &str, address: &Address) -> FirewallRule {
    let rule_builder = FirewallRule::builder()
        .name(name)
        .action(Action::Allow)
        .direction(Direction::In)
        .enabled(true);

    if let Address::Keyword(k) = address {
        rule_builder.remote_addresses([Address::from(*k)]).build()
    } else if let Address::Ip(ip) = address {
        rule_builder
            .local_addresses([Address::from(*ip)])
            .remote_addresses([Address::from(*ip)])
            .build()
    } else if let Address::Cidr(cidr) = address {
        rule_builder
            .local_addresses([Address::from(*cidr)])
            .remote_addresses([Address::from(*cidr)])
            .build()
    } else {
        rule_builder
            .local_addresses([address.clone()])
            .remote_addresses([address.clone()])
            .build()
    }
}
