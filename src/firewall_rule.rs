use getset::{Getters, Setters};
use std::collections::HashSet;
use std::convert::TryFrom;
use typed_builder::TypedBuilder;
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule;
use windows::core::BSTR;

use crate::errors::{SetRuleError, WindowsFirewallError};
use crate::utils::{
    BstrExt, bstr_to_hashset, hashset_to_bstr, hashset_to_variant, into_hashset,
    variant_to_hashset, with_rule,
};

pub use self::types::{Action, Address, Direction, InterfaceType, Port, Profile, Protocol};

pub mod operations;
pub mod types;

/// Represents a rule in the Windows Firewall.
///
/// # Mandatory Fields
/// - [`name`](FirewallRule::name): The friendly name of the rule. *(Must not contain `|` or be `"all"`)*
/// - [`direction`](FirewallRule::direction): The direction of the traffic (e.g., `Inbound`, `Outbound`).
/// - [`enabled`](FirewallRule::enabled): Whether the rule is enabled.
/// - [`action`](FirewallRule::action): The action taken (e.g., `Allow`, `Block`).
///
/// # Optional Fields
/// - [`description`](FirewallRule::description): Description of the rule. *(Must not contain `|`)*
/// - [`application_name`](FirewallRule::application_name): Friendly app name.
/// - [`service_name`](FirewallRule::service_name): Service name of the app.
/// - [`protocol`](FirewallRule::protocol): IP protocol (e.g., [`Protocol::Tcp`]).
/// - [`local_ports`](FirewallRule::local_ports): Local ports list.
/// - [`remote_ports`](FirewallRule::remote_ports): Remote ports list.
/// - [`local_addresses`](FirewallRule::local_addresses): Local addresses.
/// - [`remote_addresses`](FirewallRule::remote_addresses): Remote addresses.
/// - [`icmp_types_and_codes`](FirewallRule::icmp_types_and_codes): ICMP types & codes.
/// - [`interfaces`](FirewallRule::interfaces): Interfaces targeted by the rule.
/// - [`interface_types`](FirewallRule::interface_types): Types of interfaces targeted.
/// - [`grouping`](FirewallRule::grouping): Group this rule belongs to.
/// - [`profiles`](FirewallRule::profiles): Profiles this rule applies to.
/// - [`edge_traversal`](FirewallRule::edge_traversal): Enables edge traversal (default: `false`).
///
/// # Example
/// ```rust
/// use windows_firewall::{FirewallRule, Action, Direction, Protocol};
///
/// let rule = FirewallRule::builder()
/// .name("Allow HTTP")
/// .action(Action::Allow)
/// .direction(Direction::In)
/// .enabled(true)
/// .description("Allow inbound HTTP traffic")
/// .protocol(Protocol::Tcp)
/// .local_ports([80])
/// .build();
///
/// println!("Firewall Rule: {:?}", rule);
/// ```
#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct FirewallRule {
    /// The user-friendly name of the rule. It must not contain the "|" character and cannot be "all".
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    name: String,
    /// The direction of the traffic this rule applies to (e.g., inbound or outbound).
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    direction: Direction,
    /// Indicates whether the rule is enabled (active) or disabled.
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    enabled: bool,
    /// The action to take when the rule conditions are met (e.g., allow or block).
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    action: Action,
    /// A brief description of the rule's purpose or function. Must not contain the "|" character.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    description: Option<String>,
    /// The name of the application to which this rule applies.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    application_name: Option<String>,
    /// The service name associated with the application for this rule.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    service_name: Option<String>,
    /// The IP protocol used by the rule (e.g., TCP, UDP).
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    protocol: Option<Protocol>,
    /// A set of local ports this rule applies to. For example, specify ports like 80 or 443.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<Port>>| Some(into_hashset(items))))]
    #[getset(get = "pub", set = "pub")]
    local_ports: Option<HashSet<Port>>,
    /// A set of remote ports this rule applies to.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<Port>>| Some(into_hashset(items))))]
    #[getset(get = "pub", set = "pub")]
    remote_ports: Option<HashSet<Port>>,
    /// A set of local IP addresses this rule applies to. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<Address>>| Some(into_hashset(items))))]
    #[getset(get = "pub", set = "pub")]
    local_addresses: Option<HashSet<Address>>,
    /// A set of remote IP addresses this rule applies to. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<Address>>| Some(into_hashset(items))))]
    #[getset(get = "pub", set = "pub")]
    remote_addresses: Option<HashSet<Address>>,
    /// A list of ICMP types and codes this rule applies to, relevant for ICMP protocol rules.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    icmp_types_and_codes: Option<String>,
    /// A list of network interfaces this rule applies to, identified by their friendly names.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| Some(into_hashset(items))))]
    #[getset(get = "pub", set = "pub")]
    interfaces: Option<HashSet<String>>,
    /// A list of interface types this rule applies to (e.g., `Wireless`, `Lan`, `RemoteAccess`, or `All`).
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<InterfaceType>>| Some(into_hashset(items))))]
    #[getset(get = "pub", set = "pub")]
    interface_types: Option<HashSet<InterfaceType>>,
    /// The group name this rule belongs to, used for organizing rules.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    grouping: Option<String>,
    /// The profiles this rule is associated with (e.g., Domain, Private, Public).
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    profiles: Option<Profile>,
    /// Indicates whether edge traversal is enabled, allowing traffic to bypass NAT devices.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    edge_traversal: Option<bool>,
}

impl TryFrom<INetFwRule> for FirewallRule {
    type Error = WindowsFirewallError;

    fn try_from(fw_rule: INetFwRule) -> Result<Self, WindowsFirewallError> {
        unsafe {
            Ok(Self {
                name: fw_rule.Name().to_required_string()?,
                direction: fw_rule.Direction()?.try_into()?,
                enabled: fw_rule.Enabled()?.into(),
                action: fw_rule.Action()?.try_into()?,
                description: fw_rule.Description().to_optional_string(),
                application_name: fw_rule.ApplicationName().to_optional_string(),
                service_name: fw_rule.ServiceName().to_optional_string(),
                protocol: fw_rule.Protocol()?.try_into().ok(),
                local_ports: bstr_to_hashset(fw_rule.LocalPorts()),
                remote_ports: bstr_to_hashset(fw_rule.RemotePorts()),
                local_addresses: bstr_to_hashset(fw_rule.LocalAddresses()),
                remote_addresses: bstr_to_hashset(fw_rule.RemoteAddresses()),
                icmp_types_and_codes: fw_rule.IcmpTypesAndCodes().to_optional_string(),
                interfaces: Some(variant_to_hashset(&fw_rule.Interfaces()?)?),
                interface_types: bstr_to_hashset(fw_rule.InterfaceTypes()),
                grouping: fw_rule.Grouping().to_optional_string(),
                profiles: fw_rule.Profiles()?.try_into().ok(),
                edge_traversal: fw_rule.EdgeTraversal().ok().map(VARIANT_BOOL::as_bool),
            })
        }
    }
}

impl TryFrom<&FirewallRule> for INetFwRule {
    type Error = WindowsFirewallError;

    fn try_from(rule: &FirewallRule) -> Result<Self, WindowsFirewallError> {
        with_rule(|fw_rule| {
            unsafe {
                fw_rule
                    .SetName(&BSTR::from(&rule.name))
                    .map_err(SetRuleError::Name)
            }?;
            unsafe {
                fw_rule
                    .SetDirection(rule.direction.into())
                    .map_err(SetRuleError::Direction)
            }?;
            unsafe {
                fw_rule
                    .SetEnabled(rule.enabled.into())
                    .map_err(SetRuleError::Enabled)
            }?;
            unsafe {
                fw_rule
                    .SetAction(rule.action.into())
                    .map_err(SetRuleError::Action)
            }?;
            if let Some(ref description) = rule.description {
                unsafe {
                    fw_rule
                        .SetDescription(&BSTR::from(description))
                        .map_err(SetRuleError::Description)
                }?;
            }
            if let Some(ref app_name) = rule.application_name {
                unsafe {
                    fw_rule
                        .SetApplicationName(&BSTR::from(app_name))
                        .map_err(SetRuleError::ApplicationName)
                }?;
            }
            if let Some(ref service_name) = rule.service_name {
                unsafe {
                    fw_rule
                        .SetServiceName(&BSTR::from(service_name))
                        .map_err(SetRuleError::ServiceName)
                }?;
            }
            if let Some(protocol) = rule.protocol {
                unsafe {
                    fw_rule
                        .SetProtocol(protocol.into())
                        .map_err(SetRuleError::Protocol)
                }?;
            }
            if let Some(ref local_ports) = rule.local_ports {
                unsafe {
                    fw_rule
                        .SetLocalPorts(&hashset_to_bstr(Some(local_ports)))
                        .map_err(SetRuleError::LocalPorts)
                }?;
            }
            if let Some(ref remote_ports) = rule.remote_ports {
                unsafe {
                    fw_rule
                        .SetRemotePorts(&hashset_to_bstr(Some(remote_ports)))
                        .map_err(SetRuleError::RemotePorts)
                }?;
            }
            if let Some(ref local_addresses) = rule.local_addresses {
                unsafe {
                    fw_rule
                        .SetLocalAddresses(&hashset_to_bstr(Some(local_addresses)))
                        .map_err(SetRuleError::LocalAddresses)
                }?;
            }
            if let Some(ref remote_addresses) = rule.remote_addresses {
                unsafe {
                    fw_rule
                        .SetRemoteAddresses(&hashset_to_bstr(Some(remote_addresses)))
                        .map_err(SetRuleError::RemoteAddresses)
                }?;
            }
            if let Some(ref icmp_types_and_codes) = rule.icmp_types_and_codes {
                unsafe {
                    fw_rule
                        .SetIcmpTypesAndCodes(&BSTR::from(icmp_types_and_codes))
                        .map_err(SetRuleError::IcmpTypesAndCodes)
                }?;
            }
            if let Some(edge_traversal) = rule.edge_traversal {
                unsafe {
                    fw_rule
                        .SetEdgeTraversal(edge_traversal.into())
                        .map_err(SetRuleError::EdgeTraversal)
                }?;
            }
            if let Some(ref grouping) = rule.grouping {
                unsafe {
                    fw_rule
                        .SetGrouping(&BSTR::from(grouping))
                        .map_err(SetRuleError::Grouping)
                }?;
            }
            if let Some(ref interface) = rule.interfaces {
                unsafe {
                    fw_rule
                        .SetInterfaces(&hashset_to_variant(interface)?)
                        .map_err(SetRuleError::Interfaces)
                }?;
            }
            if let Some(ref interface_types) = rule.interface_types {
                unsafe {
                    fw_rule
                        .SetInterfaceTypes(&hashset_to_bstr(Some(interface_types)))
                        .map_err(SetRuleError::InterfaceType)
                }?;
            }
            if let Some(profiles) = rule.profiles {
                unsafe {
                    fw_rule
                        .SetProfiles(profiles.into())
                        .map_err(SetRuleError::Profiles)
                }?;
            }

            Ok(fw_rule)
        })
    }
}

/// Struct for updating Windows Firewall Rule
///
/// # Example
/// ```rust
/// use windows_firewall::{FirewallRuleUpdate, Direction, Action, Protocol};
///
/// let rule_settings = FirewallRuleUpdate::builder()
///     .name("Allow HTTP")
///     .action(Action::Allow)
///     .direction(Direction::In)
///     .enabled(true)
///     .description("Allow inbound HTTP traffic")
///     .protocol(Protocol::Tcp)
///     .local_ports([80])
///     .build();
///
/// println!("Firewall Rule Settings: {:?}", rule_settings);
/// ```
#[derive(Debug, Clone, TypedBuilder)]
pub struct FirewallRuleUpdate {
    /// The name of the firewall rule. Must not contain the "|" character and cannot be "all".
    #[builder(default, setter(strip_option, into))]
    pub(crate) name: Option<String>,
    /// The direction of the firewall rule (inbound or outbound).
    #[builder(default, setter(strip_option, into))]
    pub(crate) direction: Option<Direction>,
    /// Indicates whether the firewall rule is enabled.
    #[builder(default, setter(strip_option, into))]
    pub(crate) enabled: Option<bool>,
    /// The action to be taken by the firewall rule (allow or block).
    #[builder(default, setter(strip_option, into))]
    pub(crate) action: Option<Action>,
    /// A brief description of the firewall rule. Must not contain the "|" character.
    #[builder(default, setter(strip_option, into))]
    pub(crate) description: Option<String>,
    /// The application name associated with the firewall rule.
    #[builder(default, setter(strip_option, into))]
    pub(crate) application_name: Option<String>,
    /// The service name associated with the firewall rule.
    #[builder(default, setter(strip_option, into))]
    pub(crate) service_name: Option<String>,
    /// The IP protocol used by the rule (e.g., TCP, UDP).
    #[builder(default, setter(strip_option, into))]
    pub(crate) protocol: Option<Protocol>,
    /// A set of local ports this rule applies to. For example, specify ports like 80 or 443.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<Port>>| Some(into_hashset(items))))]
    pub(crate) local_ports: Option<HashSet<Port>>,
    /// A set of remote ports this rule applies to.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<Port>>| Some(into_hashset(items))))]
    pub(crate) remote_ports: Option<HashSet<Port>>,
    /// A set of local addresses associated with the firewall rule. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<Address>>| Some(into_hashset(items))))]
    pub(crate) local_addresses: Option<HashSet<Address>>,
    /// A set of remote addresses associated with the firewall rule. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<Address>>| Some(into_hashset(items))))]
    pub(crate) remote_addresses: Option<HashSet<Address>>,
    /// The ICMP types and codes associated with the rule, relevant for ICMP protocol rules.
    #[builder(default, setter(strip_option, into))]
    pub(crate) icmp_types_and_codes: Option<String>,
    /// A set of interfaces associated with the firewall rule.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| Some(into_hashset(items))))]
    pub(crate) interfaces: Option<HashSet<String>>,
    /// A set of interface types associated with the firewall rule (e.g., `Wireless`, `Lan`, `RemoteAccess`, or `All`).
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<InterfaceType>>| Some(into_hashset(items))))]
    pub(crate) interface_types: Option<HashSet<InterfaceType>>,
    /// The grouping of the rule, used for organizing rules.
    #[builder(default, setter(strip_option, into))]
    pub(crate) grouping: Option<String>,
    /// The profiles associated with the firewall rule (e.g., Domain, Private, Public).
    #[builder(default, setter(strip_option, into))]
    pub(crate) profiles: Option<Profile>,
    /// Indicates whether edge traversal is allowed by the rule.
    #[builder(default, setter(strip_option, into))]
    pub(crate) edge_traversal: Option<bool>,
}

impl From<FirewallRule> for FirewallRuleUpdate {
    fn from(rule: FirewallRule) -> Self {
        Self {
            name: Some(rule.name),
            direction: Some(rule.direction),
            enabled: Some(rule.enabled),
            action: Some(rule.action),
            description: rule.description,
            application_name: rule.application_name,
            service_name: rule.service_name,
            protocol: rule.protocol,
            local_ports: rule.local_ports,
            remote_ports: rule.remote_ports,
            local_addresses: rule.local_addresses,
            remote_addresses: rule.remote_addresses,
            icmp_types_and_codes: rule.icmp_types_and_codes,
            interfaces: rule.interfaces,
            interface_types: rule.interface_types,
            grouping: rule.grouping,
            profiles: rule.profiles,
            edge_traversal: rule.edge_traversal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_windows_firewall_rule_setters() {
        let mut rule = FirewallRule::builder()
            .name("test")
            .action(Action::Block)
            .direction(Direction::Out)
            .enabled(false)
            .build();

        rule.set_name("new_name".to_string());
        assert_eq!(rule.name(), "new_name");

        rule.set_direction(Direction::In);
        assert_eq!(rule.direction(), &Direction::In);

        rule.set_enabled(true);
        assert!(rule.enabled());

        rule.set_action(Action::Allow);
        assert_eq!(rule.action(), &Action::Allow);

        let desc = Some("desc".to_string());
        rule.set_description(desc);
        assert_eq!(*rule.description(), Some("desc".to_string()));
        rule.set_description(None);
        assert_eq!(*rule.description(), None);

        let app = Some("app.exe".to_string());
        rule.set_application_name(app);
        assert_eq!(*rule.application_name(), Some("app.exe".to_string()));
        rule.set_application_name(None);
        assert_eq!(*rule.application_name(), None);

        let svc = Some("svc".to_string());
        rule.set_service_name(svc);
        assert_eq!(*rule.service_name(), Some("svc".to_string()));
        rule.set_service_name(None);
        assert_eq!(*rule.service_name(), None);

        rule.set_protocol(Some(Protocol::Tcp));
        assert_eq!(*rule.protocol(), Some(Protocol::Tcp));
        rule.set_protocol(None);
        assert_eq!(*rule.protocol(), None);

        let mut ports = HashSet::new();
        ports.insert(80.into());
        rule.set_local_ports(Some(ports.clone()));
        assert_eq!(*rule.local_ports(), Some(ports));
        rule.set_local_ports(None);
        assert_eq!(*rule.local_ports(), None);

        let mut rports = HashSet::new();
        rports.insert(443.into());
        rule.set_remote_ports(Some(rports.clone()));
        assert_eq!(*rule.remote_ports(), Some(rports));
        rule.set_remote_ports(None);
        assert_eq!(*rule.remote_ports(), None);

        let mut addrs = HashSet::new();
        addrs.insert(IpAddr::from_str("127.0.0.1").unwrap().into());
        rule.set_local_addresses(Some(addrs.clone()));
        assert_eq!(*rule.local_addresses(), Some(addrs));
        rule.set_local_addresses(None);
        assert_eq!(*rule.local_addresses(), None);

        let mut raddrs = HashSet::new();
        raddrs.insert(IpAddr::from_str("8.8.8.8").unwrap().into());
        rule.set_remote_addresses(Some(raddrs.clone()));
        assert_eq!(*rule.remote_addresses(), Some(raddrs));
        rule.set_remote_addresses(None);
        assert_eq!(*rule.remote_addresses(), None);

        let icmp = Some("8:0".to_string());
        rule.set_icmp_types_and_codes(icmp);
        assert_eq!(*rule.icmp_types_and_codes(), Some("8:0".to_string()));
        rule.set_icmp_types_and_codes(None);
        assert_eq!(*rule.icmp_types_and_codes(), None);

        let mut interfaces = HashSet::new();
        interfaces.insert("Wi-Fi".to_string());
        rule.set_interfaces(Some(interfaces.clone()));
        assert_eq!(*rule.interfaces(), Some(interfaces));
        rule.set_interfaces(None);
        assert_eq!(*rule.interfaces(), None);

        let mut iftypes = HashSet::new();
        iftypes.insert(InterfaceType::Lan);
        rule.set_interface_types(Some(iftypes.clone()));
        assert_eq!(*rule.interface_types(), Some(iftypes));
        rule.set_interface_types(None);
        assert_eq!(*rule.interface_types(), None);

        let group = Some("group".to_string());
        rule.set_grouping(group);
        assert_eq!(*rule.grouping(), Some("group".to_string()));
        rule.set_grouping(None);
        assert_eq!(*rule.grouping(), None);

        rule.set_profiles(Some(Profile::Private));
        assert_eq!(*rule.profiles(), Some(Profile::Private));
        rule.set_profiles(None);
        assert_eq!(*rule.profiles(), None);

        rule.set_edge_traversal(Some(true));
        assert_eq!(*rule.edge_traversal(), Some(true));
        rule.set_edge_traversal(None);
        assert_eq!(*rule.edge_traversal(), None);
    }
}
