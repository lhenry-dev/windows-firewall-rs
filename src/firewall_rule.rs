use scopeguard::guard;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::IpAddr;
use typed_builder::TypedBuilder;
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwRule, NetFwRule};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows::core::BSTR;

use crate::constants::{DWCLSCONTEXT, DWCOINIT};
use crate::errors::WindowsFirewallError;
use crate::firewall_enums::{
    ActionFirewallWindows, DirectionFirewallWindows, ProfileFirewallWindows,
    ProtocolFirewallWindows,
};
use crate::utils::{
    convert_bstr_to_hashset, convert_hashset_to_bstr, hashset_to_variant, to_string_hashset_option,
    variant_to_hashset,
};
use crate::windows_firewall::{remove_rule, rule_exists, update_rule};
use crate::{InterfaceTypes, add_rule, add_rule_if_not_exists, disable_rule, enable_rule};

/// Represents a rule in the Windows Firewall.
///
/// # Mandatory Fields
/// - `name`: The friendly name of the rule. (must not contain "|" and must not be "all")
/// - `direction`: The direction of the traffic (e.g., inbound or outbound).
/// - `enabled`: Whether the rule is enabled or disabled.
/// - `action`: The action of the rule (e.g., allow or block traffic).
///
/// # Optional Fields
/// - `description`: A description of the rule. (must not contain "|")
/// - `application_name`: The friendly name of the application.
/// - `service_name`: The service name property of the application.
/// - `protocol`: The IP protocol for the rule (e.g., TCP/UDP).
/// - `local_ports`: A list of local ports for the rule.
/// - `remote_ports`: A list of remote ports for the rule.
/// - `local_addresses`: A list of local addresses for the rule.
/// - `remote_addresses`: A list of remote addresses for the rule.
/// - `icmp_types_and_codes`: A list of ICMP types and codes.
/// - `interfaces`: A list of interfaces to which the rule applies.
/// - `interface_types`: A list of interface types to which the rule applies.
/// - `grouping`: The group to which the rule belongs.
/// - `profiles`: Profiles to which the rule belongs.
/// - `edge_traversal`: Whether edge traversal is enabled or disabled (default: `false`).
///
/// # Example
/// ```rust
/// use windows_firewall::{WindowsFirewallRule, ActionFirewallWindows, DirectionFirewallWindows, ProtocolFirewallWindows};
///
/// let rule = WindowsFirewallRule::builder()
/// .name("Allow HTTP")
/// .action(ActionFirewallWindows::Allow)
/// .direction(DirectionFirewallWindows::In)
/// .enabled(true)
/// .description("Allow inbound HTTP traffic")
/// .protocol(ProtocolFirewallWindows::Tcp)
/// .local_ports([80])
/// .build();
///
/// println!("Firewall Rule: {:?}", rule);
/// ```
#[derive(Debug, Clone, TypedBuilder)]
pub struct WindowsFirewallRule {
    /// The user-friendly name of the rule. It must not contain the "|" character and cannot be "all".
    #[builder(setter(into))]
    name: String,

    /// The direction of the traffic this rule applies to (e.g., inbound or outbound).
    #[builder(setter(into))]
    direction: DirectionFirewallWindows,

    /// Indicates whether the rule is enabled (active) or disabled.
    #[builder(setter(into))]
    enabled: bool,

    /// The action to take when the rule conditions are met (e.g., allow or block).
    #[builder(setter(into))]
    action: ActionFirewallWindows,

    /// A brief description of the rule's purpose or function. Must not contain the "|" character.
    #[builder(default, setter(strip_option, into))]
    description: Option<String>,

    /// The name of the application to which this rule applies.
    #[builder(default, setter(strip_option, into))]
    application_name: Option<String>,

    /// The service name associated with the application for this rule.
    #[builder(default, setter(strip_option, into))]
    service_name: Option<String>,

    /// The IP protocol this rule applies to (e.g., TCP, UDP). Refer to IANA for protocol numbers.
    #[builder(default, setter(strip_option, into))]
    protocol: Option<ProtocolFirewallWindows>,

    /// A set of local ports this rule applies to. For example, specify ports like 80 or 443.
    #[builder(default, setter(strip_option, into))]
    local_ports: Option<HashSet<u16>>,

    /// A set of remote ports this rule applies to.
    #[builder(default, setter(strip_option, into))]
    remote_ports: Option<HashSet<u16>>,

    /// A set of local IP addresses this rule applies to. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = IpAddr>| Some(items.into_iter().collect())))]
    local_addresses: Option<HashSet<IpAddr>>,

    /// A set of remote IP addresses this rule applies to. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = IpAddr>| Some(items.into_iter().collect())))]
    remote_addresses: Option<HashSet<IpAddr>>,

    /// A list of ICMP types and codes this rule applies to, relevant for ICMP protocol rules.
    #[builder(default, setter(strip_option, into))]
    icmp_types_and_codes: Option<String>,

    /// A list of network interfaces this rule applies to, identified by their friendly names.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| to_string_hashset_option(items)))]
    interfaces: Option<HashSet<String>>,

    /// A list of interface types this rule applies to (e.g., Wireless, Lan, RemoteAccess, or All).
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = InterfaceTypes>| Some(items.into_iter().collect())))]
    interface_types: Option<HashSet<InterfaceTypes>>,

    /// The group name this rule belongs to, used for organizing rules.
    #[builder(default, setter(strip_option, into))]
    grouping: Option<String>,

    /// The profiles this rule is associated with (e.g., Domain, Private, Public).
    #[builder(default, setter(strip_option, into))]
    profiles: Option<ProfileFirewallWindows>,

    /// Indicates whether edge traversal is enabled, allowing traffic to bypass NAT devices.
    #[builder(default, setter(strip_option, into))]
    edge_traversal: Option<bool>,
}

impl WindowsFirewallRule {
    /// Returns the name of the firewall rule
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the direction of the firewall rule (inbound or outbound)
    pub fn direction(&self) -> &DirectionFirewallWindows {
        &self.direction
    }

    /// Returns whether the firewall rule is enabled or not
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the action to be taken by the firewall rule (allow/block)
    pub fn action(&self) -> &ActionFirewallWindows {
        &self.action
    }

    /// Returns the description of the firewall rule, if available
    pub fn description(&self) -> Option<&String> {
        self.description.as_ref()
    }

    /// Returns the application name associated with the firewall rule, if available
    pub fn application_name(&self) -> Option<&String> {
        self.application_name.as_ref()
    }

    /// Returns the service name associated with the firewall rule, if available
    pub fn service_name(&self) -> Option<&String> {
        self.service_name.as_ref()
    }

    /// Returns the protocol used by the firewall rule, if available
    pub fn protocol(&self) -> Option<&ProtocolFirewallWindows> {
        self.protocol.as_ref()
    }

    /// Returns the set of local ports associated with the firewall rule, if available
    pub fn local_ports(&self) -> Option<&HashSet<u16>> {
        self.local_ports.as_ref()
    }

    /// Returns the set of remote ports associated with the firewall rule, if available
    pub fn remote_ports(&self) -> Option<&HashSet<u16>> {
        self.remote_ports.as_ref()
    }

    /// Returns the set of local addresses associated with the firewall rule, if available
    pub fn local_addresses(&self) -> Option<&HashSet<IpAddr>> {
        self.local_addresses.as_ref()
    }

    /// Returns the set of remote addresses associated with the firewall rule, if available
    pub fn remote_addresses(&self) -> Option<&HashSet<IpAddr>> {
        self.remote_addresses.as_ref()
    }

    /// Returns the ICMP types and codes associated with the rule, if available
    pub fn icmp_types_and_codes(&self) -> Option<&String> {
        self.icmp_types_and_codes.as_ref()
    }

    /// Returns the set of interfaces associated with the firewall rule, if available
    pub fn interfaces(&self) -> Option<&HashSet<String>> {
        self.interfaces.as_ref()
    }

    /// Returns the set of interface types associated with the firewall rule, if available
    pub fn interface_types(&self) -> Option<&HashSet<InterfaceTypes>> {
        self.interface_types.as_ref()
    }

    /// Returns the grouping of the rule, if available
    pub fn grouping(&self) -> Option<&String> {
        self.grouping.as_ref()
    }

    /// Returns the profiles associated with the firewall rule, if available
    pub fn profiles(&self) -> Option<&ProfileFirewallWindows> {
        self.profiles.as_ref()
    }

    /// Returns whether edge traversal is allowed by the rule
    pub fn edge_traversal(&self) -> Option<bool> {
        self.edge_traversal
    }

    /// Adds a new firewall rule to the system.
    ///
    /// This function creates and adds a new firewall rule based on the current instance's properties.
    /// The rule is registered with the Windows Firewall, applying the specified settings such as
    /// name, direction, action, and other parameters.
    ///
    /// # Arguments
    ///
    /// This function does not take any arguments, as it operates on the current instance's fields.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<(), WindowsFirewallError>`. If the rule is added successfully,
    /// it returns `Ok(())`. In case of an error (e.g., COM initialization failure or failure to add rule),
    /// it returns a `WindowsFirewallError`.
    ///
    /// # Errors
    ///
    /// This function may return a `WindowsFirewallError` if there is a failure during:
    /// - COM initialization (`CoInitializeExFailed`).
    /// - Adding the firewall rule.
    ///
    /// # Security
    ///
    /// This function requires administrative privileges.
    pub fn add(&self) -> Result<(), WindowsFirewallError> {
        add_rule(self.clone())?;
        Ok(())
    }

    /// Adds a new firewall rule to the system only if a rule with the same name doesn't exist.
    ///
    /// This function first checks if a rule with the given name exists, and if not,
    /// adds the new rule to the Windows Firewall.
    ///
    /// # Arguments
    ///
    /// This function does not take any arguments, as it operates on the current instance's fields.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<bool, WindowsFirewallError>`. If the rule is added successfully,
    /// it returns `Ok(true)`. If the rule already exists, it returns `Ok(false)`. In case of an error
    /// (e.g., COM initialization failure or failure to add rule), it returns a `WindowsFirewallError`.
    ///
    /// # Errors
    ///
    /// This function may return a `WindowsFirewallError` if there is a failure during:
    /// - COM initialization (`CoInitializeExFailed`).
    /// - Checking if the rule exists.
    /// - Adding the firewall rule.
    ///
    /// # Security
    ///
    /// This function requires administrative privileges.
    pub fn add_if_not_exists(&self) -> Result<(), WindowsFirewallError> {
        add_rule_if_not_exists(self.clone())?;
        Ok(())
    }

    /// Deletes an existing firewall rule from the system.
    ///
    /// This function removes a firewall rule identified by its name. Once deleted, the rule
    /// can no longer be applied, and any associated settings are lost.
    ///
    /// # Arguments
    ///
    /// This function does not take any arguments, as it operates on the current instance's `name` field.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<(), WindowsFirewallError>`. If the rule is removed successfully,
    /// it returns `Ok(())`. In case of an error (e.g., COM initialization failure, rule not found),
    /// it returns a `WindowsFirewallError`.
    ///
    /// # Errors
    ///
    /// This function may return a `WindowsFirewallError` if there is a failure during:
    /// - COM initialization (`CoInitializeExFailed`).
    /// - Removing the rule.
    ///
    /// # Security
    ///
    /// This function requires administrative privileges.
    pub fn remove(self) -> Result<(), WindowsFirewallError> {
        remove_rule(&self.name)?;
        Ok(())
    }

    /// Updates an existing firewall rule with new settings.
    ///
    /// This function modifies an existing firewall rule based on the provided `settings`.
    /// It updates various properties such as name, direction, action, protocol, and addresses.
    /// If the protocol is ICMP (IPv4 or IPv6), the function ensures that local and remote ports
    /// are cleared, as they are not applicable to ICMP.
    ///
    /// # Arguments
    ///
    /// * `settings` - A reference to a `WindowsFirewallRuleSettings` struct containing the new
    ///   configuration parameters for the firewall rule.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<(), WindowsFirewallError>`. If the rule is updated successfully,
    /// it returns `Ok(())`. In case of an error (e.g., COM initialization failure, rule not found, or failure
    /// to update the rule), it returns a `WindowsFirewallError`.
    ///
    /// # Errors
    ///
    /// This function may return a `WindowsFirewallError` if there is a failure during:
    /// - COM initialization (`CoInitializeExFailed`).
    /// - Fetching the rule.
    ///
    /// # Security
    ///
    /// This function requires administrative privileges.
    pub fn update(
        &mut self,
        settings: &WindowsFirewallRuleSettings,
    ) -> Result<(), WindowsFirewallError> {
        update_rule(&self.name, settings.clone())?;

        let is_icmp = matches!(
            &settings.protocol,
            Some(ProtocolFirewallWindows::Icmpv4) | Some(ProtocolFirewallWindows::Icmpv6)
        );

        if let Some(name) = &settings.name {
            self.name = name.to_string();
        }
        if let Some(direction) = &settings.direction {
            self.direction = *direction;
        }
        if let Some(enabled) = settings.enabled {
            self.enabled = enabled;
        }
        if let Some(action) = &settings.action {
            self.action = *action;
        }
        if let Some(description) = &settings.description {
            self.description = Some(description.to_string());
        }
        if let Some(application_name) = &settings.application_name {
            self.application_name = Some(application_name.to_string());
        }
        if let Some(service_name) = &settings.service_name {
            self.service_name = Some(service_name.to_string());
        }
        if let Some(protocol) = &settings.protocol {
            if is_icmp {
                self.local_ports = None;
                self.remote_ports = None;
            }
            self.protocol = Some(*protocol);
        }
        if let Some(local_ports) = &settings.local_ports {
            self.local_ports = Some(local_ports.clone());
        }
        if let Some(remote_ports) = &settings.remote_ports {
            self.remote_ports = Some(remote_ports.clone());
        }
        if let Some(local_addresses) = &settings.local_addresses {
            self.local_addresses = Some(local_addresses.clone());
        }
        if let Some(remote_addresses) = &settings.remote_addresses {
            self.remote_addresses = Some(remote_addresses.clone());
        }
        if let Some(icmp_types_and_codes) = &settings.icmp_types_and_codes {
            self.icmp_types_and_codes = Some(icmp_types_and_codes.to_string());
        }
        if let Some(interfaces) = &settings.interfaces {
            self.interfaces = Some(interfaces.clone());
        }
        if let Some(interface_types) = &settings.interface_types {
            self.interface_types = Some(interface_types.clone());
        }
        if let Some(grouping) = &settings.grouping {
            self.grouping = Some(grouping.to_string());
        }
        if let Some(profiles) = &settings.profiles {
            self.profiles = Some(*profiles);
        }
        if let Some(edge_traversal) = &settings.edge_traversal {
            self.edge_traversal = Some(*edge_traversal);
        }
        Ok(())
    }

    /// Enables or disables an existing firewall rule.
    ///
    /// This function modifies the state of a firewall rule based on the `disable` parameter.
    /// If `disable` is `true`, the rule is disabled; otherwise, it is enabled. The function
    /// updates the `enabled` field accordingly.
    ///
    /// # Arguments
    ///
    /// * `disable` - A boolean indicating whether to disable (`true`) or enable (`false`) the rule.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<(), WindowsFirewallError>`. If the rule is enabled successfully,
    /// it returns `Ok(())`. If an error occurs (e.g., COM initialization failure, rule not found),
    /// it returns a `WindowsFirewallError`.
    ///
    /// # Errors
    ///
    /// This function may return a `WindowsFirewallError` if there is a failure during:
    /// - COM initialization (`CoInitializeExFailed`).
    /// - Fetching the rule.
    /// - Enabling the rule.
    ///
    /// # Security
    ///
    /// This function requires administrative privileges.
    pub fn disable(&mut self, disable: bool) -> Result<(), WindowsFirewallError> {
        if disable {
            disable_rule(&self.name)?;
            self.enabled = false;
        } else {
            enable_rule(&self.name)?;
            self.enabled = true;
        }
        Ok(())
    }

    /// Checks if a firewall rule with the given name exists.
    ///
    /// This function initializes COM, creates a firewall policy object, and checks if a rule
    /// with the specified name exists in the Windows Firewall rules list.
    ///
    /// # Arguments
    ///
    /// This function does not take any arguments, as it operates on the current instance's `name` field.
    ///
    /// # Returns
    ///
    /// This function returns a `Result<bool, WindowsFirewallError>`. If the rule exists, it returns `Ok(true)`,
    /// otherwise it returns `Ok(false)`. In case of an error (e.g., COM initialization failure or issue
    /// with firewall policy), it returns a `WindowsFirewallError`.
    ///
    /// # Errors
    ///
    /// This function may return a `WindowsFirewallError` in case of failures during COM initialization
    /// or while interacting with the firewall policy object.
    ///
    /// # Security
    ///
    /// This function does not require administrative privileges.
    pub fn exists(&self) -> Result<bool, WindowsFirewallError> {
        rule_exists(&self.name)
    }
}

impl TryFrom<INetFwRule> for WindowsFirewallRule {
    type Error = WindowsFirewallError;

    fn try_from(fw_rule: INetFwRule) -> Result<Self, WindowsFirewallError> {
        unsafe {
            Ok(WindowsFirewallRule {
                name: fw_rule.Name().map(|bstr| bstr.to_string())?,
                direction: fw_rule.Direction()?.try_into()?,
                enabled: fw_rule.Enabled()?.into(),
                action: fw_rule.Action()?.try_into()?,
                description: fw_rule.Description().ok().and_then(|bstr| {
                    let string = bstr.to_string();
                    if string.is_empty() {
                        None
                    } else {
                        Some(string)
                    }
                }),
                application_name: fw_rule.ApplicationName().ok().and_then(|bstr| {
                    let string = bstr.to_string();
                    if string.is_empty() {
                        None
                    } else {
                        Some(string)
                    }
                }),
                service_name: fw_rule.ServiceName().ok().and_then(|bstr| {
                    let string = bstr.to_string();
                    if string.is_empty() {
                        None
                    } else {
                        Some(string)
                    }
                }),
                protocol: fw_rule.Protocol()?.try_into().ok(),
                local_ports: convert_bstr_to_hashset(fw_rule.LocalPorts()),
                remote_ports: convert_bstr_to_hashset(fw_rule.RemotePorts()),
                local_addresses: convert_bstr_to_hashset(fw_rule.LocalAddresses()),
                remote_addresses: convert_bstr_to_hashset(fw_rule.RemoteAddresses()),
                icmp_types_and_codes: fw_rule.IcmpTypesAndCodes().ok().and_then(|bstr| {
                    let string = bstr.to_string();
                    if string.is_empty() {
                        None
                    } else {
                        Some(string)
                    }
                }),
                interfaces: Some(variant_to_hashset(&fw_rule.Interfaces()?)?),
                interface_types: convert_bstr_to_hashset(fw_rule.InterfaceTypes()),
                grouping: fw_rule.Grouping().ok().and_then(|bstr| {
                    let string = bstr.to_string();
                    if string.is_empty() {
                        None
                    } else {
                        Some(string)
                    }
                }),
                profiles: fw_rule.Profiles()?.try_into().ok(),
                edge_traversal: fw_rule.EdgeTraversal().ok().map(|v| v.as_bool()),
            })
        }
    }
}

impl TryFrom<WindowsFirewallRule> for INetFwRule {
    type Error = WindowsFirewallError;

    fn try_from(rule: WindowsFirewallRule) -> Result<Self, WindowsFirewallError> {
        unsafe {
            let hr_com_init = CoInitializeEx(None, DWCOINIT);
            if hr_com_init.is_err() {
                return Err(WindowsFirewallError::CoInitializeExFailed(
                    hr_com_init.message(),
                ));
            }

            let _com_cleanup = guard((), |_| CoUninitialize());

            let fw_rule: INetFwRule = CoCreateInstance(&NetFwRule, None, DWCLSCONTEXT)?;

            fw_rule.SetName(&BSTR::from(&rule.name))?;
            fw_rule.SetDirection(rule.direction.into())?;
            fw_rule.SetEnabled(rule.enabled.into())?;
            fw_rule.SetAction(rule.action.into())?;
            if let Some(description) = rule.description {
                fw_rule.SetDescription(&BSTR::from(description))?;
            }
            if let Some(app_name) = rule.application_name {
                fw_rule.SetApplicationName(&BSTR::from(app_name))?;
            }
            if let Some(service_name) = rule.service_name {
                fw_rule.SetServiceName(&BSTR::from(service_name))?;
            }
            if let Some(protocol) = rule.protocol {
                fw_rule.SetProtocol(protocol.into())?;
            }
            if let Some(local_ports) = rule.local_ports {
                fw_rule.SetLocalPorts(&convert_hashset_to_bstr(Some(local_ports)))?;
            }
            if let Some(remote_ports) = rule.remote_ports {
                fw_rule.SetRemotePorts(&convert_hashset_to_bstr(Some(remote_ports)))?;
            }
            if let Some(local_addresses) = rule.local_addresses {
                fw_rule.SetLocalAddresses(&convert_hashset_to_bstr(Some(local_addresses)))?;
            }
            if let Some(remote_addresses) = rule.remote_addresses {
                fw_rule.SetRemoteAddresses(&convert_hashset_to_bstr(Some(remote_addresses)))?;
            }
            if let Some(icmp_types_and_codes) = rule.icmp_types_and_codes {
                fw_rule.SetIcmpTypesAndCodes(&BSTR::from(icmp_types_and_codes))?;
            }
            if let Some(edge_traversal) = rule.edge_traversal {
                fw_rule.SetEdgeTraversal(edge_traversal.into())?;
            }
            if let Some(grouping) = rule.grouping {
                fw_rule.SetGrouping(&BSTR::from(grouping))?;
            }
            if let Some(interface) = rule.interfaces {
                fw_rule.SetInterfaces(&hashset_to_variant(&interface)?)?;
            }
            if let Some(interface_types) = rule.interface_types {
                fw_rule.SetInterfaceTypes(&convert_hashset_to_bstr(Some(interface_types)))?;
            }
            if let Some(profiles) = rule.profiles {
                fw_rule.SetProfiles(profiles.into())?;
            }

            Ok(fw_rule)
        }
    }
}

/// Struct for updating Windows Firewall Rule
///
/// # Example
/// ```rust
/// use windows_firewall::{WindowsFirewallRuleSettings, DirectionFirewallWindows, ActionFirewallWindows, ProtocolFirewallWindows};
///
/// let rule_settings = WindowsFirewallRuleSettings::builder()
///     .name("Allow HTTP")
///     .action(ActionFirewallWindows::Allow)
///     .direction(DirectionFirewallWindows::In)
///     .enabled(true)
///     .description("Allow inbound HTTP traffic")
///     .protocol(ProtocolFirewallWindows::Tcp)
///     .local_ports([80])
///     .build();
///
/// println!("Firewall Rule Settings: {:?}", rule_settings);
/// ```
#[derive(Debug, Clone, TypedBuilder)]
pub struct WindowsFirewallRuleSettings {
    /// The name of the firewall rule. Must not contain the "|" character and cannot be "all".
    #[builder(default, setter(strip_option, into))]
    pub(crate) name: Option<String>,

    /// The direction of the firewall rule (inbound or outbound).
    #[builder(default, setter(strip_option, into))]
    pub(crate) direction: Option<DirectionFirewallWindows>,

    /// Indicates whether the firewall rule is enabled.
    #[builder(default, setter(strip_option, into))]
    pub(crate) enabled: Option<bool>,

    /// The action to be taken by the firewall rule (allow or block).
    #[builder(default, setter(strip_option, into))]
    pub(crate) action: Option<ActionFirewallWindows>,

    /// A brief description of the firewall rule. Must not contain the "|" character.
    #[builder(default, setter(strip_option, into))]
    pub(crate) description: Option<String>,

    /// The application name associated with the firewall rule.
    #[builder(default, setter(strip_option, into))]
    pub(crate) application_name: Option<String>,

    /// The service name associated with the firewall rule.
    #[builder(default, setter(strip_option, into))]
    pub(crate) service_name: Option<String>,

    /// The protocol used by the firewall rule (e.g., TCP, UDP). Refer to IANA for protocol numbers.
    #[builder(default, setter(strip_option, into))]
    pub(crate) protocol: Option<ProtocolFirewallWindows>,

    /// A set of local ports associated with the firewall rule.
    #[builder(default, setter(strip_option, into))]
    pub(crate) local_ports: Option<HashSet<u16>>,

    /// A set of remote ports associated with the firewall rule.
    #[builder(default, setter(strip_option, into))]
    pub(crate) remote_ports: Option<HashSet<u16>>,

    /// A set of local addresses associated with the firewall rule. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = IpAddr>| Some(items.into_iter().collect())))]
    pub(crate) local_addresses: Option<HashSet<IpAddr>>,

    /// A set of remote addresses associated with the firewall rule. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = IpAddr>| Some(items.into_iter().collect())))]
    pub(crate) remote_addresses: Option<HashSet<IpAddr>>,

    /// The ICMP types and codes associated with the rule, relevant for ICMP protocol rules.
    #[builder(default, setter(strip_option, into))]
    pub(crate) icmp_types_and_codes: Option<String>,

    /// A set of interfaces associated with the firewall rule.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| to_string_hashset_option(items)))]
    pub(crate) interfaces: Option<HashSet<String>>,

    /// A set of interface types associated with the firewall rule (e.g., Wireless, Lan, RemoteAccess, or All).
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = InterfaceTypes>| Some(items.into_iter().collect())))]
    pub(crate) interface_types: Option<HashSet<InterfaceTypes>>,

    /// The grouping of the rule, used for organizing rules.
    #[builder(default, setter(strip_option, into))]
    pub(crate) grouping: Option<String>,

    /// The profiles associated with the firewall rule (e.g., Domain, Private, Public).
    #[builder(default, setter(strip_option, into))]
    pub(crate) profiles: Option<ProfileFirewallWindows>,

    /// Indicates whether edge traversal is allowed by the rule.
    #[builder(default, setter(strip_option, into))]
    pub(crate) edge_traversal: Option<bool>,
}
