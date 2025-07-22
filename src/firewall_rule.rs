use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::IpAddr;
use typed_builder::TypedBuilder;
use windows::core::BSTR;
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwRule, NetFwRule};
use windows::Win32::System::Com::CoCreateInstance;

use crate::constants::DWCLSCONTEXT;
use crate::errors::{SetRuleError, WindowsFirewallError};
use crate::firewall_enums::{
    ActionFirewallWindows, DirectionFirewallWindows, ProfileFirewallWindows,
    ProtocolFirewallWindows,
};
use crate::utils::{
    convert_bstr_to_hashset, convert_hashset_to_bstr, hashset_to_variant, is_not_icmp,
    is_not_tcp_or_udp, to_string_hashset, variant_to_hashset, with_com_initialized,
};
use crate::windows_firewall::{add_or_update, remove_rule, rule_exists, update_rule};
use crate::{add_rule, add_rule_if_not_exists, enable_rule, InterfaceTypes};

/// Represents a rule in the Windows Firewall.
///
/// # Mandatory Fields
/// - [`name`](WindowsFirewallRule::name): The friendly name of the rule. *(Must not contain `|` or be `"all"`)*
/// - [`direction`](WindowsFirewallRule::direction): The direction of the traffic (e.g., `Inbound`, `Outbound`).
/// - [`enabled`](WindowsFirewallRule::enabled): Whether the rule is enabled.
/// - [`action`](WindowsFirewallRule::action): The action taken (e.g., `Allow`, `Block`).
///
/// # Optional Fields
/// - [`description`](WindowsFirewallRule::description): Description of the rule. *(Must not contain `|`)*
/// - [`application_name`](WindowsFirewallRule::application_name): Friendly app name.
/// - [`service_name`](WindowsFirewallRule::service_name): Service name of the app.
/// - [`protocol`](WindowsFirewallRule::protocol): IP protocol (e.g., [`ProtocolFirewallWindows::Tcp`]).
/// - [`local_ports`](WindowsFirewallRule::local_ports): Local ports list.
/// - [`remote_ports`](WindowsFirewallRule::remote_ports): Remote ports list.
/// - [`local_addresses`](WindowsFirewallRule::local_addresses): Local addresses.
/// - [`remote_addresses`](WindowsFirewallRule::remote_addresses): Remote addresses.
/// - [`icmp_types_and_codes`](WindowsFirewallRule::icmp_types_and_codes): ICMP types & codes.
/// - [`interfaces`](WindowsFirewallRule::interfaces): Interfaces targeted by the rule.
/// - [`interface_types`](WindowsFirewallRule::interface_types): Types of interfaces targeted.
/// - [`grouping`](WindowsFirewallRule::grouping): Group this rule belongs to.
/// - [`profiles`](WindowsFirewallRule::profiles): Profiles this rule applies to.
/// - [`edge_traversal`](WindowsFirewallRule::edge_traversal): Enables edge traversal (default: `false`).
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

    /// The IP protocol used by the rule (e.g., TCP, UDP).
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
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| Some(to_string_hashset(items))))]
    interfaces: Option<HashSet<String>>,

    /// A list of interface types this rule applies to (e.g., `Wireless`, `Lan`, `RemoteAccess`, or `All`).
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

#[allow(clippy::must_use_candidate)]
impl WindowsFirewallRule {
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
    /// This function returns a [`Result<(), WindowsFirewallError>`](WindowsFirewallError). If the rule is added successfully,
    /// it returns `Ok(())`. In case of an error (e.g., COM initialization failure or failure to add rule),
    /// it returns a [`WindowsFirewallError`].
    ///
    /// # Errors
    ///
    /// This function may return a [`WindowsFirewallError`] if there is a failure during:
    /// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
    /// - Adding the firewall rule.
    ///
    /// # Security
    ///
    /// ⚠️ This function requires **administrative privileges**.
    pub fn add(&self) -> Result<(), WindowsFirewallError> {
        add_rule(self)
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
    /// This function returns a [`Result<bool, WindowsFirewallError>`](WindowsFirewallError). If the rule is added successfully,
    /// it returns `Ok(true)`. If the rule already exists, it returns `Ok(false)`. In case of an error
    /// (e.g., COM initialization failure or failure to add rule), it returns a [`WindowsFirewallError`].
    ///
    /// # Errors
    ///
    /// This function may return a [`WindowsFirewallError`] if there is a failure during:
    /// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
    /// - Checking if the rule exists.
    /// - Adding the firewall rule.
    ///
    /// # Security
    ///
    /// ⚠️ This function requires **administrative privileges**.
    pub fn add_if_not_exists(&self) -> Result<bool, WindowsFirewallError> {
        add_rule_if_not_exists(self)
    }

    /// Adds a new firewall rule to the system or updates an existing rule with the same name.
    ///
    /// This function first checks if a rule with the given name exists. If it does, the function updates
    /// the existing rule with the new settings. If the rule does not exist, it adds a new rule to the
    /// Windows Firewall.
    ///
    /// # Arguments
    ///
    /// This function does not take any arguments, as it operates on the current instance's fields.
    ///
    /// # Returns
    ///
    /// This function returns a [`Result<bool, WindowsFirewallError>`](WindowsFirewallError). If the rule is added
    /// successfully, it returns `Ok(true)`. If the rule already exists and was updated, it returns `Ok(false)`.
    /// In case of an error (e.g., COM initialization failure, failure to add or update the rule), it returns a
    /// [`WindowsFirewallError`].
    ///
    /// # Errors
    ///
    /// This function may return a [`WindowsFirewallError`] if there is a failure during:
    /// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
    /// - Fetching the existing rule or adding the new rule.
    /// - Updating the firewall rule.
    ///
    /// # Security
    ///
    /// ⚠️ This function requires **administrative privileges**.
    pub fn add_or_update(&self) -> Result<bool, WindowsFirewallError> {
        add_or_update(self)
    }

    /// Deletes an existing firewall rule from the system.
    ///
    /// This function removes a firewall rule identified by its name. Once deleted, the rule
    /// can no longer be applied, and any associated settings are lost.
    ///
    /// # Arguments
    ///
    /// This function does not take any arguments, as it operates on the current instance's [`name`](WindowsFirewallRule::name) field.
    ///
    /// # Returns
    ///
    /// This function returns a [`Result<(), WindowsFirewallError>`](WindowsFirewallError). If the rule is removed successfully,
    /// it returns `Ok(())`. In case of an error (e.g., COM initialization failure, rule not found),
    /// it returns a [`WindowsFirewallError`].
    ///
    /// # Errors
    ///
    /// This function may return a [`WindowsFirewallError`] if there is a failure during:
    /// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
    /// - Removing the rule.
    ///
    /// # Security
    ///
    /// ⚠️ This function requires **administrative privileges**.
    pub fn remove(self) -> Result<(), WindowsFirewallError> {
        remove_rule(&self.name)?;
        Ok(())
    }

    /// Updates an existing firewall rule with new settings.
    ///
    /// This function modifies an existing firewall rule based on the provided [`settings`](WindowsFirewallRuleSettings).
    /// It updates various properties such as name, direction, action, protocol, and addresses.
    /// If the protocol is ICMP (IPv4 or IPv6), the function ensures that local and remote ports
    /// are cleared, as they are not applicable to ICMP.
    ///
    /// # Arguments
    ///
    /// * `settings` - A reference to a [`WindowsFirewallRuleSettings`] struct containing the new
    ///   configuration parameters for the firewall rule.
    ///
    /// # Returns
    ///
    /// This function returns a [`Result<(), WindowsFirewallError>`](WindowsFirewallError). If the rule is updated successfully,
    /// it returns `Ok(())`. In case of an error (e.g., COM initialization failure, rule not found, or failure
    /// to update the rule), it returns a [`WindowsFirewallError`].
    ///
    /// # Errors
    ///
    /// This function may return a [`WindowsFirewallError`] if there is a failure during:
    /// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
    /// - Fetching the rule.
    ///
    /// # Security
    ///
    /// ⚠️ This function requires **administrative privileges**.
    pub fn update(
        &mut self,
        settings: &WindowsFirewallRuleSettings,
    ) -> Result<(), WindowsFirewallError> {
        update_rule(&self.name, settings)?;

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
            if is_not_tcp_or_udp(protocol) {
                self.local_ports = None;
                self.remote_ports = None;
            }
            if is_not_icmp(protocol) {
                self.icmp_types_and_codes = None;
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
    /// This function modifies the state of a firewall rule based on the `enable` parameter.
    /// If `enable` is `true`, the rule is enabled; otherwise, it is disabled. The function
    /// updates the `enabled` field accordingly.
    ///
    /// # Arguments
    ///
    /// * `enable` - A boolean indicating whether to enable (`true`) or disable (`false`) the rule.
    ///
    /// # Returns
    ///
    /// This function returns a [`Result<(), WindowsFirewallError>`](WindowsFirewallError). If the rule is updated successfully,
    /// it returns `Ok(())`. If an error occurs (e.g., COM initialization failure, rule not found),
    /// it returns a [`WindowsFirewallError`].
    ///
    /// # Errors
    ///
    /// This function may return a [`WindowsFirewallError`] if there is a failure during:
    /// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
    /// - Fetching the rule.
    /// - Enabling or disabling the rule.
    ///
    /// # Security
    ///
    /// ⚠️ This function requires **administrative privileges**.
    pub fn enable(&mut self, enable: bool) -> Result<(), WindowsFirewallError> {
        enable_rule(&self.name, enable)?;
        self.enabled = enable;
        Ok(())
    }

    /// Checks if a firewall rule with the given name exists.
    ///
    /// This function initializes COM, creates a firewall policy object, and checks if a rule
    /// with the specified name exists in the Windows Firewall rules list.
    ///
    /// # Arguments
    ///
    /// This function does not take any arguments, as it operates on the current instance's [`name`](WindowsFirewallRule::name) field.
    ///
    /// # Returns
    ///
    /// This function returns a [`Result<bool, WindowsFirewallError>`](WindowsFirewallError). If the rule exists, it returns `Ok(true)`,
    /// otherwise it returns `Ok(false)`. In case of an error (e.g., COM initialization failure or issue
    /// with firewall policy), it returns a [`WindowsFirewallError`].
    ///
    /// # Errors
    ///
    /// This function may return a [`WindowsFirewallError`] in case of failures during COM initialization
    /// or while interacting with the firewall policy object.
    ///
    /// # Security
    ///
    /// This function does not require administrative privileges.
    pub fn exists(&self) -> Result<bool, WindowsFirewallError> {
        rule_exists(&self.name)
    }

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

    /// Sets the name of the firewall rule.
    pub fn set_name(&mut self, name: impl Into<String>) -> &mut Self {
        self.name = name.into();
        self
    }

    /// Sets the direction of the firewall rule.
    pub fn set_direction(&mut self, direction: DirectionFirewallWindows) -> &mut Self {
        self.direction = direction;
        self
    }

    /// Sets whether the firewall rule is enabled.
    pub fn set_enabled(&mut self, enabled: bool) -> &mut Self {
        self.enabled = enabled;
        self
    }

    /// Sets the action of the firewall rule.
    pub fn set_action(&mut self, action: ActionFirewallWindows) -> &mut Self {
        self.action = action;
        self
    }

    /// Sets the description of the firewall rule.
    pub fn set_description(&mut self, description: Option<impl Into<String>>) -> &mut Self {
        self.description = description.map(|d| d.into());
        self
    }

    /// Sets the application name for the firewall rule.
    pub fn set_application_name(
        &mut self,
        application_name: Option<impl Into<String>>,
    ) -> &mut Self {
        self.application_name = application_name.map(|a| a.into());
        self
    }

    /// Sets the service name for the firewall rule.
    pub fn set_service_name(&mut self, service_name: Option<impl Into<String>>) -> &mut Self {
        self.service_name = service_name.map(|s| s.into());
        self
    }

    /// Sets the protocol for the firewall rule.
    pub fn set_protocol(&mut self, protocol: Option<ProtocolFirewallWindows>) -> &mut Self {
        self.protocol = protocol;
        self
    }

    /// Sets the local ports for the firewall rule.
    pub fn set_local_ports(&mut self, local_ports: Option<HashSet<u16>>) -> &mut Self {
        self.local_ports = local_ports;
        self
    }

    /// Sets the remote ports for the firewall rule.
    pub fn set_remote_ports(&mut self, remote_ports: Option<HashSet<u16>>) -> &mut Self {
        self.remote_ports = remote_ports;
        self
    }

    /// Sets the local addresses for the firewall rule.
    pub fn set_local_addresses(&mut self, local_addresses: Option<HashSet<IpAddr>>) -> &mut Self {
        self.local_addresses = local_addresses;
        self
    }

    /// Sets the remote addresses for the firewall rule.
    pub fn set_remote_addresses(&mut self, remote_addresses: Option<HashSet<IpAddr>>) -> &mut Self {
        self.remote_addresses = remote_addresses;
        self
    }

    /// Sets the ICMP types and codes for the firewall rule.
    pub fn set_icmp_types_and_codes(
        &mut self,
        icmp_types_and_codes: Option<impl Into<String>>,
    ) -> &mut Self {
        self.icmp_types_and_codes = icmp_types_and_codes.map(|i| i.into());
        self
    }

    /// Sets the interfaces for the firewall rule.
    pub fn set_interfaces(&mut self, interfaces: Option<HashSet<String>>) -> &mut Self {
        self.interfaces = interfaces;
        self
    }

    /// Sets the interface types for the firewall rule.
    pub fn set_interface_types(
        &mut self,
        interface_types: Option<HashSet<InterfaceTypes>>,
    ) -> &mut Self {
        self.interface_types = interface_types;
        self
    }

    /// Sets the grouping for the firewall rule.
    pub fn set_grouping(&mut self, grouping: Option<impl Into<String>>) -> &mut Self {
        self.grouping = grouping.map(|g| g.into());
        self
    }

    /// Sets the profiles for the firewall rule.
    pub fn set_profiles(&mut self, profiles: Option<ProfileFirewallWindows>) -> &mut Self {
        self.profiles = profiles;
        self
    }

    /// Sets whether edge traversal is enabled for the firewall rule.
    pub fn set_edge_traversal(&mut self, edge_traversal: Option<bool>) -> &mut Self {
        self.edge_traversal = edge_traversal;
        self
    }
}

impl TryFrom<INetFwRule> for WindowsFirewallRule {
    type Error = WindowsFirewallError;

    fn try_from(fw_rule: INetFwRule) -> Result<Self, WindowsFirewallError> {
        unsafe {
            Ok(Self {
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
                edge_traversal: fw_rule.EdgeTraversal().ok().map(VARIANT_BOOL::as_bool),
            })
        }
    }
}

impl TryFrom<&WindowsFirewallRule> for INetFwRule {
    type Error = WindowsFirewallError;

    fn try_from(rule: &WindowsFirewallRule) -> Result<Self, WindowsFirewallError> {
        with_com_initialized(|| unsafe {
            let fw_rule: Self = CoCreateInstance(&NetFwRule, None, DWCLSCONTEXT)?;

            fw_rule
                .SetName(&BSTR::from(&rule.name))
                .map_err(SetRuleError::Name)?;
            fw_rule
                .SetDirection(rule.direction.into())
                .map_err(SetRuleError::Direction)?;
            fw_rule
                .SetEnabled(rule.enabled.into())
                .map_err(SetRuleError::Enabled)?;
            fw_rule
                .SetAction(rule.action.into())
                .map_err(SetRuleError::Action)?;
            if let Some(ref description) = rule.description {
                fw_rule
                    .SetDescription(&BSTR::from(description))
                    .map_err(SetRuleError::Description)?;
            }
            if let Some(ref app_name) = rule.application_name {
                fw_rule
                    .SetApplicationName(&BSTR::from(app_name))
                    .map_err(SetRuleError::ApplicationName)?;
            }
            if let Some(ref service_name) = rule.service_name {
                fw_rule
                    .SetServiceName(&BSTR::from(service_name))
                    .map_err(SetRuleError::ServiceName)?;
            }
            if let Some(protocol) = rule.protocol {
                fw_rule
                    .SetProtocol(protocol.into())
                    .map_err(SetRuleError::Protocol)?;
            }
            if let Some(ref local_ports) = rule.local_ports {
                fw_rule
                    .SetLocalPorts(&convert_hashset_to_bstr(Some(local_ports)))
                    .map_err(SetRuleError::LocalPorts)?;
            }
            if let Some(ref remote_ports) = rule.remote_ports {
                fw_rule
                    .SetRemotePorts(&convert_hashset_to_bstr(Some(remote_ports)))
                    .map_err(SetRuleError::RemotePorts)?;
            }
            if let Some(ref local_addresses) = rule.local_addresses {
                fw_rule
                    .SetLocalAddresses(&convert_hashset_to_bstr(Some(local_addresses)))
                    .map_err(SetRuleError::LocalAddresses)?;
            }
            if let Some(ref remote_addresses) = rule.remote_addresses {
                fw_rule
                    .SetRemoteAddresses(&convert_hashset_to_bstr(Some(remote_addresses)))
                    .map_err(SetRuleError::RemoteAddresses)?;
            }
            if let Some(ref icmp_types_and_codes) = rule.icmp_types_and_codes {
                fw_rule
                    .SetIcmpTypesAndCodes(&BSTR::from(icmp_types_and_codes))
                    .map_err(SetRuleError::IcmpTypesAndCodes)?;
            }
            if let Some(edge_traversal) = rule.edge_traversal {
                fw_rule
                    .SetEdgeTraversal(edge_traversal.into())
                    .map_err(SetRuleError::EdgeTraversal)?;
            }
            if let Some(ref grouping) = rule.grouping {
                fw_rule
                    .SetGrouping(&BSTR::from(grouping))
                    .map_err(SetRuleError::Grouping)?;
            }
            if let Some(ref interface) = rule.interfaces {
                fw_rule
                    .SetInterfaces(&hashset_to_variant(interface)?)
                    .map_err(SetRuleError::Interfaces)?;
            }
            if let Some(ref interface_types) = rule.interface_types {
                fw_rule
                    .SetInterfaceTypes(&convert_hashset_to_bstr(Some(interface_types)))
                    .map_err(SetRuleError::InterfaceTypes)?;
            }
            if let Some(profiles) = rule.profiles {
                fw_rule
                    .SetProfiles(profiles.into())
                    .map_err(SetRuleError::Profiles)?;
            }

            Ok(fw_rule)
        })
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

    /// The IP protocol used by the rule (e.g., TCP, UDP).
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
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| Some(to_string_hashset(items))))]
    pub(crate) interfaces: Option<HashSet<String>>,

    /// A set of interface types associated with the firewall rule (e.g., `Wireless`, `Lan`, `RemoteAccess`, or `All`).
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

impl From<WindowsFirewallRule> for WindowsFirewallRuleSettings {
    fn from(rule: WindowsFirewallRule) -> Self {
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
