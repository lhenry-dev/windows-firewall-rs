use getset::{Getters, Setters};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::IpAddr;
use typed_builder::TypedBuilder;
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwRule, NetFwRule};
use windows::Win32::System::Com::CoCreateInstance;
use windows::core::BSTR;

use crate::constants::DWCLSCONTEXT;
use crate::errors::{SetRuleError, WindowsFirewallError};
use crate::firewall_enums::{
    ActionFirewallWindows, DirectionFirewallWindows, ProfileFirewallWindows,
    ProtocolFirewallWindows,
};
use crate::utils::{
    bstr_to_hashset, hashset_to_bstr, hashset_to_variant, is_not_icmp, is_not_tcp_or_udp,
    to_string_hashset, variant_to_hashset, with_com_initialized,
};
use crate::windows_firewall::{add_rule_or_update, remove_rule, rule_exists, update_rule};
use crate::{InterfaceTypes, add_rule, add_rule_if_not_exists, enable_rule};

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
#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct WindowsFirewallRule {
    /// The user-friendly name of the rule. It must not contain the "|" character and cannot be "all".
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    name: String,
    /// The direction of the traffic this rule applies to (e.g., inbound or outbound).
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    direction: DirectionFirewallWindows,
    /// Indicates whether the rule is enabled (active) or disabled.
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    enabled: bool,
    /// The action to take when the rule conditions are met (e.g., allow or block).
    #[builder(setter(into))]
    #[getset(get = "pub", set = "pub")]
    action: ActionFirewallWindows,
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
    protocol: Option<ProtocolFirewallWindows>,
    /// A set of local ports this rule applies to. For example, specify ports like 80 or 443.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    local_ports: Option<HashSet<u16>>,
    /// A set of remote ports this rule applies to.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    remote_ports: Option<HashSet<u16>>,
    /// A set of local IP addresses this rule applies to. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = IpAddr>| Some(items.into_iter().collect())))]
    #[getset(get = "pub", set = "pub")]
    local_addresses: Option<HashSet<IpAddr>>,
    /// A set of remote IP addresses this rule applies to. IPv4 and IPv6 addresses are supported.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = IpAddr>| Some(items.into_iter().collect())))]
    #[getset(get = "pub", set = "pub")]
    remote_addresses: Option<HashSet<IpAddr>>,
    /// A list of ICMP types and codes this rule applies to, relevant for ICMP protocol rules.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    icmp_types_and_codes: Option<String>,
    /// A list of network interfaces this rule applies to, identified by their friendly names.
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = impl Into<String>>| Some(to_string_hashset(items))))]
    #[getset(get = "pub", set = "pub")]
    interfaces: Option<HashSet<String>>,
    /// A list of interface types this rule applies to (e.g., `Wireless`, `Lan`, `RemoteAccess`, or `All`).
    #[builder(default, setter(transform = |items: impl IntoIterator<Item = InterfaceTypes>| Some(items.into_iter().collect())))]
    #[getset(get = "pub", set = "pub")]
    interface_types: Option<HashSet<InterfaceTypes>>,
    /// The group name this rule belongs to, used for organizing rules.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    grouping: Option<String>,
    /// The profiles this rule is associated with (e.g., Domain, Private, Public).
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    profiles: Option<ProfileFirewallWindows>,
    /// Indicates whether edge traversal is enabled, allowing traffic to bypass NAT devices.
    #[builder(default, setter(strip_option, into))]
    #[getset(get = "pub", set = "pub")]
    edge_traversal: Option<bool>,
}

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
        add_rule_or_update(self)
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
            self.name = name.clone();
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
            self.description = Some(description.clone());
        }
        if let Some(application_name) = &settings.application_name {
            self.application_name = Some(application_name.clone());
        }
        if let Some(service_name) = &settings.service_name {
            self.service_name = Some(service_name.clone());
        }
        if let Some(protocol) = &settings.protocol {
            if is_not_tcp_or_udp(*protocol) {
                self.local_ports = None;
                self.remote_ports = None;
            }
            if is_not_icmp(*protocol) {
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
            self.icmp_types_and_codes = Some(icmp_types_and_codes.clone());
        }
        if let Some(interfaces) = &settings.interfaces {
            self.interfaces = Some(interfaces.clone());
        }
        if let Some(interface_types) = &settings.interface_types {
            self.interface_types = Some(interface_types.clone());
        }
        if let Some(grouping) = &settings.grouping {
            self.grouping = Some(grouping.clone());
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
                description: fw_rule
                    .Description()
                    .ok()
                    .map(|bstr| bstr.to_string())
                    .filter(|s| !s.is_empty()),
                application_name: fw_rule
                    .ApplicationName()
                    .ok()
                    .map(|bstr| bstr.to_string())
                    .filter(|s| !s.is_empty()),
                service_name: fw_rule
                    .ServiceName()
                    .ok()
                    .map(|bstr| bstr.to_string())
                    .filter(|s| !s.is_empty()),
                protocol: fw_rule.Protocol()?.try_into().ok(),
                local_ports: bstr_to_hashset(fw_rule.LocalPorts()),
                remote_ports: bstr_to_hashset(fw_rule.RemotePorts()),
                local_addresses: bstr_to_hashset(fw_rule.LocalAddresses()),
                remote_addresses: bstr_to_hashset(fw_rule.RemoteAddresses()),
                icmp_types_and_codes: fw_rule
                    .IcmpTypesAndCodes()
                    .ok()
                    .map(|bstr| bstr.to_string())
                    .filter(|s| !s.is_empty()),
                interfaces: Some(variant_to_hashset(&fw_rule.Interfaces()?)?),
                interface_types: bstr_to_hashset(fw_rule.InterfaceTypes()),
                grouping: fw_rule
                    .Grouping()
                    .ok()
                    .map(|bstr| bstr.to_string())
                    .filter(|s| !s.is_empty()),
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
                    .SetLocalPorts(&hashset_to_bstr(Some(local_ports)))
                    .map_err(SetRuleError::LocalPorts)?;
            }
            if let Some(ref remote_ports) = rule.remote_ports {
                fw_rule
                    .SetRemotePorts(&hashset_to_bstr(Some(remote_ports)))
                    .map_err(SetRuleError::RemotePorts)?;
            }
            if let Some(ref local_addresses) = rule.local_addresses {
                fw_rule
                    .SetLocalAddresses(&hashset_to_bstr(Some(local_addresses)))
                    .map_err(SetRuleError::LocalAddresses)?;
            }
            if let Some(ref remote_addresses) = rule.remote_addresses {
                fw_rule
                    .SetRemoteAddresses(&hashset_to_bstr(Some(remote_addresses)))
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
                    .SetInterfaceTypes(&hashset_to_bstr(Some(interface_types)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_windows_firewall_rule_setters() {
        let mut rule = WindowsFirewallRule::builder()
            .name("test")
            .action(ActionFirewallWindows::Block)
            .direction(DirectionFirewallWindows::Out)
            .enabled(false)
            .build();

        rule.set_name("new_name".to_string());
        assert_eq!(rule.name(), "new_name");

        rule.set_direction(DirectionFirewallWindows::In);
        assert_eq!(rule.direction(), &DirectionFirewallWindows::In);

        rule.set_enabled(true);
        assert!(rule.enabled());

        rule.set_action(ActionFirewallWindows::Allow);
        assert_eq!(rule.action(), &ActionFirewallWindows::Allow);

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

        rule.set_protocol(Some(ProtocolFirewallWindows::Tcp));
        assert_eq!(*rule.protocol(), Some(ProtocolFirewallWindows::Tcp));
        rule.set_protocol(None);
        assert_eq!(*rule.protocol(), None);

        let mut ports = HashSet::new();
        ports.insert(80);
        rule.set_local_ports(Some(ports.clone()));
        assert_eq!(*rule.local_ports(), Some(ports));
        rule.set_local_ports(None);
        assert_eq!(*rule.local_ports(), None);

        let mut rports = HashSet::new();
        rports.insert(443);
        rule.set_remote_ports(Some(rports.clone()));
        assert_eq!(*rule.remote_ports(), Some(rports));
        rule.set_remote_ports(None);
        assert_eq!(*rule.remote_ports(), None);

        let mut addrs = HashSet::new();
        addrs.insert(IpAddr::from_str("127.0.0.1").unwrap());
        rule.set_local_addresses(Some(addrs.clone()));
        assert_eq!(*rule.local_addresses(), Some(addrs));
        rule.set_local_addresses(None);
        assert_eq!(*rule.local_addresses(), None);

        let mut raddrs = HashSet::new();
        raddrs.insert(IpAddr::from_str("8.8.8.8").unwrap());
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
        iftypes.insert(InterfaceTypes::Lan);
        rule.set_interface_types(Some(iftypes.clone()));
        assert_eq!(*rule.interface_types(), Some(iftypes));
        rule.set_interface_types(None);
        assert_eq!(*rule.interface_types(), None);

        let group = Some("group".to_string());
        rule.set_grouping(group);
        assert_eq!(*rule.grouping(), Some("group".to_string()));
        rule.set_grouping(None);
        assert_eq!(*rule.grouping(), None);

        rule.set_profiles(Some(ProfileFirewallWindows::Private));
        assert_eq!(*rule.profiles(), Some(ProfileFirewallWindows::Private));
        rule.set_profiles(None);
        assert_eq!(*rule.profiles(), None);

        rule.set_edge_traversal(Some(true));
        assert_eq!(*rule.edge_traversal(), Some(true));
        rule.set_edge_traversal(None);
        assert_eq!(*rule.edge_traversal(), None);
    }
}
