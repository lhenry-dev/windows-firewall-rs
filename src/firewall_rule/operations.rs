use crate::errors::WindowsFirewallError;
use crate::{
    FirewallRule, FirewallRuleUpdate, add_rule, add_rule_if_not_exists, add_rule_or_update,
    enable_rule, remove_rule, rule_exists, update_rule,
};

impl FirewallRule {
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
    /// This function does not take any arguments, as it operates on the current instance's [`name`](FirewallRule::name) field.
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
    /// This function modifies an existing firewall rule based on the provided [`settings`](FirewallRuleUpdate).
    /// It updates various properties such as name, direction, action, protocol, and addresses.
    /// If the protocol is ICMP (IPv4 or IPv6), the function ensures that local and remote ports
    /// are cleared, as they are not applicable to ICMP.
    ///
    /// # Arguments
    ///
    /// * `settings` - A reference to a [`FirewallRuleUpdate`] struct containing the new
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
    pub fn update(&mut self, settings: &FirewallRuleUpdate) -> Result<(), WindowsFirewallError> {
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
            if !protocol.is_tcp_or_udp() {
                self.local_ports = None;
                self.remote_ports = None;
            }
            if !protocol.is_icmp() {
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
    /// This function does not take any arguments, as it operates on the current instance's [`name`](FirewallRule::name) field.
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
