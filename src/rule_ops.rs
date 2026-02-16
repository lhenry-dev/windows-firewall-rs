use std::convert::TryFrom;
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwRule, INetFwRules};
use windows::core::BSTR;

use crate::errors::{SetRuleError, WindowsFirewallError};
use crate::firewall_rule::{Direction, FirewallRule, FirewallRuleUpdate};
use crate::utils::{hashset_to_bstr, hashset_to_variant, with_policy};

/// Checks if a firewall rule with the given name exists.
///
/// This function initializes COM, creates a firewall policy object, and checks if a rule
/// with the specified name exists in the Windows Firewall rules list.
///
/// # Arguments
///
/// * `name` - A string slice representing the name of the firewall rule to check.
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
pub fn rule_exists(name: &str) -> Result<bool, WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;

        let rule_name = BSTR::from(name);
        let exist = unsafe { fw_rules.Item(&rule_name).is_ok() };
        Ok(exist)
    })
}

/// Retrieves the firewall rule with the specified name.
///
/// This function initializes COM, creates a firewall policy object, and attempts to retrieve
/// the firewall rule with the given name. If successful, it returns the rule as a [`FirewallRule`].
///
/// # Arguments
///
/// * `name` - A string slice representing the name of the firewall rule to retrieve.
///
/// # Returns
///
/// This function returns a [`Result<FirewallRule, WindowsFirewallError>`](FirewallRule). If the rule is found and
/// successfully converted, it returns `Ok(rule)`. In case of any error (e.g., COM initialization failure,
/// rule not found, or failure during conversion), it returns a [`WindowsFirewallError`].
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if there is a failure during:
/// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
/// - Fetching the firewall rule (e.g., rule not found).
/// - Converting the rule into the [`FirewallRule`] struct.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn get_rule(name: &str) -> Result<FirewallRule, WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;

        let rule_name = BSTR::from(name);
        let rule = unsafe { fw_rules.Item(&rule_name) };
        FirewallRule::try_from(rule?)
    })
}

/// Enables or disables an existing firewall rule.
///
/// This function initializes COM, retrieves the firewall policy object,
/// and sets the enabled state of the specified firewall rule.
///
/// # Arguments
///
/// * `rule_name` - A string slice representing the name of the firewall rule to modify.
/// * `enabled` - A boolean indicating whether to enable (`true`) or disable (`false`) the rule.
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
pub fn enable_rule(rule_name: &str, enabled: bool) -> Result<(), WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;

        let rule_name = BSTR::from(rule_name);
        let rule = unsafe { fw_rules.Item(&rule_name) }?;

        unsafe {
            rule.SetEnabled(enabled.into())
                .map_err(SetRuleError::Enabled)
        }?;

        Ok(())
    })
}

/// Removes the specified firewall rule from the system.
///
/// This function initializes COM, creates a firewall policy object, and removes the firewall rule
/// with the given name from the list of active rules.
///
/// # Arguments
///
/// * `rule_name` - A string slice representing the name of the firewall rule to remove.
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
pub fn remove_rule(rule_name: &str) -> Result<(), WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;

        let rule_name = BSTR::from(rule_name);
        unsafe { fw_rules.Remove(&rule_name) }?;

        Ok(())
    })
}

/// Adds a new firewall rule to the system.
///
/// This function initializes COM, creates a firewall policy object, and adds a new rule
/// to the Windows Firewall. The provided rule is converted into an `INetFwRule` object
/// and added to the existing rules list.
///
/// # Arguments
///
/// * `rule` - A [`FirewallRule`] struct representing the firewall rule to add.
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
pub fn add_rule(rule: &FirewallRule) -> Result<(), WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;
        let new_rule: INetFwRule = rule.try_into()?;

        unsafe { fw_rules.Add(&new_rule) }?;

        Ok(())
    })
}

/// Adds a new firewall rule to the system only if a rule with the same name doesn't exist.
///
/// This function first checks if a rule with the given name exists, and if not,
/// adds the new rule to the Windows Firewall.
///
/// # Arguments
///
/// * `rule` - A [`FirewallRule`] struct representing the firewall rule to add.
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
pub fn add_rule_if_not_exists(rule: &FirewallRule) -> Result<bool, WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;

        let rule_name = BSTR::from(rule.name());
        let exist = unsafe { fw_rules.Item(&rule_name) }.is_ok();

        if exist {
            return Ok(false);
        }

        let new_rule: INetFwRule = rule.try_into()?;

        unsafe { fw_rules.Add(&new_rule) }?;

        Ok(true)
    })
}

/// Adds a new firewall rule to the system or updates an existing rule with the same name.
///
/// This function first checks if a rule with the given name exists. If it does, the function updates
/// the existing rule with the new settings. If the rule does not exist, it adds a new rule to the
/// Windows Firewall.
///
/// # Arguments
///
/// * `rule` - A [`FirewallRule`] struct representing the firewall rule to add or update.
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
pub fn add_rule_or_update(rule: &FirewallRule) -> Result<bool, WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;

        let rule_name = BSTR::from(rule.name());
        let fw_rule_result = unsafe { fw_rules.Item(&rule_name) };

        if let Ok(existing_rule) = fw_rule_result {
            let settings = rule.clone().into();
            update_inetfw_rule(&existing_rule, &settings)?;
            return Ok(false);
        }

        let new_rule: INetFwRule = rule.try_into()?;
        unsafe { fw_rules.Add(&new_rule) }?;

        Ok(true)
    })
}

/// Updates an existing firewall rule with new settings.
///
/// This function initializes COM, creates a firewall policy object, and updates the specified rule
/// with new settings provided in the [`FirewallRuleUpdate`]. The function updates various
/// properties of the rule, such as direction, action, name, and more.
///
/// # Arguments
///
/// * `rule_name` - A string slice representing the name of the firewall rule to update.
/// * `settings` - A [`FirewallRuleUpdate`] struct containing the updated settings for the rule.
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
pub fn update_rule(
    rule_name: &str,
    settings: &FirewallRuleUpdate,
) -> Result<(), WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;

        let rule_name = BSTR::from(rule_name);
        let rule = unsafe { fw_rules.Item(&rule_name) }?;

        update_inetfw_rule(&rule, settings)?;

        Ok(())
    })
}

fn update_inetfw_rule(
    rule: &INetFwRule,
    settings: &FirewallRuleUpdate,
) -> Result<(), WindowsFirewallError> {
    if let Some(name) = &settings.name {
        unsafe { rule.SetName(&BSTR::from(name)).map_err(SetRuleError::Name) }?;
    }
    if let Some(direction) = settings.direction {
        if direction != Direction::In && (unsafe { rule.EdgeTraversal() }?.as_bool()) {
            unsafe {
                rule.SetEdgeTraversal(false.into())
                    .map_err(SetRuleError::EdgeTraversal)
            }?;
        }

        unsafe {
            rule.SetDirection(direction.into())
                .map_err(SetRuleError::Direction)
        }?;
    }
    if let Some(enabled) = settings.enabled {
        unsafe {
            rule.SetEnabled(enabled.into())
                .map_err(SetRuleError::Enabled)
        }?;
    }
    if let Some(action) = settings.action {
        unsafe { rule.SetAction(action.into()).map_err(SetRuleError::Action) }?;
    }
    if let Some(description) = &settings.description {
        unsafe {
            rule.SetDescription(&BSTR::from(description))
                .map_err(SetRuleError::Description)
        }?;
    }
    if let Some(application_name) = &settings.application_name {
        unsafe {
            rule.SetApplicationName(&BSTR::from(application_name))
                .map_err(SetRuleError::ApplicationName)
        }?;
    }
    if let Some(service_name) = &settings.service_name {
        unsafe {
            rule.SetServiceName(&BSTR::from(service_name))
                .map_err(SetRuleError::ServiceName)
        }?;
    }
    if let Some(protocol) = settings.protocol {
        if !protocol.is_tcp_or_udp() {
            let _ = unsafe { rule.SetLocalPorts(&BSTR::from("")) };
            let _ = unsafe { rule.SetRemotePorts(&BSTR::from("")) };
        }
        if !protocol.is_icmp() {
            let _ = unsafe { rule.SetIcmpTypesAndCodes(&BSTR::from("")) };
        }
        unsafe {
            rule.SetProtocol(protocol.into())
                .map_err(SetRuleError::Protocol)
        }?;
    }
    if let Some(local_ports) = &settings.local_ports {
        unsafe {
            rule.SetLocalPorts(&hashset_to_bstr(Some(local_ports)))
                .map_err(SetRuleError::LocalPorts)
        }?;
    }
    if let Some(remote_ports) = &settings.remote_ports {
        unsafe {
            rule.SetRemotePorts(&hashset_to_bstr(Some(remote_ports)))
                .map_err(SetRuleError::RemotePorts)
        }?;
    }
    if let Some(local_addresses) = &settings.local_addresses {
        unsafe {
            rule.SetLocalAddresses(&hashset_to_bstr(Some(local_addresses)))
                .map_err(SetRuleError::LocalAddresses)
        }?;
    }
    if let Some(remote_addresses) = &settings.remote_addresses {
        unsafe {
            rule.SetRemoteAddresses(&hashset_to_bstr(Some(remote_addresses)))
                .map_err(SetRuleError::RemoteAddresses)
        }?;
    }
    if let Some(icmp_types_and_codes) = &settings.icmp_types_and_codes {
        unsafe {
            rule.SetIcmpTypesAndCodes(&BSTR::from(icmp_types_and_codes))
                .map_err(SetRuleError::IcmpTypesAndCodes)
        }?;
    }
    if let Some(edge_traversal) = settings.edge_traversal {
        unsafe {
            rule.SetEdgeTraversal(edge_traversal.into())
                .map_err(SetRuleError::EdgeTraversal)
        }?;
    }
    if let Some(grouping) = &settings.grouping {
        unsafe {
            rule.SetGrouping(&BSTR::from(grouping))
                .map_err(SetRuleError::Grouping)
        }?;
    }
    if let Some(interfaces) = &settings.interfaces {
        unsafe {
            rule.SetInterfaces(&hashset_to_variant(interfaces)?)
                .map_err(SetRuleError::Interfaces)
        }?;
    }
    if let Some(interface_types) = &settings.interface_types {
        unsafe {
            rule.SetInterfaceTypes(&hashset_to_bstr(Some(interface_types)))
                .map_err(SetRuleError::InterfaceType)
        }?;
    }
    if let Some(profiles) = settings.profiles {
        unsafe {
            rule.SetProfiles(profiles.into())
                .map_err(SetRuleError::Profiles)
        }?;
    }

    Ok(())
}
