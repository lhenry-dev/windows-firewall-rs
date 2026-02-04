use scopeguard::guard;
use std::convert::TryFrom;
use std::mem::ManuallyDrop;
use tracing::error;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_PROFILE_TYPE2, NetFwPolicy2,
};
use windows::Win32::System::Com::CoCreateInstance;
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

use crate::DirectionFirewallWindows;
use crate::constants::DWCLSCONTEXT;
use crate::errors::{SetRuleError, WindowsFirewallError};
use crate::firewall_enums::ProfileFirewallWindows;
use crate::firewall_rule::{WindowsFirewallRule, WindowsFirewallRuleSettings};
use crate::utils::{
    hashset_to_bstr, hashset_to_variant, is_not_icmp, is_not_tcp_or_udp, with_com_initialized,
};

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
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(name);
        let exist = fw_rules.Item(&rule_name).is_ok();
        Ok(exist)
    })
}

/// Retrieves the firewall rule with the specified name.
///
/// This function initializes COM, creates a firewall policy object, and attempts to retrieve
/// the firewall rule with the given name. If successful, it returns the rule as a [`WindowsFirewallRule`].
///
/// # Arguments
///
/// * `name` - A string slice representing the name of the firewall rule to retrieve.
///
/// # Returns
///
/// This function returns a [`Result<WindowsFirewallRule, WindowsFirewallError>`](WindowsFirewallRule). If the rule is found and
/// successfully converted, it returns `Ok(rule)`. In case of any error (e.g., COM initialization failure,
/// rule not found, or failure during conversion), it returns a [`WindowsFirewallError`].
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if there is a failure during:
/// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
/// - Fetching the firewall rule (e.g., rule not found).
/// - Converting the rule into the [`WindowsFirewallRule`] struct.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn get_rule(name: &str) -> Result<WindowsFirewallRule, WindowsFirewallError> {
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(name);
        let rule = fw_rules.Item(&rule_name);
        WindowsFirewallRule::try_from(rule?)
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
/// * `rule` - A [`WindowsFirewallRule`] struct representing the firewall rule to add.
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
pub fn add_rule(rule: &WindowsFirewallRule) -> Result<(), WindowsFirewallError> {
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;
        let new_rule: INetFwRule = rule.try_into()?;

        fw_rules.Add(&new_rule)?;

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
/// * `rule` - A [`WindowsFirewallRule`] struct representing the firewall rule to add.
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
pub fn add_rule_if_not_exists(rule: &WindowsFirewallRule) -> Result<bool, WindowsFirewallError> {
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule.name());
        let exist = fw_rules.Item(&rule_name).is_ok();

        if exist {
            return Ok(false);
        }

        let new_rule: INetFwRule = rule.try_into()?;

        fw_rules.Add(&new_rule)?;

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
/// * `rule` - A [`WindowsFirewallRule`] struct representing the firewall rule to add or update.
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
pub fn add_rule_or_update(rule: &WindowsFirewallRule) -> Result<bool, WindowsFirewallError> {
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule.name());
        let fw_rule_result = fw_rules.Item(&rule_name);

        if let Ok(existing_rule) = fw_rule_result {
            let settings = rule.clone().into();
            update_inetfw_rule(&existing_rule, &settings)?;
            return Ok(false);
        }

        let new_rule: INetFwRule = rule.try_into()?;
        fw_rules.Add(&new_rule)?;

        Ok(true)
    })
}

/// Updates an existing firewall rule with new settings.
///
/// This function initializes COM, creates a firewall policy object, and updates the specified rule
/// with new settings provided in the [`WindowsFirewallRuleSettings`]. The function updates various
/// properties of the rule, such as direction, action, name, and more.
///
/// # Arguments
///
/// * `rule_name` - A string slice representing the name of the firewall rule to update.
/// * `settings` - A [`WindowsFirewallRuleSettings`] struct containing the updated settings for the rule.
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
    settings: &WindowsFirewallRuleSettings,
) -> Result<(), WindowsFirewallError> {
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule_name);
        let rule = fw_rules.Item(&rule_name)?;

        update_inetfw_rule(&rule, settings)?;

        Ok(())
    })
}

fn update_inetfw_rule(
    rule: &INetFwRule,
    settings: &WindowsFirewallRuleSettings,
) -> Result<(), WindowsFirewallError> {
    if let Some(name) = &settings.name {
        unsafe { rule.SetName(&BSTR::from(name)).map_err(SetRuleError::Name) }?;
    }
    if let Some(direction) = settings.direction {
        if direction != DirectionFirewallWindows::In && (unsafe { rule.EdgeTraversal() }?.as_bool())
        {
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
        if is_not_tcp_or_udp(protocol) {
            let _ = unsafe { rule.SetLocalPorts(&BSTR::from("")) };
            let _ = unsafe { rule.SetRemotePorts(&BSTR::from("")) };
        }
        if is_not_icmp(protocol) {
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
                .map_err(SetRuleError::InterfaceTypes)
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
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule_name);
        let rule = fw_rules.Item(&rule_name)?;

        rule.SetEnabled(enabled.into())
            .map_err(SetRuleError::Enabled)?;

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
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule_name);
        fw_rules.Remove(&rule_name)?;

        Ok(())
    })
}

/// Retrieves all the firewall rules as a list of [`WindowsFirewallRule`] objects.
///
/// This function initializes COM, creates a firewall policy object, and enumerates through
/// all the firewall rules, converting them into [`WindowsFirewallRule`] structs and returning
/// them as a vector.
///
/// # Returns
///
/// This function returns a [`Result<Vec<WindowsFirewallRule>, WindowsFirewallError>`](WindowsFirewallRule). If the rules
/// are successfully retrieved, it returns `Ok(rules_list)`. In case of an error (e.g., COM initialization failure),
/// it returns a [`WindowsFirewallError`].
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if there is a failure during:
/// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
/// - Fetching the firewall rules.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn list_rules() -> Result<Vec<WindowsFirewallRule>, WindowsFirewallError> {
    let mut rules_list = Vec::new();

    with_com_initialized(|| {
        let fw_policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT) }?;
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;
        let rules_count = unsafe { fw_rules.Count() }?;

        let enumerator = unsafe { fw_rules._NewEnum() }?.cast::<IEnumVARIANT>()?;

        let mut variants: [VARIANT; 1] = Default::default();
        let mut pceltfetch: u32 = 0;

        for _ in 0..rules_count {
            let fetched = unsafe { enumerator.Next(&mut variants, &mut pceltfetch) };

            if fetched.is_err() {
                error!("Error while fetching rules");
                continue;
            }

            if let Some(variant) = variants.first() {
                let dispatch = unsafe { variant.Anonymous.Anonymous.Anonymous.pdispVal.clone() };

                let _dispatch_cleanup = guard(dispatch.clone(), |mut d| {
                    unsafe { ManuallyDrop::drop(&mut d) };
                });

                if let Some(dispatch) = dispatch.as_ref() {
                    let fw_rule = dispatch.cast::<INetFwRule>()?;

                    rules_list.push(fw_rule.try_into()?);
                }
            }
        }

        Ok(rules_list)
    })
}

/// Retrieves all incoming firewall rules as a list of [`WindowsFirewallRule`] objects.
///
/// This function filters the firewall rules to include only incoming rules.
/// It leverages [`list_rules()`] to get all rules and then applies a filter.
///
/// # Returns
///
/// This function returns a [`Result<Vec<WindowsFirewallRule>, WindowsFirewallError>`](WindowsFirewallRule).
/// If successful, it returns `Ok(incoming_rules)`, otherwise an error is returned.
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if [`list_rules()`] fails.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn list_incoming_rules() -> Result<Vec<WindowsFirewallRule>, WindowsFirewallError> {
    let all_rules = list_rules()?;
    let incoming_rules: Vec<WindowsFirewallRule> = all_rules
        .into_iter()
        .filter(|rule| *rule.direction() == DirectionFirewallWindows::In)
        .collect();

    Ok(incoming_rules)
}

/// Retrieves all outgoing firewall rules as a list of [`WindowsFirewallRule`] objects.
///
/// This function filters the firewall rules to include only outgoing rules.
/// It leverages [`list_rules()`] to get all rules and then applies a filter.
///
/// # Returns
///
/// This function returns a [`Result<Vec<WindowsFirewallRule>, WindowsFirewallError>`] .
/// If successful, it returns `Ok(outgoing_rules)`, otherwise an error is returned.
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if [`list_rules()`] fails.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn list_outgoing_rules() -> Result<Vec<WindowsFirewallRule>, WindowsFirewallError> {
    let all_rules = list_rules()?;
    let outgoing_rules: Vec<WindowsFirewallRule> = all_rules
        .into_iter()
        .filter(|rule| *rule.direction() == DirectionFirewallWindows::Out)
        .collect();

    Ok(outgoing_rules)
}

/// Retrieves the active firewall profile.
///
/// This function initializes COM, creates a firewall policy object, and retrieves the current
/// active firewall profile, returning it as a [`ProfileFirewallWindows`] object.
///
/// # Returns
///
/// This function returns a [`Result<ProfileFirewallWindows, WindowsFirewallError>`](ProfileFirewallWindows). If the active profile
/// is successfully retrieved, it returns [`Ok(profile)`](ProfileFirewallWindows). In case of an error (e.g., COM initialization failure),
/// it returns a [`WindowsFirewallError`].
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if there is a failure during:
/// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
/// - Fetching the active profile.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn get_active_profile() -> Result<ProfileFirewallWindows, WindowsFirewallError> {
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let active_profile = ProfileFirewallWindows::try_from(fw_policy.CurrentProfileTypes()?)?;

        Ok(active_profile)
    })
}

/// Retrieves the current state of the firewall for the specified profile.
///
/// This function initializes COM, creates a firewall policy object, and checks if the firewall
/// is enabled or disabled for the given profile. It returns `true` if the firewall is enabled,
/// and `false` otherwise.
///
/// # Arguments
///
/// * `profile` - A [`ProfileFirewallWindows`] enum value representing the firewall profile
///   (such as public, private, or domain) for which the state should be retrieved.
///
/// # Returns
///
/// This function returns a [`Result<bool, WindowsFirewallError>`](WindowsFirewallError). If the firewall state is successfully
/// retrieved, it returns `Ok(true)` for enabled or `Ok(false)` for disabled. If there is an error (e.g.,
/// COM initialization failure or inability to retrieve the firewall state), it returns a [`WindowsFirewallError`].
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if there is a failure during:
/// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
/// - Fetching the firewall state.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn get_firewall_state(profile: ProfileFirewallWindows) -> Result<bool, WindowsFirewallError> {
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let enabled = fw_policy
            .get_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile.into()))?
            .as_bool();

        Ok(enabled)
    })
}

/// Sets the firewall state (enabled or disabled) for the specified profile.
///
/// This function initializes COM, creates a firewall policy object, and enables or disables the firewall
/// for the given profile based on the provided state (`true` to enable, `false` to disable).
///
/// # Arguments
///
/// * `profile` - A [`ProfileFirewallWindows`] enum value representing the firewall profile
///   (such as public, private, or domain) for which the state should be set.
/// * `state` - A boolean value indicating the desired firewall state. `true` enables the firewall,
///   while `false` disables it.
///
/// # Returns
///
/// This function returns a [`Result<(), WindowsFirewallError>`](WindowsFirewallError). If the firewall state is successfully
/// set, it returns `Ok(())`. If there is an error (e.g., COM initialization failure or failure to set
/// the firewall state), it returns a [`WindowsFirewallError`].
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if there is a failure during:
/// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
/// - Setting the firewall state.
///
/// # Security
///
/// ⚠️ This function requires **administrative privileges**.
pub fn set_firewall_state(
    profile: ProfileFirewallWindows,
    state: bool,
) -> Result<(), WindowsFirewallError> {
    with_com_initialized(|| unsafe {
        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        fw_policy.put_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile.into()), state.into())?;
        Ok(())
    })
}
