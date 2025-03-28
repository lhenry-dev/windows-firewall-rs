use scopeguard::guard;
use std::convert::TryFrom;
use std::mem::ManuallyDrop;
use tracing::error;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_PROFILE_TYPE2, NetFwPolicy2,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CoUninitialize};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

use crate::constants::{DWCLSCONTEXT, DWCOINIT};
use crate::errors::WindowsFirewallError;
use crate::firewall_enums::ProfileFirewallWindows;
use crate::firewall_rule::{WindowsFirewallRule, WindowsFirewallRuleSettings};
use crate::utils::{convert_hashset_to_bstr, hashset_to_variant};
use crate::{DirectionFirewallWindows, ProtocolFirewallWindows};

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
pub fn rule_exists(name: &str) -> Result<bool, WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(name);
        let exist = fw_rules.Item(&rule_name).is_ok();
        Ok(exist)
    }
}

/// Retrieves the firewall rule with the specified name.
///
/// This function initializes COM, creates a firewall policy object, and attempts to retrieve
/// the firewall rule with the given name. If successful, it returns the rule as a `WindowsFirewallRule`.
///
/// # Arguments
///
/// * `name` - A string slice representing the name of the firewall rule to retrieve.
///
/// # Returns
///
/// This function returns a `Result<WindowsFirewallRule, WindowsFirewallError>`. If the rule is found and
/// successfully converted, it returns `Ok(rule)`. In case of any error (e.g., COM initialization failure,
/// rule not found, or failure during conversion), it returns a `WindowsFirewallError`.
///
/// # Errors
///
/// This function may return a `WindowsFirewallError` if there is a failure during:
/// - COM initialization (`CoInitializeExFailed`).
/// - Fetching the firewall rule (e.g., rule not found).
/// - Converting the rule into the `WindowsFirewallRule` struct.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn get_rule(name: &str) -> Result<WindowsFirewallRule, WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(name);
        let rule = fw_rules.Item(&rule_name);
        WindowsFirewallRule::try_from(rule?)
    }
}

/// Adds a new firewall rule to the system.
///
/// This function initializes COM, creates a firewall policy object, and adds a new rule
/// to the Windows Firewall. The provided rule is converted into an `INetFwRule` object
/// and added to the existing rules list.
///
/// # Arguments
///
/// * `rule` - A `WindowsFirewallRule` struct representing the firewall rule to add.
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
pub fn add_rule(rule: WindowsFirewallRule) -> Result<(), WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;
        let new_rule: INetFwRule = rule.try_into()?;

        fw_rules.Add(&new_rule)?;

        Ok(())
    }
}

/// Adds a new firewall rule to the system only if a rule with the same name doesn't exist.
///
/// This function first checks if a rule with the given name exists, and if not,
/// adds the new rule to the Windows Firewall.
///
/// # Arguments
///
/// * `rule` - A `WindowsFirewallRule` struct representing the firewall rule to add.
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
pub fn add_rule_if_not_exists(rule: WindowsFirewallRule) -> Result<bool, WindowsFirewallError> {
    let rule_name = rule.name();

    if rule_exists(rule_name)? {
        Ok(false)
    } else {
        add_rule(rule)?;
        Ok(true)
    }
}

/// Updates an existing firewall rule with new settings.
///
/// This function initializes COM, creates a firewall policy object, and updates the specified rule
/// with new settings provided in the `WindowsFirewallRuleSettings`. The function updates various
/// properties of the rule, such as direction, action, name, and more.
///
/// # Arguments
///
/// * `rule_name` - A string slice representing the name of the firewall rule to update.
/// * `settings` - A `WindowsFirewallRuleSettings` struct containing the updated settings for the rule.
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
pub fn update_rule(
    rule_name: &str,
    settings: WindowsFirewallRuleSettings,
) -> Result<(), WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule_name);
        let rule = fw_rules.Item(&rule_name)?;

        let is_icmp = matches!(
            &settings.protocol,
            Some(ProtocolFirewallWindows::Icmpv4) | Some(ProtocolFirewallWindows::Icmpv6)
        );

        if let Some(name) = settings.name {
            rule.SetName(&BSTR::from(name))?;
        }
        if let Some(direction) = settings.direction {
            rule.SetDirection(direction.into())?;
        }
        if let Some(enabled) = settings.enabled {
            rule.SetEnabled(enabled.into())?;
        }
        if let Some(action) = settings.action {
            rule.SetAction(action.into())?;
        }
        if let Some(description) = settings.description {
            rule.SetDescription(&BSTR::from(description))?;
        }
        if let Some(application_name) = settings.application_name {
            rule.SetApplicationName(&BSTR::from(application_name))?;
        }
        if let Some(service_name) = settings.service_name {
            rule.SetServiceName(&BSTR::from(service_name))?;
        }
        if let Some(protocol) = settings.protocol {
            if is_icmp {
                rule.SetLocalPorts(&BSTR::from(""))?;
                rule.SetRemotePorts(&BSTR::from(""))?;
            }
            rule.SetProtocol(protocol.into())?;
        }
        if let Some(local_ports) = settings.local_ports {
            rule.SetLocalPorts(&convert_hashset_to_bstr(Some(local_ports)))?;
        }
        if let Some(remote_ports) = settings.remote_ports {
            rule.SetRemotePorts(&convert_hashset_to_bstr(Some(remote_ports)))?;
        }
        if let Some(local_addresses) = settings.local_addresses {
            rule.SetLocalAddresses(&convert_hashset_to_bstr(Some(local_addresses)))?;
        }
        if let Some(remote_addresses) = settings.remote_addresses {
            rule.SetRemoteAddresses(&convert_hashset_to_bstr(Some(remote_addresses)))?;
        }
        if let Some(icmp_types_and_codes) = settings.icmp_types_and_codes {
            rule.SetIcmpTypesAndCodes(&BSTR::from(icmp_types_and_codes))?;
        }
        if let Some(edge_traversal) = settings.edge_traversal {
            rule.SetEdgeTraversal(edge_traversal.into())?;
        }
        if let Some(grouping) = settings.grouping {
            rule.SetGrouping(&BSTR::from(grouping))?;
        }
        if let Some(interfaces) = settings.interfaces {
            rule.SetInterfaces(&hashset_to_variant(&interfaces)?)?;
        }
        if let Some(interface_types) = settings.interface_types {
            rule.SetInterfaceTypes(&convert_hashset_to_bstr(Some(interface_types)))?;
        }
        if let Some(profiles) = settings.profiles {
            rule.SetProfiles(profiles.into())?;
        }

        Ok(())
    }
}

/// Disables an existing firewall rule.
///
/// This function initializes COM, retrieves the firewall policy object,
/// and disables the specified firewall rule.
///
/// # Arguments
///
/// * `rule_name` - A string slice representing the name of the firewall rule to disable.
///
/// # Returns
///
/// This function returns a `Result<(), WindowsFirewallError>`. If the rule is disabled successfully,
/// it returns `Ok(())`. If an error occurs (e.g., COM initialization failure, rule not found),
/// it returns a `WindowsFirewallError`.
///
/// # Errors
///
/// This function may return a `WindowsFirewallError` if there is a failure during:
/// - COM initialization (`CoInitializeExFailed`).
/// - Fetching the rule.
/// - Disabling the rule.
///
/// # Security
///
/// This function requires administrative privileges.
pub fn disable_rule(rule_name: &str) -> Result<(), WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule_name);
        let rule = fw_rules.Item(&rule_name)?;

        rule.SetEnabled(false.into())?;

        Ok(())
    }
}

/// Enables an existing firewall rule.
///
/// This function initializes COM, retrieves the firewall policy object,
/// and enables the specified firewall rule.
///
/// # Arguments
///
/// * `rule_name` - A string slice representing the name of the firewall rule to enable.
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
pub fn enable_rule(rule_name: &str) -> Result<(), WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule_name);
        let rule = fw_rules.Item(&rule_name)?;

        rule.SetEnabled(true.into())?;

        Ok(())
    }
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
pub fn remove_rule(rule_name: &str) -> Result<(), WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;

        let rule_name = BSTR::from(rule_name);
        fw_rules.Remove(&rule_name)?;

        Ok(())
    }
}

/// Retrieves all the firewall rules as a list of `WindowsFirewallRule` objects.
///
/// This function initializes COM, creates a firewall policy object, and enumerates through
/// all the firewall rules, converting them into `WindowsFirewallRule` structs and returning
/// them as a vector.
///
/// # Returns
///
/// This function returns a `Result<Vec<WindowsFirewallRule>, WindowsFirewallError>`. If the rules
/// are successfully retrieved, it returns `Ok(rules_list)`. In case of an error (e.g., COM initialization failure),
/// it returns a `WindowsFirewallError`.
///
/// # Errors
///
/// This function may return a `WindowsFirewallError` if there is a failure during:
/// - COM initialization (`CoInitializeExFailed`).
/// - Fetching the firewall rules.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn list_rules() -> Result<Vec<WindowsFirewallRule>, WindowsFirewallError> {
    let mut rules_list = Vec::new();

    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;
        let fw_rules: INetFwRules = fw_policy.Rules()?;
        let rules_count = fw_rules.Count()?;

        let enumerator = fw_rules._NewEnum()?.cast::<IEnumVARIANT>()?;

        let mut variants: [VARIANT; 1] = Default::default();
        let mut pceltfetch: u32 = 0;

        for _ in 0..rules_count {
            let fetched = enumerator.Next(&mut variants, &mut pceltfetch);

            if fetched.is_err() {
                error!("Error while fetching rules");
                continue;
            };

            if let Some(variant) = variants.first() {
                let dispatch = variant.Anonymous.Anonymous.Anonymous.pdispVal.clone();

                let _dispatch_cleanup = guard(dispatch.clone(), |mut d| {
                    ManuallyDrop::drop(&mut d);
                });

                if let Some(dispatch) = dispatch.as_ref() {
                    let fw_rule = dispatch.cast::<INetFwRule>()?;

                    rules_list.push(fw_rule.try_into()?);
                }
            }
        }

        Ok(rules_list)
    }
}

/// Retrieves all incoming firewall rules as a list of `WindowsFirewallRule` objects.
///
/// This function filters the firewall rules to include only incoming rules.
/// It leverages `list_rules()` to get all rules and then applies a filter.
///
/// # Returns
///
/// This function returns a `Result<Vec<WindowsFirewallRule>, WindowsFirewallError>`.
/// If successful, it returns `Ok(incoming_rules)`, otherwise an error is returned.
///
/// # Errors
///
/// This function may return a `WindowsFirewallError` if `list_rules()` fails.
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

/// Retrieves all outgoing firewall rules as a list of `WindowsFirewallRule` objects.
///
/// This function filters the firewall rules to include only outgoing rules.
/// It leverages `list_rules()` to get all rules and then applies a filter.
///
/// # Returns
///
/// This function returns a `Result<Vec<WindowsFirewallRule>, WindowsFirewallError>`.
/// If successful, it returns `Ok(outgoing_rules)`, otherwise an error is returned.
///
/// # Errors
///
/// This function may return a `WindowsFirewallError` if `list_rules()` fails.
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
/// active firewall profile, returning it as a `ProfileFirewallWindows` object.
///
/// # Returns
///
/// This function returns a `Result<ProfileFirewallWindows, WindowsFirewallError>`. If the active profile
/// is successfully retrieved, it returns `Ok(profile)`. In case of an error (e.g., COM initialization failure),
/// it returns a `WindowsFirewallError`.
///
/// # Errors
///
/// This function may return a `WindowsFirewallError` if there is a failure during:
/// - COM initialization (`CoInitializeExFailed`).
/// - Fetching the active profile.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn get_active_profile() -> Result<ProfileFirewallWindows, WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let active_profile = ProfileFirewallWindows::try_from(fw_policy.CurrentProfileTypes()?)?;

        Ok(active_profile)
    }
}

/// Retrieves the current state of the firewall for the specified profile.
///
/// This function initializes COM, creates a firewall policy object, and checks if the firewall
/// is enabled or disabled for the given profile. It returns `true` if the firewall is enabled,
/// and `false` otherwise.
///
/// # Arguments
///
/// * `profile` - A `ProfileFirewallWindows` enum value representing the firewall profile
///   (such as public, private, or domain) for which the state should be retrieved.
///
/// # Returns
///
/// This function returns a `Result<bool, WindowsFirewallError>`. If the firewall state is successfully
/// retrieved, it returns `Ok(true)` for enabled or `Ok(false)` for disabled. If there is an error (e.g.,
/// COM initialization failure or inability to retrieve the firewall state), it returns a `WindowsFirewallError`.
///
/// # Errors
///
/// This function may return a `WindowsFirewallError` if there is a failure during:
/// - COM initialization (`CoInitializeExFailed`).
/// - Fetching the firewall state.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn get_firewall_state(profile: ProfileFirewallWindows) -> Result<bool, WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        let enabled = fw_policy
            .get_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile.into()))?
            .as_bool();

        Ok(enabled)
    }
}

/// Sets the firewall state (enabled or disabled) for the specified profile.
///
/// This function initializes COM, creates a firewall policy object, and enables or disables the firewall
/// for the given profile based on the provided state (`true` to enable, `false` to disable).
///
/// # Arguments
///
/// * `profile` - A `ProfileFirewallWindows` enum value representing the firewall profile
///   (such as public, private, or domain) for which the state should be set.
/// * `state` - A boolean value indicating the desired firewall state. `true` enables the firewall,
///   while `false` disables it.
///
/// # Returns
///
/// This function returns a `Result<(), WindowsFirewallError>`. If the firewall state is successfully
/// set, it returns `Ok(())`. If there is an error (e.g., COM initialization failure or failure to set
/// the firewall state), it returns a `WindowsFirewallError`.
///
/// # Errors
///
/// This function may return a `WindowsFirewallError` if there is a failure during:
/// - COM initialization (`CoInitializeExFailed`).
/// - Setting the firewall state.
///
/// # Security
///
/// This function requires administrative privileges.
pub fn set_firewall_state(
    profile: ProfileFirewallWindows,
    state: bool,
) -> Result<(), WindowsFirewallError> {
    unsafe {
        let hr_com_init = CoInitializeEx(None, DWCOINIT);
        if hr_com_init.is_err() {
            return Err(WindowsFirewallError::CoInitializeExFailed(
                hr_com_init.message(),
            ));
        }

        let _com_cleanup = guard((), |_| CoUninitialize());

        let fw_policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT)?;

        fw_policy.put_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile.into()), state.into())?;

        Ok(())
    }
}
