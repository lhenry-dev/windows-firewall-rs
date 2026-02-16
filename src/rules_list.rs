use scopeguard::guard;
use std::mem::ManuallyDrop;
use tracing::warn;
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwRule, INetFwRules};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

use crate::errors::WindowsFirewallError;
use crate::firewall_rule::{Direction, FirewallRule};
use crate::utils::with_policy;

/// Retrieves the total number of firewall rules.
///
/// This function initializes COM, creates a firewall policy object, and fetches
/// the total count of firewall rules.
///
/// # Returns
///
/// Returns a [`Result<i32, WindowsFirewallError>`](WindowsFirewallError) with the
/// number of firewall rules if successful. In case of an error (e.g., COM initialization failure),
/// it returns a [`WindowsFirewallError`].
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if there is a failure during:
/// - COM initialization [`WindowsFirewallError::CoInitializeExFailed`].
/// - Fetching the firewall rules count.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn count_rules() -> Result<i32, WindowsFirewallError> {
    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;
        let rules_count = unsafe { fw_rules.Count()? };
        Ok(rules_count)
    })
}

/// Retrieves all the firewall rules as a list of [`FirewallRule`] objects.
///
/// This function initializes COM, creates a firewall policy object, and enumerates through
/// all the firewall rules, converting them into [`FirewallRule`] structs and returning
/// them as a vector.
///
/// # Returns
///
/// This function returns a [`Result<Vec<FirewallRule>, WindowsFirewallError>`](FirewallRule). If the rules
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
pub fn list_rules() -> Result<Vec<FirewallRule>, WindowsFirewallError> {
    let mut rules_list = Vec::new();

    with_policy(|fw_policy| {
        let fw_rules: INetFwRules = unsafe { fw_policy.Rules() }?;
        let rules_count = unsafe { fw_rules.Count() }?;

        let enumerator = unsafe { fw_rules._NewEnum() }?.cast::<IEnumVARIANT>()?;

        let mut variants: [VARIANT; 1] = Default::default();
        let mut pceltfetch: u32 = 0;

        for _ in 0..rules_count {
            let fetched = unsafe { enumerator.Next(&mut variants, &mut pceltfetch) };

            let (true, Some(variant)) = (fetched.is_ok(), variants.first()) else {
                warn!("Error while fetching rules");
                continue;
            };

            let dispatch = unsafe { variant.Anonymous.Anonymous.Anonymous.pdispVal.clone() };

            let _dispatch_cleanup = guard(dispatch.clone(), |mut d| {
                unsafe { ManuallyDrop::drop(&mut d) };
            });

            let Some(dispatch) = dispatch.as_ref() else {
                warn!("Variant does not contain a dispatch pointer");
                continue;
            };

            let fw_rule = dispatch.cast::<INetFwRule>()?;

            match fw_rule.try_into() {
                Ok(rule) => rules_list.push(rule),
                Err(e) => {
                    let fw_rule = dispatch.cast::<INetFwRule>()?;

                    warn!(
                        "Failed to convert {:?} rule into FirewallRule struct: {:?}",
                        unsafe { fw_rule.Name().unwrap_or_else(|_| BSTR::from("<unknown>")) },
                        e
                    );
                }
            }
        }

        Ok(rules_list)
    })
}

/// Retrieves all incoming firewall rules as a list of [`FirewallRule`] objects.
///
/// This function filters the firewall rules to include only incoming rules.
/// It leverages [`list_rules()`] to get all rules and then applies a filter.
///
/// # Returns
///
/// This function returns a [`Result<Vec<FirewallRule>, WindowsFirewallError>`](FirewallRule).
/// If successful, it returns `Ok(incoming_rules)`, otherwise an error is returned.
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if [`list_rules()`] fails.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn list_incoming_rules() -> Result<Vec<FirewallRule>, WindowsFirewallError> {
    let all_rules = list_rules()?;
    let incoming_rules: Vec<FirewallRule> = all_rules
        .into_iter()
        .filter(|rule| *rule.direction() == Direction::In)
        .collect();

    Ok(incoming_rules)
}

/// Retrieves all outgoing firewall rules as a list of [`FirewallRule`] objects.
///
/// This function filters the firewall rules to include only outgoing rules.
/// It leverages [`list_rules()`] to get all rules and then applies a filter.
///
/// # Returns
///
/// This function returns a [`Result<Vec<FirewallRule>, WindowsFirewallError>`] .
/// If successful, it returns `Ok(outgoing_rules)`, otherwise an error is returned.
///
/// # Errors
///
/// This function may return a [`WindowsFirewallError`] if [`list_rules()`] fails.
///
/// # Security
///
/// This function does not require administrative privileges.
pub fn list_outgoing_rules() -> Result<Vec<FirewallRule>, WindowsFirewallError> {
    let all_rules = list_rules()?;
    let outgoing_rules: Vec<FirewallRule> = all_rules
        .into_iter()
        .filter(|rule| *rule.direction() == Direction::Out)
        .collect();

    Ok(outgoing_rules)
}
