use scopeguard::guard;
use std::slice;
use tracing::warn;
use windows::Win32::NetworkManagement::WindowsFirewall::{INetFwRule, INetFwRules};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::{VARIANT, VariantClear};
use windows::core::{BSTR, Interface};

use crate::errors::WindowsFirewallError;
use crate::firewall_rule::{Direction, FirewallRule};
use crate::utils::with_policy;

/// Retrieves the total number of firewall rules.
///
/// This function initializes COM, creates a firewall policy object, and fetches
/// the total count of firewall rules.
///
/// See [`INetFwRules::get_Count`](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-get_count).
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
/// See [`INetFwRules::get__NewEnum`](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-get__newenum)
/// and the [`IEnumVARIANT`](https://learn.microsoft.com/en-us/windows/win32/api/oaidl/nn-oaidl-ienumvariant) interface used to iterate the rule collection.
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

        let enumerator = unsafe { fw_rules._NewEnum() }?.cast::<IEnumVARIANT>()?;

        loop {
            let mut variant = VARIANT::default();
            let mut pceltfetch: u32 = 0;

            let fetched =
                unsafe { enumerator.Next(slice::from_mut(&mut variant), &raw mut pceltfetch) };

            let variant = guard(variant, |mut v| {
                let _ = unsafe { VariantClear(&raw mut v) };
            });

            if fetched.is_err() {
                warn!("Error while fetching rules: {fetched:?}");
                break;
            }

            if pceltfetch == 0 {
                break;
            }

            let dispatch = unsafe { variant.Anonymous.Anonymous.Anonymous.pdispVal.as_ref() };

            let Some(dispatch) = dispatch else {
                warn!("Variant does not contain a dispatch pointer");
                continue;
            };

            let fw_rule = dispatch.cast::<INetFwRule>()?;

            match FirewallRule::try_from(fw_rule) {
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
