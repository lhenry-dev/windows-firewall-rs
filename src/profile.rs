use std::convert::TryFrom;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_PROFILE_TYPE2;

use crate::errors::WindowsFirewallError;
use crate::firewall_rule::Profile;
use crate::utils::with_policy;

/// Retrieves the active firewall profile.
///
/// This function initializes COM, creates a firewall policy object, and retrieves the current
/// active firewall profile, returning it as a [`Profile`] object.
///
/// # Returns
///
/// This function returns a [`Result<Profile, WindowsFirewallError>`](Profile). If the active profile
/// is successfully retrieved, it returns [`Ok(profile)`](Profile). In case of an error (e.g., COM initialization failure),
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
pub fn get_active_profile() -> Result<Profile, WindowsFirewallError> {
    with_policy(|fw_policy| {
        let active_profile = Profile::try_from(unsafe { fw_policy.CurrentProfileTypes() }?)?;

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
/// * `profile` - A [`Profile`] enum value representing the firewall profile
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
pub fn get_firewall_state(profile: Profile) -> Result<bool, WindowsFirewallError> {
    with_policy(|fw_policy| {
        let enabled =
            unsafe { fw_policy.get_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile.into())) }?
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
/// * `profile` - A [`Profile`] enum value representing the firewall profile
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
pub fn set_firewall_state(profile: Profile, state: bool) -> Result<(), WindowsFirewallError> {
    with_policy(|fw_policy| {
        unsafe {
            fw_policy.put_FirewallEnabled(NET_FW_PROFILE_TYPE2(profile.into()), state.into())
        }?;
        Ok(())
    })
}
