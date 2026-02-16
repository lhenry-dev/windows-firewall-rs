use windows::Win32::NetworkManagement::WindowsFirewall::{
    NET_FW_PROFILE_CURRENT, NET_FW_PROFILE_DOMAIN, NET_FW_PROFILE_STANDARD,
    NET_FW_PROFILE_TYPE_MAX, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE,
    NET_FW_PROFILE2_PUBLIC,
};

use crate::firewall_rule::types::InvalidRuleType;

/// Represents the various Windows Firewall profiles.
///
/// This enum includes both legacy (v1) and modern (v2) profile types.
/// Prefer using the `V2` variants unless you're targeting legacy Windows versions (pre-Vista).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Profile {
    /// Modern: Domain profile.
    Domain,
    /// Modern: Private profile (used on trusted networks like home/work).
    Private,
    /// Modern: Public profile (used on untrusted networks like public Wi-Fi).
    Public,
    /// Modern: All profiles combined (bitflag: DOMAIN | PRIVATE | PUBLIC).
    All,

    /// Legacy: Domain profile (Windows XP/2003).
    LegacyDomain,
    /// Legacy: Standard profile (aka Private/Public in older systems).
    LegacyStandard,
    /// Legacy: Current profile (represents the currently active profile).
    LegacyCurrent,
    /// Legacy: Max profile value (internal use only).
    LegacyMax,
}

/// Implements conversion from `i32` to `Profile`
impl TryFrom<i32> for Profile {
    type Error = InvalidRuleType;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            x if x == NET_FW_PROFILE2_DOMAIN.0 => Ok(Self::Domain),
            x if x == NET_FW_PROFILE2_PRIVATE.0 => Ok(Self::Private),
            x if x == NET_FW_PROFILE2_PUBLIC.0 => Ok(Self::Public),
            x if x == NET_FW_PROFILE2_ALL.0 => Ok(Self::All),

            x if x == NET_FW_PROFILE_DOMAIN.0 => Ok(Self::LegacyDomain),
            x if x == NET_FW_PROFILE_STANDARD.0 => Ok(Self::LegacyStandard),
            x if x == NET_FW_PROFILE_CURRENT.0 => Ok(Self::LegacyCurrent),
            x if x == NET_FW_PROFILE_TYPE_MAX.0 => Ok(Self::LegacyMax),
            _ => Err(InvalidRuleType::NetFwProfile),
        }
    }
}

/// Implements conversion from [`Profile`] to `i32`
impl From<Profile> for i32 {
    fn from(profile: Profile) -> Self {
        match profile {
            Profile::Domain => NET_FW_PROFILE2_DOMAIN.0,
            Profile::Private => NET_FW_PROFILE2_PRIVATE.0,
            Profile::Public => NET_FW_PROFILE2_PUBLIC.0,
            Profile::All => NET_FW_PROFILE2_ALL.0,

            Profile::LegacyDomain => NET_FW_PROFILE_DOMAIN.0,
            Profile::LegacyStandard => NET_FW_PROFILE_STANDARD.0,
            Profile::LegacyCurrent => NET_FW_PROFILE_CURRENT.0,
            Profile::LegacyMax => NET_FW_PROFILE_TYPE_MAX.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Profile, firewall_rule::types::InvalidRuleType};

    #[test]
    fn test_try_from_invalid_net_fw_profile() {
        let invalid_value = 999;

        let result = Profile::try_from(invalid_value);

        assert!(matches!(result, Err(InvalidRuleType::NetFwProfile)));
    }
}
