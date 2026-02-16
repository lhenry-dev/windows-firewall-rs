use scopeguard::guard;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwPolicy2;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule;
use windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2;
use windows::Win32::NetworkManagement::WindowsFirewall::NetFwRule;
use windows::Win32::System::Com::CoCreateInstance;
use windows::Win32::System::Com::CoInitializeEx;
use windows::Win32::System::Com::CoUninitialize;

use crate::WindowsFirewallError;
use crate::constants::DWCLSCONTEXT;
use crate::constants::DWCOINIT;

pub fn with_com_initialized<F, R>(f: F) -> Result<R, WindowsFirewallError>
where
    F: FnOnce() -> Result<R, WindowsFirewallError>,
{
    let hr_com_init = unsafe { CoInitializeEx(None, DWCOINIT) };
    if hr_com_init.is_err() {
        return Err(WindowsFirewallError::CoInitializeExFailed(
            hr_com_init.message(),
        ));
    }

    let _com_cleanup = guard((), |()| unsafe { CoUninitialize() });

    f()
}

pub fn with_policy<F, R>(f: F) -> Result<R, WindowsFirewallError>
where
    F: FnOnce(INetFwPolicy2) -> Result<R, WindowsFirewallError>,
{
    with_com_initialized(|| {
        let fw_policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, DWCLSCONTEXT) }?;
        f(fw_policy)
    })
}

pub fn with_rule<F, R>(f: F) -> Result<R, WindowsFirewallError>
where
    F: FnOnce(INetFwRule) -> Result<R, WindowsFirewallError>,
{
    with_com_initialized(|| {
        let fw_rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, DWCLSCONTEXT) }?;
        f(fw_rule)
    })
}
