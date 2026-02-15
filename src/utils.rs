use scopeguard::guard;
use std::{
    any::type_name,
    collections::HashSet,
    ffi::OsStr,
    hash::Hash,
    mem::ManuallyDrop,
    ptr::{addr_of, from_ref},
    str::FromStr,
};
use tracing::warn;
use windows::core::HRESULT;
use windows::{
    Win32::{
        Foundation::GetLastError,
        System::{
            Com::{CoInitializeEx, CoUninitialize},
            Ole::{SafeArrayCreateVector, SafeArrayDestroy, SafeArrayPutElement},
            Variant::{
                self, VARIANT, VT_ARRAY, VT_BSTR, VT_VARIANT, VariantInit, VariantToStringAlloc,
            },
        },
    },
    core::{BSTR, PWSTR},
};

use crate::{Protocol, WindowsFirewallError, constants::DWCOINIT};

const BSTR_SEPARATOR: &str = ",";
const VARIANT_SEPARATOR: &str = "; ";

pub fn is_not_icmp(protocol: Protocol) -> bool {
    !matches!(protocol, Protocol::Icmpv4 | Protocol::Icmpv6)
}

pub fn is_not_tcp_or_udp(protocol: Protocol) -> bool {
    !matches!(protocol, Protocol::Udp | Protocol::Tcp)
}

pub fn into_hashset<T, U>(items: impl IntoIterator<Item = T>) -> HashSet<U>
where
    T: Into<U>,
    U: Eq + Hash,
{
    items.into_iter().map(Into::into).collect()
}

pub fn bstr_to_hashset<T>(bstr: Result<BSTR, windows::core::Error>) -> Option<HashSet<T>>
where
    T: FromStr + Eq + std::hash::Hash,
{
    let set: HashSet<T> = bstr
        .ok()?
        .to_string()
        .split(',')
        .filter_map(|s| parse_item::<T>(s))
        .collect();

    if set.is_empty() { None } else { Some(set) }
}

fn parse_item<T: FromStr>(s: &str) -> Option<T> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(val) = trimmed.parse::<T>() {
        Some(val)
    } else {
        warn!(
            "Failed to parse '{}' into target type for type : {}",
            trimmed,
            type_name::<T>()
        );

        #[cfg(not(test))]
        return None;

        #[cfg(test)]
        panic!(
            "Failed to parse '{}' into target type for type : {}",
            trimmed,
            type_name::<T>()
        );
    }
}

pub fn hashset_to_bstr<T>(hashset: Option<&HashSet<T>>) -> BSTR
where
    T: ToString,
{
    hashset
        .filter(|hs| !hs.is_empty())
        .map(|hs| {
            let joined_str = hs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
                .join(BSTR_SEPARATOR);
            BSTR::from(joined_str)
        })
        .unwrap_or_default()
}

pub fn hashset_to_variant<T>(hashset: &HashSet<T>) -> windows::core::Result<VARIANT>
where
    T: ToString + AsRef<OsStr>,
{
    if hashset.is_empty() {
        return Ok(VARIANT::default());
    }

    let count = u32::try_from(hashset.len())?;
    let psa = unsafe { SafeArrayCreateVector(VT_VARIANT, 0, count) };

    if psa.is_null() {
        let error = unsafe { GetLastError() };
        return Err(windows::core::Error::from_hresult(HRESULT::from_win32(
            error.0,
        )));
    }

    for (i, item) in hashset.iter().enumerate() {
        let bstr = BSTR::from(item.to_string());
        let mut vt_element = unsafe { VariantInit() };

        unsafe {
            (*vt_element.Anonymous.Anonymous).vt = VT_BSTR;
            (*vt_element.Anonymous.Anonymous).Anonymous.bstrVal = ManuallyDrop::new(bstr);
        }

        let hr = unsafe {
            SafeArrayPutElement(
                psa,
                from_ref(&i32::try_from(i)?).cast(),
                addr_of!(vt_element).cast::<std::ffi::c_void>(),
            )
        };

        if let Err(e) = hr {
            unsafe { SafeArrayDestroy(psa) }?;
            return Err(e);
        }
    }

    let mut variant = unsafe { VariantInit() };
    unsafe {
        (*variant.Anonymous.Anonymous).vt = VT_ARRAY | VT_VARIANT;
        (*variant.Anonymous.Anonymous).Anonymous.parray = psa;
    }

    Ok(variant)
}

pub fn variant_to_hashset(variant: &VARIANT) -> windows::core::Result<HashSet<String>> {
    let count = unsafe { Variant::VariantGetElementCount(variant) };

    if count == 0 {
        return Ok(HashSet::new());
    }

    let pwstr: PWSTR = unsafe { VariantToStringAlloc(variant) }?;
    let wide_cstr = unsafe { pwstr.to_string() }?;

    let hashset = wide_cstr
        .split(VARIANT_SEPARATOR)
        .map(str::to_string)
        .collect();

    Ok(hashset)
}

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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use windows::core::BSTR;

    use crate::utils::{bstr_to_hashset, hashset_to_bstr, hashset_to_variant, variant_to_hashset};

    // BSTR tests
    #[test]
    fn test_convert_bstr_to_hashset_valid_input() {
        let bstr_value = Ok(BSTR::from("1, 2, 3, 4"));

        let result = bstr_to_hashset(bstr_value);

        let expected = vec![1, 2, 3, 4].into_iter().collect();
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn test_convert_bstr_to_hashset_with_empty_strings() {
        let bstr_value = Ok(BSTR::from("  ,  ,  "));

        let result: Option<HashSet<i32>> = bstr_to_hashset(bstr_value);

        assert_eq!(result, None);
    }

    #[test]
    #[should_panic(expected = "Failed to parse 'abc' into target type for type : i32")]
    fn test_convert_bstr_to_hashset_with_invalid_input() {
        let bstr_value = Ok(BSTR::from("1, abc, 3"));
        let result: Option<HashSet<i32>> = bstr_to_hashset(bstr_value);
        let expected = vec![1, 3].into_iter().collect();
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn test_convert_bstr_to_hashset_empty_input() {
        let bstr_value = Ok(BSTR::from(""));

        let result: Option<HashSet<i32>> = bstr_to_hashset(bstr_value);

        assert_eq!(result, None);
    }

    #[test]
    fn test_convert_bstr_to_hashset_error_input() {
        let bstr_value = Err(windows::core::Error::empty());

        let result: Option<HashSet<i32>> = bstr_to_hashset(bstr_value);

        assert_eq!(result, None);
    }

    #[test]
    fn test_convert_hashset_to_bstr_valid_input() {
        let hashset_data = vec![1, 2, 3, 4].into_iter().collect();
        let hashset = Some(&hashset_data);

        let result = hashset_to_bstr(hashset);

        let expected = BSTR::from("1,2,3,4");

        let result_str = result.to_string();
        let mut result_vec: Vec<_> = result_str.split(',').collect();
        result_vec.sort_unstable();

        let expected_str = expected.to_string();
        let mut expected_vec: Vec<_> = expected_str.split(',').collect();
        expected_vec.sort_unstable();

        assert_eq!(result_vec, expected_vec);
    }

    #[test]
    fn test_convert_hashset_to_bstr_empty_input() {
        let hashset_data: HashSet<i32> = HashSet::new();
        let hashset = Some(&hashset_data);

        let result = hashset_to_bstr(hashset);

        let expected = BSTR::from("");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_hashset_to_bstr_none_input() {
        let hashset: Option<&HashSet<i32>> = None;

        let result = hashset_to_bstr(hashset);

        let expected = BSTR::from("");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_hashset_to_bstr_single_element() {
        let hashset_data: HashSet<i32> = vec![42].into_iter().collect();
        let hashset = Some(&hashset_data);

        let result = hashset_to_bstr(hashset);

        let expected = BSTR::from("42");
        assert_eq!(result, expected);
    }

    // VARIANT tests
    #[test]
    fn test_empty_hashset_to_variant() {
        let empty_set: HashSet<String> = HashSet::new();

        let result = hashset_to_variant(&empty_set);

        assert!(result.is_ok());
        let round_trip_set = result.unwrap();
        assert!(round_trip_set.is_empty());

        let result = variant_to_hashset(&round_trip_set);

        assert!(result.is_ok());
        let round_trip_set = result.unwrap();
        assert!(round_trip_set.is_empty());
    }

    #[test]
    fn test_single_element_hashset_to_variant() {
        let mut set = HashSet::new();
        set.insert("single".to_string());

        let result = hashset_to_variant(&set);
        assert!(result.is_ok());
        let round_trip_set = result.unwrap();

        let result = variant_to_hashset(&round_trip_set);
        assert!(result.is_ok());
        let round_trip_set = result.unwrap();

        let mut set_vec: Vec<_> = set.into_iter().collect();
        let mut round_trip_vec: Vec<_> = round_trip_set.into_iter().collect();
        set_vec.sort();
        round_trip_vec.sort();

        assert_eq!(set_vec, round_trip_vec);
    }

    #[test]
    fn test_multiple_elements_hashset_to_variant() {
        let mut set = HashSet::new();
        set.insert("apple".to_string());
        set.insert("banana".to_string());
        set.insert("cherry".to_string());

        let result = hashset_to_variant(&set);
        assert!(result.is_ok());
        let round_trip_set = result.unwrap();

        let result = variant_to_hashset(&round_trip_set);
        assert!(result.is_ok());
        let round_trip_set = result.unwrap();

        let mut set_vec: Vec<_> = set.into_iter().collect();
        let mut round_trip_vec: Vec<_> = round_trip_set.into_iter().collect();
        set_vec.sort();
        round_trip_vec.sort();

        assert_eq!(set_vec, round_trip_vec);
    }
}
