use std::{collections::HashSet, ffi::OsStr, str::FromStr};
use windows::{
    Win32::System::{
        Ole::{SafeArrayCreateVector, SafeArrayPutElement},
        Variant::{self, VARIANT, VT_ARRAY, VT_BSTR, VT_VARIANT, VariantToStringAlloc},
    },
    core::{BSTR, PWSTR},
};

pub(crate) fn to_string_hashset_option<T, I>(items: I) -> Option<HashSet<String>>
where
    I: IntoIterator<Item = T>,
    T: Into<String>,
{
    Some(items.into_iter().map(Into::into).collect())
}

pub(crate) fn convert_bstr_to_hashset<T>(
    bstr: Result<BSTR, windows_result::Error>,
) -> Option<HashSet<T>>
where
    T: FromStr + Eq + std::hash::Hash,
{
    bstr.ok()
        .map(|bstr_value| {
            let bstr_str = bstr_value.to_string();
            bstr_str
                .split(',')
                .filter_map(|s| {
                    let trimmed = s.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        if let Ok(parsed_t) = trimmed.parse::<T>() {
                            return Some(parsed_t);
                        }

                        if let Some((ip_str, _mask_str)) = trimmed.split_once('/') {
                            if let Ok(parsed_t) = ip_str.parse::<T>() {
                                return Some(parsed_t);
                            }
                        }

                        None
                    }
                })
                .collect::<HashSet<T>>()
        })
        .filter(|hash_set| !hash_set.is_empty())
}

pub(crate) fn convert_hashset_to_bstr<T>(hashset: Option<HashSet<T>>) -> BSTR
where
    T: ToString,
{
    hashset
        .filter(|hs| !hs.is_empty())
        .map(|hs| {
            let joined_str = hs
                .into_iter()
                .map(|item| item.to_string())
                .collect::<Vec<String>>()
                .join(",");
            BSTR::from(joined_str)
        })
        .unwrap_or_default()
}

pub(crate) fn hashset_to_variant<T>(hashset: &HashSet<T>) -> windows_result::Result<VARIANT>
where
    T: ToString + AsRef<OsStr>,
{
    if hashset.is_empty() {
        return Ok(VARIANT::default());
    }

    unsafe {
        let count = hashset.len() as u32;
        let psa = SafeArrayCreateVector(VT_VARIANT, 0, count);

        if psa.is_null() {
            return Err(windows::core::Error::from_win32());
        }

        for (i, item) in hashset.iter().enumerate() {
            let bstr = BSTR::from(item.to_string());

            let mut vt_element = VARIANT::default();
            std::ptr::write(&mut (*vt_element.Anonymous.Anonymous).vt, VT_BSTR);
            std::ptr::write(
                &mut (*vt_element.Anonymous.Anonymous).Anonymous.bstrVal,
                std::mem::ManuallyDrop::new(bstr),
            );

            SafeArrayPutElement(
                psa,
                &(i as i32) as *const _,
                &vt_element as *const _ as *const std::ffi::c_void,
            )?;
        }

        let mut variant = VARIANT::default();
        std::ptr::write(
            &mut (*variant.Anonymous.Anonymous).vt,
            VT_ARRAY | VT_VARIANT,
        );
        std::ptr::write(&mut (*variant.Anonymous.Anonymous).Anonymous.parray, psa);

        Ok(variant)
    }
}

pub(crate) fn variant_to_hashset(variant: &VARIANT) -> windows::core::Result<HashSet<String>> {
    unsafe {
        let count = Variant::VariantGetElementCount(variant);

        if count == 0 {
            return Ok(HashSet::new());
        }

        let pwstr: PWSTR = VariantToStringAlloc(variant)?;
        let wide_cstr = pwstr.to_string()?;

        let substrings: Vec<&str> = wide_cstr.split("; ").collect();

        let hashset = substrings.into_iter().map(|s| s.to_string()).collect();

        Ok(hashset)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use windows::core::BSTR;
    use windows_result::Error;

    use crate::utils::{
        convert_bstr_to_hashset, convert_hashset_to_bstr, hashset_to_variant, variant_to_hashset,
    };

    // BSTR tests
    #[test]
    fn test_convert_bstr_to_hashset_valid_input() {
        let bstr_value: Result<BSTR, Error> = Ok(BSTR::from("1, 2, 3, 4"));

        let result: Option<HashSet<i32>> = convert_bstr_to_hashset(bstr_value);

        let expected: HashSet<i32> = vec![1, 2, 3, 4].into_iter().collect();
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn test_convert_bstr_to_hashset_with_empty_strings() {
        let bstr_value: Result<BSTR, Error> = Ok(BSTR::from("  ,  ,  "));

        let result: Option<HashSet<i32>> = convert_bstr_to_hashset(bstr_value);

        assert_eq!(result, None);
    }

    #[test]
    fn test_convert_bstr_to_hashset_with_invalid_input() {
        let bstr_value: Result<BSTR, Error> = Ok(BSTR::from("1, abc, 3"));

        let result: Option<HashSet<i32>> = convert_bstr_to_hashset(bstr_value);

        let expected: HashSet<i32> = vec![1, 3].into_iter().collect();
        assert_eq!(result, Some(expected));
    }

    #[test]
    fn test_convert_bstr_to_hashset_empty_input() {
        let bstr_value: Result<BSTR, Error> = Ok(BSTR::from(""));

        let result: Option<HashSet<i32>> = convert_bstr_to_hashset(bstr_value);

        assert_eq!(result, None);
    }

    #[test]
    fn test_convert_bstr_to_hashset_error_input() {
        let bstr_value: Result<BSTR, Error> = Err(windows_result::Error::empty());

        let result: Option<HashSet<i32>> = convert_bstr_to_hashset(bstr_value);

        assert_eq!(result, None);
    }

    #[test]
    fn test_convert_hashset_to_bstr_valid_input() {
        let hashset: Option<HashSet<i32>> = Some(vec![1, 2, 3, 4].into_iter().collect());

        let result: BSTR = convert_hashset_to_bstr(hashset);

        let expected = BSTR::from("1,2,3,4");

        let result_str = result.to_string();
        let mut result_vec: Vec<&str> = result_str.split(',').collect();
        result_vec.sort();

        let expected_str = expected.to_string();
        let mut expected_vec: Vec<&str> = expected_str.split(',').collect();
        expected_vec.sort();

        assert_eq!(result_vec, expected_vec);
    }

    #[test]
    fn test_convert_hashset_to_bstr_empty_input() {
        let hashset: Option<HashSet<i32>> = Some(HashSet::new());

        let result: BSTR = convert_hashset_to_bstr(hashset);

        let expected = BSTR::from("");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_hashset_to_bstr_none_input() {
        let hashset: Option<HashSet<i32>> = None;

        let result: BSTR = convert_hashset_to_bstr(hashset);

        let expected = BSTR::from("");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_convert_hashset_to_bstr_single_element() {
        let hashset: Option<HashSet<i32>> = Some(vec![42].into_iter().collect());

        let result: BSTR = convert_hashset_to_bstr(hashset);

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
