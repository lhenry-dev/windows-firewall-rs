use std::ptr::addr_of;
use std::{collections::HashSet, ffi::OsStr, mem::ManuallyDrop, ptr::from_ref};
use windows::core::HRESULT;
use windows::{
    Win32::{
        Foundation::GetLastError,
        System::{
            Ole::{SafeArrayCreateVector, SafeArrayDestroy, SafeArrayPutElement},
            Variant::{
                self, VARIANT, VT_ARRAY, VT_BSTR, VT_VARIANT, VariantInit, VariantToStringAlloc,
            },
        },
    },
    core::{BSTR, PWSTR},
};

const VARIANT_SEPARATOR: &str = "; ";

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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::utils::variant::{hashset_to_variant, variant_to_hashset};

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
