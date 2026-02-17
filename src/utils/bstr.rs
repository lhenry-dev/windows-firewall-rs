use std::{any::type_name, collections::HashSet, str::FromStr};
use tracing::warn;
use windows::core::BSTR;

use crate::WindowsFirewallError;

const BSTR_SEPARATOR: &str = ",";

pub trait BstrExt {
    fn to_optional_string(self) -> Option<String>;
    fn to_required_string(self) -> Result<String, WindowsFirewallError>;
}

impl BstrExt for windows::core::Result<BSTR> {
    fn to_optional_string(self) -> Option<String> {
        self.ok().map(|b| b.to_string()).filter(|s| !s.is_empty())
    }

    fn to_required_string(self) -> Result<String, WindowsFirewallError> {
        Ok(self?.to_string())
    }
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use windows::core::BSTR;

    use crate::utils::bstr::{bstr_to_hashset, hashset_to_bstr};

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
}
