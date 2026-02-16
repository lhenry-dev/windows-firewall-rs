use std::{collections::HashSet, hash::Hash};

pub use self::bstr::*;
pub use self::com::*;
pub use self::variant::*;

pub mod bstr;
pub mod com;
pub mod variant;

pub fn into_hashset<T, U>(items: impl IntoIterator<Item = T>) -> HashSet<U>
where
    T: Into<U>,
    U: Eq + Hash,
{
    items.into_iter().map(Into::into).collect()
}
