use windows::Win32::System::Com::{CLSCTX, CLSCTX_INPROC_SERVER, COINIT, COINIT_APARTMENTTHREADED};

pub(crate) const DWCLSCONTEXT: CLSCTX = CLSCTX_INPROC_SERVER;
pub(crate) const DWCOINIT: COINIT = COINIT_APARTMENTTHREADED;
