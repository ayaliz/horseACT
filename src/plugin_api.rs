use std::ffi::{c_char, c_void};
use std::sync::OnceLock;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitResult {
    Error = 0,
    Ok = 1,
}

#[repr(C)]
pub struct Vtable {
    // Keep only the stable prefix we actually use. Newer Hachimi versions added
    // more fields after `il2cpp_resolve_symbol`, which can shift the rest of the
    // hand-written struct and break startup if we try to read the tail directly.
    pub hachimi_instance: unsafe extern "C" fn() -> *mut c_void,
    pub hachimi_get_interceptor: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    pub interceptor_hook:
        unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void,
    pub interceptor_hook_vtable:
        unsafe extern "C" fn(*mut c_void, *mut *mut c_void, usize, *mut c_void) -> *mut c_void,
    pub interceptor_get_trampoline_addr:
        unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void,
    pub interceptor_unhook: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void,
    pub il2cpp_resolve_symbol: unsafe extern "C" fn(*const c_char) -> *mut c_void,
}

static VTABLE_ADDR: OnceLock<usize> = OnceLock::new();

pub fn store_vtable(ptr: *const Vtable) {
    let _ = VTABLE_ADDR.set(ptr as usize);
}

pub fn vtable() -> &'static Vtable {
    unsafe { &*(VTABLE_ADDR.get().copied().expect("vtable not initialized") as *const Vtable) }
}

pub unsafe fn hook(fn_ptr: usize, hook_fn: usize) -> Option<usize> {
    if fn_ptr == 0 {
        return None;
    }
    let vt = vtable();
    let hachimi = (vt.hachimi_instance)();
    let interceptor = (vt.hachimi_get_interceptor)(hachimi);
    let orig = (vt.interceptor_hook)(interceptor, fn_ptr as *mut c_void, hook_fn as *mut c_void);
    if orig.is_null() {
        None
    } else {
        Some(orig as usize)
    }
}
