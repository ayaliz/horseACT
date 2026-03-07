use std::ffi::{c_char, c_void};
use std::sync::OnceLock;

pub type GuiMenuCallback = extern "C" fn(*mut c_void);
pub type GuiMenuSectionCallback = extern "C" fn(*mut c_void, *mut c_void);
pub type GuiUiCallback = extern "C" fn(*mut c_void, *mut c_void);

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitResult {
    Error = 0,
    Ok = 1,
}

#[repr(C)]
pub struct Vtable {
    pub hachimi_instance:               unsafe extern "C" fn() -> *mut c_void,
    pub hachimi_get_interceptor:        unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    pub interceptor_hook:               unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void,
    pub interceptor_hook_vtable:        unsafe extern "C" fn(*mut c_void, *mut *mut c_void, usize, *mut c_void) -> *mut c_void,
    pub interceptor_get_trampoline_addr:unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void,
    pub interceptor_unhook:             unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void,
    pub il2cpp_resolve_symbol:          unsafe extern "C" fn(*const c_char) -> *mut c_void,
    pub il2cpp_get_assembly_image:      unsafe extern "C" fn(*const c_char) -> *mut c_void,
    pub il2cpp_get_class:               unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut c_void,
    pub il2cpp_get_method:              unsafe extern "C" fn(*mut c_void, *const c_char, i32) -> *const c_void,
    pub il2cpp_get_method_overload:     unsafe extern "C" fn(*mut c_void, *const c_char, *const i32, usize) -> *const c_void,
    pub il2cpp_get_method_addr:         unsafe extern "C" fn(*mut c_void, *const c_char, i32) -> *mut c_void,
    pub il2cpp_get_method_overload_addr:unsafe extern "C" fn(*mut c_void, *const c_char, *const i32, usize) -> *mut c_void,
    pub il2cpp_get_method_cached:       unsafe extern "C" fn(*mut c_void, *const c_char, i32) -> *const c_void,
    pub il2cpp_get_method_addr_cached:  unsafe extern "C" fn(*mut c_void, *const c_char, i32) -> *mut c_void,
    pub il2cpp_find_nested_class:       unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,
    pub il2cpp_get_field_from_name:     unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut c_void,
    pub il2cpp_get_field_value:         unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void),
    pub il2cpp_set_field_value:         unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_void),
    pub il2cpp_get_static_field_value:  unsafe extern "C" fn(*mut c_void, *mut c_void),
    pub il2cpp_set_static_field_value:  unsafe extern "C" fn(*mut c_void, *const c_void),
    pub il2cpp_unbox:                   unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    pub il2cpp_get_main_thread:         unsafe extern "C" fn() -> *mut c_void,
    pub il2cpp_get_attached_threads:    unsafe extern "C" fn(*mut usize) -> *mut *mut c_void,
    pub il2cpp_schedule_on_thread:      unsafe extern "C" fn(*mut c_void, unsafe extern "C" fn()),
    pub il2cpp_create_array:            unsafe extern "C" fn(*mut c_void, u32) -> *mut c_void,
    pub il2cpp_get_singleton_like_instance: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    pub log:                            unsafe extern "C" fn(i32, *const c_char, *const c_char),
    pub gui_register_menu_item:         unsafe extern "C" fn(*const c_char, Option<GuiMenuCallback>, *mut c_void) -> bool,
    pub gui_register_menu_section:      unsafe extern "C" fn(Option<GuiMenuSectionCallback>, *mut c_void) -> bool,
    pub gui_show_notification:          unsafe extern "C" fn(*const c_char) -> bool,
    pub gui_ui_heading:                 unsafe extern "C" fn(*mut c_void, *const c_char) -> bool,
    pub gui_ui_label:                   unsafe extern "C" fn(*mut c_void, *const c_char) -> bool,
    pub gui_ui_small:                   unsafe extern "C" fn(*mut c_void, *const c_char) -> bool,
    pub gui_ui_separator:               unsafe extern "C" fn(*mut c_void) -> bool,
    pub gui_ui_button:                  unsafe extern "C" fn(*mut c_void, *const c_char) -> bool,
    pub gui_ui_small_button:            unsafe extern "C" fn(*mut c_void, *const c_char) -> bool,
    pub gui_ui_checkbox:                unsafe extern "C" fn(*mut c_void, *const c_char, *mut bool) -> bool,
    pub gui_ui_text_edit_singleline:    unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> bool,
    pub gui_ui_horizontal:              unsafe extern "C" fn(*mut c_void, Option<GuiUiCallback>, *mut c_void) -> bool,
    pub gui_ui_grid:                    unsafe extern "C" fn(*mut c_void, *const c_char, usize, f32, f32, Option<GuiUiCallback>, *mut c_void) -> bool,
    pub gui_ui_end_row:                 unsafe extern "C" fn(*mut c_void) -> bool,
    pub gui_ui_colored_label:           unsafe extern "C" fn(*mut c_void, u8, u8, u8, u8, *const c_char) -> bool,
    pub gui_register_menu_item_icon:    unsafe extern "C" fn(*const c_char, *const c_char, *const u8, usize) -> bool,
    pub gui_register_menu_section_with_icon: unsafe extern "C" fn(*const c_char, *const c_char, *const u8, usize, Option<GuiMenuSectionCallback>, *mut c_void) -> bool,
    pub android_dex_load:               unsafe extern "C" fn(*const u8, usize, *const c_char) -> u64,
    pub android_dex_unload:             unsafe extern "C" fn(u64) -> bool,
    pub android_dex_call_static_noargs: unsafe extern "C" fn(u64, *const c_char, *const c_char) -> bool,
    pub android_dex_call_static_string: unsafe extern "C" fn(u64, *const c_char, *const c_char, *const c_char) -> bool,
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
    if orig.is_null() { None } else { Some(orig as usize) }
}
