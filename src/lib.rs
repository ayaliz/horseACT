#![allow(non_snake_case)]

mod config;
mod il2cpp;
mod reflection;
mod persistence;
mod hooks;
mod api;
mod plugin_api;

use crate::config::init_paths;
use crate::il2cpp::{init_il2cpp_methods, RawIl2CppImage};
use crate::hooks::{race_info_hook, ORIG_GET_RACE_TRACK_ID, API_HOOK_FNS, API_HOOK_ORIGS, MAX_API_HOOKS};
use crate::reflection::find_methods_in_assembly_by_param;
use crate::plugin_api::{vtable, store_vtable, hook, InitResult, Vtable};

#[no_mangle]
pub extern "C" fn hachimi_init(vtable_ptr: *const Vtable, version: i32) -> InitResult {
    if vtable_ptr.is_null() || version < 2 {
        return InitResult::Error;
    }
    store_vtable(vtable_ptr);
    init()
}

fn init() -> InitResult {
    log!("Plugin initialized.");

    if let Err(e) = init_paths() {
        log!("Failed to initialize paths: {}", e);
        return InitResult::Error;
    }

    let vt = vtable();

    unsafe {
        if !init_il2cpp_methods(|name| (vt.il2cpp_resolve_symbol)(name)) {
            log!("Failed to resolve IL2CPP scanning functions.");
            return InitResult::Error;
        }
    }

    std::thread::spawn(|| {
        unsafe { install_hooks(); }
    });

    InitResult::Ok
}

unsafe fn install_hooks() {
    let vt = vtable();

    let mut target_image = (vt.il2cpp_get_assembly_image)(c"umamusume".as_ptr());
    if target_image.is_null() { target_image = (vt.il2cpp_get_assembly_image)(c"Assembly-CSharp".as_ptr()); }
    if target_image.is_null() { target_image = (vt.il2cpp_get_assembly_image)(c"Gallop".as_ptr()); }

    if target_image.is_null() {
        log!("Error: Could not find game assembly.");
        return;
    }

    let race_info_class = (vt.il2cpp_get_class)(target_image, c"Gallop".as_ptr(), c"RaceInfo".as_ptr());
    if !race_info_class.is_null() {
        let fn_ptr = (vt.il2cpp_get_method_addr)(race_info_class, c"get_RaceTrackId".as_ptr(), 0) as usize;
        if fn_ptr != 0 {
            if let Some(orig) = hook(fn_ptr, race_info_hook as usize) {
                ORIG_GET_RACE_TRACK_ID = orig;
                log!("Hooked: Gallop.RaceInfo.get_RaceTrackId");
            }
        } else {
            log!("Failed to find get_RaceTrackId method");
        }
    } else {
        log!("Failed to find RaceInfo class");
    }

    match api::fetch_endpoint_config() {
        Ok(configs) => {
            log!("Fetched {} endpoint config(s) from server.", configs.len());
            api::store_endpoint_configs(configs.clone());
            install_endpoint_hooks(target_image as *mut RawIl2CppImage, &configs);
        }
        Err(e) => {
            log!("Failed to fetch endpoint config: {}. No API hooks installed.", e);
        }
    }
}

unsafe fn install_endpoint_hooks(
    target_image: *mut RawIl2CppImage,
    endpoints: &[crate::config::EndpointConfig],
) {
    fn is_generated(s: &str) -> bool { s.contains('<') }

    let mut slot = 0;
    for endpoint in endpoints {
        if slot >= MAX_API_HOOKS {
            log!("WARNING: Maximum of {} API hooks reached, skipping remaining endpoints.", MAX_API_HOOKS);
            break;
        }
        let results = find_methods_in_assembly_by_param(target_image, &endpoint.name);
        let result = results.iter()
            .find(|r| !is_generated(&r.method_name) && !is_generated(&r.class_name))
            .or_else(|| results.first());

        if let Some(result) = result {
            let fn_ptr = *(result.method as *const usize);
            if fn_ptr != 0 {
                if let Some(orig) = hook(fn_ptr, API_HOOK_FNS[slot] as usize) {
                    API_HOOK_ORIGS[slot] = orig;
                    log!("[{}] Hook installed on {}.{}", endpoint.name, result.class_name, result.method_name);
                    slot += 1;
                } else {
                    log!("[{}] Failed to install hook", endpoint.name);
                }
            } else {
                log!("[{}] Method pointer is null", endpoint.name);
            }
        } else {
            log!("[{}] WARNING: No matching method found", endpoint.name);
        }
    }
}
