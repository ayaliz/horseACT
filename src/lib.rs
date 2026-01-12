#![allow(non_snake_case)]

mod config;
mod il2cpp;
mod reflection;
mod persistence;
mod hooks;

use hachimi_plugin_sdk::{
    api::{Hachimi, HachimiApi},
    hachimi_plugin,
    sys::InitResult,
};

use crate::config::init_paths;
use crate::il2cpp::{init_il2cpp_methods, RawIl2CppImage, FN_CLASS_FROM_NAME, FN_CLASS_GET_METHOD_FROM_NAME};
use crate::hooks::{race_info_hook, veteran_hook, ORIG_GET_RACE_TRACK_ID, ORIG_VETERAN_APPLY};
use crate::reflection::find_methods_in_assembly_by_param;

#[hachimi_plugin]
pub fn main(api: HachimiApi) -> InitResult {
    log!("Plugin initialized.");

    if let Err(e) = init_paths() {
        log!("Failed to initialize paths: {}", e);
        return InitResult::Error;
    }

    let il2cpp = api.il2cpp();
    let hachimi = Hachimi::instance(&api);
    let interceptor = hachimi.interceptor();

    unsafe {
        if !init_il2cpp_methods(&api) {
            log!("Failed to resolve IL2CPP scanning functions.");
            return InitResult::Error;
        }
    }

    let mut target_image = il2cpp.get_assembly_image(c"umamusume");
    if target_image.is_null() { target_image = il2cpp.get_assembly_image(c"Assembly-CSharp"); }
    if target_image.is_null() { target_image = il2cpp.get_assembly_image(c"Gallop"); }

    if target_image.is_null() {
        log!("Error: Could not find game assembly.");
        return InitResult::Error;
    }

    unsafe {
        let race_info_class = FN_CLASS_FROM_NAME.unwrap()(
            target_image as *mut RawIl2CppImage,
            c"Gallop".as_ptr(),
            c"RaceInfo".as_ptr(),
        );

        if !race_info_class.is_null() {
            let method = FN_CLASS_GET_METHOD_FROM_NAME.unwrap()(
                race_info_class,
                c"get_RaceTrackId".as_ptr(),
                0,
            );

            if !method.is_null() {
                let fn_ptr = *(method as *const usize);
                if let Some(orig) = interceptor.hook(fn_ptr, race_info_hook as usize) {
                    ORIG_GET_RACE_TRACK_ID = orig;
                    log!("Hooked: Gallop.RaceInfo.get_RaceTrackId");
                }
            } else {
                 log!("Failed to find get_RaceTrackId method");
            }
        } else {
            log!("Failed to find RaceInfo class");
        }
    }

    unsafe {
        log!("Scanning for Veteran handler (param type: TrainedChara[])...");

        let results = find_methods_in_assembly_by_param(
            target_image as *mut RawIl2CppImage,
            "TrainedChara[]",
        );

        if results.is_empty() {
            log!("WARNING: No methods found for Veteran Characters");
        } else {
            let result = results
                .iter()
                .find(|r| r.class_name.contains("WorkTrainedCharaData") && r.method_name.contains("UpdateAll"))
                .or_else(|| results.first())
                .unwrap();

            if results.len() > 1 {
                log!("Multiple candidates found. Selected: {}.{}", result.class_name, result.method_name);
            }

            let fn_ptr = *(result.method as *const usize);
            if fn_ptr != 0 {
                if let Some(orig) = interceptor.hook(fn_ptr, veteran_hook as usize) {
                    ORIG_VETERAN_APPLY = orig;
                    log!("Veteran Hook installed on {}.{}", result.class_name, result.method_name);
                } else {
                    log!("Failed to hook Veteran (interceptor returned None)");
                }
            } else {
                log!("Failed to hook Veteran: method pointer is null");
            }
        }
    }

    InitResult::Ok
}