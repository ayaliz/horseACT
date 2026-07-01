#![allow(non_snake_case)]

mod api;
mod config;
mod hooks;
mod il2cpp;
mod persistence;
mod plugin_api;
mod reflection;

use crate::config::init_paths;
use crate::hooks::{
    cache_race_info_sim_data_offset, log_class_fields, log_class_methods, team_stadium_result_hook,
    race_manager_get_player_horse_index_hook, set_and_deserialize_base64_hook,
    set_sim_data_base64_hook, veteran_hook, API_HOOK_FNS, API_HOOK_ORIGS, MAX_API_HOOKS,
    ORIG_RACE_MANAGER_GET_PLAYER_HORSE_INDEX, ORIG_SET_AND_DESERIALIZE_BASE64,
    ORIG_SET_SIM_DATA_BASE64, ORIG_TEAM_STADIUM_RESULT, ORIG_VETERAN_APPLY, RACE_INFO_HOOK_FNS,
    RACE_INFO_HOOK_NAMES, RACE_INFO_HOOK_ORIGS, RACE_INFO_OBJECT_HOOK_FNS,
    RACE_INFO_OBJECT_HOOK_NAMES, RACE_INFO_OBJECT_HOOK_ORIGS, RACE_MANAGER_GET_RACE_INFO_ADDR,
    RACE_MANAGER_GET_RACE_INFO_METHOD,
};
use crate::il2cpp::{
    find_image_by_name, find_method_addr_by_name, get_class_from_image, init_il2cpp_methods,
    log_loaded_images, method_addr, RawIl2CppImage,
};
use crate::plugin_api::{hook, store_vtable, vtable, InitResult, Vtable};
use crate::reflection::find_methods_in_assembly_by_param;

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

    std::thread::spawn(|| unsafe {
        install_hooks();
    });

    InitResult::Ok
}

unsafe fn install_hooks() {
    log!("[Hooks] Starting hook installation.");
    let mut target_image = find_image_by_name("umamusume");
    if !target_image.is_null() {
        log!("[Hooks] Using target assembly image: umamusume");
    }
    if target_image.is_null() {
        target_image = find_image_by_name("Assembly-CSharp");
        if !target_image.is_null() {
            log!("[Hooks] Using target assembly image: Assembly-CSharp");
        }
    }
    if target_image.is_null() {
        target_image = find_image_by_name("Gallop");
        if !target_image.is_null() {
            log!("[Hooks] Using target assembly image: Gallop");
        }
    }

    if target_image.is_null() {
        log!("Error: Could not find game assembly.");
        log_loaded_images();
        return;
    }

    let race_info_class =
        get_class_from_image(target_image, c"Gallop".as_ptr(), c"RaceInfo".as_ptr());
    if !race_info_class.is_null() {
        log!("[RaceInfo] Found Gallop.RaceInfo class.");
        log_class_fields(race_info_class, "Gallop.RaceInfo");
        log_class_methods(race_info_class, "Gallop.RaceInfo");
        cache_race_info_sim_data_offset(race_info_class);
        install_race_info_probe_hooks(race_info_class);
        install_race_info_object_probe_hooks(race_info_class);
        install_race_info_sim_data_write_hooks(race_info_class);
    } else {
        log!("Failed to find RaceInfo class");
    }

    let race_manager_class =
        get_class_from_image(target_image, c"Gallop".as_ptr(), c"RaceManager".as_ptr());
    if !race_manager_class.is_null() {
        install_race_manager_probe_hook(race_manager_class);
    } else {
        log!("[RaceManager] Failed to find Gallop.RaceManager class");
    }

    let results =
        find_methods_in_assembly_by_param(target_image as *mut RawIl2CppImage, "TrainedChara[]");
    if results.is_empty() {
        log!("WARNING: No methods found for Veteran Characters");
    } else {
        let best_candidate = results
            .iter()
            .find(|r| {
                r.class_name.contains("WorkTrainedCharaData") && r.method_name.contains("UpdateAll")
            })
            .or_else(|| results.first());

        if let Some(result) = best_candidate {
            let fn_ptr = method_addr(result.method);
            if fn_ptr != 0 {
                if let Some(orig) = hook(fn_ptr, veteran_hook as *const () as usize) {
                    ORIG_VETERAN_APPLY = orig;
                    log!(
                        "Veteran hook installed on {}.{}",
                        result.class_name,
                        result.method_name
                    );
                } else {
                    log!("Failed to install Veteran hook");
                }
            } else {
                log!("Veteran candidate method pointer is null");
            }
        }
    }

    match api::fetch_endpoint_config() {
        Ok(configs) => {
            log!("Fetched {} endpoint config(s) from server.", configs.len());
            api::store_endpoint_configs(configs.clone());
            install_endpoint_hooks(target_image as *mut RawIl2CppImage, &configs);
        }
        Err(e) => {
            log!(
                "Failed to fetch endpoint config: {}. No API hooks installed.",
                e
            );
        }
    }

    let results =
        find_methods_in_assembly_by_param(target_image as *mut RawIl2CppImage, "CommonResponse");
    if results.is_empty() {
        log!("WARNING: No methods found taking CommonResponse parameter");
    } else {
        log!("Found {} method(s) taking CommonResponse", results.len());
        let best_candidate = results
            .iter()
            .find(|r| r.class_name.contains("TeamStadiumResult") && r.method_name == ".ctor")
            .or_else(|| results.first());

        if let Some(result) = best_candidate {
            let fn_ptr = method_addr(result.method);
            if fn_ptr != 0 {
                if let Some(orig) = hook(fn_ptr, team_stadium_result_hook as *const () as usize) {
                    ORIG_TEAM_STADIUM_RESULT = orig;
                    log!(
                        "TeamTrials hook installed on {}.{}",
                        result.class_name,
                        result.method_name
                    );
                } else {
                    log!("Failed to install TeamTrials hook");
                }
            } else {
                log!("TeamTrials candidate method pointer is null");
            }
        }
    }
}

unsafe fn install_race_info_probe_hooks(race_info_class: *mut crate::il2cpp::RawIl2CppClass) {
    install_race_info_probe_hook(race_info_class, 0, c"get_RaceTrackId".as_ptr());
    install_race_info_probe_hook(race_info_class, 2, c"get_RaceType".as_ptr());
    install_race_info_probe_hook(race_info_class, 4, c"get_ResultHorseIndex".as_ptr());
    install_race_info_probe_hook(race_info_class, 5, c"get_GroundCondition".as_ptr());
    install_race_info_probe_hook(race_info_class, 7, c"get_CourseDistanceType".as_ptr());
}

unsafe fn install_race_manager_probe_hook(
    race_manager_class: *mut crate::il2cpp::RawIl2CppClass,
) {
    let get_race_info =
        crate::il2cpp::FN_CLASS_GET_METHOD_FROM_NAME.unwrap()(race_manager_class, c"get_RaceInfo".as_ptr(), 0);
    if !get_race_info.is_null() {
        RACE_MANAGER_GET_RACE_INFO_METHOD = get_race_info as usize;
        RACE_MANAGER_GET_RACE_INFO_ADDR = method_addr(get_race_info);
        let get_race_info_addr = RACE_MANAGER_GET_RACE_INFO_ADDR;
        log!(
            "[RaceManager] get_RaceInfo addr={:#x}",
            get_race_info_addr
        );
    } else {
        log!("[RaceManager] get_RaceInfo method not found.");
    }

    let fn_ptr = find_method_addr_by_name(race_manager_class, c"GetPlayerHorseIndex".as_ptr(), 0);
    if fn_ptr == 0 {
        log!("[RaceManager] GetPlayerHorseIndex method not found.");
        return;
    }

    log!("[RaceManager] GetPlayerHorseIndex addr={:#x}", fn_ptr);
    if let Some(orig) = hook(fn_ptr, race_manager_get_player_horse_index_hook as usize) {
        ORIG_RACE_MANAGER_GET_PLAYER_HORSE_INDEX = orig;
        log!("[RaceManager] Hook installed on Gallop.RaceManager.GetPlayerHorseIndex");
    } else {
        log!("[RaceManager] Failed to install GetPlayerHorseIndex hook");
    }
}

unsafe fn install_race_info_probe_hook(
    race_info_class: *mut crate::il2cpp::RawIl2CppClass,
    slot: usize,
    method_name: *const std::ffi::c_char,
) {
    let hook_name = RACE_INFO_HOOK_NAMES[slot];
    let fn_ptr = find_method_addr_by_name(race_info_class, method_name, 0);
    if fn_ptr == 0 {
        log!("[RaceInfo] Probe method {} not found.", hook_name);
        return;
    }

    log!("[RaceInfo] Probe method {} addr={:#x}", hook_name, fn_ptr);
    if let Some(orig) = hook(fn_ptr, RACE_INFO_HOOK_FNS[slot] as usize) {
        RACE_INFO_HOOK_ORIGS[slot] = orig;
        log!(
            "[RaceInfo] Probe hook installed on Gallop.RaceInfo.{}",
            hook_name
        );
    } else {
        log!(
            "[RaceInfo] Failed to install probe hook on Gallop.RaceInfo.{}",
            hook_name
        );
    }
}

unsafe fn install_race_info_object_probe_hooks(
    race_info_class: *mut crate::il2cpp::RawIl2CppClass,
) {
    install_race_info_object_probe_hook(race_info_class, 0, c"get_SimDataBase64".as_ptr());
    install_race_info_object_probe_hook(race_info_class, 1, c"get_SimData".as_ptr());
    install_race_info_object_probe_hook(race_info_class, 2, c"get_RaceHorse".as_ptr());
}

unsafe fn install_race_info_object_probe_hook(
    race_info_class: *mut crate::il2cpp::RawIl2CppClass,
    slot: usize,
    method_name: *const std::ffi::c_char,
) {
    let hook_name = RACE_INFO_OBJECT_HOOK_NAMES[slot];
    let fn_ptr = find_method_addr_by_name(race_info_class, method_name, 0);
    if fn_ptr == 0 {
        log!("[RaceInfo] Object probe method {} not found.", hook_name);
        return;
    }

    log!(
        "[RaceInfo] Object probe method {} addr={:#x}",
        hook_name,
        fn_ptr
    );
    if let Some(orig) = hook(fn_ptr, RACE_INFO_OBJECT_HOOK_FNS[slot] as usize) {
        RACE_INFO_OBJECT_HOOK_ORIGS[slot] = orig;
        log!(
            "[RaceInfo] Object probe hook installed on Gallop.RaceInfo.{}",
            hook_name
        );
    } else {
        log!(
            "[RaceInfo] Failed to install object probe hook on Gallop.RaceInfo.{}",
            hook_name
        );
    }
}

unsafe fn install_race_info_sim_data_write_hooks(
    race_info_class: *mut crate::il2cpp::RawIl2CppClass,
) {
    let setter = find_method_addr_by_name(race_info_class, c"set_SimDataBase64".as_ptr(), 1);
    if setter != 0 {
        log!("[RaceInfo] set_SimDataBase64 addr={:#x}", setter);
        if let Some(orig) = hook(setter, set_sim_data_base64_hook as usize) {
            ORIG_SET_SIM_DATA_BASE64 = orig;
            log!("[RaceInfo] Hook installed on Gallop.RaceInfo.set_SimDataBase64");
        } else {
            log!("[RaceInfo] Failed to install set_SimDataBase64 hook");
        }
    } else {
        log!("[RaceInfo] set_SimDataBase64 method not found.");
    }

    let deserializer =
        find_method_addr_by_name(race_info_class, c"SetAndDeserializeBase64".as_ptr(), 1);
    if deserializer != 0 {
        log!(
            "[RaceInfo] SetAndDeserializeBase64 addr={:#x}",
            deserializer
        );
        if let Some(orig) = hook(deserializer, set_and_deserialize_base64_hook as usize) {
            ORIG_SET_AND_DESERIALIZE_BASE64 = orig;
            log!("[RaceInfo] Hook installed on Gallop.RaceInfo.SetAndDeserializeBase64");
        } else {
            log!("[RaceInfo] Failed to install SetAndDeserializeBase64 hook");
        }
    } else {
        log!("[RaceInfo] SetAndDeserializeBase64 method not found.");
    }
}

unsafe fn install_endpoint_hooks(
    target_image: *mut RawIl2CppImage,
    endpoints: &[crate::config::EndpointConfig],
) {
    fn is_generated(s: &str) -> bool {
        s.contains('<')
    }

    let mut slot = 0;
    for endpoint in endpoints {
        if slot >= MAX_API_HOOKS {
            log!(
                "WARNING: Maximum of {} API hooks reached, skipping remaining endpoints.",
                MAX_API_HOOKS
            );
            break;
        }
        let results = find_methods_in_assembly_by_param(target_image, &endpoint.name);
        let result = results
            .iter()
            .find(|r| !is_generated(&r.method_name) && !is_generated(&r.class_name))
            .or_else(|| results.first());

        if let Some(result) = result {
            let fn_ptr = method_addr(result.method);
            if fn_ptr != 0 {
                if let Some(orig) = hook(fn_ptr, API_HOOK_FNS[slot] as usize) {
                    API_HOOK_ORIGS[slot] = orig;
                    log!(
                        "[{}] Hook installed on {}.{}",
                        endpoint.name,
                        result.class_name,
                        result.method_name
                    );
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
