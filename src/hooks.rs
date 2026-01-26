use std::ffi::{CStr, CString};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::mem::transmute;

use crate::il2cpp::*;
use crate::config::{dump_static_variable_define, dump_enums};
use crate::reflection::{convert_object_to_value, dump_class_recursive};
use crate::persistence::{save_race_info, save_enums as persist_enums, save_static_data, save_veteran_data};
use crate::log;

pub static mut ORIG_GET_RACE_TRACK_ID: usize = 0;
pub static mut ORIG_VETERAN_APPLY: usize = 0;
static LAST_DUMPED_PTR: AtomicUsize = AtomicUsize::new(0);
static mut LAST_SIM_DATA_PTR: usize = 0;
static mut SIM_DATA_OFFSET: i32 = -1;

pub unsafe extern "C" fn race_info_hook(
    this: *mut RawIl2CppObject,
    method: *const RawMethodInfo
) -> i32 {

    let current_addr = this as usize;
    let last_addr = LAST_DUMPED_PTR.load(Ordering::SeqCst);
    let mut current_sim_ptr: usize = 0;
    let mut should_dump = false;

    // Check if we can do a fast uniqueness check using SimData
    if unsafe { SIM_DATA_OFFSET } != -1 {
        // We have the offset, check the SimData pointer
        let val_addr = (current_addr as isize + unsafe { SIM_DATA_OFFSET } as isize) as *const usize;
        current_sim_ptr = unsafe { *val_addr };

        // If SimData is null, we definitely don't want to save (empty race data)
        if current_sim_ptr != 0 {
            // It is a new race if:
            // 1. The object address changed (standard case)
            // 2. The object address is reused, BUT the SimData pointer changed (fast restart/grind case)
            if current_addr != last_addr || current_sim_ptr != unsafe { LAST_SIM_DATA_PTR } {
                should_dump = true;
            }
        }
    } else {
        // Fallback: We haven't found the offset yet. Rely on address check.
        // This will only happen on the very first race or if offset lookup failed.
        if !this.is_null() && current_addr != last_addr {
            should_dump = true;
        }
    }

    if should_dump {
        log!("[RaceInfo] New Candidate Found ({:p}). SimDataPtr: {:#x}", this, current_sim_ptr);

        let domain = FN_DOMAIN_GET.unwrap()();
        let mut thread = FN_THREAD_CURRENT.unwrap()();
        let mut manually_attached = false;

        if thread.is_null() && !domain.is_null() {
            thread = FN_THREAD_ATTACH.unwrap()(domain);
            manually_attached = true;
        }

        if !thread.is_null() {
            let _ = std::panic::catch_unwind(|| {
                let klass = FN_OBJECT_GET_CLASS.unwrap()(this);
                if !klass.is_null() {
                    let name_ptr = FN_CLASS_GET_NAME.unwrap()(klass);
                    let name = CStr::from_ptr(name_ptr).to_string_lossy();

                    if name.contains("RaceInfo") {
                        let mut current_sim_ptr = current_sim_ptr;
                        // resolve offset if not yet found
                        if unsafe { SIM_DATA_OFFSET } == -1 {
                             let mut iter = std::ptr::null_mut();
                             loop {
                                 let field = FN_CLASS_GET_FIELDS.unwrap()(klass, &mut iter);
                                 if field.is_null() { break; }
                                 
                                 let fname_ptr = FN_FIELD_GET_NAME.unwrap()(field);
                                 let fname = CStr::from_ptr(fname_ptr).to_string_lossy();
                                 
                                 if fname == "<SimDataBase64>k__BackingField" {
                                     unsafe { SIM_DATA_OFFSET = FN_FIELD_GET_OFFSET.unwrap()(field) as i32; }
                                     log!("[RaceInfo] Found SimData offset: {}", unsafe { SIM_DATA_OFFSET });
                                     
                                     // Re-read sim ptr now that we have offset
                                     let val_addr = (current_addr as isize + unsafe { SIM_DATA_OFFSET } as isize) as *const usize;
                                     current_sim_ptr = *val_addr;
                                     break;
                                 }
                             }
                        }

                        // Final check before committing to dump
                        if current_sim_ptr != 0 {
                            LAST_DUMPED_PTR.store(current_addr, Ordering::SeqCst);
                            unsafe { LAST_SIM_DATA_PTR = current_sim_ptr; }

                            log!("[RaceInfo] Dumping valid race data...");

                            let mut visited = HashSet::new();
                            let val = convert_object_to_value(this, 0, &mut visited);
                            save_race_info(val);

                            if dump_static_variable_define() {
                                let image = FN_CLASS_GET_IMAGE.unwrap()(klass);
                                if !image.is_null() {
                                    let outer_ns = CString::new("Gallop").unwrap();
                                    let outer_name = CString::new("StaticVariableDefine").unwrap();

                                    let outer_class = FN_CLASS_FROM_NAME.unwrap()(
                                        image,
                                        outer_ns.as_ptr(),
                                        outer_name.as_ptr()
                                    );

                                    if !outer_class.is_null() {
                                        log!("[RaceInfo] Dumping full StaticVariableDefine hierarchy...");
                                        let all_statics = dump_class_recursive(outer_class, 0);
                                        save_static_data("StaticVariableDefine", all_statics);

                                    } else {
                                        log!("[Warning] Could not find Gallop.StaticVariableDefine");
                                    }
                                }
                            }

                            if dump_enums() {
                                persist_enums();
                            }

                            log!("[RaceInfo] Dump Complete.");
                        } else {
                            log!("[RaceInfo] Skipped dump: SimData is null (empty race)");
                        }
                    }
                }
            });
        }

        if manually_attached {
            FN_THREAD_DETACH.unwrap()(thread);
        }
    }

    if ORIG_GET_RACE_TRACK_ID != 0 {
        let orig: extern "C" fn(*mut RawIl2CppObject, *const RawMethodInfo) -> i32 =
            transmute(ORIG_GET_RACE_TRACK_ID);
        return orig(this, method);
    }

    0
}

pub unsafe extern "C" fn veteran_hook(
    this: *mut RawIl2CppObject,
    trained_chara_array: *mut RawIl2CppObject,
) {
    if ORIG_VETERAN_APPLY != 0 {
        let orig: extern "C" fn(*mut RawIl2CppObject, *mut RawIl2CppObject) =
            transmute(ORIG_VETERAN_APPLY);
        orig(this, trained_chara_array);
    }

    log!("[Veteran] Hook Triggered");

    if trained_chara_array.is_null() {
        log!("[Veteran] Error: TrainedChara array parameter is null");
        return;
    }

    let mut visited = HashSet::new();
    let array_data = convert_object_to_value(trained_chara_array, 0, &mut visited);

    if array_data.is_null() {
        log!("[Veteran] Error: Failed to convert TrainedChara array to JSON");
        return;
    }

    save_veteran_data(array_data);
}