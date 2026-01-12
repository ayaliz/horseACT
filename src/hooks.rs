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

pub unsafe extern "C" fn race_info_hook(
    this: *mut RawIl2CppObject,
    method: *const RawMethodInfo
) -> i32 {

    let current_addr = this as usize;
    let last_addr = LAST_DUMPED_PTR.load(Ordering::SeqCst);

    // Only dump if new instance
    if !this.is_null() && current_addr != last_addr {

        LAST_DUMPED_PTR.store(current_addr, Ordering::SeqCst);
        log!("[RaceInfo] New Instance ({:p}). Dumping...", this);

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