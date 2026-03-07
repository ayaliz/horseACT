use std::ffi::CStr;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::mem::transmute;

use crate::il2cpp::*;
use crate::persistence::save_race_info;
use crate::reflection::convert_object_to_value;
use crate::log;

pub static mut ORIG_GET_RACE_TRACK_ID: usize = 0;

pub const MAX_API_HOOKS: usize = 8;
pub static mut API_HOOK_ORIGS: [usize; MAX_API_HOOKS] = [0; MAX_API_HOOKS];

type ApiHookFn = unsafe extern "C" fn(*mut RawIl2CppObject, *mut RawIl2CppObject, *const RawMethodInfo);

macro_rules! api_hook_slot {
    ($idx:expr, $fn_name:ident) => {
        unsafe extern "C" fn $fn_name(
            this: *mut RawIl2CppObject,
            response: *mut RawIl2CppObject,
            method: *const RawMethodInfo,
        ) {
            let orig = API_HOOK_ORIGS[$idx];
            if orig != 0 {
                let orig_fn: ApiHookFn = transmute(orig);
                orig_fn(this, response, method);
            }
            if response.is_null() { return; }
            let name = &crate::api::endpoint_configs()[$idx].name;
            let mut visited = HashSet::new();
            let val = convert_object_to_value(response, 0, &mut visited);
            crate::api::dispatch(name, val);
        }
    };
}

api_hook_slot!(0, api_hook_slot_0);
api_hook_slot!(1, api_hook_slot_1);
api_hook_slot!(2, api_hook_slot_2);
api_hook_slot!(3, api_hook_slot_3);
api_hook_slot!(4, api_hook_slot_4);
api_hook_slot!(5, api_hook_slot_5);
api_hook_slot!(6, api_hook_slot_6);
api_hook_slot!(7, api_hook_slot_7);

pub static API_HOOK_FNS: [ApiHookFn; MAX_API_HOOKS] = [
    api_hook_slot_0, api_hook_slot_1, api_hook_slot_2, api_hook_slot_3,
    api_hook_slot_4, api_hook_slot_5, api_hook_slot_6, api_hook_slot_7,
];

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

    if unsafe { SIM_DATA_OFFSET } != -1 {
        let val_addr = (current_addr as isize + unsafe { SIM_DATA_OFFSET } as isize) as *const usize;
        current_sim_ptr = unsafe { *val_addr };

        if current_sim_ptr != 0 {
            // It is a new race if:
            // 1. The object address changed
            // 2. The object address is reused, BUT the SimData pointer changed (apparently this is a thing that can happen)
            if current_addr != last_addr || current_sim_ptr != unsafe { LAST_SIM_DATA_PTR } {
                should_dump = true;
            }
        }
    } else {
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

                                     let val_addr = (current_addr as isize + unsafe { SIM_DATA_OFFSET } as isize) as *const usize;
                                     current_sim_ptr = *val_addr;
                                     break;
                                 }
                             }
                        }

                        if current_sim_ptr != 0 {
                            LAST_DUMPED_PTR.store(current_addr, Ordering::SeqCst);
                            unsafe { LAST_SIM_DATA_PTR = current_sim_ptr; }

                            log!("[RaceInfo] Dumping valid race data...");

                            let mut visited = HashSet::new();
                            let val = convert_object_to_value(this, 0, &mut visited);
                            save_race_info(val);

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
