use std::collections::HashSet;
use std::ffi::CStr;
use std::mem::transmute;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::il2cpp::*;
use crate::log;
use crate::persistence::{save_race_info, save_team_trial_result, save_veteran_data};
use crate::reflection::convert_object_to_value;

pub static mut ORIG_VETERAN_APPLY: usize = 0;
pub static mut ORIG_TEAM_STADIUM_RESULT: usize = 0;
pub static mut ORIG_RACE_INITIALIZER_CREATE_RACE_INFO: usize = 0;
pub static mut RACE_MANAGER_GET_RACE_INFO_ADDR: usize = 0;
pub static mut RACE_MANAGER_GET_RACE_INFO_METHOD: usize = 0;

pub const MAX_API_HOOKS: usize = 8;
pub static mut API_HOOK_ORIGS: [usize; MAX_API_HOOKS] = [0; MAX_API_HOOKS];

type StaticRaceInfoGetterFn = unsafe extern "C" fn(*const RawMethodInfo) -> *mut RawIl2CppObject;
type StaticObjectArgHookFn = unsafe extern "C" fn(*mut RawIl2CppObject, *const RawMethodInfo);
type ApiHookFn =
    unsafe extern "C" fn(*mut RawIl2CppObject, *mut RawIl2CppObject, *const RawMethodInfo);

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
            if response.is_null() {
                return;
            }
            let endpoint_config = &crate::api::endpoint_configs()[$idx];
            let mut visited = HashSet::new();
            let val = convert_object_to_value(
                response,
                0,
                &mut visited,
                &endpoint_config.sensitive_fields,
            );
            crate::api::dispatch(&endpoint_config.name, val);
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
    api_hook_slot_0,
    api_hook_slot_1,
    api_hook_slot_2,
    api_hook_slot_3,
    api_hook_slot_4,
    api_hook_slot_5,
    api_hook_slot_6,
    api_hook_slot_7,
];

static LAST_DUMPED_PTR: AtomicUsize = AtomicUsize::new(0);
static LOGGED_NULL_THIS: AtomicBool = AtomicBool::new(false);
static LOGGED_SIMDATA_FIELD_MISSING: AtomicBool = AtomicBool::new(false);
static NON_RACEINFO_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static NULL_SIMDATA_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static mut LAST_SIM_DATA_PTR: usize = 0;
static mut SIM_DATA_OFFSET: i32 = -1;

unsafe fn get_current_race_info() -> *mut RawIl2CppObject {
    if RACE_MANAGER_GET_RACE_INFO_ADDR == 0 || RACE_MANAGER_GET_RACE_INFO_METHOD == 0 {
        return std::ptr::null_mut();
    }

    let getter: StaticRaceInfoGetterFn = transmute(RACE_MANAGER_GET_RACE_INFO_ADDR);
    getter(RACE_MANAGER_GET_RACE_INFO_METHOD as *const RawMethodInfo)
}

pub unsafe extern "C" fn race_initializer_create_race_info_hook(
    load_race_info: *mut RawIl2CppObject,
    method: *const RawMethodInfo,
) {
    log!(
        "[RaceInitializer] Entered CreateRaceInfo(loadRaceInfo={:p}).",
        load_race_info
    );

    if ORIG_RACE_INITIALIZER_CREATE_RACE_INFO != 0 {
        let orig: StaticObjectArgHookFn = transmute(ORIG_RACE_INITIALIZER_CREATE_RACE_INFO);
        orig(load_race_info, method);
    }

    let race_info = get_current_race_info();
    log!(
        "[RaceInitializer] CreateRaceInfo returned; stored RaceInfo={:p}.",
        race_info
    );
    if !race_info.is_null() {
        inspect_race_info_candidate(race_info, "RaceInitializer.CreateRaceInfo", 0);
    }
}

unsafe fn class_name(klass: *mut RawIl2CppClass) -> String {
    if klass.is_null() {
        return "<null class>".to_string();
    }

    let name_ptr = FN_CLASS_GET_NAME.unwrap()(klass);
    if name_ptr.is_null() {
        return "<null class name>".to_string();
    }

    CStr::from_ptr(name_ptr).to_string_lossy().to_string()
}

pub unsafe fn log_class_fields(klass: *mut RawIl2CppClass, label: &str) {
    if klass.is_null() {
        log!("[Debug] {} field dump skipped: class is null", label);
        return;
    }

    log!("[Debug] Fields for {} ({})", label, class_name(klass));
    let mut iter = std::ptr::null_mut();
    let mut count = 0usize;
    loop {
        let field = FN_CLASS_GET_FIELDS.unwrap()(klass, &mut iter);
        if field.is_null() {
            break;
        }

        count += 1;
        let name_ptr = FN_FIELD_GET_NAME.unwrap()(field);
        let field_name = if name_ptr.is_null() {
            "<null field name>".to_string()
        } else {
            CStr::from_ptr(name_ptr).to_string_lossy().to_string()
        };
        let offset = FN_FIELD_GET_OFFSET.unwrap()(field);
        let flags = FN_FIELD_GET_FLAGS.unwrap()(field);
        let ftype = FN_FIELD_GET_TYPE.unwrap()(field);
        let type_enum = if ftype.is_null() {
            -1
        } else {
            FN_TYPE_GET_TYPE.unwrap()(ftype)
        };
        log!(
            "[Debug] Field {}.{} offset={} flags={:#x} type_enum={:#x}",
            class_name(klass),
            field_name,
            offset,
            flags,
            type_enum
        );
    }
    log!("[Debug] Field count for {}: {}", label, count);
}

pub unsafe fn cache_race_info_sim_data_offset(klass: *mut RawIl2CppClass) {
    if klass.is_null() {
        log!("[RaceInfo] Cannot cache SimData offset: RaceInfo class is null.");
        return;
    }

    let mut iter = std::ptr::null_mut();
    loop {
        let field = FN_CLASS_GET_FIELDS.unwrap()(klass, &mut iter);
        if field.is_null() {
            break;
        }

        let fname_ptr = FN_FIELD_GET_NAME.unwrap()(field);
        if fname_ptr.is_null() {
            continue;
        }

        let fname = CStr::from_ptr(fname_ptr).to_string_lossy();
        if fname == "<SimDataBase64>k__BackingField" {
            let offset = FN_FIELD_GET_OFFSET.unwrap()(field) as i32;
            SIM_DATA_OFFSET = offset;
            log!("[RaceInfo] Cached SimData offset: {}", offset);
            return;
        }
    }

    log!("[RaceInfo] Failed to cache SimData offset from RaceInfo class.");
}

unsafe fn inspect_race_info_candidate(
    this: *mut RawIl2CppObject,
    hook_name: &str,
    return_ptr: usize,
) {
    if this.is_null() {
        if !LOGGED_NULL_THIS.swap(true, Ordering::SeqCst) {
            log!(
                "[RaceInfo] Hook '{}' called with null this pointer.",
                hook_name
            );
        }
        return;
    }

    let klass = FN_OBJECT_GET_CLASS.unwrap()(this);
    if klass.is_null() {
        log!(
            "[RaceInfo] Hook '{}' target object class is null; this={:p}",
            hook_name,
            this
        );
        return;
    }

    let name = class_name(klass);
    if !name.contains("RaceInfo") {
        let count = NON_RACEINFO_LOG_COUNT.fetch_add(1, Ordering::SeqCst);
        if count < 20 {
            log!(
                "[RaceInfo] Hook '{}' target object class was '{}' instead of RaceInfo; this={:p}",
                hook_name,
                name,
                this
            );
        }
        return;
    }

    if unsafe { SIM_DATA_OFFSET } == -1 {
        if !LOGGED_SIMDATA_FIELD_MISSING.swap(true, Ordering::SeqCst) {
            log!(
                "[RaceInfo] Cannot inspect RaceInfo from '{}': SimData offset is not cached.",
                hook_name
            );
            log_class_fields(klass, "runtime RaceInfo");
        }
        return;
    }

    let current_addr = this as usize;
    let last_addr = LAST_DUMPED_PTR.load(Ordering::SeqCst);
    let val_addr = (current_addr as isize + unsafe { SIM_DATA_OFFSET } as isize) as *const usize;
    let current_sim_ptr = unsafe { *val_addr };

    if current_sim_ptr == 0 {
        let count = NULL_SIMDATA_LOG_COUNT.fetch_add(1, Ordering::SeqCst);
        if count < 100 || hook_name == "get_SimDataBase64" || hook_name == "get_SimData" {
            log!(
                "[RaceInfo] RaceInfo via {} has null SimData (this={:p}, return_ptr={:#x})",
                hook_name,
                this,
                return_ptr
            );
        }
        return;
    }

    // It is a new race if:
    // 1. The object address changed
    // 2. The object address is reused, BUT the SimData pointer changed (apparently this is a thing that can happen)
    let should_dump = current_addr != last_addr || current_sim_ptr != unsafe { LAST_SIM_DATA_PTR };

    if should_dump {
        log!(
            "[RaceInfo] New Candidate Found via {} ({:p}). SimDataPtr: {:#x}, return_ptr={:#x}",
            hook_name,
            this,
            current_sim_ptr,
            return_ptr
        );

        let domain = FN_DOMAIN_GET.unwrap()();
        let mut thread = FN_THREAD_CURRENT.unwrap()();
        let mut manually_attached = false;

        if thread.is_null() && !domain.is_null() {
            thread = FN_THREAD_ATTACH.unwrap()(domain);
            manually_attached = true;
        }

        if !thread.is_null() {
            let _ = std::panic::catch_unwind(|| {
                LAST_DUMPED_PTR.store(current_addr, Ordering::SeqCst);
                unsafe {
                    LAST_SIM_DATA_PTR = current_sim_ptr;
                }

                log!("[RaceInfo] Dumping valid race data...");

                let mut visited = HashSet::new();
                let val = convert_object_to_value(this, 0, &mut visited, &[]);
                save_race_info(val);

                log!("[RaceInfo] Dump Complete.");
            })
            .map_err(|_| {
                log!("[RaceInfo] Panic while inspecting RaceInfo candidate.");
            })
            .ok();
        } else {
            log!(
                "[RaceInfo] Could not inspect candidate: thread is null after attach attempt (domain_null={}).",
                domain.is_null()
            );
        }

        if manually_attached {
            FN_THREAD_DETACH.unwrap()(thread);
        }
    }
}

pub unsafe extern "C" fn team_stadium_result_hook(
    this: *mut RawIl2CppObject,
    response: *mut RawIl2CppObject,
    method: *const RawMethodInfo,
) {
    if ORIG_TEAM_STADIUM_RESULT != 0 {
        let orig: ApiHookFn = transmute(ORIG_TEAM_STADIUM_RESULT);
        orig(this, response, method);
    }

    if response.is_null() {
        log!("[TeamTrials] CommonResponse is null; skipping.");
        return;
    }

    let mut visited = HashSet::new();
    let val = convert_object_to_value(response, 0, &mut visited, &[]);
    save_team_trial_result(val);
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
    let array_data = convert_object_to_value(trained_chara_array, 0, &mut visited, &[]);

    if array_data.is_null() {
        log!("[Veteran] Error: Failed to convert TrainedChara array to JSON");
        return;
    }

    save_veteran_data(array_data);
}
