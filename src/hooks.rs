use std::collections::HashSet;
use std::ffi::{c_void, CStr};
use std::mem::transmute;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::il2cpp::*;
use crate::log;
use crate::persistence::{save_race_info, save_team_trial_result, save_veteran_data};
use crate::reflection::convert_object_to_value;

pub static mut ORIG_VETERAN_APPLY: usize = 0;
pub static mut ORIG_TEAM_STADIUM_RESULT: usize = 0;
pub static mut ORIG_RACE_INITIALIZER_CREATE_RACE_INFO: usize = 0;
pub static mut ORIG_RACE_UTIL_SET_TRAINED_CHARA_DATA: usize = 0;
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
static PENDING_TRAINED_CHARA_RACE_PTR: AtomicUsize = AtomicUsize::new(0);
static LOGGED_NULL_THIS: AtomicBool = AtomicBool::new(false);
static LOGGED_SIMDATA_FIELD_MISSING: AtomicBool = AtomicBool::new(false);
static NON_RACEINFO_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static NULL_SIMDATA_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static mut LAST_SIM_DATA_PTR: usize = 0;
static mut SIM_DATA_OFFSET: i32 = -1;

#[derive(Clone)]
struct CachedTrainedChara {
    viewer_id: i64,
    trained_chara_id: i32,
    value: Value,
}

struct TrainedCharaCache {
    captured_at: Instant,
    entries: Vec<CachedTrainedChara>,
}

static TRAINED_CHARA_CACHE: Mutex<Option<TrainedCharaCache>> = Mutex::new(None);
const TRAINED_CHARA_CACHE_MAX_AGE: Duration = Duration::from_secs(30 * 60);

pub unsafe extern "C" fn race_util_set_trained_chara_data_hook(
    trained_chara_array: *mut RawIl2CppObject,
    method: *const RawMethodInfo,
) {
    cache_trained_chara_array(trained_chara_array);

    if ORIG_RACE_UTIL_SET_TRAINED_CHARA_DATA != 0 {
        let orig: StaticObjectArgHookFn = transmute(ORIG_RACE_UTIL_SET_TRAINED_CHARA_DATA);
        orig(trained_chara_array, method);
    }

    let pending = PENDING_TRAINED_CHARA_RACE_PTR.swap(0, Ordering::SeqCst);
    if pending == 0 {
        return;
    }

    let race_info = get_current_race_info();
    if race_info as usize != pending {
        log!(
            "[RaceInfoEnrichment] SetTrainedCharaData arrived, but current RaceInfo {:p} did not match pending RaceInfo {:#x}.",
            race_info,
            pending
        );
        return;
    }

    log!(
        "[RaceInfoEnrichment] SetTrainedCharaData applied; refreshing pending RaceInfo {:p}.",
        race_info
    );
    inspect_race_info_candidate(
        race_info,
        "RaceUtil.SetTrainedCharaData",
        0,
        std::ptr::null_mut(),
        true,
    );
}

unsafe fn cache_trained_chara_array(trained_chara_array: *mut RawIl2CppObject) {
    if trained_chara_array.is_null() {
        log!("[RaceInfoEnrichment] RaceUtil.SetTrainedCharaData received a null array.");
        return;
    }

    let len = FN_ARRAY_LENGTH.unwrap()(trained_chara_array as *mut RawIl2CppArray) as usize;
    let data_start = (trained_chara_array as *mut u8).add(32) as *const *mut RawIl2CppObject;
    let sensitive_fields = ["succession_history_array".to_string()];
    let mut entries = Vec::with_capacity(len);

    for index in 0..len {
        let trained_chara = *data_start.add(index);
        if trained_chara.is_null() {
            continue;
        }

        let Some(trained_chara_id) = read_i32_field(trained_chara, "trained_chara_id") else {
            continue;
        };
        let viewer_id = read_i64_field(trained_chara, "viewer_id").unwrap_or(0);
        let mut visited = HashSet::new();
        let value = convert_object_to_value(trained_chara, 0, &mut visited, &sensitive_fields);
        entries.push(CachedTrainedChara {
            viewer_id,
            trained_chara_id,
            value,
        });
    }

    let captured = entries.len();
    match TRAINED_CHARA_CACHE.lock() {
        Ok(mut cache) => {
            let existing = cache
                .take()
                .filter(|existing| existing.captured_at.elapsed() <= TRAINED_CHARA_CACHE_MAX_AGE);
            let mut merged = existing
                .map(|existing| existing.entries)
                .unwrap_or_default();
            for entry in entries {
                if let Some(old) = merged.iter_mut().find(|old| {
                    old.viewer_id == entry.viewer_id
                        && old.trained_chara_id == entry.trained_chara_id
                }) {
                    *old = entry;
                } else {
                    merged.push(entry);
                }
            }
            let total = merged.len();
            *cache = Some(TrainedCharaCache {
                captured_at: Instant::now(),
                entries: merged,
            });
            log!(
                "[RaceInfoEnrichment] Captured {}/{} entries from RaceUtil.SetTrainedCharaData; cache now has {} entries.",
                captured,
                len,
                total
            );
        }
        Err(_) => {
            log!("[RaceInfoEnrichment] Trained-character cache lock was poisoned.");
        }
    }
}

fn cached_trained_chara(viewer_id: i64, trained_chara_id: i32) -> Option<Value> {
    let cache = TRAINED_CHARA_CACHE.lock().ok()?;
    let cache = cache.as_ref()?;
    if cache.captured_at.elapsed() > TRAINED_CHARA_CACHE_MAX_AGE {
        return None;
    }

    if viewer_id != 0 {
        return cache
            .entries
            .iter()
            .find(|entry| {
                entry.trained_chara_id == trained_chara_id && entry.viewer_id == viewer_id
            })
            .map(|entry| entry.value.clone());
    }

    let mut matches = cache
        .entries
        .iter()
        .filter(|entry| entry.trained_chara_id == trained_chara_id);
    let first = matches.next()?;
    matches.next().is_none().then(|| first.value.clone())
}

fn enrich_cached_trained_chara_in_json(value: &mut Value) -> (usize, usize) {
    fn visit(value: &mut Value, matched: &mut usize, candidates: &mut usize) {
        match value {
            Value::Array(items) => {
                for item in items {
                    visit(item, matched, candidates);
                }
            }
            Value::Object(map) => {
                for child in map.values_mut() {
                    visit(child, matched, candidates);
                }

                let is_horse_data = map.contains_key("trained_chara_id")
                    && map.contains_key("card_id")
                    && map.contains_key("skill_array");
                let already_enriched = map.contains_key("trained_chara_data")
                    || map.contains_key("trainedCharaData")
                    || map.contains_key("<TrainedCharaData>k__BackingField");

                if is_horse_data && !already_enriched {
                    *candidates += 1;
                    let trained_chara_id = map
                        .get("trained_chara_id")
                        .and_then(Value::as_i64)
                        .and_then(|id| i32::try_from(id).ok());
                    let viewer_id = map.get("viewer_id").and_then(Value::as_i64).unwrap_or(0);
                    if let Some(trained_chara) =
                        trained_chara_id.and_then(|id| cached_trained_chara(viewer_id, id))
                    {
                        map.insert("trained_chara_data".to_string(), trained_chara);
                        *matched += 1;
                    }
                }
            }
            _ => {}
        }
    }

    let mut matched = 0;
    let mut candidates = 0;
    visit(value, &mut matched, &mut candidates);
    (matched, candidates)
}

fn remove_json_field(value: &mut Value, field_name: &str) {
    match value {
        Value::Array(items) => {
            for item in items {
                remove_json_field(item, field_name);
            }
        }
        Value::Object(map) => {
            map.remove(field_name);
            for child in map.values_mut() {
                remove_json_field(child, field_name);
            }
        }
        _ => {}
    }
}

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

    let trained_chara_accessor =
        read_object_field(load_race_info, "<TrainedCharaDataAccessor>k__BackingField");
    if trained_chara_accessor.is_null() {
        log!("[RaceInfoEnrichment] LoadRaceInfo has no trained-character accessor.");
    } else {
        let accessor_class = FN_OBJECT_GET_CLASS.unwrap()(trained_chara_accessor);
        log!(
            "[RaceInfoEnrichment] Captured accessor {:p} ({})",
            trained_chara_accessor,
            class_name(accessor_class)
        );
    }

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
        if trained_chara_accessor.is_null() {
            PENDING_TRAINED_CHARA_RACE_PTR.store(race_info as usize, Ordering::SeqCst);
        } else {
            PENDING_TRAINED_CHARA_RACE_PTR.store(0, Ordering::SeqCst);
        }
        inspect_race_info_candidate(
            race_info,
            "RaceInitializer.CreateRaceInfo",
            0,
            trained_chara_accessor,
            false,
        );
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

unsafe fn find_instance_field(
    mut klass: *mut RawIl2CppClass,
    field_name: &str,
) -> *mut RawFieldInfo {
    while !klass.is_null() {
        let mut iter = std::ptr::null_mut();
        loop {
            let field = FN_CLASS_GET_FIELDS.unwrap()(klass, &mut iter);
            if field.is_null() {
                break;
            }
            if FN_FIELD_GET_FLAGS.unwrap()(field) & FIELD_ATTRIBUTE_STATIC != 0 {
                continue;
            }

            let name_ptr = FN_FIELD_GET_NAME.unwrap()(field);
            if !name_ptr.is_null() && CStr::from_ptr(name_ptr).to_bytes() == field_name.as_bytes() {
                return field;
            }
        }
        klass = FN_CLASS_GET_PARENT.unwrap()(klass);
    }
    std::ptr::null_mut()
}

unsafe fn field_addr(obj: *mut RawIl2CppObject, field_name: &str) -> *mut u8 {
    if obj.is_null() {
        return std::ptr::null_mut();
    }
    let klass = FN_OBJECT_GET_CLASS.unwrap()(obj);
    let field = find_instance_field(klass, field_name);
    if field.is_null() {
        return std::ptr::null_mut();
    }
    (obj as *mut u8).add(FN_FIELD_GET_OFFSET.unwrap()(field))
}

unsafe fn read_object_field(obj: *mut RawIl2CppObject, field_name: &str) -> *mut RawIl2CppObject {
    let addr = field_addr(obj, field_name);
    if addr.is_null() {
        std::ptr::null_mut()
    } else {
        *(addr as *const *mut RawIl2CppObject)
    }
}

unsafe fn read_i32_field(obj: *mut RawIl2CppObject, field_name: &str) -> Option<i32> {
    let addr = field_addr(obj, field_name);
    (!addr.is_null()).then(|| *(addr as *const i32))
}

unsafe fn read_i64_field(obj: *mut RawIl2CppObject, field_name: &str) -> Option<i64> {
    let addr = field_addr(obj, field_name);
    (!addr.is_null()).then(|| *(addr as *const i64))
}

unsafe fn invoke_trained_chara_accessor(
    accessor: *mut RawIl2CppObject,
    viewer_id: i64,
    trained_chara_id: i32,
) -> *mut RawIl2CppObject {
    if accessor.is_null() {
        return std::ptr::null_mut();
    }

    let klass = FN_OBJECT_GET_CLASS.unwrap()(accessor);
    if klass.is_null() {
        return std::ptr::null_mut();
    }

    let two_arg = FN_CLASS_GET_METHOD_FROM_NAME.unwrap()(klass, c"GetTrainedCharaData".as_ptr(), 2);
    if !two_arg.is_null() {
        let mut viewer_id_arg = viewer_id;
        let mut trained_chara_id_arg = trained_chara_id;
        let mut args = [
            &mut viewer_id_arg as *mut i64 as *mut c_void,
            &mut trained_chara_id_arg as *mut i32 as *mut c_void,
        ];
        let mut exception = std::ptr::null_mut();
        let result =
            FN_RUNTIME_INVOKE.unwrap()(two_arg, accessor, args.as_mut_ptr(), &mut exception);
        if exception.is_null() && !result.is_null() {
            return result;
        }
        if !exception.is_null() {
            log!(
                "[RaceInfoEnrichment] Two-argument accessor threw for viewer_id={}, trained_chara_id={} (exception={:p}).",
                viewer_id,
                trained_chara_id,
                exception
            );
        }
    }

    let one_arg = FN_CLASS_GET_METHOD_FROM_NAME.unwrap()(klass, c"GetTrainedCharaData".as_ptr(), 1);
    if one_arg.is_null() {
        return std::ptr::null_mut();
    }

    let mut trained_chara_id_arg = trained_chara_id;
    let mut args = [&mut trained_chara_id_arg as *mut i32 as *mut c_void];
    let mut exception = std::ptr::null_mut();
    let result = FN_RUNTIME_INVOKE.unwrap()(one_arg, accessor, args.as_mut_ptr(), &mut exception);
    if !exception.is_null() {
        log!(
            "[RaceInfoEnrichment] One-argument accessor threw for trained_chara_id={} (exception={:p}).",
            trained_chara_id,
            exception
        );
        return std::ptr::null_mut();
    }
    result
}

unsafe fn enrich_trained_chara_data(
    race_info: *mut RawIl2CppObject,
    accessor: *mut RawIl2CppObject,
    value: &mut Value,
) {
    let horse_array = read_object_field(race_info, "<RaceHorse>k__BackingField");
    let Some(json_horses) = value
        .get_mut("<RaceHorse>k__BackingField")
        .and_then(Value::as_array_mut)
    else {
        log!("[RaceInfoEnrichment] Converted RaceInfo has no RaceHorse array.");
        return;
    };

    if horse_array.is_null() {
        log!("[RaceInfoEnrichment] Live RaceInfo has a null RaceHorse array.");
        return;
    }

    let horse_count = FN_ARRAY_LENGTH.unwrap()(horse_array as *mut RawIl2CppArray) as usize;
    let data_start = (horse_array as *mut u8).add(32) as *const *mut RawIl2CppObject;
    let mut already_present = 0usize;
    let mut resolved_from_accessor = 0usize;
    let mut resolved_from_cache = 0usize;
    let mut unresolved = 0usize;

    for index in 0..horse_count.min(json_horses.len()) {
        let horse = *data_start.add(index);
        if horse.is_null() {
            unresolved += 1;
            continue;
        }

        let existing = read_object_field(horse, "<TrainedCharaData>k__BackingField");
        if !existing.is_null() {
            already_present += 1;
            continue;
        }

        let response_horse = read_object_field(horse, "_responseHorseData");
        let Some(trained_chara_id) = read_i32_field(response_horse, "trained_chara_id") else {
            unresolved += 1;
            continue;
        };
        let viewer_id = read_i64_field(response_horse, "viewer_id").unwrap_or(0);
        let trained_chara = invoke_trained_chara_accessor(accessor, viewer_id, trained_chara_id);
        let trained_value = if !trained_chara.is_null() {
            let mut visited = HashSet::new();
            resolved_from_accessor += 1;
            convert_object_to_value(trained_chara, 0, &mut visited, &[])
        } else if let Some(cached) = cached_trained_chara(viewer_id, trained_chara_id) {
            resolved_from_cache += 1;
            cached
        } else {
            unresolved += 1;
            continue;
        };

        if let Some(horse_map) = json_horses[index].as_object_mut() {
            horse_map.insert(
                "<TrainedCharaData>k__BackingField".to_string(),
                trained_value,
            );
        } else {
            if !trained_chara.is_null() {
                resolved_from_accessor -= 1;
            } else {
                resolved_from_cache -= 1;
            }
            unresolved += 1;
        }
    }

    log!(
        "[RaceInfoEnrichment] horses={}, already_present={}, accessor_resolved={}, cache_resolved={}, unresolved={}, accessor={:p}",
        horse_count,
        already_present,
        resolved_from_accessor,
        resolved_from_cache,
        unresolved,
        accessor
    );
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
    trained_chara_accessor: *mut RawIl2CppObject,
    force_dump: bool,
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
    let should_dump =
        force_dump || current_addr != last_addr || current_sim_ptr != unsafe { LAST_SIM_DATA_PTR };

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
                let mut val = convert_object_to_value(this, 0, &mut visited, &[]);
                enrich_trained_chara_data(this, trained_chara_accessor, &mut val);
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
    let mut val = convert_object_to_value(response, 0, &mut visited, &["viewer_id".to_string()]);
    let (matched, candidates) = enrich_cached_trained_chara_in_json(&mut val);
    remove_json_field(&mut val, "viewer_id");
    log!(
        "[TeamTrials] Trained-character enrichment matched {}/{} horse records.",
        matched,
        candidates
    );
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
