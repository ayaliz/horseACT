use core::ffi::{c_void, CStr};
use std::{ptr, slice};
use std::sync::Mutex;
use std::collections::HashSet;
use serde_json::{Map, Number, Value};
use crate::il2cpp::*;
use crate::config::is_field_blacklisted;
use crate::log;

const MAX_OBJECT_DEPTH: usize = 50;
const MAX_ARRAY_LENGTH: u32 = 2000;

pub struct MethodSearchResult {
    pub method: *mut RawMethodInfo,
    pub class_name: String,
    pub method_name: String,
}

pub unsafe fn find_methods_in_assembly_by_param(
    image: *mut RawIl2CppImage,
    param_type_name: &str,
) -> Vec<MethodSearchResult> {
    let mut results = Vec::new();

    if image.is_null() {
        log!("Assembly scan failed: image is null");
        return results;
    }

    let class_count = FN_IMAGE_GET_CLASS_COUNT.unwrap()(image);
    log!("Scanning {} classes in assembly for methods taking '{}'...", class_count, param_type_name);

    for i in 0..class_count {
        let klass = FN_IMAGE_GET_CLASS.unwrap()(image, i);
        if klass.is_null() {
            continue;
        }

        let class_name_ptr = FN_CLASS_GET_NAME.unwrap()(klass);
        let class_name = CStr::from_ptr(class_name_ptr).to_string_lossy().to_string();

        if let Some(method) = find_method_taking_param_by_name(klass, param_type_name) {
            let method_name_ptr = FN_METHOD_GET_NAME.unwrap()(method);
            let method_name = CStr::from_ptr(method_name_ptr).to_string_lossy().to_string();

            log!("Found match: {}.{}", class_name, method_name);

            results.push(MethodSearchResult {
                method,
                class_name,
                method_name,
            });
        }
    }

    if results.is_empty() {
        log!("No methods found taking parameter type '{}'", param_type_name);
    } else {
        log!("Found {} matching method(s)", results.len());
    }

    results
}

unsafe fn find_method_taking_param_by_name(
    target_klass: *mut RawIl2CppClass,
    param_type_name: &str,
) -> Option<*mut RawMethodInfo> {
    if target_klass.is_null() {
        return None;
    }

    let mut iter: *mut c_void = ptr::null_mut();
    loop {
        let method = FN_CLASS_GET_METHODS.unwrap()(target_klass, &mut iter);
        if method.is_null() {
            break;
        }

        let param_count = FN_METHOD_GET_PARAM_COUNT.unwrap()(method);
        for i in 0..param_count {
            let p_type = FN_METHOD_GET_PARAM.unwrap()(method, i);
            let p_class = FN_CLASS_FROM_TYPE.unwrap()(p_type);

            if !p_class.is_null() {
                let class_name_ptr = FN_CLASS_GET_NAME.unwrap()(p_class);
                let class_name = CStr::from_ptr(class_name_ptr).to_string_lossy();

                if class_name.contains(param_type_name) {
                    return Some(method);
                }
            }
        }
    }
    None
}

pub static CAPTURED_ENUMS: Mutex<Option<Map<String, Value>>> = Mutex::new(None);

fn get_or_init_enum_cache() -> std::sync::MutexGuard<'static, Option<Map<String, Value>>> {
    let mut guard = CAPTURED_ENUMS.lock().unwrap();
    if guard.is_none() {
        *guard = Some(Map::new());
    }
    guard
}

// Deal with obfuscation
unsafe fn try_decrypt_obscured(
    struct_ptr: *mut c_void,
    klass: *mut RawIl2CppClass,
    class_name: &str
) -> Option<Value> {

    let mut hidden_off: Option<usize> = None;
    let mut key_off: Option<usize> = None;

    let mut iter: *mut c_void = ptr::null_mut();
    loop {
        let field = FN_CLASS_GET_FIELDS.unwrap()(klass, &mut iter);
        if field.is_null() { break; }

        let flags = FN_FIELD_GET_FLAGS.unwrap()(field);
        if (flags & FIELD_ATTRIBUTE_STATIC) != 0 { continue; }

        let name_ptr = FN_FIELD_GET_NAME.unwrap()(field);
        let name = CStr::from_ptr(name_ptr).to_string_lossy();

        let offset = FN_FIELD_GET_OFFSET.unwrap()(field);
        if offset < 0x10 { continue; }
        let raw_offset = offset - 0x10;

        match name.as_ref() {
            "hiddenValue" => hidden_off = Some(raw_offset),
            "currentCryptoKey" => key_off = Some(raw_offset),
            _ => {}
        }
    }

    let base = struct_ptr as *mut u8;

    if let (Some(h_off), Some(k_off)) = (hidden_off, key_off) {
        match class_name {
            "ObscuredInt" => {
                let hidden = *(base.add(h_off) as *const i32);
                let key = *(base.add(k_off) as *const i32);
                return Some(Value::Number(Number::from(hidden ^ key)));
            },
            "ObscuredLong" => {
                let hidden = *(base.add(h_off) as *const i64);
                let key = *(base.add(k_off) as *const i64);
                return Some(Value::Number(Number::from(hidden ^ key)));
            },
            "ObscuredBool" => {
                let hidden = *(base.add(h_off) as *const i32);
                let key = *(base.add(k_off) as *const i32);
                return Some(Value::Bool((hidden ^ key) != 0));
            },
            "ObscuredFloat" => {
                let hidden = *(base.add(h_off) as *const i32);
                let key = *(base.add(k_off) as *const i32);
                let real_bits = (hidden as u32) ^ (key as u32);
                let real = f32::from_bits(real_bits);
                return Number::from_f64(real as f64).map(Value::Number);
            },
            "ObscuredDouble" => {
                let hidden = *(base.add(h_off) as *const i64);
                let key = *(base.add(k_off) as *const i64);
                let real_bits = (hidden as u64) ^ (key as u64);
                let real = f64::from_bits(real_bits);
                return Number::from_f64(real).map(Value::Number);
            },
            _ => {}
        }
    }
    None
}

unsafe fn resolve_enum_to_string(
    enum_ptr: *mut u8,
    klass: *mut RawIl2CppClass
) -> Value {
    let current_val = *(enum_ptr as *const i32);
    let class_name_ptr = FN_CLASS_GET_NAME.unwrap()(klass);
    let class_name = CStr::from_ptr(class_name_ptr).to_string_lossy().to_string();

    {
        let mut cache_guard = get_or_init_enum_cache();
        let cache_map = cache_guard.as_mut().unwrap();

        if !cache_map.contains_key(&class_name) {
            let mut enum_entries = Map::new();
            let mut iter: *mut c_void = ptr::null_mut();
            loop {
                let field = FN_CLASS_GET_FIELDS.unwrap()(klass, &mut iter);
                if field.is_null() { break; }
                let flags = FN_FIELD_GET_FLAGS.unwrap()(field);
                if (flags & FIELD_ATTRIBUTE_STATIC) != 0 && (flags & FIELD_ATTRIBUTE_LITERAL) != 0 {
                    let mut static_val_buf: i32 = 0;
                    FN_FIELD_STATIC_GET_VALUE.unwrap()(field, &mut static_val_buf as *mut i32 as *mut c_void);
                    let field_name_ptr = FN_FIELD_GET_NAME.unwrap()(field);
                    let field_name = CStr::from_ptr(field_name_ptr).to_string_lossy().to_string();
                    enum_entries.insert(field_name, Value::Number(Number::from(static_val_buf)));
                }
            }
            cache_map.insert(class_name.clone(), Value::Object(enum_entries));
        }

        if let Some(Value::Object(entries)) = cache_map.get(&class_name) {
            for (key, val) in entries {
                if val.as_i64() == Some(current_val as i64) {
                    return Value::String(key.clone());
                }
            }
        }
    }
    Value::Number(Number::from(current_val))
}

unsafe fn read_value_from_addr(
    addr: *mut u8,
    type_enum: i32,
    ftype: *mut RawIl2CppType,
    depth: usize,
    visited: &mut HashSet<usize>,
) -> Value {
    match type_enum {
        0x2 => Value::Bool(*(addr as *const bool)),
        0x3..=0x9 => Value::Number(Number::from(*(addr as *const i32))),
        0xA | 0xB => Value::Number(Number::from(*(addr as *const i64))),
        0xC => Number::from_f64(*(addr as *const f32) as f64).map(Value::Number).unwrap_or(Value::Null),
        0xD => Number::from_f64(*(addr as *const f64)).map(Value::Number).unwrap_or(Value::Null),
        0xE => {
             let ptr = *(addr as *mut *mut RawIl2CppObject);
             convert_object_to_value(ptr, depth + 1, visited)
        },
        0x12 | 0x1D | 0x15 => {
            let ptr = *(addr as *mut *mut RawIl2CppObject);
            convert_object_to_value(ptr, depth + 1, visited)
        },
        0x11 => {
            if !ftype.is_null() {
                let klass = FN_CLASS_FROM_TYPE.unwrap()(ftype);
                if !klass.is_null() {
                    let name_ptr = FN_CLASS_GET_NAME.unwrap()(klass);
                    let name = CStr::from_ptr(name_ptr).to_string_lossy();

                    if name.starts_with("Obscured") {
                        if let Some(val) = try_decrypt_obscured(addr as *mut c_void, klass, &name) { return val; }
                    }
                    if FN_CLASS_IS_ENUM.unwrap()(klass) {
                        return resolve_enum_to_string(addr, klass);
                    }
                    return convert_struct_to_value(addr as *mut c_void, klass, depth + 1, visited);
                }
            }
            Value::String("UnknownStruct".to_string())
        }
        _ => Value::Number(Number::from(*(addr as *const i32))),
    }
}

pub unsafe fn convert_struct_to_value(
    struct_ptr: *mut c_void,
    klass: *mut RawIl2CppClass,
    depth: usize,
    visited: &mut HashSet<usize>,
) -> Value {
    if depth > MAX_OBJECT_DEPTH { return Value::String("<Max Depth>".to_string()); }

    let mut map = Map::new();
    let mut iter: *mut c_void = ptr::null_mut();

    loop {
        let field = FN_CLASS_GET_FIELDS.unwrap()(klass, &mut iter);
        if field.is_null() { break; }

        let flags = FN_FIELD_GET_FLAGS.unwrap()(field);
        if (flags & FIELD_ATTRIBUTE_STATIC) != 0 { continue; }

        let name = CStr::from_ptr(FN_FIELD_GET_NAME.unwrap()(field))
            .to_string_lossy()
            .to_string();

        let offset = FN_FIELD_GET_OFFSET.unwrap()(field);

        if offset < 0x10 {
            map.insert(name, Value::String("<Invalid Offset>".to_string()));
            continue;
        }

        let raw_offset = offset - 0x10;
        let field_addr = (struct_ptr as *mut u8).add(raw_offset);
        let ftype = FN_FIELD_GET_TYPE.unwrap()(field);
        let type_enum = FN_TYPE_GET_TYPE.unwrap()(ftype);

        let val = read_value_from_addr(field_addr, type_enum, ftype, depth, visited);
        map.insert(name, val);
    }
    Value::Object(map)
}

pub unsafe fn convert_object_to_value(
    obj: *mut RawIl2CppObject,
    depth: usize,
    visited: &mut HashSet<usize>,
) -> Value {
    if obj.is_null() { return Value::Null; }

    let obj_addr = obj as usize;
    if visited.contains(&obj_addr) {
        return Value::String(format!("<Cycle: {:p}>", obj));
    }
    visited.insert(obj_addr);

    if depth > MAX_OBJECT_DEPTH {
        visited.remove(&obj_addr);
        return Value::String("<Max Depth>".to_string());
    }

    let klass = FN_OBJECT_GET_CLASS.unwrap()(obj);
    if klass.is_null() {
        visited.remove(&obj_addr);
        return Value::Null;
    }

    let class_name_ptr = FN_CLASS_GET_NAME.unwrap()(klass);
    let class_name = CStr::from_ptr(class_name_ptr).to_string_lossy();

    if class_name.ends_with("[]") {
        let array = obj as *mut RawIl2CppArray;
        let len = FN_ARRAY_LENGTH.unwrap()(array);
        let data_start = (obj as *mut u8).add(32);

        if len > MAX_ARRAY_LENGTH {
            visited.remove(&obj_addr);
            return Value::String(format!("<Array len={} (Truncated)>", len));
        }

        if class_name == "Int32[]" || class_name == "System.Int32[]" {
            let slice = slice::from_raw_parts(data_start as *mut i32, len as usize);
            let res = Value::Array(slice.iter().map(|v| Value::Number(Number::from(*v))).collect());
            visited.remove(&obj_addr);
            return res;
        }
        if class_name == "Single[]" || class_name == "System.Single[]" {
            let slice = slice::from_raw_parts(data_start as *mut f32, len as usize);
            let res = Value::Array(slice.iter().map(|v| Number::from_f64(*v as f64).map(Value::Number).unwrap_or(Value::Null)).collect());
            visited.remove(&obj_addr);
            return res;
        }
        if class_name == "Byte[]" || class_name == "System.Byte[]" {
            let slice = slice::from_raw_parts(data_start as *mut u8, len as usize);
            let res = Value::Array(slice.iter().map(|v| Value::Number(Number::from(*v))).collect());
            visited.remove(&obj_addr);
            return res;
        }
        if class_name == "Boolean[]" || class_name == "System.Boolean[]" {
            let slice = slice::from_raw_parts(data_start as *mut bool, len as usize);
            let res = Value::Array(slice.iter().map(|v| Value::Bool(*v)).collect());
            visited.remove(&obj_addr);
            return res;
        }

        let element_class = FN_CLASS_GET_ELEMENT_CLASS.unwrap()(klass);
        if !element_class.is_null() {
            let is_value_type = FN_CLASS_IS_VALUETYPE.unwrap()(element_class);

            if !is_value_type {
                // Reference Array
                let mut vec = Vec::with_capacity(len as usize);
                for i in 0..len {
                    let elem_ptr_addr = (data_start as *mut *mut RawIl2CppObject).add(i as usize);
                    let elem_ptr = *elem_ptr_addr;
                    if !elem_ptr.is_null() {
                        vec.push(convert_object_to_value(elem_ptr, depth + 1, visited));
                    } else {
                        vec.push(Value::Null);
                    }
                }
                visited.remove(&obj_addr);
                return Value::Array(vec);
            } else {
                // Generic Struct Array
                let mut align: u32 = 0;
                let stride = FN_CLASS_VALUE_SIZE.unwrap()(element_class, &mut align) as usize;

                if stride > 0 {
                    let mut vec = Vec::with_capacity(len as usize);
                    for i in 0..len {
                        let elem_ptr = data_start.add((i as usize) * stride);

                        let val = if FN_CLASS_IS_ENUM.unwrap()(element_class) {
                            resolve_enum_to_string(elem_ptr, element_class)
                        } else {
                            let name_ptr = FN_CLASS_GET_NAME.unwrap()(element_class);
                            let name = CStr::from_ptr(name_ptr).to_string_lossy();
                            if name.starts_with("Obscured") {
                                if let Some(v) = try_decrypt_obscured(elem_ptr as *mut c_void, element_class, &name) {
                                    v
                                } else {
                                    convert_struct_to_value(elem_ptr as *mut c_void, element_class, depth + 1, visited)
                                }
                            } else {
                                convert_struct_to_value(elem_ptr as *mut c_void, element_class, depth + 1, visited)
                            }
                        };
                        vec.push(val);
                    }
                    visited.remove(&obj_addr);
                    return Value::Array(vec);
                }

                visited.remove(&obj_addr);
                return Value::String(format!("<Array: {} (Struct Array, Unknown Stride)>", class_name));
            }
        }
    }

    if class_name == "String" {
        let len = *((obj as *mut u8).add(0x10) as *mut i32) as usize;
        let chars_ptr = (obj as *mut u8).add(0x14) as *mut u16;
        visited.remove(&obj_addr);
        if !chars_ptr.is_null() && len > 0 {
            let slice = slice::from_raw_parts(chars_ptr, len);
            return Value::String(String::from_utf16_lossy(slice));
        }
        return Value::String("".to_string());
    }

    let mut map = Map::new();
    let mut current_dump_class = klass;

    while !current_dump_class.is_null() {
        let mut iter: *mut c_void = ptr::null_mut();
        loop {
            let field = FN_CLASS_GET_FIELDS.unwrap()(current_dump_class, &mut iter);
            if field.is_null() { break; }

            let flags = FN_FIELD_GET_FLAGS.unwrap()(field);
            if (flags & FIELD_ATTRIBUTE_STATIC) != 0 { continue; }

            let name = CStr::from_ptr(FN_FIELD_GET_NAME.unwrap()(field))
                .to_string_lossy()
                .to_string();

            if is_field_blacklisted(&name) { continue; }

            let offset = FN_FIELD_GET_OFFSET.unwrap()(field);
            let ftype = FN_FIELD_GET_TYPE.unwrap()(field);
            let type_enum = FN_TYPE_GET_TYPE.unwrap()(ftype);
            let field_addr = (obj as *mut u8).add(offset);

            let val = read_value_from_addr(field_addr, type_enum, ftype, depth, visited);
            map.insert(name, val);
        }

        current_dump_class = FN_CLASS_GET_PARENT.unwrap()(current_dump_class);
        if !current_dump_class.is_null() {
            let p_name = FN_CLASS_GET_NAME.unwrap()(current_dump_class);
            let p_str = CStr::from_ptr(p_name).to_string_lossy();
            if p_str == "Object" || p_str == "ValueType" {
                break;
            }
        }
    }

    visited.remove(&obj_addr);
    Value::Object(map)
}