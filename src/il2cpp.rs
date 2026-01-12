use core::ffi::{c_char, c_void, CStr};
use hachimi_plugin_sdk::api::HachimiApi;
use std::mem::transmute;

// Type Definitions
pub type RawIl2CppObject = c_void;
pub type RawIl2CppArray = c_void;
pub type RawIl2CppClass = c_void;
pub type RawFieldInfo = c_void;
pub type RawMethodInfo = c_void;
pub type RawIl2CppType = c_void;
pub type RawIl2CppImage = c_void;
pub type RawIl2CppDomain = c_void;
pub type RawIl2CppThread = c_void;

// Attribute Constants
pub const FIELD_ATTRIBUTE_STATIC: u32 = 0x0010;
pub const FIELD_ATTRIBUTE_LITERAL: u32 = 0x0040;

// Function Pointer Types
pub type FnClassGetFields = unsafe extern "C" fn(*mut RawIl2CppClass, *mut *mut c_void) -> *mut RawFieldInfo;
pub type FnFieldGetName = unsafe extern "C" fn(*mut RawFieldInfo) -> *const c_char;
pub type FnFieldGetType = unsafe extern "C" fn(*mut RawFieldInfo) -> *mut RawIl2CppType;
pub type FnFieldGetOffset = unsafe extern "C" fn(*mut RawFieldInfo) -> usize;
pub type FnTypeGetType = unsafe extern "C" fn(*mut RawIl2CppType) -> i32;
pub type FnArrayLength = unsafe extern "C" fn(*mut RawIl2CppArray) -> u32;
pub type FnObjectGetClass = unsafe extern "C" fn(*mut RawIl2CppObject) -> *mut RawIl2CppClass;
pub type FnClassGetName = unsafe extern "C" fn(*mut RawIl2CppClass) -> *const c_char;
pub type FnClassGetParent = unsafe extern "C" fn(*mut RawIl2CppClass) -> *mut RawIl2CppClass;
pub type FnClassGetMethods = unsafe extern "C" fn(*mut RawIl2CppClass, *mut *mut c_void) -> *mut RawMethodInfo;
pub type FnMethodGetParamCount = unsafe extern "C" fn(*mut RawMethodInfo) -> u32;
pub type FnMethodGetParam = unsafe extern "C" fn(*mut RawMethodInfo, u32) -> *mut RawIl2CppType;
pub type FnClassFromType = unsafe extern "C" fn(*mut RawIl2CppType) -> *mut RawIl2CppClass;
pub type FnMethodGetName = unsafe extern "C" fn(*mut RawMethodInfo) -> *const c_char;
pub type FnImageGetClassCount = unsafe extern "C" fn(*mut RawIl2CppImage) -> usize;
pub type FnImageGetClass = unsafe extern "C" fn(*mut RawIl2CppImage, usize) -> *mut RawIl2CppClass;
pub type FnArrayNew = unsafe extern "C" fn(*mut RawIl2CppClass, usize) -> *mut RawIl2CppArray;
pub type FnClassFromName = unsafe extern "C" fn(*const RawIl2CppImage, *const c_char, *const c_char) -> *mut RawIl2CppClass;
pub type FnClassGetMethodFromName = unsafe extern "C" fn(*mut RawIl2CppClass, *const c_char, i32) -> *const RawMethodInfo;
pub type FnGetCorlib = unsafe extern "C" fn() -> *const RawIl2CppImage;
pub type FnFieldGetValueObject = unsafe extern "C" fn(*mut RawFieldInfo, *mut RawIl2CppObject) -> *mut RawIl2CppObject;
pub type FnDomainGet = unsafe extern "C" fn() -> *mut RawIl2CppDomain;
pub type FnThreadCurrent = unsafe extern "C" fn() -> *mut RawIl2CppThread;
pub type FnThreadAttach = unsafe extern "C" fn(*mut RawIl2CppDomain) -> *mut RawIl2CppThread;
pub type FnThreadDetach = unsafe extern "C" fn(*mut RawIl2CppThread);
pub type FnFieldGetFlags = unsafe extern "C" fn(*mut RawFieldInfo) -> u32;
pub type FnClassIsEnum = unsafe extern "C" fn(*mut RawIl2CppClass) -> bool;
pub type FnFieldStaticGetValue = unsafe extern "C" fn(*mut RawFieldInfo, *mut c_void);
pub type FnClassGetElementClass = unsafe extern "C" fn(*mut RawIl2CppClass) -> *mut RawIl2CppClass;
pub type FnClassIsValueType = unsafe extern "C" fn(*mut RawIl2CppClass) -> bool;
pub type FnClassValueSize = unsafe extern "C" fn(*mut RawIl2CppClass, *mut u32) -> i32;
pub type FnClassIsInterface = unsafe extern "C" fn(*mut RawIl2CppClass) -> bool;
pub type FnClassGetImage = unsafe extern "C" fn(*mut RawIl2CppClass) -> *mut RawIl2CppImage;
pub type FnClassGetNestedTypes = unsafe extern "C" fn(*mut RawIl2CppClass, *mut *mut c_void) -> *mut RawIl2CppClass;
pub type FnRuntimeClassInit = unsafe extern "C" fn(*mut RawIl2CppClass);
pub type FnClassIsGeneric = unsafe extern "C" fn(*mut RawIl2CppClass) -> bool;

// Global Function Pointers
pub static mut FN_CLASS_GET_FIELDS: Option<FnClassGetFields> = None;
pub static mut FN_FIELD_GET_NAME: Option<FnFieldGetName> = None;
pub static mut FN_FIELD_GET_TYPE: Option<FnFieldGetType> = None;
pub static mut FN_FIELD_GET_OFFSET: Option<FnFieldGetOffset> = None;
pub static mut FN_TYPE_GET_TYPE: Option<FnTypeGetType> = None;
pub static mut FN_ARRAY_LENGTH: Option<FnArrayLength> = None;
pub static mut FN_OBJECT_GET_CLASS: Option<FnObjectGetClass> = None;
pub static mut FN_CLASS_GET_NAME: Option<FnClassGetName> = None;
pub static mut FN_CLASS_GET_PARENT: Option<FnClassGetParent> = None;
pub static mut FN_CLASS_GET_METHODS: Option<FnClassGetMethods> = None;
pub static mut FN_METHOD_GET_PARAM_COUNT: Option<FnMethodGetParamCount> = None;
pub static mut FN_METHOD_GET_PARAM: Option<FnMethodGetParam> = None;
pub static mut FN_CLASS_FROM_TYPE: Option<FnClassFromType> = None;
pub static mut FN_METHOD_GET_NAME: Option<FnMethodGetName> = None;
pub static mut FN_IMAGE_GET_CLASS_COUNT: Option<FnImageGetClassCount> = None;
pub static mut FN_IMAGE_GET_CLASS: Option<FnImageGetClass> = None;
pub static mut FN_ARRAY_NEW: Option<FnArrayNew> = None;
pub static mut FN_CLASS_FROM_NAME: Option<FnClassFromName> = None;
pub static mut FN_CLASS_GET_METHOD_FROM_NAME: Option<FnClassGetMethodFromName> = None;
pub static mut FN_GET_CORLIB: Option<FnGetCorlib> = None;
pub static mut FN_DOMAIN_GET: Option<FnDomainGet> = None;
pub static mut FN_THREAD_CURRENT: Option<FnThreadCurrent> = None;
pub static mut FN_THREAD_ATTACH: Option<FnThreadAttach> = None;
pub static mut FN_THREAD_DETACH: Option<FnThreadDetach> = None;
pub static mut FN_FIELD_GET_FLAGS: Option<FnFieldGetFlags> = None;
pub static mut FN_CLASS_IS_ENUM: Option<FnClassIsEnum> = None;
pub static mut FN_FIELD_STATIC_GET_VALUE: Option<FnFieldStaticGetValue> = None;
pub static mut FN_CLASS_GET_ELEMENT_CLASS: Option<FnClassGetElementClass> = None;
pub static mut FN_CLASS_IS_VALUETYPE: Option<FnClassIsValueType> = None;
pub static mut FN_CLASS_VALUE_SIZE: Option<FnClassValueSize> = None;
pub static mut FN_CLASS_IS_INTERFACE: Option<FnClassIsInterface> = None;
pub static mut FN_CLASS_GET_IMAGE: Option<FnClassGetImage> = None;
pub static mut FN_CLASS_GET_NESTED_TYPES: Option<FnClassGetNestedTypes> = None;
pub static mut FN_RUNTIME_CLASS_INIT: Option<FnRuntimeClassInit> = None;
pub static mut FN_CLASS_IS_GENERIC: Option<FnClassIsGeneric> = None;
pub static mut FN_FIELD_GET_VALUE_OBJECT: Option<FnFieldGetValueObject> = None;

pub unsafe fn init_il2cpp_methods(api: &HachimiApi) -> bool {
    let il2cpp = api.il2cpp();
    let resolve = |name: &CStr| il2cpp.resolve_symbol(name);

    macro_rules! resolve_func {
        ($name:expr) => {
            transmute(resolve($name))
        };
    }

    FN_CLASS_GET_FIELDS = resolve_func!(c"il2cpp_class_get_fields");
    FN_FIELD_GET_NAME = resolve_func!(c"il2cpp_field_get_name");
    FN_FIELD_GET_TYPE = resolve_func!(c"il2cpp_field_get_type");
    FN_FIELD_GET_OFFSET = resolve_func!(c"il2cpp_field_get_offset");
    FN_TYPE_GET_TYPE = resolve_func!(c"il2cpp_type_get_type");
    FN_ARRAY_LENGTH = resolve_func!(c"il2cpp_array_length");
    FN_OBJECT_GET_CLASS = resolve_func!(c"il2cpp_object_get_class");
    FN_CLASS_GET_NAME = resolve_func!(c"il2cpp_class_get_name");
    FN_CLASS_GET_PARENT = resolve_func!(c"il2cpp_class_get_parent");
    FN_CLASS_GET_METHODS = resolve_func!(c"il2cpp_class_get_methods");
    FN_METHOD_GET_PARAM_COUNT = resolve_func!(c"il2cpp_method_get_param_count");
    FN_METHOD_GET_PARAM = resolve_func!(c"il2cpp_method_get_param");
    FN_CLASS_FROM_TYPE = resolve_func!(c"il2cpp_class_from_type");
    FN_METHOD_GET_NAME = resolve_func!(c"il2cpp_method_get_name");
    FN_IMAGE_GET_CLASS_COUNT = resolve_func!(c"il2cpp_image_get_class_count");
    FN_IMAGE_GET_CLASS = resolve_func!(c"il2cpp_image_get_class");
    FN_ARRAY_NEW = resolve_func!(c"il2cpp_array_new");
    FN_CLASS_FROM_NAME = resolve_func!(c"il2cpp_class_from_name");
    FN_CLASS_GET_METHOD_FROM_NAME = resolve_func!(c"il2cpp_class_get_method_from_name");
    FN_GET_CORLIB = resolve_func!(c"il2cpp_get_corlib");
    FN_FIELD_GET_VALUE_OBJECT = resolve_func!(c"il2cpp_field_get_value_object");

    FN_DOMAIN_GET = resolve_func!(c"il2cpp_domain_get");
    FN_THREAD_CURRENT = resolve_func!(c"il2cpp_thread_current");
    FN_THREAD_ATTACH = resolve_func!(c"il2cpp_thread_attach");
    FN_THREAD_DETACH = resolve_func!(c"il2cpp_thread_detach");
    FN_FIELD_GET_FLAGS = resolve_func!(c"il2cpp_field_get_flags");

    FN_CLASS_IS_ENUM = resolve_func!(c"il2cpp_class_is_enum");
    FN_FIELD_STATIC_GET_VALUE = resolve_func!(c"il2cpp_field_static_get_value");
    FN_CLASS_GET_ELEMENT_CLASS = resolve_func!(c"il2cpp_class_get_element_class");
    FN_CLASS_IS_VALUETYPE = resolve_func!(c"il2cpp_class_is_valuetype");
    FN_CLASS_VALUE_SIZE = resolve_func!(c"il2cpp_class_value_size");
    FN_CLASS_IS_INTERFACE = resolve_func!(c"il2cpp_class_is_interface");

    FN_CLASS_GET_IMAGE = resolve_func!(c"il2cpp_class_get_image");
    FN_CLASS_GET_NESTED_TYPES = resolve_func!(c"il2cpp_class_get_nested_types");
    FN_RUNTIME_CLASS_INIT = resolve_func!(c"il2cpp_runtime_class_init");
    FN_CLASS_IS_GENERIC = resolve_func!(c"il2cpp_class_is_generic");

    matches!(FN_CLASS_GET_FIELDS, Some(_))
        && matches!(FN_CLASS_GET_METHODS, Some(_))
        && matches!(FN_IMAGE_GET_CLASS_COUNT, Some(_))
        && matches!(FN_IMAGE_GET_CLASS, Some(_))
        && matches!(FN_FIELD_GET_FLAGS, Some(_))
        && matches!(FN_CLASS_VALUE_SIZE, Some(_))
        && matches!(FN_CLASS_GET_IMAGE, Some(_))
        && matches!(FN_CLASS_GET_NESTED_TYPES, Some(_))
        && matches!(FN_RUNTIME_CLASS_INIT, Some(_))
        && matches!(FN_CLASS_IS_GENERIC, Some(_))
        && matches!(FN_CLASS_IS_INTERFACE, Some(_))
}