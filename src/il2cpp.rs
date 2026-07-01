use crate::log;
use core::ffi::{c_char, c_void};
use std::ffi::CStr;
use std::mem::transmute;
use std::ptr;

// Type Definitions
pub type RawIl2CppObject = c_void;
pub type RawIl2CppArray = c_void;
pub type RawIl2CppClass = c_void;
pub type RawFieldInfo = c_void;
pub type RawMethodInfo = c_void;
pub type RawIl2CppType = c_void;
pub type RawIl2CppImage = c_void;
pub type RawIl2CppAssembly = c_void;
pub type RawIl2CppDomain = c_void;
pub type RawIl2CppThread = c_void;

// Attribute Constants
pub const FIELD_ATTRIBUTE_STATIC: u32 = 0x0010;
pub const FIELD_ATTRIBUTE_LITERAL: u32 = 0x0040;

// Function Pointer Types
pub type FnClassGetFields =
    unsafe extern "C" fn(*mut RawIl2CppClass, *mut *mut c_void) -> *mut RawFieldInfo;
pub type FnFieldGetName = unsafe extern "C" fn(*mut RawFieldInfo) -> *const c_char;
pub type FnFieldGetType = unsafe extern "C" fn(*mut RawFieldInfo) -> *mut RawIl2CppType;
pub type FnFieldGetOffset = unsafe extern "C" fn(*mut RawFieldInfo) -> usize;
pub type FnTypeGetType = unsafe extern "C" fn(*mut RawIl2CppType) -> i32;
pub type FnArrayLength = unsafe extern "C" fn(*mut RawIl2CppArray) -> u32;
pub type FnObjectGetClass = unsafe extern "C" fn(*mut RawIl2CppObject) -> *mut RawIl2CppClass;
pub type FnClassGetName = unsafe extern "C" fn(*mut RawIl2CppClass) -> *const c_char;
pub type FnClassGetParent = unsafe extern "C" fn(*mut RawIl2CppClass) -> *mut RawIl2CppClass;
pub type FnClassGetMethods =
    unsafe extern "C" fn(*mut RawIl2CppClass, *mut *mut c_void) -> *mut RawMethodInfo;
pub type FnMethodGetParamCount = unsafe extern "C" fn(*mut RawMethodInfo) -> u32;
pub type FnMethodGetParam = unsafe extern "C" fn(*mut RawMethodInfo, u32) -> *mut RawIl2CppType;
pub type FnClassFromType = unsafe extern "C" fn(*mut RawIl2CppType) -> *mut RawIl2CppClass;
pub type FnMethodGetName = unsafe extern "C" fn(*mut RawMethodInfo) -> *const c_char;
pub type FnImageGetClassCount = unsafe extern "C" fn(*mut RawIl2CppImage) -> usize;
pub type FnImageGetClass = unsafe extern "C" fn(*mut RawIl2CppImage, usize) -> *mut RawIl2CppClass;
pub type FnArrayNew = unsafe extern "C" fn(*mut RawIl2CppClass, usize) -> *mut RawIl2CppArray;
pub type FnClassFromName = unsafe extern "C" fn(
    *const RawIl2CppImage,
    *const c_char,
    *const c_char,
) -> *mut RawIl2CppClass;
pub type FnGetCorlib = unsafe extern "C" fn() -> *const RawIl2CppImage;
pub type FnDomainGetAssemblies =
    unsafe extern "C" fn(*mut RawIl2CppDomain, *mut usize) -> *mut *const RawIl2CppAssembly;
pub type FnAssemblyGetImage = unsafe extern "C" fn(*const RawIl2CppAssembly) -> *mut RawIl2CppImage;
pub type FnImageGetName = unsafe extern "C" fn(*const RawIl2CppImage) -> *const c_char;
pub type FnFieldGetValueObject =
    unsafe extern "C" fn(*mut RawFieldInfo, *mut RawIl2CppObject) -> *mut RawIl2CppObject;
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
pub type FnClassGetNestedTypes =
    unsafe extern "C" fn(*mut RawIl2CppClass, *mut *mut c_void) -> *mut RawIl2CppClass;
pub type FnRuntimeClassInit = unsafe extern "C" fn(*mut RawIl2CppClass);
pub type FnClassIsGeneric = unsafe extern "C" fn(*mut RawIl2CppClass) -> bool;
pub type FnRuntimeInvoke = unsafe extern "C" fn(
    *const RawMethodInfo,
    *mut c_void,
    *mut *mut c_void,
    *mut *mut c_void,
) -> *mut RawIl2CppObject;
pub type FnMethodGetFlags = unsafe extern "C" fn(*const RawMethodInfo, *mut u32) -> u32;
pub type FnClassGetMethodFromName =
    unsafe extern "C" fn(*mut RawIl2CppClass, *const c_char, i32) -> *mut RawMethodInfo;

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
pub static mut FN_GET_CORLIB: Option<FnGetCorlib> = None;
pub static mut FN_DOMAIN_GET_ASSEMBLIES: Option<FnDomainGetAssemblies> = None;
pub static mut FN_ASSEMBLY_GET_IMAGE: Option<FnAssemblyGetImage> = None;
pub static mut FN_IMAGE_GET_NAME: Option<FnImageGetName> = None;
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
pub static mut FN_RUNTIME_INVOKE: Option<FnRuntimeInvoke> = None;
pub static mut FN_METHOD_GET_FLAGS: Option<FnMethodGetFlags> = None;
pub static mut FN_CLASS_GET_METHOD_FROM_NAME: Option<FnClassGetMethodFromName> = None;

pub unsafe fn init_il2cpp_methods<F>(resolve: F) -> bool
where
    F: Fn(*const c_char) -> *mut c_void,
{
    macro_rules! resolve_func {
        ($name:expr) => {
            transmute(resolve($name.as_ptr()))
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
    FN_GET_CORLIB = resolve_func!(c"il2cpp_get_corlib");
    FN_DOMAIN_GET_ASSEMBLIES = resolve_func!(c"il2cpp_domain_get_assemblies");
    FN_ASSEMBLY_GET_IMAGE = resolve_func!(c"il2cpp_assembly_get_image");
    FN_IMAGE_GET_NAME = resolve_func!(c"il2cpp_image_get_name");
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
    FN_RUNTIME_INVOKE = resolve_func!(c"il2cpp_runtime_invoke");
    FN_METHOD_GET_FLAGS = resolve_func!(c"il2cpp_method_get_flags");
    FN_CLASS_GET_METHOD_FROM_NAME = resolve_func!(c"il2cpp_class_get_method_from_name");

    matches!(FN_CLASS_GET_FIELDS, Some(_))
        && matches!(FN_CLASS_GET_METHODS, Some(_))
        && matches!(FN_IMAGE_GET_CLASS_COUNT, Some(_))
        && matches!(FN_IMAGE_GET_CLASS, Some(_))
        && matches!(FN_DOMAIN_GET_ASSEMBLIES, Some(_))
        && matches!(FN_ASSEMBLY_GET_IMAGE, Some(_))
        && matches!(FN_IMAGE_GET_NAME, Some(_))
        && matches!(FN_FIELD_GET_FLAGS, Some(_))
        && matches!(FN_CLASS_VALUE_SIZE, Some(_))
        && matches!(FN_CLASS_GET_IMAGE, Some(_))
        && matches!(FN_CLASS_GET_NESTED_TYPES, Some(_))
        && matches!(FN_RUNTIME_CLASS_INIT, Some(_))
        && matches!(FN_CLASS_IS_GENERIC, Some(_))
        && matches!(FN_CLASS_IS_INTERFACE, Some(_))
        && matches!(FN_CLASS_GET_METHOD_FROM_NAME, Some(_))
}

pub unsafe fn find_image_by_name(name: &str) -> *mut RawIl2CppImage {
    let domain = FN_DOMAIN_GET.unwrap()();
    if domain.is_null() {
        return ptr::null_mut();
    }

    let mut count = 0usize;
    let assemblies = FN_DOMAIN_GET_ASSEMBLIES.unwrap()(domain, &mut count);
    if assemblies.is_null() {
        return ptr::null_mut();
    }

    for i in 0..count {
        let assembly = *assemblies.add(i);
        if assembly.is_null() {
            continue;
        }

        let image = FN_ASSEMBLY_GET_IMAGE.unwrap()(assembly);
        if image.is_null() {
            continue;
        }

        let image_name_ptr = FN_IMAGE_GET_NAME.unwrap()(image);
        if image_name_ptr.is_null() {
            continue;
        }

        let image_name = CStr::from_ptr(image_name_ptr).to_string_lossy();
        if image_name.eq_ignore_ascii_case(name)
            || image_name
                .trim_end_matches(".dll")
                .eq_ignore_ascii_case(name)
        {
            return image;
        }
    }

    ptr::null_mut()
}

pub unsafe fn log_loaded_images() {
    let domain = FN_DOMAIN_GET.unwrap()();
    if domain.is_null() {
        log!("[IL2CPP] Cannot list loaded images: domain is null");
        return;
    }

    let mut count = 0usize;
    let assemblies = FN_DOMAIN_GET_ASSEMBLIES.unwrap()(domain, &mut count);
    if assemblies.is_null() {
        log!("[IL2CPP] Cannot list loaded images: assembly list is null");
        return;
    }

    log!("[IL2CPP] Loaded assembly image count: {}", count);
    for i in 0..count {
        let assembly = *assemblies.add(i);
        if assembly.is_null() {
            log!("[IL2CPP] image[{}]: <null assembly>", i);
            continue;
        }

        let image = FN_ASSEMBLY_GET_IMAGE.unwrap()(assembly);
        if image.is_null() {
            log!("[IL2CPP] image[{}]: <null image>", i);
            continue;
        }

        let image_name_ptr = FN_IMAGE_GET_NAME.unwrap()(image);
        if image_name_ptr.is_null() {
            log!("[IL2CPP] image[{}]: <null image name>", i);
            continue;
        }

        let image_name = CStr::from_ptr(image_name_ptr).to_string_lossy();
        log!("[IL2CPP] image[{}]: {}", i, image_name);
    }
}

pub unsafe fn get_class_from_image(
    image: *mut RawIl2CppImage,
    namespace: *const c_char,
    class_name: *const c_char,
) -> *mut RawIl2CppClass {
    if image.is_null() {
        return ptr::null_mut();
    }

    FN_CLASS_FROM_NAME.unwrap()(image, namespace, class_name)
}

pub unsafe fn method_addr(method: *mut RawMethodInfo) -> usize {
    if method.is_null() {
        0
    } else {
        *(method as *const usize)
    }
}

pub unsafe fn find_method_addr_by_name(
    klass: *mut RawIl2CppClass,
    method_name: *const c_char,
    arg_count: i32,
) -> usize {
    if klass.is_null() {
        return 0;
    }

    let method = FN_CLASS_GET_METHOD_FROM_NAME.unwrap()(klass, method_name, arg_count);
    method_addr(method)
}
