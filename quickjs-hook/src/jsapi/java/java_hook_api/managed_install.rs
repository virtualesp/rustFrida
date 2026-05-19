use crate::ffi;
use crate::jsapi::callback_util::{throw_internal_error, with_registry_mut};
use crate::jsapi::console::output_message;
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use super::super::art_controller::{ensure_art_controller_initialized, refresh_walkstack_sigsegv_guard};
use super::super::art_method::*;
use super::super::callback::*;
use super::super::java_fast_api::{compile_art_method_to_quick, RequestedCompileKind};
use super::super::jni_core::*;
use super::super::reflect::{decode_method_id, find_class_safe, get_app_classloader_local_ref};
use super::install_support::{create_class_global_ref, update_original_method_flags_for_hook, JavaHookInstallGuard};
use super::managed_dex_builder::{
    build_managed_dsl_dex, GeneratedCounter, GeneratedMessageChannel, GeneratedStringLiteral, MANAGED_MESSAGE_CAPACITY,
    MANAGED_MESSAGE_CODES_FIELD, MANAGED_MESSAGE_DROPPED_FIELD, MANAGED_MESSAGE_HEAD_FIELD, MANAGED_MESSAGE_TAIL_FIELD,
    MANAGED_MESSAGE_TEXTS_FIELD, MANAGED_MESSAGE_VALUES_FIELD,
};

struct DynamicManagedHelperRefs {
    class_name: String,
    class_global_ref: u64,
    loader_global_ref: u64,
    dex_bytes: Vec<u8>,
}

static DYNAMIC_MANAGED_HELPER_REFS: Mutex<Vec<DynamicManagedHelperRefs>> = Mutex::new(Vec::new());
static DYNAMIC_MANAGED_CLASS_ID: AtomicU64 = AtomicU64::new(1);
static NATIVE_MANAGED_COUNTERS: OnceLock<Mutex<HashMap<(String, String), Box<AtomicU64>>>> = OnceLock::new();

fn native_counter_registry() -> &'static Mutex<HashMap<(String, String), Box<AtomicU64>>> {
    NATIVE_MANAGED_COUNTERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn install_native_counter_ptrs(helper_class: &str, counter_fields: &[String]) -> Vec<*mut u64> {
    let mut registry = native_counter_registry().lock().unwrap_or_else(|e| e.into_inner());
    let mut ptrs = Vec::with_capacity(counter_fields.len());
    for field_name in counter_fields {
        let counter = registry
            .entry((helper_class.to_string(), field_name.clone()))
            .or_insert_with(|| Box::new(AtomicU64::new(0)));
        ptrs.push(counter.as_ref() as *const AtomicU64 as *mut u64);
    }
    ptrs
}

fn read_native_counter(helper_class: &str, field_name: &str) -> Option<u64> {
    let registry = NATIVE_MANAGED_COUNTERS.get()?;
    let registry = registry.lock().unwrap_or_else(|e| e.into_inner());
    registry.iter().find_map(|((class, field), counter)| {
        if class == helper_class && field == field_name {
            Some(counter.load(Ordering::Relaxed))
        } else {
            None
        }
    })
}

pub fn managed_native_counter_value(helper_class: &str, field_name: &str) -> Option<u64> {
    read_native_counter(helper_class, field_name)
}

unsafe fn load_dynamic_managed_helper_class(
    env: JniEnv,
    dex_bytes: Vec<u8>,
    helper_class_name: &str,
) -> Result<*mut std::ffi::c_void, String> {
    let slot_index = {
        let mut refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        let idx = refs.len();
        refs.push(DynamicManagedHelperRefs {
            class_name: helper_class_name.to_string(),
            class_global_ref: 0,
            loader_global_ref: 0,
            dex_bytes,
        });
        idx
    };

    let (dex_ptr, dex_len) = {
        let refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        let dex = &refs[slot_index].dex_bytes;
        (dex.as_ptr() as *mut std::ffi::c_void, dex.len() as i64)
    };

    let find_loader_cls = find_class_safe(env, "dalvik/system/InMemoryDexClassLoader");
    if find_loader_cls.is_null() {
        return Err("InMemoryDexClassLoader class not found".to_string());
    }

    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let new_object: NewObjectAFn = jni_fn!(env, NewObjectAFn, JNI_NEW_OBJECT_A);
    let new_direct: NewDirectByteBufferFn = jni_fn!(env, NewDirectByteBufferFn, JNI_NEW_DIRECT_BYTE_BUFFER);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);

    let ctor_name = CString::new("<init>").unwrap();
    let ctor_sig = CString::new("(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V").unwrap();
    let ctor = get_mid(env, find_loader_cls, ctor_name.as_ptr(), ctor_sig.as_ptr());
    if ctor.is_null() || jni_check_exc(env) {
        delete_local_ref(env, find_loader_cls);
        return Err("InMemoryDexClassLoader(ByteBuffer, ClassLoader) constructor not found".to_string());
    }

    let dex_buf = new_direct(env, dex_ptr, dex_len);
    if dex_buf.is_null() || jni_check_exc(env) {
        delete_local_ref(env, find_loader_cls);
        return Err("NewDirectByteBuffer for dynamic managed dex failed".to_string());
    }

    let parent_loader = get_app_classloader_local_ref(env);
    let args = [dex_buf as u64, parent_loader as u64];
    let loader = new_object(env, find_loader_cls, ctor, args.as_ptr() as *const std::ffi::c_void);
    if loader.is_null() || jni_check_exc(env) {
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("new dynamic InMemoryDexClassLoader failed".to_string());
    }

    let class_loader_cls = find_class_safe(env, "java/lang/ClassLoader");
    if class_loader_cls.is_null() {
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("java.lang.ClassLoader class not found".to_string());
    }
    let load_name = CString::new("loadClass").unwrap();
    let load_sig = CString::new("(Ljava/lang/String;)Ljava/lang/Class;").unwrap();
    let load_mid = get_mid(env, class_loader_cls, load_name.as_ptr(), load_sig.as_ptr());
    if load_mid.is_null() || jni_check_exc(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("ClassLoader.loadClass method not found".to_string());
    }

    let helper_name = CString::new(helper_class_name).map_err(|_| "invalid helper class name".to_string())?;
    let helper_jstr = new_string_utf(env, helper_name.as_ptr());
    if helper_jstr.is_null() || jni_check_exc(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("NewStringUTF for dynamic helper class failed".to_string());
    }
    let load_args = [helper_jstr as u64];
    let helper_cls = call_obj(env, loader, load_mid, load_args.as_ptr() as *const std::ffi::c_void);
    delete_local_ref(env, helper_jstr);
    if helper_cls.is_null() || jni_check_exc(env) {
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("dynamic managed helper loadClass failed".to_string());
    }

    let helper_global = new_global_ref(env, helper_cls);
    let loader_global = new_global_ref(env, loader);
    if helper_global.is_null() || loader_global.is_null() || jni_check_exc(env) {
        delete_local_ref(env, helper_cls);
        delete_local_ref(env, class_loader_cls);
        delete_local_ref(env, loader);
        if !parent_loader.is_null() {
            delete_local_ref(env, parent_loader);
        }
        delete_local_ref(env, dex_buf);
        delete_local_ref(env, find_loader_cls);
        return Err("dynamic helper global ref creation failed".to_string());
    }

    {
        let mut refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(slot) = refs.get_mut(slot_index) {
            slot.class_global_ref = helper_global as u64;
            slot.loader_global_ref = loader_global as u64;
        }
    }

    delete_local_ref(env, class_loader_cls);
    delete_local_ref(env, loader);
    if !parent_loader.is_null() {
        delete_local_ref(env, parent_loader);
    }
    delete_local_ref(env, dex_buf);
    delete_local_ref(env, find_loader_cls);

    Ok(helper_cls)
}

fn find_dynamic_managed_helper_class(class_name: &str) -> Option<*mut std::ffi::c_void> {
    let refs = DYNAMIC_MANAGED_HELPER_REFS.lock().unwrap_or_else(|e| e.into_inner());
    refs.iter()
        .find(|slot| slot.class_name == class_name && slot.class_global_ref != 0)
        .map(|slot| slot.class_global_ref as *mut std::ffi::c_void)
}

unsafe fn initialize_generated_string_literals(
    env: JniEnv,
    helper_cls: *mut std::ffi::c_void,
    literals: &[GeneratedStringLiteral],
) -> Result<(), String> {
    if literals.is_empty() {
        return Ok(());
    }

    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    type SetStaticObjectFieldFn =
        unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
    let set_static_object_field: SetStaticObjectFieldFn =
        jni_fn!(env, SetStaticObjectFieldFn, JNI_SET_STATIC_OBJECT_FIELD);
    let new_string_utf: NewStringUtfFn = jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let string_sig = CString::new("Ljava/lang/String;").unwrap();

    for lit in literals {
        let field_name = CString::new(lit.field_name.as_str())
            .map_err(|_| format!("invalid generated string field name {}", lit.field_name))?;
        let field_id = get_static_field_id(env, helper_cls, field_name.as_ptr(), string_sig.as_ptr());
        if field_id.is_null() || jni_check_exc(env) {
            return Err(format!("generated string field {} not found", lit.field_name));
        }

        let value = CString::new(lit.value.as_str())
            .map_err(|_| format!("string literal for {} contains NUL byte", lit.field_name))?;
        let jstr = new_string_utf(env, value.as_ptr());
        if jstr.is_null() || jni_check_exc(env) {
            return Err(format!(
                "NewStringUTF failed for generated string field {}",
                lit.field_name
            ));
        }
        set_static_object_field(env, helper_cls, field_id, jstr);
        delete_local_ref(env, jstr);
        if jni_check_exc(env) {
            return Err(format!(
                "SetStaticObjectField failed for generated string field {}",
                lit.field_name
            ));
        }
    }
    output_message(&format!(
        "[managedHook] initialized {} generated string literal field(s)",
        literals.len()
    ));
    Ok(())
}

unsafe fn initialize_generated_message_queue(
    env: JniEnv,
    helper_cls: *mut std::ffi::c_void,
    channels: &[GeneratedMessageChannel],
    capacity: i32,
) -> Result<(), String> {
    if channels.is_empty() {
        return Ok(());
    }

    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    type SetStaticObjectFieldFn =
        unsafe extern "C" fn(JniEnv, *mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void);
    let set_static_object_field: SetStaticObjectFieldFn =
        jni_fn!(env, SetStaticObjectFieldFn, JNI_SET_STATIC_OBJECT_FIELD);
    let set_static_int_field: SetStaticIntFieldFn = jni_fn!(env, SetStaticIntFieldFn, JNI_SET_STATIC_INT_FIELD);
    let new_int_array: NewPrimitiveArrayFn = jni_fn!(env, NewPrimitiveArrayFn, JNI_NEW_INT_ARRAY);
    let new_object_array: NewObjectArrayFn = jni_fn!(env, NewObjectArrayFn, JNI_NEW_OBJECT_ARRAY);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let int_sig = CString::new("I").unwrap();
    for field in [
        MANAGED_MESSAGE_HEAD_FIELD,
        MANAGED_MESSAGE_TAIL_FIELD,
        MANAGED_MESSAGE_DROPPED_FIELD,
    ] {
        let name = CString::new(field).unwrap();
        let fid = get_static_field_id(env, helper_cls, name.as_ptr(), int_sig.as_ptr());
        if fid.is_null() || jni_check_exc(env) {
            return Err(format!("generated message field {} not found", field));
        }
        set_static_int_field(env, helper_cls, fid, 0);
        if jni_check_exc(env) {
            return Err(format!(
                "SetStaticIntField failed for generated message field {}",
                field
            ));
        }
    }

    let int_array_sig = CString::new("[I").unwrap();
    for field in [MANAGED_MESSAGE_CODES_FIELD, MANAGED_MESSAGE_VALUES_FIELD] {
        let name = CString::new(field).unwrap();
        let fid = get_static_field_id(env, helper_cls, name.as_ptr(), int_array_sig.as_ptr());
        if fid.is_null() || jni_check_exc(env) {
            return Err(format!("generated message array field {} not found", field));
        }
        let array = new_int_array(env, capacity);
        if array.is_null() || jni_check_exc(env) {
            return Err(format!("NewIntArray failed for generated message array {}", field));
        }
        set_static_object_field(env, helper_cls, fid, array);
        delete_local_ref(env, array);
        if jni_check_exc(env) {
            return Err(format!(
                "SetStaticObjectField failed for generated message array {}",
                field
            ));
        }
    }

    let string_array_sig = CString::new("[Ljava/lang/String;").unwrap();
    let string_array_name = CString::new(MANAGED_MESSAGE_TEXTS_FIELD).unwrap();
    let string_array_fid = get_static_field_id(env, helper_cls, string_array_name.as_ptr(), string_array_sig.as_ptr());
    if string_array_fid.is_null() || jni_check_exc(env) {
        return Err(format!(
            "generated message array field {} not found",
            MANAGED_MESSAGE_TEXTS_FIELD
        ));
    }
    let string_cls = find_class_safe(env, "java.lang.String");
    if string_cls.is_null() || jni_check_exc(env) {
        return Err("java.lang.String class not found for generated message text array".to_string());
    }
    let string_array = new_object_array(env, capacity, string_cls, std::ptr::null_mut());
    delete_local_ref(env, string_cls);
    if string_array.is_null() || jni_check_exc(env) {
        return Err(format!(
            "NewObjectArray failed for generated message array {}",
            MANAGED_MESSAGE_TEXTS_FIELD
        ));
    }
    set_static_object_field(env, helper_cls, string_array_fid, string_array);
    delete_local_ref(env, string_array);
    if jni_check_exc(env) {
        return Err(format!(
            "SetStaticObjectField failed for generated message array {}",
            MANAGED_MESSAGE_TEXTS_FIELD
        ));
    }

    output_message(&format!(
        "[managedHook] initialized message queue capacity={} channel(s)={}",
        capacity,
        channels.len(),
    ));
    Ok(())
}

unsafe fn direct_buffer_range(env: JniEnv, buffer: *mut c_void, offset: i32, length: i32) -> Option<(*mut u8, usize)> {
    if buffer.is_null() || offset < 0 || length <= 0 {
        return None;
    }
    let get_address: GetDirectBufferAddressFn = jni_fn!(env, GetDirectBufferAddressFn, JNI_GET_DIRECT_BUFFER_ADDRESS);
    let get_capacity: GetDirectBufferCapacityFn =
        jni_fn!(env, GetDirectBufferCapacityFn, JNI_GET_DIRECT_BUFFER_CAPACITY);
    let base = get_address(env, buffer) as *mut u8;
    let capacity = get_capacity(env, buffer);
    if base.is_null() || capacity <= 0 || jni_check_exc(env) {
        return None;
    }
    let offset = offset as i64;
    if offset >= capacity {
        return None;
    }
    let available = capacity - offset;
    let len = std::cmp::min(length as i64, available) as usize;
    if len == 0 {
        return None;
    }
    Some((base.add(offset as usize), len))
}

unsafe extern "C" fn managed_dbb_fill(
    env: JniEnv,
    _cls: *mut c_void,
    buffer: *mut c_void,
    offset: i32,
    length: i32,
    value: i32,
) -> i32 {
    let Some((dst, len)) = direct_buffer_range(env, buffer, offset, length) else {
        return 0;
    };
    std::ptr::write_bytes(dst, value as u8, len);
    len as i32
}

unsafe extern "C" fn managed_dbb_copy_from_byte_array(
    env: JniEnv,
    _cls: *mut c_void,
    buffer: *mut c_void,
    dst_offset: i32,
    src: *mut c_void,
    src_offset: i32,
    length: i32,
) -> i32 {
    if src.is_null() || src_offset < 0 || length <= 0 {
        return 0;
    }
    let get_array_length: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_region: GetByteArrayRegionFn = jni_fn!(env, GetByteArrayRegionFn, JNI_GET_BYTE_ARRAY_REGION);
    let src_len = get_array_length(env, src);
    if src_len <= 0 || src_offset >= src_len || jni_check_exc(env) {
        return 0;
    }
    let Some((dst, dst_len)) = direct_buffer_range(env, buffer, dst_offset, length) else {
        return 0;
    };
    let src_available = src_len - src_offset;
    let len = std::cmp::min(dst_len, std::cmp::min(length, src_available) as usize);
    if len == 0 || len > i32::MAX as usize {
        return 0;
    }
    let mut tmp = vec![0i8; len];
    get_region(env, src, src_offset, len as i32, tmp.as_mut_ptr());
    if jni_check_exc(env) {
        return 0;
    }
    std::ptr::copy_nonoverlapping(tmp.as_ptr() as *const u8, dst, len);
    len as i32
}

unsafe extern "C" fn managed_dbb_copy_to_byte_array(
    env: JniEnv,
    _cls: *mut c_void,
    buffer: *mut c_void,
    src_offset: i32,
    dst: *mut c_void,
    dst_offset: i32,
    length: i32,
) -> i32 {
    if dst.is_null() || dst_offset < 0 || length <= 0 {
        return 0;
    }
    let get_array_length: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let set_region: SetByteArrayRegionFn = jni_fn!(env, SetByteArrayRegionFn, JNI_SET_BYTE_ARRAY_REGION);
    let dst_len = get_array_length(env, dst);
    if dst_len <= 0 || dst_offset >= dst_len || jni_check_exc(env) {
        return 0;
    }
    let Some((src, src_len)) = direct_buffer_range(env, buffer, src_offset, length) else {
        return 0;
    };
    let dst_available = dst_len - dst_offset;
    let len = std::cmp::min(src_len, std::cmp::min(length, dst_available) as usize);
    if len == 0 || len > i32::MAX as usize {
        return 0;
    }
    set_region(env, dst, dst_offset, len as i32, src as *const i8);
    if jni_check_exc(env) {
        return 0;
    }
    len as i32
}

unsafe extern "C" fn managed_dbb_capacity(env: JniEnv, _cls: *mut c_void, buffer: *mut c_void) -> i32 {
    if buffer.is_null() {
        return -1;
    }
    let get_capacity: GetDirectBufferCapacityFn =
        jni_fn!(env, GetDirectBufferCapacityFn, JNI_GET_DIRECT_BUFFER_CAPACITY);
    let capacity = get_capacity(env, buffer);
    if jni_check_exc(env) || capacity < 0 {
        return -1;
    }
    std::cmp::min(capacity, i32::MAX as i64) as i32
}

unsafe extern "C" fn managed_dbb_get_u8(env: JniEnv, _cls: *mut c_void, buffer: *mut c_void, offset: i32) -> i32 {
    let Some((src, _len)) = direct_buffer_range(env, buffer, offset, 1) else {
        return -1;
    };
    *src as i32
}

unsafe extern "C" fn managed_reentry_guard_enter(_env: JniEnv, _cls: *mut c_void) {
    crate::ffi::hook::hook_managed_reentry_guard_enter();
}

unsafe extern "C" fn managed_reentry_guard_leave(_env: JniEnv, _cls: *mut c_void) {
    crate::ffi::hook::hook_managed_reentry_guard_leave();
}

unsafe fn register_managed_guard_helpers(env: JniEnv, helper_cls: *mut c_void) -> Result<(), String> {
    let register_natives: RegisterNativesFn = jni_fn!(env, RegisterNativesFn, JNI_REGISTER_NATIVES);
    let names = [
        CString::new("__rf_guard_enter").unwrap(),
        CString::new("__rf_guard_leave").unwrap(),
    ];
    let sigs = [CString::new("()V").unwrap(), CString::new("()V").unwrap()];
    let methods = [
        JniNativeMethod {
            name: names[0].as_ptr(),
            signature: sigs[0].as_ptr(),
            fn_ptr: managed_reentry_guard_enter as *mut c_void,
        },
        JniNativeMethod {
            name: names[1].as_ptr(),
            signature: sigs[1].as_ptr(),
            fn_ptr: managed_reentry_guard_leave as *mut c_void,
        },
    ];
    if register_natives(env, helper_cls, methods.as_ptr(), methods.len() as i32) != 0 || jni_check_exc(env) {
        return Err("RegisterNatives failed for managed reentrancy guard helpers".to_string());
    }
    Ok(())
}

unsafe fn register_direct_buffer_helpers(env: JniEnv, helper_cls: *mut c_void) -> Result<(), String> {
    let register_natives: RegisterNativesFn = jni_fn!(env, RegisterNativesFn, JNI_REGISTER_NATIVES);
    let names = [
        CString::new("__rf_dbb_fill").unwrap(),
        CString::new("__rf_dbb_copy_from_byte_array").unwrap(),
        CString::new("__rf_dbb_copy_to_byte_array").unwrap(),
        CString::new("__rf_dbb_capacity").unwrap(),
        CString::new("__rf_dbb_get_u8").unwrap(),
    ];
    let sigs = [
        CString::new("(Ljava/nio/ByteBuffer;III)I").unwrap(),
        CString::new("(Ljava/nio/ByteBuffer;I[BII)I").unwrap(),
        CString::new("(Ljava/nio/ByteBuffer;I[BII)I").unwrap(),
        CString::new("(Ljava/nio/ByteBuffer;)I").unwrap(),
        CString::new("(Ljava/nio/ByteBuffer;I)I").unwrap(),
    ];
    let methods = [
        JniNativeMethod {
            name: names[0].as_ptr(),
            signature: sigs[0].as_ptr(),
            fn_ptr: managed_dbb_fill as *mut c_void,
        },
        JniNativeMethod {
            name: names[1].as_ptr(),
            signature: sigs[1].as_ptr(),
            fn_ptr: managed_dbb_copy_from_byte_array as *mut c_void,
        },
        JniNativeMethod {
            name: names[2].as_ptr(),
            signature: sigs[2].as_ptr(),
            fn_ptr: managed_dbb_copy_to_byte_array as *mut c_void,
        },
        JniNativeMethod {
            name: names[3].as_ptr(),
            signature: sigs[3].as_ptr(),
            fn_ptr: managed_dbb_capacity as *mut c_void,
        },
        JniNativeMethod {
            name: names[4].as_ptr(),
            signature: sigs[4].as_ptr(),
            fn_ptr: managed_dbb_get_u8 as *mut c_void,
        },
    ];
    if register_natives(env, helper_cls, methods.as_ptr(), methods.len() as i32) != 0 || jni_check_exc(env) {
        return Err("RegisterNatives failed for managed DirectByteBuffer helpers".to_string());
    }
    output_message("[managedHook] registered DirectByteBuffer native helpers");
    Ok(())
}

unsafe fn set_orig_backup_entrypoint(
    backup_art_method: u64,
    art_method_size: usize,
    access_flags_offset: usize,
    entry_point_offset: usize,
    entrypoint: u64,
) -> Result<(), String> {
    if backup_art_method == 0 || entrypoint == 0 {
        return Err("invalid managed orig backup entrypoint state".to_string());
    }
    if entry_point_offset + std::mem::size_of::<u64>() > art_method_size {
        return Err(format!(
            "invalid managed orig backup entrypoint layout: ep_offset={} size={}",
            entry_point_offset, art_method_size
        ));
    }
    if access_flags_offset + std::mem::size_of::<u32>() > art_method_size {
        return Err(format!(
            "invalid managed orig backup flags layout: flags_offset={} size={}",
            access_flags_offset, art_method_size
        ));
    }

    let flags = std::ptr::read_volatile((backup_art_method as usize + access_flags_offset) as *const u32);
    std::ptr::write_volatile(
        (backup_art_method as usize + access_flags_offset) as *mut u32,
        flags | k_acc_compile_dont_bother(),
    );
    std::ptr::write_volatile(
        (backup_art_method as usize + entry_point_offset) as *mut u64,
        entrypoint,
    );
    crate::ffi::hook::hook_flush_cache(backup_art_method as *mut std::ffi::c_void, art_method_size);
    output_message(&format!(
        "[managedHook] orig backup ArtMethod entrypoint -> stub {:#x}",
        entrypoint
    ));
    Ok(())
}

unsafe fn install_managed_method_helper(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    actual_sig: &str,
    resolved_art_method: Option<u64>,
    helper_cls: *mut std::ffi::c_void,
    helper_method_name_str: &str,
    helper_method_sig_str: &str,
    orig_backup_name_sig: Option<(&str, &str)>,
    label: &str,
    _uses_orig: bool,
) -> Result<(), String> {
    let art_method = if let Some(art_method) = resolved_art_method {
        art_method
    } else {
        resolve_art_method(env, class_name, method_name, actual_sig, false)?.0
    };

    init_java_registry();
    if crate::jsapi::callback_util::with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false)
    {
        return Err(format!(
            "{}.{}{} already hooked — unhook first",
            class_name, method_name, actual_sig
        ));
    }

    let get_static_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
    let helper_method_sig = CString::new(helper_method_sig_str).unwrap();
    let helper_method_name = CString::new(helper_method_name_str).unwrap();
    let helper_method_id = get_static_mid(env, helper_cls, helper_method_name.as_ptr(), helper_method_sig.as_ptr());
    if helper_method_id.is_null() || jni_check_exc(env) {
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        delete_local_ref(env, helper_cls);
        return Err(format!("managed helper {} method not found", helper_method_name_str));
    }
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let helper_art_method = decode_method_id(env, helper_cls, helper_method_id as u64, true);
    if helper_art_method == 0 {
        delete_local_ref(env, helper_cls);
        return Err("managed helper ArtMethod decode failed".to_string());
    }
    let orig_backup_art_method = if let Some((backup_name_str, backup_sig_str)) = orig_backup_name_sig {
        let backup_name = CString::new(backup_name_str).unwrap();
        let backup_sig = CString::new(backup_sig_str).unwrap();
        let backup_method_id = get_static_mid(env, helper_cls, backup_name.as_ptr(), backup_sig.as_ptr());
        if backup_method_id.is_null() || jni_check_exc(env) {
            delete_local_ref(env, helper_cls);
            return Err(format!("managed helper {} method not found", backup_name_str));
        }
        let art_method = decode_method_id(env, helper_cls, backup_method_id as u64, true);
        if art_method == 0 {
            delete_local_ref(env, helper_cls);
            return Err("managed helper orig backup ArtMethod decode failed".to_string());
        }
        Some(art_method)
    } else {
        None
    };
    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;
    let original_access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let mut original_entry_point = read_entry_point(art_method, ep_offset);
    let bridge = find_art_bridge_functions(env, ep_offset);

    if is_art_quick_entrypoint(original_entry_point, bridge) {
        let compile = compile_art_method_to_quick(env, art_method, ep_offset, bridge, RequestedCompileKind::Auto);
        output_message(&format!(
            "[managedHook] compile original {}.{}{}: success={} compiled={} before={:#x} after={:#x} {}",
            class_name,
            method_name,
            actual_sig,
            compile.success,
            compile.compiled,
            compile.before,
            compile.after,
            compile.message
        ));
        original_entry_point = read_entry_point(art_method, ep_offset);
    }
    if is_art_quick_entrypoint(original_entry_point, bridge) {
        return Err(format!(
            "{}.{}{} still has shared ART entrypoint after compile",
            class_name, method_name, actual_sig
        ));
    }

    let helper_spec = get_art_method_spec(env, helper_art_method);
    let helper_compile = compile_art_method_to_quick(
        env,
        helper_art_method,
        helper_spec.entry_point_offset,
        bridge,
        RequestedCompileKind::Auto,
    );
    output_message(&format!(
        "[managedHook] compile helper: success={} compiled={} before={:#x} after={:#x} {}",
        helper_compile.success,
        helper_compile.compiled,
        helper_compile.before,
        helper_compile.after,
        helper_compile.message
    ));
    if is_art_quick_entrypoint(
        read_entry_point(helper_art_method, helper_spec.entry_point_offset),
        bridge,
    ) {
        return Err("managed helper still has shared ART entrypoint after compile".to_string());
    }
    let helper_entry_point = read_entry_point(helper_art_method, helper_spec.entry_point_offset);
    let orig_bypass_art_method = art_method;
    let class_global_ref = create_class_global_ref(env, class_name)?;
    let mut install_guard = JavaHookInstallGuard::new(
        art_method,
        spec.access_flags_offset,
        data_off,
        ep_offset,
        original_access_flags,
        original_data,
        original_entry_point,
        class_global_ref,
    );

    ensure_art_controller_initialized(&bridge, ep_offset, env as *mut std::ffi::c_void);
    update_original_method_flags_for_hook(art_method, spec.access_flags_offset, original_access_flags);
    install_guard.set_original_method_mutated();

    let (hook_addr, stealth_flag) =
        super::super::art_controller::prepare_hook_target(original_entry_point, env as *mut std::ffi::c_void)
            .map_err(|e| format!("prepare_hook_target: {}", e))?;
    let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
    let quick_trampoline = crate::ffi::hook::hook_install_managed_direct_router(
        hook_addr as *mut std::ffi::c_void,
        stealth_flag,
        env as *mut std::ffi::c_void,
        &mut hooked_target,
        helper_art_method,
        helper_entry_point,
        orig_bypass_art_method,
        0,
    );
    if quick_trampoline.is_null() {
        delete_local_ref(env, helper_cls);
        return Err("hook_install_managed_direct_router failed".to_string());
    }
    super::super::art_controller::try_fixup_trampoline_pub(quick_trampoline, original_entry_point);
    if let Some(backup_art_method) = orig_backup_art_method {
        let orig_stub = crate::ffi::hook::hook_create_managed_orig_stub(art_method, quick_trampoline);
        if orig_stub.is_null() {
            delete_local_ref(env, helper_cls);
            return Err("hook_create_managed_orig_stub failed".to_string());
        }
        set_orig_backup_entrypoint(
            backup_art_method,
            spec.size,
            spec.access_flags_offset,
            ep_offset,
            orig_stub as u64,
        )?;
    }
    let per_method_hook_target = if !hooked_target.is_null() {
        Some(hooked_target as u64)
    } else {
        Some(hook_addr)
    };
    let quick_trampoline = quick_trampoline as u64;
    delete_local_ref(env, helper_cls);
    let use_blr = false;

    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_entry_point,
                original_data,
                hook_type: HookType::Managed {
                    replacement_art_method: helper_art_method,
                    sentinel_addr: 0,
                    per_method_hook_target,
                },
                clone_addr: 0,
                class_global_ref,
                return_type: get_return_type_from_sig(actual_sig),
                return_type_sig: get_return_type_sig(actual_sig),
                ctx: 0,
                callback_bytes: [0u8; 16],
                method_key: method_key(class_name, method_name, actual_sig),
                is_static: false,
                param_count: count_jni_params(actual_sig),
                param_types: parse_jni_param_types(actual_sig),
                class_name: class_name.to_string(),
                quick_trampoline,
                use_blr,
                native_entry_hook_target: 0,
                native_entry_trampoline: 0,
                native_entry_critical: false,
            },
        );
    });

    cache_fields_for_class(env, class_name);
    output_message(&format!(
        "[managedHook] installed {} {}.{}{} -> helper ArtMethod={:#x}, original={:#x}, trampoline={:#x}",
        label, class_name, method_name, actual_sig, helper_art_method, art_method, quick_trampoline
    ));

    install_guard.commit();
    Ok(())
}

unsafe fn install_count_orig_fast_path(
    env: JniEnv,
    class_name: &str,
    method_name: &str,
    actual_sig: &str,
    art_method: u64,
    is_static: bool,
    helper_class: &str,
    counter_fields: &[String],
) -> Result<u64, String> {
    if counter_fields.is_empty() {
        return Err("count-orig fast path requires at least one counter".to_string());
    }

    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;
    let original_access_flags = std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let mut original_entry_point = read_entry_point(art_method, ep_offset);
    let bridge = find_art_bridge_functions(env, ep_offset);

    if is_art_quick_entrypoint(original_entry_point, bridge) {
        let compile = compile_art_method_to_quick(env, art_method, ep_offset, bridge, RequestedCompileKind::Auto);
        output_message(&format!(
            "[managedHook] compile original {}.{}{} for count-orig: success={} compiled={} before={:#x} after={:#x} {}",
            class_name,
            method_name,
            actual_sig,
            compile.success,
            compile.compiled,
            compile.before,
            compile.after,
            compile.message
        ));
        original_entry_point = read_entry_point(art_method, ep_offset);
    }
    if is_art_quick_entrypoint(original_entry_point, bridge) {
        return Err(format!(
            "{}.{}{} still has shared ART entrypoint after compile",
            class_name, method_name, actual_sig
        ));
    }

    let class_global_ref = create_class_global_ref(env, class_name)?;
    let mut install_guard = JavaHookInstallGuard::new(
        art_method,
        spec.access_flags_offset,
        data_off,
        ep_offset,
        original_access_flags,
        original_data,
        original_entry_point,
        class_global_ref,
    );

    ensure_art_controller_initialized(&bridge, ep_offset, env as *mut std::ffi::c_void);
    update_original_method_flags_for_hook(art_method, spec.access_flags_offset, original_access_flags);
    install_guard.set_original_method_mutated();

    let (hook_addr, stealth_flag) =
        super::super::art_controller::prepare_hook_target(original_entry_point, env as *mut std::ffi::c_void)
            .map_err(|e| format!("prepare_hook_target: {}", e))?;
    let mut counter_ptrs = install_native_counter_ptrs(helper_class, counter_fields);
    let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
    let quick_trampoline = crate::ffi::hook::hook_install_count_orig_router(
        hook_addr as *mut std::ffi::c_void,
        stealth_flag,
        env as *mut std::ffi::c_void,
        &mut hooked_target,
        counter_ptrs.as_mut_ptr() as *mut *mut u64,
        counter_ptrs.len() as u32,
    );
    if quick_trampoline.is_null() {
        return Err("hook_install_count_orig_router failed".to_string());
    }
    super::super::art_controller::try_fixup_trampoline_pub(quick_trampoline, original_entry_point);

    let per_method_hook_target = if !hooked_target.is_null() {
        Some(hooked_target as u64)
    } else {
        Some(hook_addr)
    };
    let quick_trampoline = quick_trampoline as u64;
    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_entry_point,
                original_data,
                hook_type: HookType::Managed {
                    replacement_art_method: 0,
                    sentinel_addr: 0,
                    per_method_hook_target,
                },
                clone_addr: 0,
                class_global_ref,
                return_type: get_return_type_from_sig(actual_sig),
                return_type_sig: get_return_type_sig(actual_sig),
                ctx: 0,
                callback_bytes: [0u8; 16],
                method_key: method_key(class_name, method_name, actual_sig),
                is_static,
                param_count: count_jni_params(actual_sig),
                param_types: parse_jni_param_types(actual_sig),
                class_name: class_name.to_string(),
                quick_trampoline,
                use_blr: false,
                native_entry_hook_target: 0,
                native_entry_trampoline: 0,
                native_entry_critical: false,
            },
        );
    });

    cache_fields_for_class(env, class_name);
    output_message(&format!(
        "[managedHook] installed count-orig fast path {}.{}{} counters={} original={:#x}, trampoline={:#x}",
        class_name,
        method_name,
        actual_sig,
        counter_fields.len(),
        art_method,
        quick_trampoline
    ));

    install_guard.commit();
    Ok(quick_trampoline)
}

struct ManagedDslInstallResult {
    helper_class: String,
    helper_method: String,
    helper_signature: String,
    uses_orig: bool,
    optimized_passthrough: bool,
    optimized_native_count_orig: bool,
    counters: Vec<GeneratedCounter>,
    message_channels: Vec<GeneratedMessageChannel>,
    message_capacity: i32,
}

unsafe fn install_managed_dsl_inner(
    class_name: &str,
    method_name: &str,
    sig: &str,
    dsl: &str,
    message_capacity: i32,
) -> Result<ManagedDslInstallResult, String> {
    let scoped_env = scoped_jni_env()?;
    let env = scoped_env.env();
    let (art_method, is_static) = resolve_art_method(env, class_name, method_name, sig, false)?;
    init_java_registry();
    if crate::jsapi::callback_util::with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false)
    {
        return Err(format!(
            "{}.{}{} already hooked — unhook first",
            class_name, method_name, sig
        ));
    }
    let class_id = DYNAMIC_MANAGED_CLASS_ID.fetch_add(1, Ordering::Relaxed);
    let generated = build_managed_dsl_dex(
        env,
        class_id,
        class_name,
        method_name,
        sig,
        is_static,
        dsl,
        message_capacity,
    )?;
    let helper_class = generated.class_name.clone();
    let helper_method = generated.method_name.clone();
    let helper_signature = generated.method_sig.clone();
    let uses_orig = generated.uses_orig;
    let optimized_passthrough = generated.orig_only_passthrough;
    let optimized_native_count_orig = !generated.fast_tail_orig_counter_fields.is_empty();
    let counters = generated.counters.clone();
    let message_channels = generated.message_channels.clone();
    let message_capacity = generated.message_capacity;
    output_message(&format!(
        "[managedHook] generated generic DSL dex class={} target={}.{}{} static={} fastTailOrig={} origOnlyPassthrough={} nativeCountOrig={} dexSize={}",
        generated.class_name,
        class_name,
        method_name,
        sig,
        is_static,
        generated.fast_tail_orig,
        generated.orig_only_passthrough,
        optimized_native_count_orig,
        generated.dex.len()
    ));
    if generated.orig_only_passthrough {
        output_message(&format!(
            "[managedHook] optimized {}.{}{} return-orig DSL as pass-through; no method patch installed",
            class_name, method_name, sig
        ));
        return Ok(ManagedDslInstallResult {
            helper_class,
            helper_method,
            helper_signature,
            uses_orig,
            optimized_passthrough,
            optimized_native_count_orig: false,
            counters,
            message_channels,
            message_capacity,
        });
    }
    if optimized_native_count_orig {
        install_count_orig_fast_path(
            env,
            class_name,
            method_name,
            sig,
            art_method,
            is_static,
            &helper_class,
            &generated.fast_tail_orig_counter_fields,
        )?;
        refresh_walkstack_sigsegv_guard();
        return Ok(ManagedDslInstallResult {
            helper_class,
            helper_method,
            helper_signature,
            uses_orig,
            optimized_passthrough,
            optimized_native_count_orig,
            counters,
            message_channels,
            message_capacity,
        });
    }
    let helper_cls = load_dynamic_managed_helper_class(env, generated.dex, &generated.class_name)?;
    register_managed_guard_helpers(env, helper_cls)?;
    initialize_generated_string_literals(env, helper_cls, &generated.string_literals)?;
    initialize_generated_message_queue(env, helper_cls, &generated.message_channels, generated.message_capacity)?;
    if generated.uses_direct_buffer_helpers {
        register_direct_buffer_helpers(env, helper_cls)?;
    }
    install_managed_method_helper(
        env,
        class_name,
        method_name,
        sig,
        Some(art_method),
        helper_cls,
        &generated.method_name,
        &generated.method_sig,
        generated
            .orig_backup_name
            .as_deref()
            .zip(generated.orig_backup_sig.as_deref()),
        "generic-dsl",
        generated.uses_orig,
    )?;
    refresh_walkstack_sigsegv_guard();
    Ok(ManagedDslInstallResult {
        helper_class,
        helper_method,
        helper_signature,
        uses_orig,
        optimized_passthrough,
        optimized_native_count_orig,
        counters,
        message_channels,
        message_capacity,
    })
}

unsafe fn extract_string_prop(
    ctx: *mut ffi::JSContext,
    obj: JSValue,
    names: &[&str],
    api: &str,
) -> Result<String, ffi::JSValue> {
    for name in names {
        let value = obj.get_property(ctx, name);
        if !value.is_undefined() && !value.is_null() {
            let result = value.to_string(ctx);
            value.free(ctx);
            if let Some(result) = result {
                return Ok(result);
            }
            return Err(throw_internal_error(
                ctx,
                format!("{} option '{}' must be a string", api, name),
            ));
        }
        value.free(ctx);
    }
    Err(throw_internal_error(
        ctx,
        format!("{} option missing: {}", api, names.join("/")),
    ))
}

unsafe fn extract_optional_i32_prop(
    ctx: *mut ffi::JSContext,
    obj: JSValue,
    names: &[&str],
    api: &str,
) -> Result<Option<i32>, ffi::JSValue> {
    for name in names {
        let value = obj.get_property(ctx, name);
        if !value.is_undefined() && !value.is_null() {
            let Some(parsed) = value.to_i64(ctx) else {
                value.free(ctx);
                return Err(throw_internal_error(
                    ctx,
                    format!("{} option '{}' must be an integer", api, name),
                ));
            };
            value.free(ctx);
            if parsed < i32::MIN as i64 || parsed > i32::MAX as i64 {
                return Err(throw_internal_error(
                    ctx,
                    format!("{} option '{}' is out of i32 range: {}", api, name, parsed),
                ));
            }
            return Ok(Some(parsed as i32));
        }
        value.free(ctx);
    }
    Ok(None)
}

unsafe fn extract_managed_hook_dsl_args(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> Result<(String, String, String, String, i32), ffi::JSValue> {
    if argc == 1 {
        let opts = JSValue(*argv);
        if !opts.is_object() || ffi::JS_IsArray(ctx, opts.raw()) != 0 {
            return Err(ffi::JS_ThrowTypeError(
                ctx,
                b"Java.managedHookDsl(object) requires an options object\0".as_ptr() as *const _,
            ));
        }
        let class_name = extract_string_prop(ctx, opts, &["className", "class"], "managedHookDsl")?;
        let method_name = extract_string_prop(ctx, opts, &["methodName", "method"], "managedHookDsl")?;
        let sig = extract_string_prop(ctx, opts, &["signature", "sig"], "managedHookDsl")?;
        let dsl = extract_string_prop(ctx, opts, &["dsl", "script"], "managedHookDsl")?;
        let message_capacity =
            extract_optional_i32_prop(ctx, opts, &["buff"], "managedHookDsl")?.unwrap_or(MANAGED_MESSAGE_CAPACITY);
        return Ok((class_name, method_name, sig, dsl, message_capacity));
    }

    if argc >= 4 {
        let Some(class_name) = JSValue(*argv).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg1 className must be a string",
            ));
        };
        let Some(method_name) = JSValue(*argv.add(1)).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg2 methodName must be a string",
            ));
        };
        let Some(sig) = JSValue(*argv.add(2)).to_string(ctx) else {
            return Err(throw_internal_error(
                ctx,
                "managedHookDsl arg3 signature must be a string",
            ));
        };
        let Some(dsl) = JSValue(*argv.add(3)).to_string(ctx) else {
            return Err(throw_internal_error(ctx, "managedHookDsl arg4 dsl must be a string"));
        };
        let message_capacity = if argc >= 5 {
            match JSValue(*argv.add(4)).to_i64(ctx) {
                Some(value) => value,
                None => return Err(throw_internal_error(ctx, "managedHookDsl arg5 buff must be an integer")),
            }
        } else {
            MANAGED_MESSAGE_CAPACITY as i64
        };
        if message_capacity < i32::MIN as i64 || message_capacity > i32::MAX as i64 {
            return Err(throw_internal_error(
                ctx,
                format!("managedHookDsl arg5 buff is out of i32 range: {}", message_capacity),
            ));
        }
        return Ok((class_name, method_name, sig, dsl, message_capacity as i32));
    }

    Err(throw_internal_error(
        ctx,
        "managedHookDsl requires object or (className, methodName, signature, dsl)",
    ))
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_managed_hook_dsl(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let (class_name, method_name, sig, dsl, message_capacity) = match extract_managed_hook_dsl_args(ctx, argc, argv) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let result = match install_managed_dsl_inner(&class_name, &method_name, &sig, &dsl, message_capacity) {
        Ok(result) => result,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let obj = JSValue(ffi::JS_NewObject(ctx));
    obj.set_property(ctx, "success", JSValue::bool(true));
    obj.set_property(ctx, "helperClass", JSValue::string(ctx, &result.helper_class));
    obj.set_property(ctx, "helperMethod", JSValue::string(ctx, &result.helper_method));
    obj.set_property(ctx, "helperSignature", JSValue::string(ctx, &result.helper_signature));
    obj.set_property(ctx, "usesOrig", JSValue::bool(result.uses_orig));
    obj.set_property(ctx, "optimizedPassThrough", JSValue::bool(result.optimized_passthrough));
    obj.set_property(
        ctx,
        "optimizedNativeCountOrig",
        JSValue::bool(result.optimized_native_count_orig),
    );
    let counters = JSValue(ffi::JS_NewObject(ctx));
    for counter in result.counters {
        counters.set_property(ctx, &counter.name, JSValue::string(ctx, &counter.field_name));
    }
    obj.set_property(ctx, "counters", counters);
    let messages = JSValue(ffi::JS_NewObject(ctx));
    for channel in result.message_channels {
        messages.set_property(ctx, &channel.name, JSValue::int(channel.code));
    }
    obj.set_property(ctx, "messages", messages);
    obj.set_property(ctx, "buff", JSValue::int(result.message_capacity));
    obj.raw()
}

unsafe fn extract_helper_class_arg(
    ctx: *mut ffi::JSContext,
    value: JSValue,
    api: &str,
) -> Result<String, ffi::JSValue> {
    if value.is_object() && ffi::JS_IsArray(ctx, value.raw()) == 0 {
        return extract_string_prop(ctx, value, &["helperClass", "className", "class"], api);
    }
    value
        .to_string(ctx)
        .ok_or_else(|| throw_internal_error(ctx, format!("{} helperClass must be a string or dslInfo object", api)))
}

unsafe fn managed_static_field_id(
    env: JniEnv,
    helper_cls: *mut std::ffi::c_void,
    name: &str,
    sig: &str,
) -> Result<*mut std::ffi::c_void, String> {
    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    let name = CString::new(name).map_err(|_| format!("invalid managed field name {}", name))?;
    let sig = CString::new(sig).map_err(|_| format!("invalid managed field sig {}", sig))?;
    let fid = get_static_field_id(env, helper_cls, name.as_ptr(), sig.as_ptr());
    if fid.is_null() || jni_check_exc(env) {
        return Err("managed message field not found".to_string());
    }
    Ok(fid)
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_managed_drain_messages(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return throw_internal_error(ctx, "managedDrainMessages requires (dslInfoOrHelperClass[, max])");
    }
    let helper_class = match extract_helper_class_arg(ctx, JSValue(*argv), "managedDrainMessages") {
        Ok(value) => value,
        Err(err) => return err,
    };
    let max_items_requested = if argc >= 2 {
        match JSValue(*argv.add(1)).to_i64(ctx) {
            Some(value) => Some(value),
            None => return throw_internal_error(ctx, "managedDrainMessages max must be an integer"),
        }
    } else {
        None
    };
    let Some(helper_cls) = find_dynamic_managed_helper_class(&helper_class) else {
        return throw_internal_error(ctx, format!("managed helper class not found: {}", helper_class));
    };
    let scoped_env = match scoped_jni_env() {
        Ok(env) => env,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let env = scoped_env.env();
    let get_static_int_field: GetStaticIntFieldFn = jni_fn!(env, GetStaticIntFieldFn, JNI_GET_STATIC_INT_FIELD);
    let set_static_int_field: SetStaticIntFieldFn = jni_fn!(env, SetStaticIntFieldFn, JNI_SET_STATIC_INT_FIELD);
    let get_static_object_field: GetStaticObjectFieldFn =
        jni_fn!(env, GetStaticObjectFieldFn, JNI_GET_STATIC_OBJECT_FIELD);
    let get_array_length: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_int_array_region: GetIntArrayRegionFn = jni_fn!(env, GetIntArrayRegionFn, JNI_GET_INT_ARRAY_REGION);
    let get_object_array_element: GetObjectArrayElementFn =
        jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let head_fid = match managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_HEAD_FIELD, "I") {
        Ok(fid) => fid,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let tail_fid = match managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_TAIL_FIELD, "I") {
        Ok(fid) => fid,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let dropped_fid = match managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_DROPPED_FIELD, "I") {
        Ok(fid) => fid,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let codes_fid = match managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_CODES_FIELD, "[I") {
        Ok(fid) => fid,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let values_fid = match managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_VALUES_FIELD, "[I") {
        Ok(fid) => fid,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let texts_fid = match managed_static_field_id(env, helper_cls, MANAGED_MESSAGE_TEXTS_FIELD, "[Ljava/lang/String;") {
        Ok(fid) => fid,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let head = get_static_int_field(env, helper_cls, head_fid);
    let tail = get_static_int_field(env, helper_cls, tail_fid);
    let dropped = get_static_int_field(env, helper_cls, dropped_fid);
    if jni_check_exc(env) {
        return throw_internal_error(ctx, "managedDrainMessages failed to read queue counters");
    }
    let codes_array = get_static_object_field(env, helper_cls, codes_fid);
    let values_array = get_static_object_field(env, helper_cls, values_fid);
    let texts_array = get_static_object_field(env, helper_cls, texts_fid);
    if codes_array.is_null() || values_array.is_null() || texts_array.is_null() || jni_check_exc(env) {
        return throw_internal_error(ctx, "managedDrainMessages message arrays are not initialized");
    }
    let capacity = get_array_length(env, codes_array)
        .min(get_array_length(env, values_array))
        .min(get_array_length(env, texts_array));
    if capacity <= 0 || jni_check_exc(env) {
        delete_local_ref(env, codes_array);
        delete_local_ref(env, values_array);
        delete_local_ref(env, texts_array);
        return throw_internal_error(ctx, "managedDrainMessages message arrays have invalid capacity");
    }
    let available = (head as i64 - tail as i64).clamp(0, capacity as i64) as i32;
    let max_items = max_items_requested
        .map(|value| value.clamp(0, capacity as i64) as i32)
        .unwrap_or(capacity);
    let count = available.min(max_items);

    let arr = ffi::JS_NewArray(ctx);
    if count > 0 {
        let mut codes = vec![0i32; capacity as usize];
        let mut values = vec![0i32; capacity as usize];
        get_int_array_region(env, codes_array, 0, capacity, codes.as_mut_ptr());
        get_int_array_region(env, values_array, 0, capacity, values.as_mut_ptr());
        if jni_check_exc(env) {
            delete_local_ref(env, codes_array);
            delete_local_ref(env, values_array);
            delete_local_ref(env, texts_array);
            return throw_internal_error(ctx, "managedDrainMessages failed to read message arrays");
        }
        let mask = capacity - 1;
        for i in 0..count {
            let slot = ((tail + i) & mask) as usize;
            let item = JSValue(ffi::JS_NewObject(ctx));
            item.set_property(ctx, "code", JSValue::int(codes[slot]));
            let text_obj = get_object_array_element(env, texts_array, slot as i32);
            if !text_obj.is_null() && !jni_check_exc(env) {
                if let Some(text) = unsafe { super::super::try_read_jstring(env as u64, text_obj as u64) } {
                    let value = JSValue::string(ctx, &text);
                    item.set_property(ctx, "value", value);
                    item.set_property(ctx, "text", JSValue::string(ctx, &text));
                } else {
                    item.set_property(ctx, "value", JSValue::int(values[slot]));
                }
                delete_local_ref(env, text_obj);
            } else {
                jni_check_exc(env);
                item.set_property(ctx, "value", JSValue::int(values[slot]));
            }
            ffi::JS_SetPropertyUint32(ctx, arr, i as u32, item.raw());
        }
    }
    delete_local_ref(env, codes_array);
    delete_local_ref(env, values_array);
    delete_local_ref(env, texts_array);
    let new_tail = tail.wrapping_add(count);
    set_static_int_field(env, helper_cls, tail_fid, new_tail);
    if jni_check_exc(env) {
        return throw_internal_error(ctx, "managedDrainMessages failed to update queue tail");
    }

    let out = JSValue(arr);
    out.set_property(ctx, "head", JSValue::int(head));
    out.set_property(ctx, "tail", JSValue::int(new_tail));
    out.set_property(ctx, "dropped", JSValue::int(dropped));
    out.set_property(ctx, "capacity", JSValue::int(capacity));
    out.raw()
}

pub(in crate::jsapi::java) unsafe extern "C" fn js_managed_read_counter(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_internal_error(ctx, "managedReadCounter requires (helperClass, fieldName)");
    }
    let Some(helper_class) = JSValue(*argv).to_string(ctx) else {
        return throw_internal_error(ctx, "managedReadCounter helperClass must be a string");
    };
    let Some(field_name) = JSValue(*argv.add(1)).to_string(ctx) else {
        return throw_internal_error(ctx, "managedReadCounter fieldName must be a string");
    };
    if let Some(value) = read_native_counter(&helper_class, &field_name) {
        return ffi::JS_NewBigUint64(ctx, value);
    }
    let Some(helper_cls) = find_dynamic_managed_helper_class(&helper_class) else {
        return throw_internal_error(ctx, format!("managed helper class not found: {}", helper_class));
    };
    let scoped_env = match scoped_jni_env() {
        Ok(env) => env,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let env = scoped_env.env();
    let get_static_field_id: GetStaticFieldIdFn = jni_fn!(env, GetStaticFieldIdFn, JNI_GET_STATIC_FIELD_ID);
    let get_static_int_field: GetStaticIntFieldFn = jni_fn!(env, GetStaticIntFieldFn, JNI_GET_STATIC_INT_FIELD);
    let field_name = match CString::new(field_name.as_str()) {
        Ok(value) => value,
        Err(_) => return throw_internal_error(ctx, "managedReadCounter fieldName contains NUL byte"),
    };
    let int_sig = CString::new("I").unwrap();
    let field_id = get_static_field_id(env, helper_cls, field_name.as_ptr(), int_sig.as_ptr());
    if field_id.is_null() || jni_check_exc(env) {
        return throw_internal_error(ctx, "managedReadCounter counter field not found");
    }
    let value = get_static_int_field(env, helper_cls, field_id);
    if jni_check_exc(env) {
        return throw_internal_error(ctx, "managedReadCounter GetStaticIntField failed");
    }
    ffi::JS_NewBigUint64(ctx, value as u32 as u64)
}
