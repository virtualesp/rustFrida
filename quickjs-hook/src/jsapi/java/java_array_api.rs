// ============================================================================
// Java array 访问：JS 侧 arr.length / arr[i] → JNI GetArrayLength / GetObjectArrayElement
//
// Java proxy wrapper 对 __jclass[0] == '[' 的对象（数组类型）调这两个 helper：
// - `Java._arrayLength(jptr)`：返回长度
// - `Java._arrayGet(jptr, idx, arrClass)`：返回元素的 wrapper / 原始值
//
// 目前只支持 object 数组（[L... / [[...）。原始类型数组（[I / [J / [Z ...）
// 返回时需要 GetIntArrayRegion 等，暂未实现。
// ============================================================================

use crate::ffi;
use crate::value::JSValue;

use super::callback::wrap_java_object_ref_for_array_elem;
use super::jni_core::get_thread_env;
use super::jni_core::{
    jni_check_exc, jni_fn_ptr, GetArrayLengthFn, GetObjectArrayElementFn, JniEnv, JNI_GET_ARRAY_LENGTH,
    JNI_GET_OBJECT_ARRAY_ELEMENT,
};

/// JS: `_arrayLength(jptr) -> number`
pub(super) unsafe extern "C" fn js_java_array_length(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return JSValue::int(-1).raw();
    }
    let jptr_val = JSValue(*argv);
    let jptr = match jptr_val.to_u64(ctx) {
        Some(p) if p != 0 => p,
        _ => return JSValue::int(-1).raw(),
    };

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return JSValue::int(-1).raw(),
    };

    let get_len: GetArrayLengthFn =
        std::mem::transmute::<*const std::ffi::c_void, GetArrayLengthFn>(jni_fn_ptr(env, JNI_GET_ARRAY_LENGTH));
    let len = get_len(env, jptr as *mut std::ffi::c_void);
    if jni_check_exc(env) {
        return JSValue::int(-1).raw();
    }
    JSValue::int(len).raw()
}

/// JS: `_arrayGet(jptr, idx, arrClass) -> wrapper`
/// arrClass 格式例如 `"[Ljava.lang.StackTraceElement;"`。
/// 元素类名 = 去掉首字符 `[`、去掉 `L` 前缀和 `;` 后缀（若存在）。
pub(super) unsafe extern "C" fn js_java_array_get(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::qjs_undefined();
    }
    let jptr_val = JSValue(*argv);
    let idx_val = JSValue(*argv.add(1));
    let cls_val = JSValue(*argv.add(2));

    let jptr = match jptr_val.to_u64(ctx) {
        Some(p) if p != 0 => p,
        _ => return ffi::qjs_null(),
    };
    let idx = match idx_val.to_i64(ctx) {
        Some(n) if n >= 0 && n < i32::MAX as i64 => n as i32,
        _ => return ffi::qjs_undefined(),
    };
    let arr_class = match cls_val.to_string(ctx) {
        Some(s) => s,
        None => return ffi::qjs_undefined(),
    };

    // 元素类名: `[Lfoo.Bar;` → `foo.Bar`; `[[Lfoo;` → `[Lfoo;`; `[I` → `I`(暂不支持)
    let elem_class = if !arr_class.starts_with('[') {
        arr_class.clone()
    } else {
        let inner = &arr_class[1..];
        if inner.starts_with('L') && inner.ends_with(';') && inner.len() >= 2 {
            inner[1..inner.len() - 1].to_string()
        } else {
            // 多维数组或原始类型数组 — 把内层 signature 原样带走
            inner.to_string()
        }
    };

    let env = match get_thread_env() {
        Ok(e) => e,
        Err(_) => return ffi::qjs_null(),
    };

    let get_elem: GetObjectArrayElementFn = std::mem::transmute::<*const std::ffi::c_void, GetObjectArrayElementFn>(
        jni_fn_ptr(env, JNI_GET_OBJECT_ARRAY_ELEMENT),
    );
    let obj = get_elem(env, jptr as *mut std::ffi::c_void, idx);
    if obj.is_null() || jni_check_exc(env) {
        return ffi::qjs_null();
    }

    // 转全局引用 + 生成 {__jptr, __jclass} wrapper，让 JS 侧可继续调方法。
    wrap_java_object_ref_for_array_elem(ctx, env, obj, &elem_class)
}
