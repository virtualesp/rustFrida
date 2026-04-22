// ============================================================================
// callOriginal() — JS CFunction invoked from user's hook callback
// ============================================================================

/// Dispatch a JNI call via either static or nonvirtual variant, based on `$is_static`.
/// Consolidates the static/instance arms into one match expression.
macro_rules! dispatch_call {
    ($env:expr, $static_idx:expr, $nonvirt_idx:expr,
     $cls:expr, $this:expr, $mid:expr, $args:expr, $is_static:expr, $ret_ty:ty) => {{
        if $is_static {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> $ret_ty;
            let f: F = jni_fn!($env, F, $static_idx);
            f($env, $cls, $mid, $args)
        } else {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> $ret_ty;
            let f: F = jni_fn!($env, F, $nonvirt_idx);
            f($env, $this, $cls, $mid, $args)
        }
    }};
}

/// Convert a JS value to a JNI jvalue (u64) based on the parameter type descriptor.
///
/// Handles: primitives (Z/B/C/S/I/J/F/D), String (JS string → NewStringUTF),
/// objects ({__jptr} or Proxy → extract raw pointer), BigUint64 (raw pointer),
/// null/undefined → 0.
pub(super) unsafe fn marshal_js_to_jvalue(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
    type_sig: Option<&str>,
) -> u64 {
    if val.is_null() || val.is_undefined() {
        return 0;
    }

    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => {
            // No type info — try number or bigint
            return js_value_to_u64_or_zero(ctx, val);
        }
    };

    match sig.as_bytes()[0] {
        b'Z' => {
            if let Some(b) = val.to_bool() {
                b as u64
            } else if let Some(n) = val.to_i64(ctx) {
                (n != 0) as u64
            } else {
                0
            }
        }
        b'B' | b'S' | b'I' => {
            if let Some(n) = val.to_i64(ctx) {
                n as u64
            } else {
                0
            }
        }
        b'C' => {
            // char: JS string (first char) or number
            if let Some(s) = val.to_string(ctx) {
                s.chars().next().map(|c| c as u64).unwrap_or(0)
            } else if let Some(n) = val.to_i64(ctx) {
                n as u64
            } else {
                0
            }
        }
        b'J' => {
            js_value_to_u64_or_zero(ctx, val)
        }
        b'F' => {
            if let Some(f) = val.to_float() {
                (f as f32).to_bits() as u64
            } else {
                0
            }
        }
        b'D' => {
            if let Some(f) = val.to_float() {
                f.to_bits()
            } else {
                0
            }
        }
        b'[' => {
            // 数组类型: JS array → Java primitive array (via NewXxxArray + SetXxxArrayRegion)
            // Fallback: JS object with __jptr (已存在的 Java 数组) → 透传
            if ffi::JS_IsArray(ctx, val.raw()) != 0 {
                return js_array_to_java_primitive_array(ctx, env, val, sig).unwrap_or(0);
            }
            if val.is_object() {
                let jptr_val = val.get_property(ctx, "__jptr");
                if !jptr_val.is_undefined() && !jptr_val.is_null() {
                    let result = js_value_to_u64_or_zero(ctx, jptr_val);
                    jptr_val.free(ctx);
                    return result;
                }
                jptr_val.free(ctx);
            }
            0
        }
        b'L' => {
            // JS string → NewStringUTF for ANY Object type (not just Ljava/lang/String;).
            // ctx.orig() 返回 String 时 marshal_jni_arg_to_js 会 unbox 为 JS string，
            // 但 return_type_sig 可能是 Ljava/lang/Object; (如 HashMap.put)。
            // 必须对所有 L 类型创建 JNI String，否则 fallback 返回 QuickJS 内部指针 → SIGSEGV。
            if val.is_string() {
                if let Some(s) = val.to_string(ctx) {
                    let cstr = match CString::new(s) {
                        Ok(c) => c,
                        Err(_) => return 0,
                    };
                    let new_str: NewStringUtfFn =
                        jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
                    let jstr = new_str(env, cstr.as_ptr());
                    return jstr as u64;
                }
                return 0;
            }
            // JS array → Java Object[] (每个元素按 Ljava/lang/Object; 再 marshal);
            // 只在目标是 Object/Serializable/Comparable 等通用 L 类型时触发, 避免遮蔽
            // 其它 L 类型 (例 Ljava/util/Map; 用户手动 __jptr 传递)。
            if ffi::JS_IsArray(ctx, val.raw()) != 0 {
                let is_generic_object = matches!(
                    sig,
                    "Ljava/lang/Object;" | "Ljava/io/Serializable;" | "Ljava/lang/Comparable;"
                );
                if is_generic_object {
                    return js_array_to_java_primitive_array(
                        ctx, env, val, "[Ljava/lang/Object;",
                    )
                    .unwrap_or(0);
                }
            }
            // JS object → try __jptr property (Proxy-wrapped or {__jptr, __jclass})
            if val.is_object() {
                let jptr_val = val.get_property(ctx, "__jptr");
                if !jptr_val.is_undefined() && !jptr_val.is_null() {
                    let result = js_value_to_u64_or_zero(ctx, jptr_val);
                    jptr_val.free(ctx);
                    return result;
                }
                jptr_val.free(ctx);
            }
            // Autobox: JS number/boolean/bigint → Java 包装类型
            // 传入目标类型签名，精确匹配 Long/Float/Short/Byte 等
            if let Some(boxed) = autobox_primitive_to_jobject(ctx, env, val, sig) {
                return boxed;
            }
            0
        }
        _ => js_value_to_u64_or_zero(ctx, val),
    }
}

/// 读 JS 数组长度 (通过 length property).
unsafe fn js_array_len(ctx: *mut ffi::JSContext, arr: JSValue) -> i32 {
    let len_atom = ffi::JS_NewAtom(ctx, b"length\0".as_ptr() as *const _);
    let len_val_raw = ffi::qjs_get_property(ctx, arr.raw(), len_atom);
    ffi::JS_FreeAtom(ctx, len_atom);
    let len_val = JSValue(len_val_raw);
    let len = len_val.to_i64(ctx).unwrap_or(0);
    len_val.free(ctx);
    if len < 0 || len > i32::MAX as i64 { 0 } else { len as i32 }
}

/// JS array → Java 原始类型数组 (`[B`/`[Z`/`[C`/`[S`/`[I`/`[J`/`[F`/`[D`)。
/// 非原始类型数组 (如 `[Ljava/lang/String;`) 不处理, 返回 None。
///
/// 流程: NewXxxArray(len) → Rust Vec 填值 → SetXxxArrayRegion → 返回 jobject。
unsafe fn js_array_to_java_primitive_array(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    arr: JSValue,
    sig: &str,
) -> Option<u64> {
    let elem_type = sig.as_bytes().get(1).copied()?;
    let len = js_array_len(ctx, arr);

    macro_rules! build_array {
        ($new_idx:ident, $set_idx:ident, $set_fn:ident, $elem:ty, $convert:expr) => {{
            let new_fn: NewPrimitiveArrayFn = jni_fn!(env, NewPrimitiveArrayFn, $new_idx);
            let jarr = new_fn(env, len);
            if jarr.is_null() {
                return None;
            }
            let mut buf: Vec<$elem> = Vec::with_capacity(len as usize);
            for i in 0..len {
                let elem_raw = ffi::JS_GetPropertyUint32(ctx, arr.raw(), i as u32);
                let elem = JSValue(elem_raw);
                buf.push($convert(ctx, elem));
                elem.free(ctx);
            }
            let set_fn: $set_fn = jni_fn!(env, $set_fn, $set_idx);
            set_fn(env, jarr, 0, len, buf.as_ptr());
            Some(jarr as u64)
        }};
    }

    match elem_type {
        b'Z' => build_array!(
            JNI_NEW_BOOLEAN_ARRAY, JNI_SET_BOOLEAN_ARRAY_REGION, SetBooleanArrayRegionFn, u8,
            |_ctx: *mut ffi::JSContext, v: JSValue| {
                if let Some(b) = v.to_bool() { b as u8 }
                else { v.to_i64(_ctx).map(|n| (n != 0) as u8).unwrap_or(0) }
            }
        ),
        b'B' => build_array!(
            JNI_NEW_BYTE_ARRAY, JNI_SET_BYTE_ARRAY_REGION, SetByteArrayRegionFn, i8,
            |ctx: *mut ffi::JSContext, v: JSValue| v.to_i64(ctx).unwrap_or(0) as i8
        ),
        b'C' => build_array!(
            JNI_NEW_CHAR_ARRAY, JNI_SET_CHAR_ARRAY_REGION, SetCharArrayRegionFn, u16,
            |ctx: *mut ffi::JSContext, v: JSValue| {
                if let Some(s) = v.to_string(ctx) {
                    s.chars().next().map(|c| c as u16).unwrap_or(0)
                } else {
                    v.to_i64(ctx).unwrap_or(0) as u16
                }
            }
        ),
        b'S' => build_array!(
            JNI_NEW_SHORT_ARRAY, JNI_SET_SHORT_ARRAY_REGION, SetShortArrayRegionFn, i16,
            |ctx: *mut ffi::JSContext, v: JSValue| v.to_i64(ctx).unwrap_or(0) as i16
        ),
        b'I' => build_array!(
            JNI_NEW_INT_ARRAY, JNI_SET_INT_ARRAY_REGION, SetIntArrayRegionFn, i32,
            |ctx: *mut ffi::JSContext, v: JSValue| v.to_i64(ctx).unwrap_or(0) as i32
        ),
        b'J' => build_array!(
            JNI_NEW_LONG_ARRAY, JNI_SET_LONG_ARRAY_REGION, SetLongArrayRegionFn, i64,
            |ctx: *mut ffi::JSContext, v: JSValue| v.to_i64(ctx).unwrap_or(0)
        ),
        b'F' => build_array!(
            JNI_NEW_FLOAT_ARRAY, JNI_SET_FLOAT_ARRAY_REGION, SetFloatArrayRegionFn, f32,
            |_ctx: *mut ffi::JSContext, v: JSValue| v.to_float().unwrap_or(0.0) as f32
        ),
        b'D' => build_array!(
            JNI_NEW_DOUBLE_ARRAY, JNI_SET_DOUBLE_ARRAY_REGION, SetDoubleArrayRegionFn, f64,
            |_ctx: *mut ffi::JSContext, v: JSValue| v.to_float().unwrap_or(0.0)
        ),
        b'L' | b'[' => {
            // 对象数组 `[Ljava/...;` 或嵌套数组 `[[X`。
            // 对象数组: 元素类名取 inner_sig 的 `L...;` 去壳 (例: "java/lang/String")
            // 嵌套数组: 元素类名本身就是 inner_sig (例: "[I" / "[[B" / "[Ljava/lang/String;")
            // FindClass 对 array-of-primitive / nested-array 形式都接受 JNI 签名字符串。
            let inner_sig = &sig[1..];
            let elem_class_name: String = if elem_type == b'L' {
                if !inner_sig.starts_with('L') || !inner_sig.ends_with(';') {
                    return None;
                }
                inner_sig[1..inner_sig.len() - 1].to_string()
            } else {
                // nested array — FindClass 吃 "[I" / "[[Ljava/lang/String;" 原样
                inner_sig.to_string()
            };
            let cls = super::reflect::find_class_safe(env, &elem_class_name);
            if cls.is_null() {
                return None;
            }
            let new_obj_arr: NewObjectArrayFn = jni_fn!(env, NewObjectArrayFn, JNI_NEW_OBJECT_ARRAY);
            let jarr = new_obj_arr(env, len, cls, std::ptr::null_mut());
            let delete: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
            if jarr.is_null() {
                delete(env, cls);
                return None;
            }
            let set_elem: SetObjectArrayElementFn =
                jni_fn!(env, SetObjectArrayElementFn, JNI_SET_OBJECT_ARRAY_ELEMENT);
            for i in 0..len {
                let elem_raw = ffi::JS_GetPropertyUint32(ctx, arr.raw(), i as u32);
                let elem = JSValue(elem_raw);
                // 递归 marshal: 内层若是 "[X" 会再进 js_array_to_java_primitive_array,
                // 内层若是 "Ljava/.../X;" 走 L 分支 (string/autobox/__jptr)
                let elem_jval = marshal_js_to_jvalue(ctx, env, elem, Some(inner_sig));
                elem.free(ctx);
                set_elem(env, jarr, i, elem_jval as *mut std::ffi::c_void);
            }
            delete(env, cls);
            Some(jarr as u64)
        }
        _ => None,
    }
}

/// Autobox JS primitive → Java wrapper object via JNI static valueOf().
/// 根据目标类型签名精确选择装箱类型，fallback 到默认推断。
unsafe fn autobox_primitive_to_jobject(
    _ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
    target_sig: &str,
) -> Option<u64> {
    use super::jni_core::*;
    use super::reflect::find_class_safe;

    macro_rules! box_via_valueof {
        ($class:expr, $sig:expr, $raw:expr) => {{
            let cls = find_class_safe(env, $class);
            if cls.is_null() { return None; }
            let get_mid: GetStaticMethodIdFn = jni_fn!(env, GetStaticMethodIdFn, JNI_GET_STATIC_METHOD_ID);
            let mid = get_mid(env, cls, b"valueOf\0".as_ptr() as _, $sig.as_ptr() as _);
            let delete: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
            if mid.is_null() { delete(env, cls); return None; }
            let call: CallStaticObjectMethodAFn =
                jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
            let jval: u64 = $raw;
            let result = call(env, cls, mid, &jval as *const u64 as *const std::ffi::c_void);
            delete(env, cls);
            if result.is_null() { None } else { Some(result as u64) }
        }};
    }

    // boolean → Boolean
    if val.is_bool() {
        let b = val.to_bool().unwrap_or(false);
        return box_via_valueof!("java/lang/Boolean", b"(Z)Ljava/lang/Boolean;\0", b as u64);
    }

    // number → 根据目标签名选择精确的包装类型
    if let Some(f) = val.to_float() {
        return match target_sig {
            "Ljava/lang/Byte;" => box_via_valueof!("java/lang/Byte", b"(B)Ljava/lang/Byte;\0", f as i8 as u8 as u64),
            "Ljava/lang/Short;" => box_via_valueof!("java/lang/Short", b"(S)Ljava/lang/Short;\0", f as i16 as u16 as u64),
            "Ljava/lang/Long;" => box_via_valueof!("java/lang/Long", b"(J)Ljava/lang/Long;\0", f as i64 as u64),
            "Ljava/lang/Float;" => box_via_valueof!("java/lang/Float", b"(F)Ljava/lang/Float;\0", (f as f32).to_bits() as u64),
            "Ljava/lang/Double;" => box_via_valueof!("java/lang/Double", b"(D)Ljava/lang/Double;\0", f.to_bits()),
            "Ljava/lang/Integer;" => box_via_valueof!("java/lang/Integer", b"(I)Ljava/lang/Integer;\0", f as i32 as u32 as u64),
            _ => {
                // 默认: int 范围→Integer, 否则→Double
                let fits_int = f == (f as i32 as f64) && f.abs() < (i32::MAX as f64);
                if fits_int {
                    box_via_valueof!("java/lang/Integer", b"(I)Ljava/lang/Integer;\0", f as i32 as u32 as u64)
                } else {
                    box_via_valueof!("java/lang/Double", b"(D)Ljava/lang/Double;\0", f.to_bits())
                }
            }
        };
    }

    // bigint → 根据目标签名选择
    if let Some(n) = val.to_i64(_ctx) {
        return match target_sig {
            "Ljava/lang/Integer;" => box_via_valueof!("java/lang/Integer", b"(I)Ljava/lang/Integer;\0", n as i32 as u32 as u64),
            "Ljava/lang/Short;" => box_via_valueof!("java/lang/Short", b"(S)Ljava/lang/Short;\0", n as i16 as u16 as u64),
            "Ljava/lang/Byte;" => box_via_valueof!("java/lang/Byte", b"(B)Ljava/lang/Byte;\0", n as i8 as u8 as u64),
            _ => box_via_valueof!("java/lang/Long", b"(J)Ljava/lang/Long;\0", n as u64),
        };
    }

    None
}

/// Invoke original ArtMethod via JNI using provided jvalue args.
///
/// 2-ArtMethod 模型: 直接用原始 ArtMethod 地址作为 JNI method ID，
/// 无需 clone，declaring_class_ 由 GC 自动维护。
///
/// Shared by `js_call_original` (JS callback) and fallback path (JS engine busy).
/// Returns the raw u64 return value for writing to HookContext.x[0].
/// For void methods, returns 0.
/// app 原方法抛的 Java 异常 **不 clear, 不 take** — 保留 pending 在 JNIEnv,
/// 让它沿标准 JNI 路径自然传播到 Java 调用方 (Frida 行为)。
///
/// 约束: JS 回调里如果 orig() 后再做 JNI 调用, CheckJNI 见 pending 会 abort;
/// 用户需自己处理 (try/catch 或避免后续 JNI)。
pub(super) unsafe fn invoke_original_jni(
    env: JniEnv,
    art_method_addr: u64,
    class_global_ref: usize,
    this_obj: u64,
    return_type: u8,
    is_static: bool,
    jargs_ptr: *const std::ffi::c_void,
    quick_trampoline: u64,
) -> u64 {
    jni_check_exc(env);

    crate::jsapi::java::art_controller::set_call_original_bypass(art_method_addr);

    let result = invoke_original_jni_inner(
        env, art_method_addr, class_global_ref, this_obj, return_type, is_static, jargs_ptr,
    );

    crate::jsapi::java::art_controller::clear_call_original_bypass();
    result
}

unsafe fn invoke_original_jni_inner(
    env: JniEnv,
    art_method_addr: u64,
    class_global_ref: usize,
    this_obj: u64,
    return_type: u8,
    is_static: bool,
    jargs_ptr: *const std::ffi::c_void,
) -> u64 {
    let method_id = art_method_addr as *mut std::ffi::c_void;
    let cls = class_global_ref as *mut std::ffi::c_void;
    let this_ptr = this_obj as *mut std::ffi::c_void;

    match return_type {
        b'V' => {
            dispatch_call!(
                env,
                JNI_CALL_STATIC_VOID_METHOD_A,
                JNI_CALL_NONVIRTUAL_VOID_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                ()
            );
            0
        }
        b'Z' => {
            let ret: u8 = dispatch_call!(
                env,
                JNI_CALL_STATIC_BOOLEAN_METHOD_A,
                JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                u8
            );
            ret as u64
        }
        b'I' | b'B' | b'C' | b'S' => {
            let ret: i32 = dispatch_call!(
                env,
                JNI_CALL_STATIC_INT_METHOD_A,
                JNI_CALL_NONVIRTUAL_INT_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                i32
            );
            ret as u64
        }
        b'J' => {
            let ret: i64 = dispatch_call!(
                env,
                JNI_CALL_STATIC_LONG_METHOD_A,
                JNI_CALL_NONVIRTUAL_LONG_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                i64
            );
            ret as u64
        }
        b'F' => {
            let ret: f32 = dispatch_call!(
                env,
                JNI_CALL_STATIC_FLOAT_METHOD_A,
                JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                f32
            );
            jni_check_exc(env);
            ret.to_bits() as u64
        }
        b'D' => {
            let ret: f64 = dispatch_call!(
                env,
                JNI_CALL_STATIC_DOUBLE_METHOD_A,
                JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                f64
            );
            jni_check_exc(env);
            ret.to_bits()
        }
        b'L' | b'[' => {
            let ret: *mut std::ffi::c_void = dispatch_call!(
                env,
                JNI_CALL_STATIC_OBJECT_METHOD_A,
                JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A,
                cls,
                this_ptr,
                method_id,
                jargs_ptr,
                is_static,
                *mut std::ffi::c_void
            );
            ret as u64
        }
        _ => 0,
    }
}

/// Build jvalue args from HookContext registers (ARM64 JNI calling convention).
pub(super) unsafe fn build_jargs_from_registers(
    hook_ctx: &hook_ffi::HookContext,
    param_count: usize,
    param_types: &[String],
) -> Vec<u64> {
    let mut jargs: Vec<u64> = Vec::with_capacity(param_count);
    let mut gp_index: usize = 0;
    let mut fp_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let (gp_val, fp_val) = extract_jni_arg(
            hook_ctx,
            is_floating_point_type(type_sig),
            &mut gp_index,
            &mut fp_index,
        );
        jargs.push(if is_floating_point_type(type_sig) {
            fp_val
        } else {
            gp_val
        });
    }
    jargs
}

/// JS CFunction: ctx.orig() or ctx.orig(arg0, arg1, ...)
///
/// No arguments: invokes the original method with the original register arguments.
/// With arguments: invokes the original method with user-specified arguments (JS → jvalue conversion).
///
/// 2-ArtMethod 模型: 直接用原始 ArtMethod 地址作为 JNI method ID 调用。
/// Returns the method's return value as a JS value.
///
/// Must be called from a hook context object created by java_hook_callback.
unsafe extern "C" fn js_call_original(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let art_method_addr = get_js_u64_property(ctx, this_val, "__hookArtMethod");
    let ctx_ptr = get_js_u64_property(ctx, this_val, "__hookCtxPtr") as *mut hook_ffi::HookContext;
    if ctx_ptr.is_null() || art_method_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"orig() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // Look up hook data
    let (
        class_global_ref,
        return_type,
        return_type_sig,
        param_count,
        is_static,
        param_types,
        quick_trampoline,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"orig: hook registry not initialized\0".as_ptr() as *const _,
                );
            }
        };
        let data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"orig: hook data not found\0".as_ptr() as *const _,
                );
            }
        };
        (
            data.class_global_ref,
            data.return_type,
            data.return_type_sig.clone(),
            data.param_count,
            data.is_static,
            data.param_types.clone(),
            data.quick_trampoline,
        )
    }; // lock released

    // art_method_addr 已在上方检查 (!=0), 此处无需再检查

    let hook_ctx = &*ctx_ptr;

    // Unified JNI calling convention: x0=JNIEnv*, x1=this/class, x2+=args
    let env: JniEnv = {
        let e = hook_ctx.x[0] as JniEnv;
        if e.is_null() {
            return ffi::JS_ThrowInternalError(
                ctx,
                b"orig: JNIEnv* is null\0".as_ptr() as *const _,
            );
        }
        e
    };

    // 始终从 hook_ctx 寄存器读参数 (transition ref)。
    // transition ref 指向 GenericJNI 帧 vreg CompressedReference，GC 会实时更新该值。
    // 比从 JS __jptr 缓存读更安全（__jptr 和 transition ref 是同一个栈地址，
    // 但绕过 marshal 避免潜在的 JS 对象生命周期问题）。
    // TODO: 支持用户修改参数时需要 hybrid 策略
    let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };

    let ret_raw = invoke_original_jni(
        env,
        art_method_addr,
        class_global_ref,
        hook_ctx.x[1],
        return_type,
        is_static,
        jargs_ptr,
        quick_trampoline,
    );

    match return_type {
        b'V' => ffi::qjs_undefined(),
        b'Z' => JSValue::bool(ret_raw != 0).raw(),
        b'I' | b'B' | b'C' | b'S' => JSValue::int(ret_raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, ret_raw),
        b'F' => JSValue::float(f32::from_bits(ret_raw as u32) as f64).raw(),
        b'D' => JSValue::float(f64::from_bits(ret_raw)).raw(),
        b'L' | b'[' => {
            if ret_raw == 0 {
                ffi::qjs_null()
            } else {
                let js_val = marshal_jni_arg_to_js(ctx, env, ret_raw, 0, Some(&return_type_sig));
                // 如果 marshal 返回了 {__jptr} wrapper（普通 Object），直接用
                if JSValue(js_val).is_object() {
                    let jptr = JSValue(js_val).get_property(ctx, "__jptr");
                    let has_jptr = !jptr.is_undefined();
                    jptr.free(ctx);
                    if has_jptr {
                        return js_val;
                    }
                }
                // unboxed (String/Integer/Boolean/Array 等):
                // 包装为 {value: 可读值, __origJobject: 原始 jobject}
                // handle_result 优先读 __origJobject，确保所有类型安全 round-trip
                let wrapper = ffi::JS_NewObject(ctx);
                let w = JSValue(wrapper);
                w.set_property(ctx, "value", JSValue(js_val));
                let ptr_val = ffi::JS_NewBigUint64(ctx, ret_raw);
                w.set_property(ctx, "__origJobject", JSValue(ptr_val));
                // toString() 返回可读值，console.log 友好
                let to_str_src = b"(function(){return String(this.value);})\0";
                let to_str = ffi::JS_Eval(ctx, to_str_src.as_ptr() as *const _,
                    (to_str_src.len() - 1) as _, b"<toString>\0".as_ptr() as *const _, 0);
                if ffi::qjs_is_exception(to_str) == 0 {
                    w.set_property(ctx, "toString", JSValue(to_str));
                } else {
                    ffi::qjs_free_value(ctx, to_str);
                }
                wrapper
            }
        }
        _ => ffi::qjs_undefined(),
    }
}
