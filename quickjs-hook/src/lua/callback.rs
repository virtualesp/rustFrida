use super::ffi as lua_ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::java::callback::{
    extract_jni_arg, is_floating_point_type, build_jargs_from_registers,
    invoke_original_jni, InFlightJavaHookGuard, JavaHookCallbackScope,
};

/// 传递给 orig() upvalue 的上下文
#[repr(C)]
pub(crate) struct CallbackContext {
    pub env: crate::jsapi::java::jni_core::JniEnv,
    pub art_method: u64,
    pub class_global_ref: usize,
    pub this_obj: u64,
    pub return_type: u8,
    pub is_static: bool,
    pub jargs_ptr: *const std::ffi::c_void,
    pub quick_trampoline: u64,
}

/// Lua callback 入口 — 从 java_hook_callback dispatch 过来
pub unsafe extern "C" fn lua_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _in_flight = InFlightJavaHookGuard::enter();
    let _scope = JavaHookCallbackScope::enter();

    let art_method_addr = user_data as u64;

    let entry_data = match super::with_lua_hook(art_method_addr, |e| {
        (
            e.bytecode.clone(),
            e.is_raw_bytecode,
            e.is_static,
            e.param_count,
            e.param_types.clone(),
            e.return_type,
            e.class_global_ref,
            e.quick_trampoline,
        )
    }) {
        Some(d) => d,
        None => {
            (*ctx_ptr).x[0] = 0;
            return;
        }
    };

    let (
        bytecode,
        is_raw_bytecode,
        is_static,
        param_count,
        param_types,
        return_type,
        class_global_ref,
        quick_trampoline,
    ) = entry_data;

    let env = (*ctx_ptr).x[0] as crate::jsapi::java::jni_core::JniEnv;
    let hook_ctx = &*ctx_ptr;

    // 设置线程局部 env，供 jstr() / print() 自动 toString 使用
    super::api::set_current_env(env as *const std::ffi::c_void);

    let tls = match super::get_thread_lua_state() {
        Some(t) => t,
        None => {
            fallback_call_original(
                ctx_ptr, env, art_method_addr, class_global_ref,
                param_count, &param_types, return_type, is_static, quick_trampoline,
            );
            return;
        }
    };

    let func_ref = match super::ensure_hook_loaded(tls, art_method_addr, &bytecode, is_raw_bytecode) {
        Ok(r) => r,
        Err(e) => {
            crate::jsapi::console::output_message(&format!(
                "[lua] 加载 callback 失败: {}", e
            ));
            fallback_call_original(
                ctx_ptr, env, art_method_addr, class_global_ref,
                param_count, &param_types, return_type, is_static, quick_trampoline,
            );
            return;
        }
    };

    let L = tls.state.as_ptr();

    // 从 registry 获取 callback function
    lua_ffi::lua_rawgeti(L, lua_ffi::LUA_REGISTRYINDEX, func_ref as lua_ffi::lua_Integer);

    // 构建 ctx table
    lua_ffi::lua_createtable(L, 0, 4);

    // ctx.args = {arg1, arg2, ...}
    lua_ffi::lua_createtable(L, param_count as i32, 0);
    {
        let mut gp_index: usize = 0;
        let mut fp_index: usize = 0;
        for i in 0..param_count {
            let type_sig = param_types.get(i).map(|s| s.as_str());
            let (raw, fp_raw) = extract_jni_arg(
                hook_ctx,
                is_floating_point_type(type_sig),
                &mut gp_index,
                &mut fp_index,
            );
            super::api::push_jni_arg(L, raw, fp_raw, type_sig, env as *const std::ffi::c_void);
            lua_ffi::lua_rawseti(L, -2, (i + 1) as lua_ffi::lua_Integer);
        }
    }
    let cstr_args = c"args";
    lua_ffi::lua_setfield(L, -2, cstr_args.as_ptr());

    // ctx.thisObj
    if !is_static {
        let this_obj = hook_ctx.x[1];
        if this_obj != 0 {
            lua_ffi::lua_pushlightuserdata(L, this_obj as *mut std::ffi::c_void);
        } else {
            lua_ffi::lua_pushnil(L);
        }
        let cstr_this = c"thisObj";
        lua_ffi::lua_setfield(L, -2, cstr_this.as_ptr());
    }

    // ctx.env
    lua_ffi::lua_pushinteger(L, env as lua_ffi::lua_Integer);
    let cstr_env = c"env";
    lua_ffi::lua_setfield(L, -2, cstr_env.as_ptr());

    // ctx:orig()
    let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
    let jargs_ptr: *const std::ffi::c_void = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };
    let cb_ctx = CallbackContext {
        env,
        art_method: art_method_addr,
        class_global_ref,
        this_obj: hook_ctx.x[1],
        return_type,
        is_static,
        jargs_ptr,
        quick_trampoline,
    };
    lua_ffi::lua_pushlightuserdata(L, &cb_ctx as *const _ as *mut std::ffi::c_void);
    lua_ffi::lua_pushcclosure(L, Some(super::api::lua_call_original), 1);
    let cstr_orig = c"orig";
    lua_ffi::lua_setfield(L, -2, cstr_orig.as_ptr());

    // callback(ctx) → 1 返回值
    let call_ret = lua_ffi::lua_pcall(L, 1, 1, 0);
    if call_ret != lua_ffi::LUA_OK as i32 {
        let err_s = lua_ffi::lua_tostring_ex(L, -1);
        if !err_s.is_null() {
            let err = std::ffi::CStr::from_ptr(err_s).to_string_lossy();
            crate::jsapi::console::output_message(&format!("[lua] callback error: {}", err));
        }
        lua_ffi::lua_pop(L, 1);
        super::api::clear_current_env();
        fallback_call_original(
            ctx_ptr, env, art_method_addr, class_global_ref,
            param_count, &param_types, return_type, is_static, quick_trampoline,
        );
        return;
    }

    // 提取返回值
    if return_type != b'V' {
        let ret_val = extract_lua_return(L, -1, return_type);
        (*ctx_ptr).x[0] = ret_val;
    }
    lua_ffi::lua_pop(L, 1);
    super::api::clear_current_env();
}

unsafe fn extract_lua_return(
    L: *mut lua_ffi::lua_State,
    idx: i32,
    return_type: u8,
) -> u64 {
    match return_type {
        b'V' => 0,
        b'Z' => lua_ffi::lua_toboolean(L, idx) as u64,
        b'B' => lua_ffi::lua_tointeger_ex(L, idx) as i8 as u64,
        b'C' => lua_ffi::lua_tointeger_ex(L, idx) as u16 as u64,
        b'S' => lua_ffi::lua_tointeger_ex(L, idx) as i16 as u64,
        b'I' => lua_ffi::lua_tointeger_ex(L, idx) as i32 as u64,
        b'J' => lua_ffi::lua_tointeger_ex(L, idx) as u64,
        b'F' => (lua_ffi::lua_tonumber_ex(L, idx) as f32).to_bits() as u64,
        b'D' => (lua_ffi::lua_tonumber_ex(L, idx)).to_bits(),
        b'L' | b'[' => {
            if lua_ffi::lua_isnil(L, idx) {
                0
            } else if lua_ffi::lua_type(L, idx) == lua_ffi::LUA_TLIGHTUSERDATA as i32 {
                lua_ffi::lua_touserdata(L, idx) as u64
            } else {
                lua_ffi::lua_tointeger_ex(L, idx) as u64
            }
        }
        _ => lua_ffi::lua_tointeger_ex(L, idx) as u64,
    }
}

unsafe fn fallback_call_original(
    ctx_ptr: *mut hook_ffi::HookContext,
    env: crate::jsapi::java::jni_core::JniEnv,
    art_method_addr: u64,
    class_global_ref: usize,
    param_count: usize,
    param_types: &[String],
    return_type: u8,
    is_static: bool,
    quick_trampoline: u64,
) {
    if env.is_null() {
        (*ctx_ptr).x[0] = 0;
        return;
    }
    let hook_ctx = &*ctx_ptr;
    let jargs = build_jargs_from_registers(hook_ctx, param_count, param_types);
    let jargs_ptr: *const std::ffi::c_void = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };
    let ret = invoke_original_jni(
        env, art_method_addr, class_global_ref,
        hook_ctx.x[1], return_type, is_static, jargs_ptr, quick_trampoline, false,
    );
    if return_type != b'V' {
        (*ctx_ptr).x[0] = ret;
    }
}
