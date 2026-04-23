use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{extract_string_arg, throw_internal_error, with_registry_mut};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;

use super::super::art_controller::ensure_art_controller_initialized;
use super::super::art_method::*;
use super::super::callback::*;
use super::super::jni_core::*;
use super::install_support::{
    create_class_global_ref, create_replacement_art_method,
    install_per_method_router_hook, update_original_method_flags_for_hook, JavaHookInstallGuard,
};

/// 核心安装逻辑 — Lua hook (从 JS 或 Lua 调用)
pub(crate) unsafe fn install_lua_hook_inner(
    class_name: &str,
    method_name: &str,
    sig: &str,
    bytecode: Vec<u8>,
    is_raw_bytecode: bool,
) -> Result<(), String> {
    let (actual_sig, force_static) = if let Some(stripped) = sig.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig.to_string(), false)
    };

    let env = ensure_jni_initialized()?;

    let (art_method, is_static) =
        resolve_art_method(env, class_name, method_name, &actual_sig, force_static)?;

    init_java_registry();
    crate::lua::init_lua_registry();

    if crate::lua::is_lua_hook(art_method) {
        crate::lua::register_lua_hook(art_method, crate::lua::LuaHookEntry {
            bytecode, is_raw_bytecode,
            is_static,
            param_count: count_jni_params(&actual_sig),
            param_types: parse_jni_param_types(&actual_sig),
            return_type: get_return_type_from_sig(&actual_sig),
            return_type_sig: get_return_type_sig(&actual_sig),
            class_global_ref: 0,
            quick_trampoline: 0,
            art_method,
        });
        output_verbose(&format!(
            "[lua hook] callback 已替换: {}.{}{}",
            class_name, method_name, actual_sig
        ));
        return Ok(());
    }

    if crate::jsapi::callback_util::with_registry(&JAVA_HOOK_REGISTRY, |r| {
        r.contains_key(&art_method)
    })
    .unwrap_or(false)
    {
        return Err("method already hooked via JS — unhook first".to_string());
    }

    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;
    let original_access_flags =
        std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let original_entry_point = read_entry_point(art_method, ep_offset);

    let bridge = find_art_bridge_functions(env, ep_offset);
    let jni_trampoline = bridge.quick_generic_jni_trampoline;
    if jni_trampoline == 0 {
        return Err("art_quick_generic_jni_trampoline not found".to_string());
    }

    let class_global_ref = create_class_global_ref(env, class_name)?;
    let clone_size = spec.size;
    let mut install_guard = JavaHookInstallGuard::new(
        art_method, spec.access_flags_offset, data_off, ep_offset,
        original_access_flags, original_data, original_entry_point, class_global_ref,
    );

    let return_type = get_return_type_from_sig(&actual_sig);
    let has_independent_code = !is_art_quick_entrypoint(original_entry_point, bridge);

    let thunk = hook_ffi::hook_create_native_trampoline(
        art_method, Some(java_hook_callback), art_method as *mut std::ffi::c_void, 0,
    );
    if thunk.is_null() {
        return Err("hook_create_native_trampoline failed".to_string());
    }
    install_guard.set_redirect_installed();

    let replacement_addr = create_replacement_art_method(
        art_method, clone_size, spec, original_access_flags, data_off, ep_offset,
        thunk, jni_trampoline,
    )?;
    install_guard.set_replacement_addr(replacement_addr);

    ensure_art_controller_initialized(&bridge, ep_offset, env as *mut std::ffi::c_void);

    set_replacement_method(art_method, replacement_addr as u64);
    install_guard.set_replacement_registered();

    update_original_method_flags_for_hook(art_method, spec.access_flags_offset, original_access_flags);
    install_guard.set_original_method_mutated();

    if bridge.nterp_entry_point != 0 && original_entry_point == bridge.nterp_entry_point {
        let interp_bridge = bridge.quick_to_interpreter_bridge;
        if interp_bridge != 0 {
            std::ptr::write_volatile((art_method as usize + ep_offset) as *mut u64, interp_bridge);
            hook_ffi::hook_flush_cache(
                (art_method as usize + ep_offset) as *mut std::ffi::c_void, 8,
            );
        }
    }

    let (_per_method_hook_target, quick_trampoline, _use_blr) =
        install_per_method_router_hook(
            has_independent_code, original_entry_point, &bridge, ep_offset, env,
            art_method, method_name == "<init>",
        )?;

    let bytecode_len = bytecode.len();
    crate::lua::register_lua_hook(art_method, crate::lua::LuaHookEntry {
        bytecode, is_raw_bytecode, is_static,
        param_count: count_jni_params(&actual_sig),
        param_types: parse_jni_param_types(&actual_sig),
        return_type,
        return_type_sig: get_return_type_sig(&actual_sig),
        class_global_ref, quick_trampoline, art_method,
    });

    let dummy_bytes = [0u8; 16];
    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(art_method, JavaHookData {
            art_method, original_access_flags, original_entry_point, original_data,
            hook_type: HookType::Replaced { replacement_addr, per_method_hook_target: _per_method_hook_target },
            clone_addr: 0, class_global_ref, return_type,
            return_type_sig: get_return_type_sig(&actual_sig),
            ctx: 0, callback_bytes: dummy_bytes,
            method_key: method_key(class_name, method_name, &actual_sig),
            is_static, param_count: count_jni_params(&actual_sig),
            param_types: parse_jni_param_types(&actual_sig),
            class_name: class_name.to_string(), quick_trampoline, use_blr: false,
        });
    });

    cache_fields_for_class(env, class_name);
    output_verbose(&format!(
        "[lua hook] 安装完成: {}.{}{} (ArtMethod={:#x}, bytecode={}B)",
        class_name, method_name, actual_sig, art_method, bytecode_len
    ));

    install_guard.commit();
    Ok(())
}

/// JS API: Java.luaHook(class, method, sig, luaCode)
pub(in crate::jsapi::java) unsafe extern "C" fn js_lua_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.luaHook() requires 4 args: class, method, signature, luaCode\0".as_ptr() as *const _,
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg1 must be class name\0") {
        Ok(v) => v, Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg2 must be method name\0") {
        Ok(v) => v, Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg3 must be signature\0") {
        Ok(v) => v, Err(e) => return e,
    };
    let lua_code = match extract_string_arg(ctx, JSValue(*argv.add(3)), b"arg4 must be lua code\0") {
        Ok(v) => v, Err(e) => return e,
    };

    let lua_source = format!("return function(ctx)\n{}\nend", lua_code);
    let bytecode = match crate::lua::compile_lua_callback(&lua_source) {
        Ok(bc) => bc,
        Err(e) => return throw_internal_error(ctx, format!("Lua compile error: {}", e)),
    };

    match install_lua_hook_inner(&class_name, &method_name, &sig_str, bytecode, false) {
        Ok(()) => JSValue::bool(true).raw(),
        Err(e) => throw_internal_error(ctx, e),
    }
}
