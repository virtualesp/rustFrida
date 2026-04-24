//! hook() and unhook() API implementation

mod callback;
mod functions;
#[cfg(feature = "qbdi")]
mod qbdi;
mod registry;

use crate::context::JSContext;
use crate::ffi;
use crate::jsapi::callback_util::set_js_u64_property;
use crate::jsapi::util::add_cfunction_to_object;

use callback::{in_flight_native_hook_callbacks, wait_for_in_flight_native_hook_callbacks};
use functions::{
    js_call_native, js_diag_alloc_near, js_hook, js_interceptor_attach, js_interceptor_detach_all,
    js_interceptor_flush, js_interceptor_replace, js_native_call, js_recomp_hook, js_unhook,
};
#[cfg(feature = "qbdi")]
pub use qbdi::preload_qbdi_helper;
#[cfg(feature = "qbdi")]
pub use qbdi::shutdown_qbdi_helper;
pub use registry::StealthMode;
use registry::{HOOK_REGISTRY, STEALTH_NORMAL, STEALTH_RECOMP, STEALTH_WXSHADOW};

/// Register hook API
pub fn register_hook_api(ctx: &JSContext) {
    let global = ctx.global_object();

    unsafe {
        let g = global.raw();
        add_cfunction_to_object(ctx.as_ptr(), g, "hook", js_hook, 3);
        add_cfunction_to_object(ctx.as_ptr(), g, "unhook", js_unhook, 1);
        add_cfunction_to_object(ctx.as_ptr(), g, "callNative", js_call_native, 1);
        add_cfunction_to_object(ctx.as_ptr(), g, "recompHook", js_recomp_hook, 2);
        add_cfunction_to_object(ctx.as_ptr(), g, "diagAllocNear", js_diag_alloc_near, 1);
        // __nativeCall: 底层 shim，由 JS 侧的 NativeFunction wrapper 调用
        add_cfunction_to_object(ctx.as_ptr(), g, "__nativeCall", js_native_call, 6);

        // Hook.NORMAL = 0, Hook.WXSHADOW = 1, Hook.RECOMP = 2
        let hook_obj = ffi::JS_NewObject(ctx.as_ptr());
        set_js_u64_property(ctx.as_ptr(), hook_obj, "NORMAL", STEALTH_NORMAL as u64);
        set_js_u64_property(ctx.as_ptr(), hook_obj, "WXSHADOW", STEALTH_WXSHADOW as u64);
        set_js_u64_property(ctx.as_ptr(), hook_obj, "RECOMP", STEALTH_RECOMP as u64);
        global.set_property(ctx.as_ptr(), "Hook", crate::value::JSValue(hook_obj));

        // Frida-compatible Interceptor: attach (双阶段) / replace (单阶段) / detachAll / flush
        let interceptor = ffi::JS_NewObject(ctx.as_ptr());
        add_cfunction_to_object(ctx.as_ptr(), interceptor, "attach", js_interceptor_attach, 2);
        add_cfunction_to_object(ctx.as_ptr(), interceptor, "replace", js_interceptor_replace, 2);
        add_cfunction_to_object(ctx.as_ptr(), interceptor, "detachAll", js_interceptor_detach_all, 0);
        add_cfunction_to_object(ctx.as_ptr(), interceptor, "flush", js_interceptor_flush, 0);
        global.set_property(ctx.as_ptr(), "Interceptor", crate::value::JSValue(interceptor));
    }

    #[cfg(feature = "qbdi")]
    {
        let qbdi = ctx.new_object();
        qbdi::register_qbdi_api(ctx.as_ptr(), qbdi.raw());
        global.set_property(ctx.as_ptr(), "qbdi", qbdi);
    }

    global.free(ctx.as_ptr());

    // Load NativeFunction JS wrapper (Frida-compatible API)
    let boot = include_str!("native_boot.js");
    match ctx.eval(boot, "<native_boot>") {
        Ok(val) => val.free(ctx.as_ptr()),
        Err(e) => crate::jsapi::console::output_message(&format!("[hook_api] native_boot error: {}", e)),
    }

    // Load Interceptor helpers (args/retval Proxy wrappers for Frida-compatible onEnter/onLeave)
    let interceptor_boot = include_str!("interceptor_boot.js");
    match ctx.eval(interceptor_boot, "<interceptor_boot>") {
        Ok(val) => val.free(ctx.as_ptr()),
        Err(e) => crate::jsapi::console::output_message(&format!("[hook_api] interceptor_boot error: {}", e)),
    }
}

/// 移除单个 native hook: hook_remove + revert_slot_patch (stealth2)。
/// 供 js_unhook 和 cleanup_hooks 复用。
pub(crate) unsafe fn remove_single_hook(addr: u64, data: &registry::HookData) {
    let remove_addr = if data.mode == StealthMode::Recomp {
        data.recomp_addr
    } else {
        addr
    };
    ffi::hook::hook_remove(remove_addr as *mut std::ffi::c_void);
    if data.mode == StealthMode::Recomp {
        let _ = crate::recomp::revert_slot_patch(addr as usize);
    }
}

/// 释放单个 hook 的 JS callback 引用（on_enter/replace + attach 的 on_leave）。
pub(crate) unsafe fn free_hook_callback(data: &registry::HookData) {
    let ctx = data.ctx as *mut ffi::JSContext;
    if data.has_on_enter {
        let callback: ffi::JSValue = std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, callback);
    }
    if data.has_on_leave {
        let on_leave: ffi::JSValue = std::ptr::read(data.on_leave_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, on_leave);
    }
}

/// Phase 1 - 切断 native hook 入口 (hook() JS API 装的所有 hook，不释放 callback)。
/// 注册表条目不 take，保留到 `free_native_hooks` 再批量释放 JS callback。
pub fn cut_native_hooks() {
    let guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.as_ref() {
        for (addr, data) in registry.iter() {
            unsafe {
                remove_single_hook(*addr, data);
            }
        }
    }
}

/// Phase 3 - 释放 native hook 的 JS callback。必须在全局 drain 之后调用，
/// 保证 callback 引用的 JSValue 不再被正在执行的 thunk 访问。
pub fn free_native_hooks() {
    let mut guard = HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.take() {
        for (_addr, data) in registry {
            unsafe {
                free_hook_callback(&data);
            }
        }
    }
}

/// 兼容旧调用: 依次 cut → 本地 200ms 小 drain → free。
/// 新代码应该用编排器模式 (cut_native_hooks → 全局 drain → free_native_hooks)。
pub fn cleanup_hooks() {
    cut_native_hooks();
    if !wait_for_in_flight_native_hook_callbacks(std::time::Duration::from_millis(200)) {
        crate::jsapi::console::output_message(&format!(
            "[hook cleanup] waiting for in-flight callbacks timed out, remaining={}",
            in_flight_native_hook_callbacks()
        ));
    }
    free_native_hooks();
}
