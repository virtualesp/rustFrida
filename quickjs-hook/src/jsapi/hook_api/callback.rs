//! Hook callback wrapper (cross-thread safety, context building) — replace mode
//!
//! The thunk saves context and calls on_enter, then restores x0 and returns.
//! The callback can optionally call the original function via orig().

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    acquire_js_engine_for_callback, get_js_u64_property_atom, handle_js_exception, hot_atoms,
    invoke_hook_callback_common, js_u64_to_js_number_or_bigint, js_value_to_u64_or_zero, set_js_cfunction_property,
    set_js_u64_property_atom,
};
use std::cell::RefCell;
use std::sync::{Condvar, Mutex};

use super::registry::HOOK_REGISTRY;

#[derive(Clone, Copy)]
struct NativeHookFrame {
    ctx_ptr: usize,
    trampoline: u64,
    orig_called: bool,
}

// JS 回调在全局引擎锁下串行执行，因此用一个栈保存 native hook 回调状态即可支持嵌套 hook。
static NATIVE_HOOK_STACK: Mutex<Vec<NativeHookFrame>> = Mutex::new(Vec::new());
static IN_FLIGHT_NATIVE_HOOK_CALLBACKS: Mutex<usize> = Mutex::new(0);
static IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV: Condvar = Condvar::new();

struct InFlightNativeHookGuard;

impl InFlightNativeHookGuard {
    fn enter() -> Self {
        let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_flight += 1;
        Self
    }
}

impl Drop for InFlightNativeHookGuard {
    fn drop(&mut self) {
        let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *in_flight = in_flight.saturating_sub(1);
        if *in_flight == 0 {
            IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV.notify_all();
        }
    }
}

fn push_native_hook_frame(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    stack.push(NativeHookFrame {
        ctx_ptr: ctx_ptr as usize,
        trampoline,
        orig_called: false,
    });
}

fn pop_native_hook_frame(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) -> bool {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frame) = stack.pop() {
        debug_assert_eq!(frame.ctx_ptr, ctx_ptr as usize);
        debug_assert_eq!(frame.trampoline, trampoline);
        frame.orig_called
    } else {
        false
    }
}

fn mark_native_hook_frame_orig_called(ctx_ptr: *mut hook_ffi::HookContext, trampoline: u64) -> bool {
    let mut stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(frame) = stack
        .iter_mut()
        .rfind(|frame| frame.ctx_ptr == ctx_ptr as usize && frame.trampoline == trampoline)
    {
        frame.orig_called = true;
        true
    } else {
        false
    }
}

fn current_native_hook_frame() -> Option<(*mut hook_ffi::HookContext, u64)> {
    let stack = NATIVE_HOOK_STACK.lock().unwrap_or_else(|e| e.into_inner());
    stack
        .last()
        .map(|frame| (frame.ctx_ptr as *mut hook_ffi::HookContext, frame.trampoline))
}

pub(crate) fn wait_for_in_flight_native_hook_callbacks(timeout: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let mut in_flight = IN_FLIGHT_NATIVE_HOOK_CALLBACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    while *in_flight != 0 {
        let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
            return false;
        };
        let (guard, wait_result) = IN_FLIGHT_NATIVE_HOOK_CALLBACKS_CV
            .wait_timeout(in_flight, remaining)
            .unwrap_or_else(|e| e.into_inner());
        in_flight = guard;
        if wait_result.timed_out() && *in_flight != 0 {
            return false;
        }
    }
    true
}

pub(super) fn in_flight_native_hook_callbacks() -> usize {
    *IN_FLIGHT_NATIVE_HOOK_CALLBACKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Hook callback that calls the JS function (replace mode)
pub(crate) unsafe extern "C" fn hook_callback_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightNativeHookGuard::enter();

    let target_addr = user_data as u64;

    // Copy callback data then release the lock before QuickJS operations.
    let (ctx_usize, callback_bytes, trampoline) = {
        let guard = match HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let hook_data = match registry.get(&target_addr) {
            Some(d) => d,
            None => return,
        };
        (hook_data.ctx, hook_data.callback_bytes, hook_data.trampoline)
    }; // HOOK_REGISTRY lock released here

    push_native_hook_frame(ctx_ptr, trampoline);

    // Track whether the JS callback completed without exception and wrote back x0.
    let mut result_was_set = false;

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "hook",
        target_addr,
        // 构建 JS 上下文对象：x0-x30, sp, pc, trampoline, orig()
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let atoms = hot_atoms();

            for i in 0..31 {
                set_js_u64_property_atom(ctx, js_ctx, atoms.x[i], hook_ctx.x[i]);
            }
            set_js_u64_property_atom(ctx, js_ctx, atoms.sp, hook_ctx.sp);
            set_js_u64_property_atom(ctx, js_ctx, atoms.pc, hook_ctx.pc);
            set_js_u64_property_atom(ctx, js_ctx, atoms.trampoline, trampoline);
            // Bind callback-local state to the context object so ctx.orig() remains stable
            // even if nested hooks temporarily overwrite the global fallback state.
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, ctx_ptr as usize as u64);
            set_js_u64_property_atom(ctx, js_ctx, atoms.hook_trampoline, trampoline);
            set_js_cfunction_property(ctx, js_ctx, "orig", js_native_call_original, 0);

            js_ctx
        },
        // 处理返回值：
        // 1. 先同步 JS ctx 上所有被修改的寄存器到 C HookContext
        // 2. 显式 return 值 → 覆盖 x0
        // 3. 不 return（undefined）→ 保持 ctx.x0 的值（可能被 JS 修改或被 orig() 写入）
        |ctx, js_ctx, result| {
            result_was_set = true;
            // 同步 JS ctx 属性 → C HookContext（用户可能修改了 ctx.x0 等）
            let atoms = hot_atoms();
            for i in 0..31 {
                (*ctx_ptr).x[i] = get_js_u64_property_atom(ctx, js_ctx, atoms.x[i]);
            }
            // 显式 return 值覆盖 x0
            let result_val = ffi::JSValue {
                u: result.u,
                tag: result.tag,
            };
            if ffi::qjs_is_undefined(result_val) == 0 {
                (*ctx_ptr).x[0] = js_value_to_u64_or_zero(ctx, crate::value::JSValue(result_val));
            }
            // undefined 时保持 ctx.x0 (可能是 orig() 写入的返回值或 JS 修改的值)
        },
        // native hook 不需要 JS 异常内 fallback (外层 trampoline 兜底已够)
        |_ctx, _js_ctx| {},
    );

    let orig_called = pop_native_hook_frame(ctx_ptr, trampoline);

    // Fallback: if the JS callback was skipped (engine busy) or threw an exception,
    // treat the hook as transparent and invoke the original function.
    if !result_was_set && trampoline != 0 && !orig_called {
        (*ctx_ptr).x[0] = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline as *mut std::ffi::c_void);
    }
}

/// JS CFunction: ctx.orig(...args?)
///
/// 无参数: 先同步 JS ctx 对象上被修改的寄存器到 C HookContext，再调用 trampoline。
/// 有参数: 用传入的参数覆盖 x0-xN（最多 6 个），其余寄存器同步自 JS ctx。
///
/// 返回原函数的返回值 (BigUint64 或 Number)，同时写入 ctx.x[0]。
unsafe extern "C" fn js_native_call_original(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let atoms = hot_atoms();
    let ctx_ptr = {
        let value = get_js_u64_property_atom(ctx, this_val, atoms.hook_ctx_ptr) as *mut hook_ffi::HookContext;
        if !value.is_null() {
            value
        } else {
            current_native_hook_frame()
                .map(|(ctx_ptr, _)| ctx_ptr)
                .unwrap_or(std::ptr::null_mut())
        }
    };
    let trampoline = {
        let value = get_js_u64_property_atom(ctx, this_val, atoms.hook_trampoline);
        if value != 0 {
            value
        } else {
            current_native_hook_frame()
                .map(|(_, trampoline)| trampoline)
                .unwrap_or(0)
        }
    };

    if ctx_ptr.is_null() || trampoline == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"orig() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // 同步 JS ctx 属性到 C HookContext（用户可能修改了 ctx.x0 等）
    let hook_ctx = &mut *ctx_ptr;
    for i in 0..31 {
        hook_ctx.x[i] = get_js_u64_property_atom(ctx, this_val, atoms.x[i]);
    }
    hook_ctx.sp = get_js_u64_property_atom(ctx, this_val, atoms.sp);

    // 如果 orig() 传了参数，按顺序覆盖 x0-xN (最多 x0-x30)
    let max_args = (argc as usize).min(31);
    for i in 0..max_args {
        let val = crate::value::JSValue(*argv.add(i));
        hook_ctx.x[i] = js_value_to_u64_or_zero(ctx, val);
    }

    let _ = mark_native_hook_frame_orig_called(ctx_ptr, trampoline);
    let result = hook_ffi::hook_invoke_trampoline(ctx_ptr, trampoline as *mut std::ffi::c_void);

    // Write result back to HookContext.x[0] so the thunk's final RET returns this value
    (*ctx_ptr).x[0] = result;

    // 同步返回值到 JS ctx.x0 属性，使 ctx.orig() 后读 ctx.x0 能拿到返回值
    set_js_u64_property_atom(ctx, this_val, atoms.x[0], result);

    // Return value: Number (≤2^53) or BigUint64
    js_u64_to_js_number_or_bigint(ctx, result)
}

// ══════════════════════════════════════════════════════════════════════════════
// Attach 模式 (Frida Interceptor.attach)
//
// hook_attach 的 thunk 自动执行 BLR trampoline (原函数)，不需要 ctx.orig()。
// on_enter 在调用原函数前运行，可改 x0-x7 (参数) 或 ctx.intercept_leave。
// on_leave 在原函数返回后运行，可改 x0 (返回值)。
//
// Frida 语义：onEnter 和 onLeave 的 `this` 是同一个 invocation object，
// 允许用户通过 `this.foo = 1` 跨阶段传状态。用 thread_local! 栈实现：
// on_enter push，on_leave pop。嵌套 hook 自然按栈式工作。
// ══════════════════════════════════════════════════════════════════════════════

thread_local! {
    // 每线程独立 invocation stack。存 dup 过的 JSValue 原始字节 (16B)。
    // on_enter 末尾 push（仅当 has_on_leave=true），on_leave 开头 pop。
    static INVOCATION_STACK: RefCell<Vec<[u8; 16]>> = const { RefCell::new(Vec::new()) };
}

fn invocation_push(bytes: [u8; 16]) {
    INVOCATION_STACK.with(|s| s.borrow_mut().push(bytes));
}

fn invocation_pop() -> Option<[u8; 16]> {
    INVOCATION_STACK.with(|s| s.borrow_mut().pop())
}

/// 构造 invocation context JS 对象: x0-x30 / sp / pc / lr / returnAddress / __hookCtxPtr
unsafe fn build_invocation_ctx(ctx: *mut ffi::JSContext, hook_ctx_ptr: *mut hook_ffi::HookContext) -> ffi::JSValue {
    let js_ctx = ffi::JS_NewObject(ctx);
    let hook_ctx = &*hook_ctx_ptr;
    let atoms = hot_atoms();
    for i in 0..31 {
        set_js_u64_property_atom(ctx, js_ctx, atoms.x[i], hook_ctx.x[i]);
    }
    set_js_u64_property_atom(ctx, js_ctx, atoms.sp, hook_ctx.sp);
    set_js_u64_property_atom(ctx, js_ctx, atoms.pc, hook_ctx.pc);
    set_js_u64_property_atom(ctx, js_ctx, atoms.lr, hook_ctx.x[30]);
    set_js_u64_property_atom(ctx, js_ctx, atoms.return_address, hook_ctx.x[30]);
    set_js_u64_property_atom(ctx, js_ctx, atoms.hook_ctx_ptr, hook_ctx_ptr as usize as u64);
    js_ctx
}

/// 把 js_ctx 上 x0-x30 + sp 同步回 C HookContext
unsafe fn sync_js_ctx_to_hook_ctx(
    ctx: *mut ffi::JSContext,
    js_ctx: ffi::JSValue,
    hook_ctx_ptr: *mut hook_ffi::HookContext,
) {
    let hook_ctx = &mut *hook_ctx_ptr;
    let atoms = hot_atoms();
    for i in 0..31 {
        hook_ctx.x[i] = get_js_u64_property_atom(ctx, js_ctx, atoms.x[i]);
    }
    hook_ctx.sp = get_js_u64_property_atom(ctx, js_ctx, atoms.sp);
}

/// 调用 JS 全局 helper `helper_name(userFn, js_ctx)`。
/// helper 由 interceptor_boot.js 提供（args/retval proxy 包装）。
/// helper 不存在时降级直接调 userFn(js_ctx)。
unsafe fn call_interceptor_helper(
    ctx: *mut ffi::JSContext,
    user_bytes: &[u8; 16],
    js_ctx: ffi::JSValue,
    helper_name: &[u8], // 必须带末尾 \0
    log_tag: &str,
) {
    let user_fn: ffi::JSValue = std::ptr::read(user_bytes.as_ptr() as *const ffi::JSValue);
    let user_dup = ffi::qjs_dup_value(ctx, user_fn);
    let global = ffi::JS_GetGlobalObject(ctx);
    let helper = ffi::JS_GetPropertyStr(ctx, global, helper_name.as_ptr() as *const _);
    let result = if ffi::JS_IsFunction(ctx, helper) != 0 {
        let mut args = [user_dup, js_ctx];
        ffi::JS_Call(ctx, helper, global, 2, args.as_mut_ptr())
    } else {
        let mut args = [js_ctx];
        ffi::JS_Call(ctx, user_dup, global, 1, args.as_mut_ptr())
    };
    let _ = handle_js_exception(ctx, result, log_tag);
    ffi::qjs_free_value(ctx, result);
    ffi::qjs_free_value(ctx, helper);
    ffi::qjs_free_value(ctx, global);
    ffi::qjs_free_value(ctx, user_dup);
}

/// attach 模式 on_enter C 回调。C thunk 已保存所有寄存器到 HookContext。
/// 语义：
///   1. 从 registry 取 (ctx, on_enter_bytes, on_leave_bytes, has_on_enter, has_on_leave)
///   2. 获取 JS 引擎锁后构造 invocation ctx 对象
///   3. 若 has_on_enter: 调 __interceptorEnter(userFn, js_ctx)
///   4. 同步 js_ctx 的 x0-x30/sp 回 C HookContext
///   5. has_on_leave=true: push js_ctx 到 thread_local 栈供 on_leave 使用（不 free）
///      has_on_leave=false: free js_ctx + set ctx.intercept_leave=0 走 tail-jump 快路径
pub(crate) unsafe extern "C" fn attach_on_enter_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightNativeHookGuard::enter();

    let target_addr = user_data as u64;

    let (ctx_usize, has_on_enter, has_on_leave, on_enter_bytes) = {
        let guard = match HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let data = match registry.get(&target_addr) {
            Some(d) => d,
            None => return,
        };
        (data.ctx, data.has_on_enter, data.has_on_leave, data.callback_bytes)
    };

    let ctx = ctx_usize as *mut ffi::JSContext;
    let _js_guard = match acquire_js_engine_for_callback(ctx, "interceptor.onEnter", target_addr) {
        Some(g) => g,
        None => return,
    };

    let js_ctx = build_invocation_ctx(ctx, ctx_ptr);

    if has_on_enter {
        call_interceptor_helper(
            ctx,
            &on_enter_bytes,
            js_ctx,
            b"__interceptorEnter\0",
            "interceptor.onEnter",
        );
    }

    sync_js_ctx_to_hook_ctx(ctx, js_ctx, ctx_ptr);

    if has_on_leave {
        // 保留 js_ctx 供 on_leave 复用，不 free。push 原引用 (ref=1) 到栈。
        let mut bytes = [0u8; 16];
        std::ptr::copy_nonoverlapping(&js_ctx as *const _ as *const u8, bytes.as_mut_ptr(), 16);
        invocation_push(bytes);
    } else {
        ffi::qjs_free_value(ctx, js_ctx);
        // 仅当 on_leave==NULL 时 C thunk 才生成 tail-jump 分支，此处安全。
        (*ctx_ptr).intercept_leave = 0;
    }
}

/// attach 模式 on_leave C 回调。此时 x0 已是 trampoline 返回值。
/// 语义：
///   1. pop thread_local 栈拿到 this 对象（on_enter push 的）；栈空则新建（!has_on_enter 的情况）
///   2. 刷新 x0-x30 → js_ctx（反映原函数返回后的状态）
///   3. 调 __interceptorLeave(userFn, js_ctx)
///   4. 同步 js_ctx.x0 回 C HookContext
///   5. free js_ctx（ref 降到 0 释放）
pub(crate) unsafe extern "C" fn attach_on_leave_wrapper(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }
    let _in_flight_guard = InFlightNativeHookGuard::enter();

    let target_addr = user_data as u64;

    let (ctx_usize, on_leave_bytes, has_on_leave) = {
        let guard = match HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => return,
        };
        let data = match registry.get(&target_addr) {
            Some(d) => d,
            None => return,
        };
        (data.ctx, data.on_leave_bytes, data.has_on_leave)
    };

    if !has_on_leave {
        // 注册期间 on_leave 被移除了?理论上不该发生; 直接返回。
        return;
    }

    let ctx = ctx_usize as *mut ffi::JSContext;
    let _js_guard = match acquire_js_engine_for_callback(ctx, "interceptor.onLeave", target_addr) {
        Some(g) => g,
        None => return,
    };

    // pop on_enter 留下的 this 对象；若 !has_on_enter 或 stack 意外为空，新建一个
    let js_ctx = match invocation_pop() {
        Some(bytes) => std::ptr::read(bytes.as_ptr() as *const ffi::JSValue),
        None => build_invocation_ctx(ctx, ctx_ptr),
    };

    // 刷新 x0-x30 到 js_ctx（trampoline 刚返回，x0 已是新的返回值）
    let hook_ctx = &*ctx_ptr;
    let atoms = hot_atoms();
    for i in 0..31 {
        set_js_u64_property_atom(ctx, js_ctx, atoms.x[i], hook_ctx.x[i]);
    }

    call_interceptor_helper(
        ctx,
        &on_leave_bytes,
        js_ctx,
        b"__interceptorLeave\0",
        "interceptor.onLeave",
    );

    // 同步可能被 onLeave 改过的 x0
    sync_js_ctx_to_hook_ctx(ctx, js_ctx, ctx_ptr);

    ffi::qjs_free_value(ctx, js_ctx);
}
