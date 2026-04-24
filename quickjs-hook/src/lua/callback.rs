use super::ffi as lua_ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::java::callback::{
    build_jargs_from_registers, extract_jni_arg, invoke_original_jni, is_floating_point_type, InFlightJavaHookGuard,
    JavaHookCallbackScope,
};
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// 传递给 orig() upvalue 的上下文
#[repr(C)]
pub(crate) struct CallbackContext {
    pub env: crate::jsapi::java::jni_core::JniEnv,
    pub hook_ctx_ptr: *mut hook_ffi::HookContext,
    pub art_method: u64,
    pub class_global_ref: usize,
    pub this_obj: u64,
    pub return_type: u8,
    pub return_type_sig: String,
    pub is_static: bool,
    pub param_count: usize,
    pub param_types: Vec<String>,
    pub jargs_ptr: *const std::ffi::c_void,
    pub quick_trampoline: u64,
    pub use_blr: bool,
}

#[repr(C)]
struct QuickOrigContext {
    hook_ctx_ptr: *mut hook_ffi::HookContext,
    art_method: u64,
    class_global_ref: usize,
    return_type: u8,
    is_static: bool,
    param_count: usize,
    param_types: Vec<String>,
    quick_trampoline: u64,
    quick_orig_precall: bool,
    local_refs: *mut Vec<*mut std::ffi::c_void>,
}

const QUICK_PREORIG_RET_REG: usize = 16;
static QUICK_SIGSEGV_GUARD_REFRESH: AtomicU64 = AtomicU64::new(0);
static QUICK_DROP_BEGIN: AtomicU64 = AtomicU64::new(0);
static QUICK_DROP_END: AtomicU64 = AtomicU64::new(0);
static QUICK_FULL_SUSPEND_BEGIN: AtomicU64 = AtomicU64::new(0);
static QUICK_FULL_SUSPEND_END: AtomicU64 = AtomicU64::new(0);
static QUICK_ACTIVE_SLOTS: OnceLock<Vec<QuickActiveSlot>> = OnceLock::new();

const QUICK_STAGE_ENTER: u64 = 1;
const QUICK_STAGE_TLS_READY: u64 = 2;
const QUICK_STAGE_CACHE_READY: u64 = 3;
const QUICK_STAGE_NATIVE_READY: u64 = 4;
const QUICK_STAGE_LUA_CALL_BEGIN: u64 = 5;
const QUICK_STAGE_LUA_CALL_END: u64 = 6;
const QUICK_STAGE_RETURN_BEGIN: u64 = 7;
const QUICK_STAGE_CLEANUP: u64 = 8;
const QUICK_STAGE_DROP_BEGIN: u64 = 90;
const QUICK_STAGE_FULL_SUSPEND: u64 = 91;

struct QuickActiveSlot {
    tid: AtomicU64,
    tpidr: AtomicU64,
    method: AtomicU64,
    stage: AtomicU64,
    since_ms: AtomicU64,
}

impl QuickActiveSlot {
    fn new() -> Self {
        Self {
            tid: AtomicU64::new(0),
            tpidr: AtomicU64::new(0),
            method: AtomicU64::new(0),
            stage: AtomicU64::new(0),
            since_ms: AtomicU64::new(0),
        }
    }
}

fn quick_active_slots() -> &'static [QuickActiveSlot] {
    QUICK_ACTIVE_SLOTS
        .get_or_init(|| (0..128).map(|_| QuickActiveSlot::new()).collect())
        .as_slice()
}

#[inline]
fn quick_diag_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[inline]
fn quick_diag_tid() -> u64 {
    unsafe { libc::syscall(libc::SYS_gettid as libc::c_long) as u64 }
}

fn quick_diag_enter(method: u64) -> usize {
    let tid = quick_diag_tid();
    let tpidr = crate::current_thread_id_u64();
    let slots = quick_active_slots();
    let preferred = (tid as usize) % slots.len();
    for offset in 0..slots.len() {
        let index = (preferred + offset) % slots.len();
        let slot = &slots[index];
        let cur = slot.tid.load(Ordering::Acquire);
        if cur == tid
            || (cur == 0
                && slot
                    .tid
                    .compare_exchange(0, tid, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok())
        {
            slot.tpidr.store(tpidr, Ordering::Release);
            slot.method.store(method, Ordering::Release);
            slot.since_ms.store(quick_diag_now_ms(), Ordering::Release);
            slot.stage.store(QUICK_STAGE_ENTER, Ordering::Release);
            return index;
        }
    }
    usize::MAX
}

struct QuickDiagGuard {
    slot: usize,
}

impl QuickDiagGuard {
    fn enter(method: u64) -> Self {
        Self {
            slot: quick_diag_enter(method),
        }
    }

    fn stage(&self, stage: u64) {
        quick_diag_stage(self.slot, stage);
    }
}

impl Drop for QuickDiagGuard {
    fn drop(&mut self) {
        quick_diag_leave(self.slot);
    }
}

#[inline]
fn quick_diag_stage(slot_index: usize, stage: u64) {
    if let Some(slot) = quick_active_slots().get(slot_index) {
        slot.stage.store(stage, Ordering::Release);
    }
}

#[inline]
fn quick_diag_leave(slot_index: usize) {
    if let Some(slot) = quick_active_slots().get(slot_index) {
        slot.stage.store(0, Ordering::Release);
        slot.method.store(0, Ordering::Release);
        slot.since_ms.store(0, Ordering::Release);
        slot.tpidr.store(0, Ordering::Release);
        slot.tid.store(0, Ordering::Release);
    }
}

pub(crate) fn quick_diag_snapshot() -> (u64, u64, u64, u64, String) {
    let now = quick_diag_now_ms();
    let mut active = 0u64;
    let mut oldest_age = 0u64;
    let mut rows = Vec::new();
    for slot in quick_active_slots() {
        let tid = slot.tid.load(Ordering::Acquire);
        let stage = slot.stage.load(Ordering::Acquire);
        if tid == 0 || stage == 0 {
            continue;
        }
        let since = slot.since_ms.load(Ordering::Acquire);
        let age = now.saturating_sub(since);
        oldest_age = oldest_age.max(age);
        active += 1;
        if rows.len() < 16 {
            rows.push(format!(
                "tid={} tpidr=0x{:x} method=0x{:x} stage={} ageMs={}",
                tid,
                slot.tpidr.load(Ordering::Acquire),
                slot.method.load(Ordering::Acquire),
                stage,
                age
            ));
        }
    }
    (
        active,
        oldest_age,
        QUICK_DROP_BEGIN.load(Ordering::Acquire),
        QUICK_DROP_END.load(Ordering::Acquire),
        format!(
            "fullSuspendBegin={} fullSuspendEnd={} slots=[{}]",
            QUICK_FULL_SUSPEND_BEGIN.load(Ordering::Acquire),
            QUICK_FULL_SUSPEND_END.load(Ordering::Acquire),
            rows.join("; ")
        ),
    )
}

pub(crate) fn reset_quick_diag() {
    QUICK_DROP_BEGIN.store(0, Ordering::Release);
    QUICK_DROP_END.store(0, Ordering::Release);
    QUICK_FULL_SUSPEND_BEGIN.store(0, Ordering::Release);
    QUICK_FULL_SUSPEND_END.store(0, Ordering::Release);
    for slot in quick_active_slots() {
        slot.stage.store(0, Ordering::Release);
        slot.method.store(0, Ordering::Release);
        slot.since_ms.store(0, Ordering::Release);
        slot.tpidr.store(0, Ordering::Release);
        slot.tid.store(0, Ordering::Release);
    }
}

type ArtJniTransitionFn = unsafe extern "C" fn(*mut std::ffi::c_void);
type ArtQuickTransitionFn = unsafe extern "C" fn();
type ArtFullSuspendCheckFn = unsafe extern "C" fn(*mut std::ffi::c_void, bool);

#[derive(Clone, Copy)]
enum ArtTransitionBridge {
    RawState,
    Direct {
        start: ArtJniTransitionFn,
        end: ArtJniTransitionFn,
    },
    QuickEntrypoint {
        start: ArtQuickTransitionFn,
        end: ArtQuickTransitionFn,
    },
}

impl ArtTransitionBridge {
    unsafe fn start(self, thread: *mut std::ffi::c_void) {
        match self {
            ArtTransitionBridge::RawState => raw_thread_to_native(thread),
            ArtTransitionBridge::Direct { start, .. } => start(thread),
            ArtTransitionBridge::QuickEntrypoint { start, .. } => call_quick_jni_transition(start, thread),
        }
    }

    unsafe fn end(self, thread: *mut std::ffi::c_void, diag_slot: usize) {
        match self {
            ArtTransitionBridge::RawState => raw_thread_to_runnable(thread, diag_slot),
            ArtTransitionBridge::Direct { end, .. } => end(thread),
            ArtTransitionBridge::QuickEntrypoint { end, .. } => call_quick_jni_transition(end, thread),
        }
    }
}

#[derive(Clone, Copy)]
struct CurrentQuickTransition {
    thread: *mut std::ffi::c_void,
    bridge: ArtTransitionBridge,
    diag_slot: usize,
}

std::thread_local! {
    static CURRENT_QUICK_TRANSITION: RefCell<Option<CurrentQuickTransition>> = const { RefCell::new(None) };
}

pub(crate) unsafe fn with_current_quick_runnable<R>(f: impl FnOnce(*mut std::ffi::c_void) -> R) -> Option<R> {
    let current = CURRENT_QUICK_TRANSITION.with(|c| *c.borrow());
    let current = current?;
    current.bridge.end(current.thread, current.diag_slot);
    let result = f(current.thread);
    current.bridge.start(current.thread);
    Some(result)
}

struct ArtNativeTransition {
    thread: *mut std::ffi::c_void,
    bridge: ArtTransitionBridge,
    diag_slot: usize,
    managed_stack_top: Option<ManagedStackTopGuard>,
    previous_transition: Option<CurrentQuickTransition>,
}

impl ArtNativeTransition {
    unsafe fn enter_from_quick(ctx_ptr: *mut hook_ffi::HookContext, diag_slot: usize) -> Option<Self> {
        if ctx_ptr.is_null() {
            super::record_native_transition_fail();
            return None;
        }

        // x19 is ART Thread::Current() on the quick path. Keep the raw tagged
        // pointer when crossing back into ART: MarkCompact compares Thread*
        // against Thread::Current() byte-for-byte during checkpoint root
        // marking, so stripping the top-byte tag makes `thread != self` and can
        // abort/ANR while GC is waiting for the mutator.
        let thread = (*ctx_ptr).x[19] as *mut std::ffi::c_void;
        if thread.is_null() {
            super::record_native_transition_fail();
            return None;
        }

        let bridge = if let Some(bridge) = *ART_JNI_TRANSITION.get_or_init(resolve_art_jni_transition) {
            bridge
        } else if let Some(bridge) =
            *ART_QUICK_JNI_TRANSITION.get_or_init(|| unsafe { resolve_quick_entrypoint_transition(thread as u64) })
        {
            bridge
        } else {
            super::record_native_transition_fail();
            crate::jsapi::console::output_message(
                "[lua quick] ART JNI transition unavailable; keeping callback thread runnable",
            );
            return None;
        };

        let managed_stack_top = ManagedStackTopGuard::publish(thread, ctx_ptr);

        bridge.start(thread);
        super::record_native_transition_enter();
        let current = CurrentQuickTransition {
            thread,
            bridge,
            diag_slot,
        };
        let previous_transition = CURRENT_QUICK_TRANSITION.with(|c| c.replace(Some(current)));
        Some(Self {
            thread,
            bridge,
            diag_slot,
            managed_stack_top,
            previous_transition,
        })
    }
}

impl Drop for ArtNativeTransition {
    fn drop(&mut self) {
        quick_diag_stage(self.diag_slot, QUICK_STAGE_DROP_BEGIN);
        QUICK_DROP_BEGIN.fetch_add(1, Ordering::Relaxed);
        CURRENT_QUICK_TRANSITION.with(|c| {
            c.replace(self.previous_transition);
        });
        unsafe {
            self.bridge.end(self.thread, self.diag_slot);
        }
        if let Some(guard) = self.managed_stack_top.take() {
            guard.restore();
        }
        QUICK_DROP_END.fetch_add(1, Ordering::Relaxed);
        super::record_native_transition_leave();
    }
}

struct ManagedStackTopGuard {
    slot: *mut u64,
    old_top: u64,
}

impl ManagedStackTopGuard {
    unsafe fn publish(thread: *mut std::ffi::c_void, ctx_ptr: *mut hook_ffi::HookContext) -> Option<Self> {
        if thread.is_null() || ctx_ptr.is_null() {
            return None;
        }
        const ART_ROUTER_FRAME_SIZE: u64 = 224;
        let router_frame = (*ctx_ptr).sp.checked_sub(ART_ROUTER_FRAME_SIZE)?;
        let offset = crate::jsapi::java::art_controller::cached_thread_top_quick_frame_offset()?;
        let slot = (thread as usize + offset) as *mut u64;
        let old_top = std::ptr::read_volatile(slot);
        std::ptr::write_volatile(slot, router_frame);
        Some(Self { slot, old_top })
    }

    fn restore(self) {
        unsafe {
            std::ptr::write_volatile(self.slot, self.old_top);
        }
    }
}

static ART_JNI_TRANSITION: OnceLock<Option<ArtTransitionBridge>> = OnceLock::new();
static ART_QUICK_JNI_TRANSITION: OnceLock<Option<ArtTransitionBridge>> = OnceLock::new();
static ART_FULL_SUSPEND_CHECK: OnceLock<Option<ArtFullSuspendCheckFn>> = OnceLock::new();

const ART_THREAD_STATE_AND_FLAGS_OFFSET: usize = 0;
const ART_THREAD_FLAG_SUSPEND_REQUEST: u32 = 1 << 0;
const ART_THREAD_FLAG_CHECKPOINT_REQUEST: u32 = 1 << 1;
const ART_THREAD_FLAG_EMPTY_CHECKPOINT_REQUEST: u32 = 1 << 2;
const ART_THREAD_FLAG_ACTIVE_SUSPEND_BARRIER: u32 = 1 << 3;
const ART_THREAD_STATE_MASK: u32 = 0xff00_0000;
const ART_THREAD_STATE_RUNNABLE: u32 = 0 << 24;
const ART_THREAD_STATE_NATIVE: u32 = 92 << 24;

unsafe fn raw_thread_to_native(thread: *mut std::ffi::c_void) {
    let state = (thread as usize + ART_THREAD_STATE_AND_FLAGS_OFFSET) as *mut u32;
    let old = std::ptr::read_volatile(state);
    if (old & ART_THREAD_STATE_MASK) == ART_THREAD_STATE_RUNNABLE {
        std::ptr::write_volatile(state, (old & !ART_THREAD_STATE_MASK) | ART_THREAD_STATE_NATIVE);
    }
}

unsafe fn raw_thread_to_runnable(thread: *mut std::ffi::c_void, diag_slot: usize) {
    let state = (thread as usize + ART_THREAD_STATE_AND_FLAGS_OFFSET) as *mut u32;
    let cur = std::ptr::read_volatile(state);
    let checked_flags = ART_THREAD_FLAG_SUSPEND_REQUEST
        | ART_THREAD_FLAG_CHECKPOINT_REQUEST
        | ART_THREAD_FLAG_EMPTY_CHECKPOINT_REQUEST
        | ART_THREAD_FLAG_ACTIVE_SUSPEND_BARRIER;

    if (cur & ART_THREAD_FLAG_SUSPEND_REQUEST) != 0 {
        std::ptr::write_volatile(state, (cur & !ART_THREAD_STATE_MASK) | ART_THREAD_STATE_RUNNABLE);
        if let Some(full_suspend_check) = resolve_full_suspend_check() {
            quick_diag_stage(diag_slot, QUICK_STAGE_FULL_SUSPEND);
            QUICK_FULL_SUSPEND_BEGIN.fetch_add(1, Ordering::Relaxed);
            full_suspend_check(thread, false);
            QUICK_FULL_SUSPEND_END.fetch_add(1, Ordering::Relaxed);
            return;
        }

        for _ in 0..1_000_000 {
            let retry = std::ptr::read_volatile(state);
            if (retry & ART_THREAD_FLAG_SUSPEND_REQUEST) == 0 {
                break;
            }
            libc::sched_yield();
        }
        return;
    }

    if (cur & checked_flags) == 0 {
        std::ptr::write_volatile(state, (cur & !ART_THREAD_STATE_MASK) | ART_THREAD_STATE_RUNNABLE);
        return;
    }

    std::ptr::write_volatile(state, (cur & !ART_THREAD_STATE_MASK) | ART_THREAD_STATE_RUNNABLE);
}

unsafe fn resolve_full_suspend_check() -> Option<ArtFullSuspendCheckFn> {
    *ART_FULL_SUSPEND_CHECK.get_or_init(|| {
        let sym = crate::jsapi::module::libart_dlsym("_ZN3art6Thread16FullSuspendCheckEb");
        if sym.is_null() {
            crate::jsapi::console::output_message("[lua quick] ART FullSuspendCheck symbol missing");
            None
        } else {
            Some(std::mem::transmute(sym))
        }
    })
}

fn resolve_art_jni_transition() -> Option<ArtTransitionBridge> {
    unsafe {
        let start = crate::jsapi::module::libart_dlsym("artJniMethodStart");
        let end = crate::jsapi::module::libart_dlsym("artJniMethodEnd");
        if !start.is_null() && !end.is_null() {
            return Some(ArtTransitionBridge::Direct {
                start: std::mem::transmute(start),
                end: std::mem::transmute(end),
            });
        }

        crate::jsapi::console::output_message(&format!(
            "[lua quick] ART JNI transition direct symbols missing: start={:?} end={:?}; using Thread quick entrypoints",
            start, end
        ));
        None
    }
}

unsafe fn resolve_quick_entrypoint_transition(thread_ptr: u64) -> Option<ArtTransitionBridge> {
    if thread_ptr == 0 {
        return None;
    }

    const QUICK_ENTRYPOINT_COUNT: usize = 174;
    const QUICK_JNI_METHOD_START_INDEX: usize = 45;
    const QUICK_JNI_METHOD_END_INDEX: usize = 46;
    const QUICK_SCAN_LIMIT: usize = 16384;
    const QUICK_MIN_LIBART_POINTERS: usize = 40;

    let max_off = QUICK_SCAN_LIMIT.saturating_sub(QUICK_ENTRYPOINT_COUNT * 8);
    let mut best_off = 0usize;
    let mut best_count = 0usize;
    let mut best_start = 0u64;
    let mut best_end = 0u64;
    for off in (0..=max_off).step_by(8) {
        let base = (thread_ptr as usize + off) as *const u64;
        let start = std::ptr::read_volatile(base.add(QUICK_JNI_METHOD_START_INDEX));
        let end = std::ptr::read_volatile(base.add(QUICK_JNI_METHOD_END_INDEX));

        let mut libart_ptrs = 0usize;
        for i in 0..QUICK_ENTRYPOINT_COUNT {
            let p = std::ptr::read_volatile(base.add(i));
            if crate::jsapi::module::is_in_libart(p) {
                libart_ptrs += 1;
            }
        }
        if libart_ptrs > best_count {
            best_count = libart_ptrs;
            best_off = off;
            best_start = start;
            best_end = end;
        }
        if !crate::jsapi::module::is_in_libart(start) || !crate::jsapi::module::is_in_libart(end) {
            continue;
        }
        if off < 16 {
            continue;
        }
        let prev0 = std::ptr::read_volatile((thread_ptr as usize + off - 16) as *const u64);
        let prev1 = std::ptr::read_volatile((thread_ptr as usize + off - 8) as *const u64);
        if !crate::jsapi::module::is_in_libart(prev0) || !crate::jsapi::module::is_in_libart(prev1) {
            continue;
        }
        if libart_ptrs < QUICK_MIN_LIBART_POINTERS {
            continue;
        }

        crate::jsapi::console::output_message(&format!(
            "[lua quick] ART JNI transition via quick entrypoints: Thread+0x{:x}, start={:#x}, end={:#x}, libart_ptrs={}",
            off, start, end, libart_ptrs
        ));
        return Some(ArtTransitionBridge::QuickEntrypoint {
            start: std::mem::transmute(start as usize),
            end: std::mem::transmute(end as usize),
        });
    }

    crate::jsapi::console::output_message(&format!(
        "[lua quick] ART JNI transition quick entrypoint scan failed: thread={:#x}, best=Thread+0x{:x}, count={}, start={:#x}, end={:#x}",
        thread_ptr, best_off, best_count, best_start, best_end
    ));
    None
}

#[cfg(target_arch = "aarch64")]
unsafe fn call_quick_jni_transition(entry: ArtQuickTransitionFn, thread: *mut std::ffi::c_void) {
    core::arch::asm!(
        "str x19, [sp, #-16]!",
        "mov x19, x10",
        "blr x11",
        "ldr x19, [sp], #16",
        in("x10") thread as usize,
        in("x11") entry as usize,
        clobber_abi("C"),
    );
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn call_quick_jni_transition(entry: ArtQuickTransitionFn, _thread: *mut std::ffi::c_void) {
    entry();
}

/// Lua callback 入口 — 全程无 Mutex，per-thread 缓存 + safepoint
pub unsafe extern "C" fn lua_hook_callback(ctx_ptr: *mut hook_ffi::HookContext, user_data: *mut std::ffi::c_void) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _lua_callback_guard = super::LuaCallbackGuard::enter();
    let _in_flight = InFlightJavaHookGuard::enter();
    let _scope = JavaHookCallbackScope::enter();
    if QUICK_SIGSEGV_GUARD_REFRESH.fetch_add(1, Ordering::Relaxed) & 0xfff == 0 {
        crate::jsapi::java::art_controller::refresh_walkstack_sigsegv_guard();
    }

    let art_method_addr = user_data as u64;
    let env = (*ctx_ptr).x[0] as crate::jsapi::java::jni_core::JniEnv;
    let hook_ctx = &*ctx_ptr;

    super::api::clear_fast_orig_requested();
    super::api::set_current_env(env as *const std::ffi::c_void);

    let tls = match super::get_thread_lua_state() {
        Some(t) => t,
        None => {
            super::api::clear_current_env();
            (*ctx_ptr).x[0] = 0;
            return;
        }
    };
    let cached = match super::get_cached_hook(tls, art_method_addr) {
        Some(c) => c,
        None => {
            super::api::clear_current_env();
            (*ctx_ptr).x[0] = 0;
            return;
        }
    };

    let func_ref = cached.func_ref;
    let is_static = cached.is_static;
    let param_count = cached.param_count;
    let return_type = cached.return_type;
    let class_global_ref = cached.class_global_ref;
    let quick_trampoline = cached.quick_trampoline;
    let use_blr = cached.use_blr;
    let return_type_sig = cached.return_type_sig.clone();
    let param_types = cached.param_types.clone();

    // Lua 热路径默认不再为每次 callback 的对象参数创建 JNI local refs。
    // 高热点方法（如 HashMap.put）下这会引入显著 JNI/GC 压力。
    // orig() 已改为调用瞬间从 HookContext 重建原始参数，避免依赖这里缓存的引用。
    let use_local_refs = false;
    let mut local_refs: Vec<*mut std::ffi::c_void> = Vec::new();
    super::api::set_current_local_refs(&mut local_refs);
    let this_obj = if use_local_refs && !is_static && hook_ctx.x[1] != 0 {
        new_jni_local_ref(env, hook_ctx.x[1], &mut local_refs) as u64
    } else {
        hook_ctx.x[1]
    };

    let L = tls.state.as_ptr();

    lua_ffi::lua_rawgeti(L, lua_ffi::LUA_REGISTRYINDEX, func_ref as lua_ffi::lua_Integer);

    let jargs = build_local_jargs_from_registers(hook_ctx, param_count, &param_types, env, &mut local_refs);
    let jargs_ptr: *const std::ffi::c_void = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };
    let cb_ctx = CallbackContext {
        env,
        hook_ctx_ptr: ctx_ptr,
        art_method: art_method_addr,
        class_global_ref,
        this_obj,
        return_type,
        return_type_sig,
        is_static,
        param_count,
        param_types: param_types.clone(),
        jargs_ptr,
        quick_trampoline,
        use_blr,
    };

    lua_ffi::lua_createtable(L, 0, 2);

    lua_ffi::lua_pushlightuserdata(L, &cb_ctx as *const _ as *mut std::ffi::c_void);
    lua_ffi::lua_pushcclosure(L, Some(super::api::lua_call_original), 1);
    lua_ffi::lua_setfield(L, -2, c"orig".as_ptr());

    if !is_static && this_obj != 0 {
        lua_ffi::lua_pushlightuserdata(L, this_obj as *mut std::ffi::c_void);
        lua_ffi::lua_setfield(L, -2, c"__jptr".as_ptr());
    }

    if use_local_refs {
        // self table 构建完毕 — 切断 native gap
        jni_safepoint(env);
    }

    let mut gp_index: usize = 0;
    let mut fp_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let (mut raw, fp_raw) =
            extract_jni_arg(hook_ctx, is_floating_point_type(type_sig), &mut gp_index, &mut fp_index);
        if use_local_refs && is_object_type(type_sig) && raw != 0 {
            raw = new_jni_local_ref(env, raw, &mut local_refs) as u64;
        }
        super::api::push_jni_arg(L, raw, fp_raw, type_sig, env as *const std::ffi::c_void);
    }

    if use_local_refs {
        // 参数推栈完毕 — 再切一次
        jni_safepoint(env);
    }

    let nargs = 1 + param_count as i32;
    let call_ret = lua_ffi::lua_pcall(L, nargs, 1, 0);

    if super::api::take_fast_orig_requested() {
        lua_ffi::lua_pop(L, 1);
        crate::jsapi::java::run_pending_art_checkpoints(env);
        super::api::clear_current_env();
        return;
    }

    if use_local_refs {
        // ART safepoint — lua_pcall 返回后再给一次 suspend 机会
        jni_safepoint(env);
    }

    if call_ret != lua_ffi::LUA_OK as i32 {
        let err_s = lua_ffi::lua_tostring_ex(L, -1);
        if !err_s.is_null() {
            let err = std::ffi::CStr::from_ptr(err_s).to_string_lossy();
            crate::jsapi::console::output_message(&format!("[lua] callback error: {}", err));
        }
        lua_ffi::lua_pop(L, 1);
        super::api::clear_current_env();
        delete_local_refs(env, local_refs);
        fallback_call_original(
            ctx_ptr,
            env,
            art_method_addr,
            class_global_ref,
            param_count,
            &param_types,
            return_type,
            is_static,
            quick_trampoline,
        );
        return;
    }

    if return_type != b'V' {
        let ret_val = extract_lua_return(L, -1, return_type, env);
        (*ctx_ptr).x[0] = ret_val;
    }
    lua_ffi::lua_pop(L, 1);
    super::api::clear_current_env();
    delete_local_refs(env, local_refs);
}

/// Lua callback for ART quick-code router.
///
/// This path is intentionally not a JNI replacement callback. It runs directly
/// from the quick router with raw quick-call registers, uses the current
/// thread's Lua state, and leaves `intercept_leave=0` by default so the router
/// continues to the original method after Lua returns.
pub unsafe extern "C" fn lua_hook_dispatch_from_quick(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    let _lua_callback_guard = super::LuaCallbackGuard::enter();
    let _in_flight = InFlightJavaHookGuard::enter();
    let _scope = JavaHookCallbackScope::enter();

    let art_method_addr = user_data as u64;
    let quick_diag = QuickDiagGuard::enter(art_method_addr);
    let hook_ctx = &*ctx_ptr;
    (*ctx_ptr).intercept_leave = 0;

    super::api::clear_fast_orig_requested();
    super::api::clear_quick_orig_result();
    super::api::set_current_env(std::ptr::null());

    let tls = match super::get_thread_lua_state() {
        Some(t) => t,
        None => {
            super::api::clear_current_env();
            return;
        }
    };
    quick_diag.stage(QUICK_STAGE_TLS_READY);
    let cached = match super::get_cached_hook(tls, art_method_addr) {
        Some(c) => c,
        None => {
            super::api::clear_current_env();
            return;
        }
    };
    quick_diag.stage(QUICK_STAGE_CACHE_READY);

    let func_ref = cached.func_ref;
    let is_static = cached.is_static;
    let param_count = cached.param_count;
    let return_type = cached.return_type;
    let class_global_ref = cached.class_global_ref;
    let quick_trampoline = cached.quick_trampoline;
    let quick_orig_precall = cached.quick_orig_precall;
    let param_types = cached.param_types.clone();
    (*ctx_ptr).intercept_leave = if quick_orig_precall { 1 } else { 0 };
    let mut local_refs: Vec<*mut std::ffi::c_void> = Vec::new();
    super::api::set_current_local_refs(&mut local_refs);
    let quick_orig_ctx = QuickOrigContext {
        hook_ctx_ptr: ctx_ptr,
        art_method: art_method_addr,
        class_global_ref,
        return_type,
        is_static,
        param_count,
        param_types: param_types.clone(),
        quick_trampoline,
        quick_orig_precall,
        local_refs: &mut local_refs,
    };

    let art_native = ArtNativeTransition::enter_from_quick(ctx_ptr, quick_diag.slot);
    if art_native.is_some() {
        let env = crate::jsapi::java::jni_core::get_thread_env().unwrap_or(std::ptr::null_mut());
        super::api::set_current_raw_mirror_env(env as *const std::ffi::c_void);
    }
    quick_diag.stage(QUICK_STAGE_NATIVE_READY);

    let L = tls.state.as_ptr();
    lua_ffi::lua_rawgeti(L, lua_ffi::LUA_REGISTRYINDEX, func_ref as lua_ffi::lua_Integer);

    lua_ffi::lua_createtable(L, 0, 2);
    lua_ffi::lua_pushlightuserdata(L, &quick_orig_ctx as *const _ as *mut std::ffi::c_void);
    lua_ffi::lua_pushcclosure(L, Some(lua_call_original_quick), 1);
    lua_ffi::lua_setfield(L, -2, c"orig".as_ptr());
    if !is_static && hook_ctx.x[1] != 0 {
        lua_ffi::lua_pushlightuserdata(L, hook_ctx.x[1] as *mut std::ffi::c_void);
        lua_ffi::lua_setfield(L, -2, c"__jptr".as_ptr());
    }

    let mut gp_index: usize = if is_static { 1 } else { 2 };
    let mut fp_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let is_fp = is_floating_point_type(type_sig);
        let (raw, fp_raw) = if is_fp {
            let fp_raw = if fp_index < 8 { hook_ctx.d[fp_index] } else { 0 };
            fp_index += 1;
            (0, fp_raw)
        } else {
            let raw = if gp_index < 8 {
                hook_ctx.x[gp_index]
            } else {
                let sp = hook_ctx.sp as usize;
                *((sp + (gp_index - 8) * 8) as *const u64)
            };
            gp_index += 1;
            (raw, 0)
        };
        super::api::push_jni_arg(L, raw, fp_raw, type_sig, std::ptr::null());
    }

    let nargs = 1 + param_count as i32;
    quick_diag.stage(QUICK_STAGE_LUA_CALL_BEGIN);
    let call_ret = lua_ffi::lua_pcall(L, nargs, 1, 0);
    quick_diag.stage(QUICK_STAGE_LUA_CALL_END);
    if super::api::take_fast_orig_requested() {
        lua_ffi::lua_pop(L, 1);
        super::api::clear_current_env();
        super::api::clear_quick_orig_result();
        delete_local_refs(std::ptr::null_mut(), local_refs);
        return;
    }
    if call_ret != lua_ffi::LUA_OK as i32 {
        let err_s = lua_ffi::lua_tostring_ex(L, -1);
        if !err_s.is_null() {
            let err = std::ffi::CStr::from_ptr(err_s).to_string_lossy();
            crate::jsapi::console::output_message(&format!("[lua quick] callback error: {}", err));
        }
        lua_ffi::lua_pop(L, 1);
        super::api::clear_current_env();
        super::api::clear_quick_orig_result();
        if !local_refs.is_empty() {
            let env = crate::jsapi::java::jni_core::get_thread_env().unwrap_or(std::ptr::null_mut());
            delete_local_refs(env, local_refs);
        }
        return;
    }

    quick_diag.stage(QUICK_STAGE_RETURN_BEGIN);
    let quick_orig_result = super::api::take_quick_orig_result();
    let preorig_result = if quick_orig_precall {
        Some(read_preorig_return(ctx_ptr, return_type))
    } else {
        None
    };
    if !lua_ffi::lua_isnil(L, -1) {
        if return_type != b'V' {
            let env = if matches!(return_type, b'L' | b'[') && lua_ffi::lua_type(L, -1) == lua_ffi::LUA_TSTRING as i32 {
                crate::jsapi::java::jni_core::get_thread_env().unwrap_or(std::ptr::null_mut())
            } else {
                std::ptr::null_mut()
            };
            write_quick_return(ctx_ptr, extract_lua_return(L, -1, return_type, env), return_type);
        }
        (*ctx_ptr).intercept_leave = 1;
    } else if let Some(ret_raw) = quick_orig_result {
        if return_type != b'V' {
            write_quick_return(ctx_ptr, ret_raw, return_type);
        }
        (*ctx_ptr).intercept_leave = 1;
    } else if let Some(ret_raw) = preorig_result {
        if return_type != b'V' {
            write_quick_return(ctx_ptr, ret_raw, return_type);
        }
        (*ctx_ptr).intercept_leave = 1;
    }
    lua_ffi::lua_pop(L, 1);
    quick_diag.stage(QUICK_STAGE_CLEANUP);
    super::api::clear_current_env();
    if !local_refs.is_empty() {
        let env = crate::jsapi::java::jni_core::get_thread_env().unwrap_or(std::ptr::null_mut());
        delete_local_refs(env, local_refs);
    }
}

/// Lua callback for ART interpreter DoCall.
///
/// DoCall receives the caller ShadowFrame and invoke instruction. Unlike the
/// quick path, arguments are not in registers yet; ART copies them from caller
/// vregs into the callee frame inside DoCallCommon. We mirror that decode here
/// and keep the attach hook in tail-jump mode so the original DoCall still runs.
pub unsafe fn lua_hook_dispatch_from_do_call(ctx_ptr: *mut hook_ffi::HookContext, is_range: bool) {
    if ctx_ptr.is_null() {
        return;
    }

    let hook_ctx = &*ctx_ptr;
    let art_method_addr = hook_ctx.x[0];
    let shadow_frame = hook_ctx.x[2] as *const u8;
    let inst = hook_ctx.x[3] as *const u16;
    let inst_data = hook_ctx.x[4] as u16;
    let string_init = hook_ctx.x[5] != 0;
    if art_method_addr == 0 || shadow_frame.is_null() || inst.is_null() || string_init {
        return;
    }

    let input_regs = match decode_do_call_input_regs(inst, inst_data, is_range) {
        Some(v) => v,
        None => return,
    };

    let _lua_callback_guard = super::LuaCallbackGuard::enter();
    let _in_flight = InFlightJavaHookGuard::enter();
    let _scope = JavaHookCallbackScope::enter();

    super::api::clear_fast_orig_requested();
    super::api::set_current_env(std::ptr::null());

    let tls = match super::get_thread_lua_state() {
        Some(t) => t,
        None => {
            super::api::clear_current_env();
            return;
        }
    };
    let cached = match super::get_cached_hook(tls, art_method_addr) {
        Some(c) => c,
        None => {
            super::api::clear_current_env();
            return;
        }
    };

    let func_ref = cached.func_ref;
    let is_static = cached.is_static;
    let param_count = cached.param_count;
    let param_types = cached.param_types.clone();

    let L = tls.state.as_ptr();
    lua_ffi::lua_rawgeti(L, lua_ffi::LUA_REGISTRYINDEX, func_ref as lua_ffi::lua_Integer);

    lua_ffi::lua_createtable(L, 0, 2);
    lua_ffi::lua_pushcfunction(L, Some(lua_quick_orig));
    lua_ffi::lua_setfield(L, -2, c"orig".as_ptr());

    let mut input_word_index = 0usize;
    if !is_static {
        let this_obj = input_regs
            .first()
            .and_then(|&r| read_shadow_frame_ref(shadow_frame, r))
            .unwrap_or(0);
        if this_obj != 0 {
            lua_ffi::lua_pushlightuserdata(L, this_obj as *mut std::ffi::c_void);
            lua_ffi::lua_setfield(L, -2, c"__jptr".as_ptr());
        }
        input_word_index = 1;
    }

    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let is_wide = matches!(type_sig, Some("J") | Some("D"));
        let raw = input_regs
            .get(input_word_index)
            .and_then(|&r| read_shadow_frame_arg(shadow_frame, r, type_sig))
            .unwrap_or(0);
        let fp_raw = if is_floating_point_type(type_sig) { raw } else { 0 };
        super::api::push_jni_arg(L, raw, fp_raw, type_sig, std::ptr::null());
        input_word_index += if is_wide { 2 } else { 1 };
    }

    let nargs = 1 + param_count as i32;
    let call_ret = lua_ffi::lua_pcall(L, nargs, 1, 0);
    if call_ret != lua_ffi::LUA_OK as i32 {
        let err_s = lua_ffi::lua_tostring_ex(L, -1);
        if !err_s.is_null() {
            let err = std::ffi::CStr::from_ptr(err_s).to_string_lossy();
            crate::jsapi::console::output_message(&format!("[lua docall] callback error: {}", err));
        }
    }
    lua_ffi::lua_pop(L, 1);
    super::api::clear_current_env();
}

unsafe extern "C" fn lua_quick_orig(L: *mut lua_ffi::lua_State) -> std::os::raw::c_int {
    super::record_orig_request();
    super::api::mark_fast_orig_requested();
    lua_ffi::lua_pushnil(L);
    1
}

unsafe extern "C" fn lua_call_original_quick(L: *mut lua_ffi::lua_State) -> std::os::raw::c_int {
    let ctx_ptr = lua_ffi::lua_touserdata(L, super::api::lua_upvalueindex(1));
    if ctx_ptr.is_null() {
        lua_ffi::lua_pushnil(L);
        return 1;
    }
    let cb_ctx = &*(ctx_ptr as *const QuickOrigContext);
    if cb_ctx.hook_ctx_ptr.is_null() {
        lua_ffi::lua_pushnil(L);
        return 1;
    }

    super::record_orig_request();

    if !cb_ctx.quick_orig_precall {
        super::api::mark_fast_orig_requested();
        lua_ffi::lua_pushnil(L);
        return 1;
    }

    let ret = read_preorig_return(cb_ctx.hook_ctx_ptr, cb_ctx.return_type);

    super::api::set_quick_orig_result(ret);
    push_quick_return_value(L, ret, cb_ctx.return_type);
    1
}

unsafe fn read_preorig_return(ctx_ptr: *mut hook_ffi::HookContext, return_type: u8) -> u64 {
    if ctx_ptr.is_null() {
        return 0;
    }
    match return_type {
        b'F' | b'D' => (*ctx_ptr).d[0],
        _ => (*ctx_ptr).x[QUICK_PREORIG_RET_REG],
    }
}

unsafe fn write_quick_return(ctx_ptr: *mut hook_ffi::HookContext, raw: u64, return_type: u8) {
    if ctx_ptr.is_null() {
        return;
    }
    match return_type {
        b'F' | b'D' => (*ctx_ptr).d[0] = raw,
        _ => (*ctx_ptr).x[0] = raw,
    }
}

unsafe fn build_local_jargs_from_registers(
    hook_ctx: &hook_ffi::HookContext,
    param_count: usize,
    param_types: &[String],
    env: crate::jsapi::java::jni_core::JniEnv,
    local_refs: &mut Vec<*mut std::ffi::c_void>,
) -> Vec<u64> {
    let mut jargs: Vec<u64> = Vec::with_capacity(param_count);
    let mut gp_index: usize = 0;
    let mut fp_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let is_fp = is_floating_point_type(type_sig);
        let (mut gp_val, fp_val) = extract_jni_arg(hook_ctx, is_fp, &mut gp_index, &mut fp_index);
        if is_object_type(type_sig) && gp_val != 0 {
            gp_val = new_jni_local_ref(env, gp_val, local_refs) as u64;
        }
        jargs.push(if is_fp { fp_val } else { gp_val });
    }
    jargs
}

unsafe fn build_quick_local_jargs_from_registers(
    hook_ctx: &hook_ffi::HookContext,
    is_static: bool,
    param_count: usize,
    param_types: &[String],
    env: crate::jsapi::java::jni_core::JniEnv,
    local_refs: &mut Vec<*mut std::ffi::c_void>,
) -> Vec<u64> {
    let mut jargs: Vec<u64> = Vec::with_capacity(param_count);
    let mut gp_index: usize = if is_static { 1 } else { 2 };
    let mut fp_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let is_fp = is_floating_point_type(type_sig);
        let (mut raw, fp_raw) = if is_fp {
            let fp_raw = if fp_index < 8 { hook_ctx.d[fp_index] } else { 0 };
            fp_index += 1;
            (0, fp_raw)
        } else {
            let raw = if gp_index < 8 {
                hook_ctx.x[gp_index]
            } else {
                let sp = hook_ctx.sp as usize;
                *((sp + (gp_index - 8) * 8) as *const u64)
            };
            gp_index += 1;
            (raw, 0)
        };
        if is_object_type(type_sig) && raw != 0 && !env.is_null() {
            raw = raw_mirror_to_local_ref(env, raw, local_refs) as u64;
        }
        jargs.push(if is_fp { fp_raw } else { raw });
    }
    jargs
}

unsafe fn quick_return_raw(
    env: crate::jsapi::java::jni_core::JniEnv,
    ret: u64,
    return_type: u8,
    local_refs: *mut Vec<*mut std::ffi::c_void>,
) -> u64 {
    if !matches!(return_type, b'L' | b'[') || ret == 0 || env.is_null() {
        return ret;
    }
    if !local_refs.is_null() {
        (*local_refs).push(ret as *mut std::ffi::c_void);
    }
    crate::jsapi::java::decode_jobject_raw(env, ret as *mut std::ffi::c_void).unwrap_or(0)
}

unsafe fn push_quick_return_value(L: *mut lua_ffi::lua_State, raw: u64, return_type: u8) {
    match return_type {
        b'V' => lua_ffi::lua_pushnil(L),
        b'Z' => lua_ffi::lua_pushboolean(L, if raw != 0 { 1 } else { 0 }),
        b'B' => lua_ffi::lua_pushinteger(L, raw as i8 as lua_ffi::lua_Integer),
        b'C' => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            let cs = std::ffi::CString::new(s).unwrap();
            lua_ffi::lua_pushstring(L, cs.as_ptr());
        }
        b'S' => lua_ffi::lua_pushinteger(L, raw as i16 as lua_ffi::lua_Integer),
        b'I' => lua_ffi::lua_pushinteger(L, raw as i32 as lua_ffi::lua_Integer),
        b'J' => lua_ffi::lua_pushinteger(L, raw as lua_ffi::lua_Integer),
        b'F' => lua_ffi::lua_pushnumber(L, f32::from_bits(raw as u32) as lua_ffi::lua_Number),
        b'D' => lua_ffi::lua_pushnumber(L, f64::from_bits(raw) as lua_ffi::lua_Number),
        b'L' | b'[' => {
            if raw == 0 {
                lua_ffi::lua_pushnil(L);
            } else {
                lua_ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
            }
        }
        _ => lua_ffi::lua_pushinteger(L, raw as lua_ffi::lua_Integer),
    }
}

const SHADOW_FRAME_NUMBER_OF_VREGS_OFFSET: usize = 24;
const SHADOW_FRAME_VREGS_OFFSET: usize = 36;

unsafe fn decode_do_call_input_regs(inst: *const u16, inst_data: u16, is_range: bool) -> Option<Vec<u32>> {
    let count = if is_range {
        (inst_data >> 8) as usize
    } else {
        (inst_data >> 12) as usize
    };
    if count == 0 {
        return Some(Vec::new());
    }
    if is_range {
        let first = *inst.add(2) as u32;
        return Some((0..count).map(|i| first + i as u32).collect());
    }
    if count > 5 {
        return None;
    }
    let reg_list = *inst.add(2);
    let mut regs = Vec::with_capacity(count);
    if count >= 1 {
        regs.push((reg_list & 0x0f) as u32);
    }
    if count >= 2 {
        regs.push(((reg_list >> 4) & 0x0f) as u32);
    }
    if count >= 3 {
        regs.push(((reg_list >> 8) & 0x0f) as u32);
    }
    if count >= 4 {
        regs.push(((reg_list >> 12) & 0x0f) as u32);
    }
    if count >= 5 {
        regs.push(((inst_data >> 8) & 0x0f) as u32);
    }
    Some(regs)
}

unsafe fn shadow_frame_num_vregs(shadow_frame: *const u8) -> usize {
    *(shadow_frame.add(SHADOW_FRAME_NUMBER_OF_VREGS_OFFSET) as *const u32) as usize
}

unsafe fn read_shadow_frame_vreg_u32(shadow_frame: *const u8, vreg: u32) -> Option<u32> {
    let idx = vreg as usize;
    if idx >= shadow_frame_num_vregs(shadow_frame) {
        return None;
    }
    Some(*(shadow_frame.add(SHADOW_FRAME_VREGS_OFFSET + idx * 4) as *const u32))
}

unsafe fn read_shadow_frame_ref(shadow_frame: *const u8, vreg: u32) -> Option<u64> {
    let num_vregs = shadow_frame_num_vregs(shadow_frame);
    let idx = vreg as usize;
    if idx >= num_vregs {
        return None;
    }
    let refs_off = SHADOW_FRAME_VREGS_OFFSET + num_vregs * 4;
    let compressed = *(shadow_frame.add(refs_off + idx * 4) as *const u32);
    if compressed == 0 {
        None
    } else {
        Some(compressed as u64)
    }
}

unsafe fn read_shadow_frame_arg(shadow_frame: *const u8, vreg: u32, type_sig: Option<&str>) -> Option<u64> {
    match type_sig.and_then(|s| s.as_bytes().first()).copied() {
        Some(b'L') | Some(b'[') => read_shadow_frame_ref(shadow_frame, vreg),
        Some(b'J') | Some(b'D') => {
            let lo = read_shadow_frame_vreg_u32(shadow_frame, vreg)? as u64;
            let hi = read_shadow_frame_vreg_u32(shadow_frame, vreg + 1)? as u64;
            Some(lo | (hi << 32))
        }
        _ => read_shadow_frame_vreg_u32(shadow_frame, vreg).map(|v| v as u64),
    }
}

#[inline]
fn is_object_type(type_sig: Option<&str>) -> bool {
    matches!(type_sig, Some(s) if s.starts_with('L') || s.starts_with('['))
}

unsafe fn new_jni_local_ref(
    env: crate::jsapi::java::jni_core::JniEnv,
    obj: u64,
    local_refs: &mut Vec<*mut std::ffi::c_void>,
) -> *mut std::ffi::c_void {
    if obj == 0 || env.is_null() {
        return obj as *mut std::ffi::c_void;
    }
    let vtable = *(env as *const *const *const std::ffi::c_void);
    let new_local_ref: unsafe extern "C" fn(
        crate::jsapi::java::jni_core::JniEnv,
        *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void = std::mem::transmute(*vtable.add(25));
    let local = new_local_ref(env, obj as *mut std::ffi::c_void);
    if !local.is_null() {
        local_refs.push(local);
        return local;
    }
    obj as *mut std::ffi::c_void
}

unsafe fn raw_mirror_to_local_ref(
    env: crate::jsapi::java::jni_core::JniEnv,
    raw: u64,
    local_refs: &mut Vec<*mut std::ffi::c_void>,
) -> *mut std::ffi::c_void {
    if raw == 0 || env.is_null() {
        return std::ptr::null_mut();
    }

    type ArtNewLocalRefFn = unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    static ART_NEW_LOCAL_REF: std::sync::OnceLock<Option<ArtNewLocalRefFn>> = std::sync::OnceLock::new();

    let local = if let Some(add_ref) = *ART_NEW_LOCAL_REF.get_or_init(|| {
        let sym = crate::jsapi::module::libart_dlsym("_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE");
        if sym.is_null() {
            None
        } else {
            Some(std::mem::transmute(sym))
        }
    }) {
        add_ref(env as *mut std::ffi::c_void, raw as *mut std::ffi::c_void)
    } else {
        let vtable = *(env as *const *const *const std::ffi::c_void);
        let new_local_ref: unsafe extern "C" fn(
            crate::jsapi::java::jni_core::JniEnv,
            *mut std::ffi::c_void,
        ) -> *mut std::ffi::c_void = std::mem::transmute(*vtable.add(25));
        new_local_ref(env, raw as *mut std::ffi::c_void)
    };

    if !local.is_null() {
        local_refs.push(local);
    }
    local
}

unsafe fn delete_local_refs(env: crate::jsapi::java::jni_core::JniEnv, local_refs: Vec<*mut std::ffi::c_void>) {
    if env.is_null() {
        return;
    }
    let vtable = *(env as *const *const *const std::ffi::c_void);
    let delete_local_ref: unsafe extern "C" fn(crate::jsapi::java::jni_core::JniEnv, *mut std::ffi::c_void) =
        std::mem::transmute(*vtable.add(23));
    for local in local_refs {
        if !local.is_null() {
            delete_local_ref(env, local);
        }
    }
}

unsafe fn extract_lua_return(
    L: *mut lua_ffi::lua_State,
    idx: i32,
    return_type: u8,
    env: crate::jsapi::java::jni_core::JniEnv,
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
            } else if lua_ffi::lua_type(L, idx) == lua_ffi::LUA_TSTRING as i32 && !env.is_null() {
                super::api::lua_string_to_jstring(L, idx, env)
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
        env,
        art_method_addr,
        class_global_ref,
        hook_ctx.x[1],
        return_type,
        is_static,
        jargs_ptr,
        quick_trampoline,
        false,
    );
    if return_type != b'V' {
        (*ctx_ptr).x[0] = ret;
    }
}

#[inline]
unsafe fn jni_safepoint(env: crate::jsapi::java::jni_core::JniEnv) {
    if env.is_null() {
        return;
    }
    let vtable = *(env as *const *const *const std::ffi::c_void);
    let exc_check: unsafe extern "C" fn(crate::jsapi::java::jni_core::JniEnv) -> u8 =
        std::mem::transmute(*vtable.add(228));
    if exc_check(env) != 0 {
        let exc_clear: unsafe extern "C" fn(crate::jsapi::java::jni_core::JniEnv) =
            std::mem::transmute(*vtable.add(17));
        exc_clear(env);
    }
}

/// Lua VM count hook — 每 N 条指令调一次，让 ART 有机会 suspend 线程
pub(super) unsafe extern "C" fn lua_art_checkpoint_hook(
    _L: *mut super::ffi::lua_State,
    _ar: *mut super::ffi::lua_Debug,
) {
    let env = super::api::get_current_env();
    if !env.is_null() {
        jni_safepoint(env as crate::jsapi::java::jni_core::JniEnv);
    }
}
