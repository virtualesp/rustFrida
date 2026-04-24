pub mod api;
pub mod callback;
pub mod ffi;
pub mod state;

use state::LuaState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

/// Lua 回调注册表：art_method -> (bytecode, metadata)
pub(crate) struct LuaHookEntry {
    pub bytecode: Vec<u8>,
    pub is_raw_bytecode: bool,
    pub is_static: bool,
    pub param_count: usize,
    pub param_types: Vec<String>,
    pub return_type: u8,
    pub return_type_sig: String,
    pub class_global_ref: usize,
    pub quick_trampoline: u64,
    pub use_blr: bool,
    pub quick_orig_precall: bool,
    pub art_method: u64,
}

unsafe impl Send for LuaHookEntry {}
unsafe impl Sync for LuaHookEntry {}

// 全局注册表 — 只在 hook 安装/卸载时写（Mutex 保护），回调热路径不碰
static LUA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, LuaHookEntry>>> = Mutex::new(None);

// 无锁快速路径 — is_lua_hook 用 AtomicPtr<Vec<u64>> (sorted)
static LUA_HOOK_SET: AtomicPtr<Vec<u64>> = AtomicPtr::new(std::ptr::null_mut());
static LUA_CALLBACK_TOTAL: AtomicU64 = AtomicU64::new(0);
static LUA_CALLBACK_ACTIVE: AtomicU64 = AtomicU64::new(0);
static LUA_CALLBACK_MAX_ACTIVE: AtomicU64 = AtomicU64::new(0);
static LUA_THREAD_STATES_CREATED: AtomicU64 = AtomicU64::new(0);
static LUA_ORIG_REQUEST_TOTAL: AtomicU64 = AtomicU64::new(0);
static LUA_NATIVE_TRANSITION_ENTER: AtomicU64 = AtomicU64::new(0);
static LUA_NATIVE_TRANSITION_LEAVE: AtomicU64 = AtomicU64::new(0);
static LUA_NATIVE_TRANSITION_FAIL: AtomicU64 = AtomicU64::new(0);

pub(crate) struct LuaCallbackGuard;

impl LuaCallbackGuard {
    pub(crate) fn enter() -> Self {
        LUA_CALLBACK_TOTAL.fetch_add(1, Ordering::Relaxed);
        let active = LUA_CALLBACK_ACTIVE.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        let mut observed = LUA_CALLBACK_MAX_ACTIVE.load(Ordering::Acquire);
        while active > observed {
            match LUA_CALLBACK_MAX_ACTIVE.compare_exchange(observed, active, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(v) => observed = v,
            }
        }
        Self
    }
}

impl Drop for LuaCallbackGuard {
    fn drop(&mut self) {
        LUA_CALLBACK_ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn record_orig_request() {
    LUA_ORIG_REQUEST_TOTAL.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_native_transition_enter() {
    LUA_NATIVE_TRANSITION_ENTER.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_native_transition_leave() {
    LUA_NATIVE_TRANSITION_LEAVE.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_native_transition_fail() {
    LUA_NATIVE_TRANSITION_FAIL.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn callback_stats() -> (u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        LUA_CALLBACK_TOTAL.load(Ordering::Acquire),
        LUA_CALLBACK_ACTIVE.load(Ordering::Acquire),
        LUA_CALLBACK_MAX_ACTIVE.load(Ordering::Acquire),
        LUA_THREAD_STATES_CREATED.load(Ordering::Acquire),
        LUA_ORIG_REQUEST_TOTAL.load(Ordering::Acquire),
        LUA_NATIVE_TRANSITION_ENTER.load(Ordering::Acquire),
        LUA_NATIVE_TRANSITION_LEAVE.load(Ordering::Acquire),
        LUA_NATIVE_TRANSITION_FAIL.load(Ordering::Acquire),
    )
}

pub(crate) fn reset_callback_stats() {
    let active = LUA_CALLBACK_ACTIVE.load(Ordering::Acquire);
    LUA_CALLBACK_TOTAL.store(0, Ordering::Release);
    LUA_CALLBACK_MAX_ACTIVE.store(active, Ordering::Release);
    LUA_THREAD_STATES_CREATED.store(0, Ordering::Release);
    LUA_ORIG_REQUEST_TOTAL.store(0, Ordering::Release);
    LUA_NATIVE_TRANSITION_ENTER.store(0, Ordering::Release);
    LUA_NATIVE_TRANSITION_LEAVE.store(0, Ordering::Release);
    LUA_NATIVE_TRANSITION_FAIL.store(0, Ordering::Release);
    api::reset_callback_log_mark();
    callback::reset_quick_diag();
}

fn update_hook_set(reg: &Option<HashMap<u64, LuaHookEntry>>) {
    let mut keys: Vec<u64> = reg.as_ref().map_or_else(Vec::new, |m| m.keys().copied().collect());
    keys.sort_unstable();
    let new_box = Box::new(keys);
    let old = LUA_HOOK_SET.swap(Box::into_raw(new_box), Ordering::Release);
    if !old.is_null() {
        let old_usize = old as usize;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            unsafe {
                drop(Box::from_raw(old_usize as *mut Vec<u64>));
            }
        });
    }
}

pub(crate) fn init_lua_registry() {
    let mut reg = LUA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if reg.is_none() {
        *reg = Some(HashMap::new());
    }
}

pub(crate) fn register_lua_hook(art_method: u64, entry: LuaHookEntry) {
    let mut reg = LUA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = reg.as_mut() {
        map.insert(art_method, entry);
    }
    update_hook_set(&reg);
}

pub(crate) fn remove_lua_hook(art_method: u64) -> bool {
    let mut reg = LUA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let removed = if let Some(map) = reg.as_mut() {
        map.remove(&art_method).is_some()
    } else {
        false
    };
    if removed {
        update_hook_set(&reg);
    }
    removed
}

/// 无锁热路径：二分查找 sorted Vec，零 Mutex 竞争
pub(crate) fn is_lua_hook(art_method: u64) -> bool {
    let ptr = LUA_HOOK_SET.load(Ordering::Acquire);
    if ptr.is_null() {
        return false;
    }
    let set = unsafe { &*ptr };
    set.binary_search(&art_method).is_ok()
}

/// 从全局注册表读取 hook entry（仅首次 per-thread 缓存时调用，非热路径）
pub(crate) fn with_lua_hook<F, R>(art_method: u64, f: F) -> Option<R>
where
    F: FnOnce(&LuaHookEntry) -> R,
{
    let reg = LUA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    reg.as_ref().and_then(|m| m.get(&art_method).map(f))
}

// Per-thread Lua state + hook 元数据缓存
static LUA_TLS_KEY_INIT: std::sync::Once = std::sync::Once::new();
static mut LUA_TLS_KEY: libc::pthread_key_t = 0;

/// Per-thread 缓存的 hook 数据（从全局注册表拷贝一次，之后不再碰全局锁）
pub(crate) struct CachedHook {
    pub func_ref: i32,
    pub is_static: bool,
    pub param_count: usize,
    pub param_types: Vec<String>,
    pub return_type: u8,
    pub return_type_sig: String,
    pub class_global_ref: usize,
    pub quick_trampoline: u64,
    pub use_blr: bool,
    pub quick_orig_precall: bool,
}

pub(crate) struct ThreadLuaState {
    pub(crate) state: LuaState,
    pub(crate) cached_hooks: HashMap<u64, CachedHook>,
}

unsafe extern "C" fn thread_lua_state_destructor(ptr: *mut std::ffi::c_void) {
    if !ptr.is_null() {
        let _ = Box::from_raw(ptr as *mut ThreadLuaState);
    }
}

fn ensure_tls_key() {
    LUA_TLS_KEY_INIT.call_once(|| unsafe {
        libc::pthread_key_create(&mut LUA_TLS_KEY, Some(thread_lua_state_destructor));
    });
}

pub(crate) unsafe fn get_thread_lua_state() -> Option<&'static mut ThreadLuaState> {
    ensure_tls_key();
    let ptr = libc::pthread_getspecific(LUA_TLS_KEY) as *mut ThreadLuaState;
    if !ptr.is_null() {
        return Some(&mut *ptr);
    }
    let state = LuaState::new()?;
    LUA_THREAD_STATES_CREATED.fetch_add(1, Ordering::Relaxed);
    api::register_lua_apis(&state);
    // 每 200 条 Lua 指令触发 ART checkpoint，让 GC 能 suspend 本线程
    ffi::lua_sethook(
        state.as_ptr(),
        Some(callback::lua_art_checkpoint_hook),
        ffi::LUA_MASKCOUNT as i32,
        200,
    );
    let tls = Box::new(ThreadLuaState {
        state,
        cached_hooks: HashMap::new(),
    });
    let raw = Box::into_raw(tls);
    libc::pthread_setspecific(LUA_TLS_KEY, raw as *const _);
    Some(&mut *raw)
}

/// 获取 per-thread 缓存的 hook 数据。首次访问时从全局注册表拷贝+编译，之后零锁。
pub(crate) unsafe fn get_cached_hook(tls: &mut ThreadLuaState, art_method: u64) -> Option<&CachedHook> {
    if tls.cached_hooks.contains_key(&art_method) {
        return tls.cached_hooks.get(&art_method);
    }

    let entry_data = with_lua_hook(art_method, |e| {
        (
            e.bytecode.clone(),
            e.is_raw_bytecode,
            e.is_static,
            e.param_count,
            e.param_types.clone(),
            e.return_type,
            e.return_type_sig.clone(),
            e.class_global_ref,
            e.quick_trampoline,
            e.use_blr,
            e.quick_orig_precall,
        )
    })?;

    let (
        bytecode,
        is_raw_bytecode,
        is_static,
        param_count,
        param_types,
        return_type,
        return_type_sig,
        class_global_ref,
        quick_trampoline,
        use_blr,
        quick_orig_precall,
    ) = entry_data;

    let L = tls.state.as_ptr();
    if tls.state.load_bytecode(&bytecode, "<hook>").is_err() {
        return None;
    }
    if !is_raw_bytecode {
        if tls.state.pcall(0, 1).is_err() {
            return None;
        }
    }
    if !ffi::lua_isfunction_ex(L, -1) {
        ffi::lua_pop(L, 1);
        return None;
    }
    let func_ref = ffi::luaL_ref(L, ffi::LUA_REGISTRYINDEX);

    tls.cached_hooks.insert(
        art_method,
        CachedHook {
            func_ref,
            is_static,
            param_count,
            param_types,
            return_type,
            return_type_sig,
            class_global_ref,
            quick_trampoline,
            use_blr,
            quick_orig_precall,
        },
    );
    tls.cached_hooks.get(&art_method)
}

pub fn compile_lua_callback(source: &str) -> Result<Vec<u8>, String> {
    let state = LuaState::new().ok_or("failed to create Lua state for compilation")?;
    unsafe {
        state.load_string(source, "<callback>")?;
        state.dump_function()
    }
}

pub(crate) fn cleanup_lua() {
    let mut reg = LUA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    *reg = None;
    let old = LUA_HOOK_SET.swap(std::ptr::null_mut(), Ordering::Release);
    if !old.is_null() {
        let old_usize = old as usize;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            unsafe {
                drop(Box::from_raw(old_usize as *mut Vec<u64>));
            }
        });
    }
}
