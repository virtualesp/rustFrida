pub mod ffi;
pub mod state;
pub mod api;
pub mod callback;
pub mod script;

use state::LuaState;
use std::collections::HashMap;
use std::sync::Mutex;

/// Lua 回调注册表：art_method -> (bytecode, metadata)
pub(crate) struct LuaHookEntry {
    pub bytecode: Vec<u8>,
    /// true = lua_dump 的裸函数字节码 (loadbuffer 后直接是 callback function)
    /// false = "return function(ctx)...end" chunk (loadbuffer 后需 pcall 取返回值)
    pub is_raw_bytecode: bool,
    pub is_static: bool,
    pub param_count: usize,
    pub param_types: Vec<String>,
    pub return_type: u8,
    pub return_type_sig: String,
    pub class_global_ref: usize,
    pub quick_trampoline: u64,
    pub art_method: u64,
}

unsafe impl Send for LuaHookEntry {}
unsafe impl Sync for LuaHookEntry {}

static LUA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, LuaHookEntry>>> = Mutex::new(None);

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
}

pub(crate) fn remove_lua_hook(art_method: u64) -> bool {
    let mut reg = LUA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = reg.as_mut() {
        map.remove(&art_method).is_some()
    } else {
        false
    }
}

pub(crate) fn is_lua_hook(art_method: u64) -> bool {
    let reg = LUA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    reg.as_ref().map_or(false, |m| m.contains_key(&art_method))
}

pub(crate) fn with_lua_hook<F, R>(art_method: u64, f: F) -> Option<R>
where
    F: FnOnce(&LuaHookEntry) -> R,
{
    let reg = LUA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    reg.as_ref().and_then(|m| m.get(&art_method).map(f))
}

/// Per-thread Lua state 管理 (TLS)
static LUA_TLS_KEY_INIT: std::sync::Once = std::sync::Once::new();
static mut LUA_TLS_KEY: libc::pthread_key_t = 0;

struct ThreadLuaState {
    state: LuaState,
    loaded_hooks: HashMap<u64, i32>,
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
    api::register_lua_apis(&state);
    let tls = Box::new(ThreadLuaState {
        state,
        loaded_hooks: HashMap::new(),
    });
    let raw = Box::into_raw(tls);
    libc::pthread_setspecific(LUA_TLS_KEY, raw as *const _);
    Some(&mut *raw)
}

/// 确保 per-thread state 中已加载指定 hook 的 callback 函数。
/// 返回 registry ref (luaL_ref) 指向该 callback function。
pub(crate) unsafe fn ensure_hook_loaded(
    tls: &mut ThreadLuaState,
    art_method: u64,
    bytecode: &[u8],
    is_raw_bytecode: bool,
) -> Result<i32, String> {
    if let Some(&ref_id) = tls.loaded_hooks.get(&art_method) {
        return Ok(ref_id);
    }
    let L = tls.state.as_ptr();
    tls.state.load_bytecode(bytecode, "<hook>")?;
    if is_raw_bytecode {
        // lua_dump 的裸函数: loadbuffer 后栈顶直接是 callback function
    } else {
        // "return function(ctx)...end" chunk: pcall 取返回值
        tls.state.pcall(0, 1)?;
    }
    if !ffi::lua_isfunction_ex(L, -1) {
        ffi::lua_pop(L, 1);
        return Err("Lua hook chunk did not return a function".to_string());
    }
    let ref_id = ffi::luaL_ref(L, ffi::LUA_REGISTRYINDEX);
    tls.loaded_hooks.insert(art_method, ref_id);
    Ok(ref_id)
}

/// 编译 Lua callback 源码为字节码。
/// 源码应为 `return function(ctx) ... end` 形式。
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
}
