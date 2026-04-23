use super::ffi;
use super::state::LuaState;
use std::sync::Mutex;

static MASTER_STATE: Mutex<Option<LuaState>> = Mutex::new(None);

fn get_or_init_master() -> Result<(), String> {
    let mut guard = MASTER_STATE.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_some() {
        return Ok(());
    }
    let state = LuaState::new().ok_or("failed to create master Lua state")?;
    unsafe {
        super::api::register_lua_apis(&state);
        register_all_apis(&state);
    }
    *guard = Some(state);
    Ok(())
}

pub fn load_lua_script(code: &str, filename: &str) -> Result<String, String> {
    get_or_init_master()?;
    let guard = MASTER_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let state = guard.as_ref().ok_or("master Lua state not initialized")?;
    unsafe {
        state.load_string(code, filename)?;
        state.pcall(0, 0)?;
    }
    Ok("ok".to_string())
}

unsafe fn register_all_apis(state: &LuaState) {
    let L = state.as_ptr();

    // ---- Java ----
    ffi::lua_createtable(L, 0, 3);
    set_cfn(L, c"hook", lua_java_hook);
    set_cfn(L, c"unhook", lua_java_unhook);
    set_cfn(L, c"jstring", lua_jstring);
    ffi::lua_setglobal(L, c"Java".as_ptr());

    // ---- Module ----
    ffi::lua_createtable(L, 0, 3);
    set_cfn(L, c"findExportByName", lua_module_find_export);
    set_cfn(L, c"findBaseAddress", lua_module_find_base);
    set_cfn(L, c"enumerateModules", lua_module_enumerate);
    ffi::lua_setglobal(L, c"Module".as_ptr());

    // ---- Memory ----
    ffi::lua_createtable(L, 0, 12);
    set_cfn(L, c"readU8", lua_mem_read_u8);
    set_cfn(L, c"readU16", lua_mem_read_u16);
    set_cfn(L, c"readU32", lua_mem_read_u32);
    set_cfn(L, c"readU64", lua_mem_read_u64);
    set_cfn(L, c"readPointer", lua_mem_read_u64);
    set_cfn(L, c"readCString", lua_mem_read_cstring);
    set_cfn(L, c"writeU8", lua_mem_write_u8);
    set_cfn(L, c"writeU16", lua_mem_write_u16);
    set_cfn(L, c"writeU32", lua_mem_write_u32);
    set_cfn(L, c"writeU64", lua_mem_write_u64);
    set_cfn(L, c"writePointer", lua_mem_write_u64);
    ffi::lua_setglobal(L, c"Memory".as_ptr());

    // ---- hook / unhook (native) ----
    ffi::lua_pushcfunction(L, Some(lua_native_hook));
    ffi::lua_setglobal(L, c"hook".as_ptr());
    ffi::lua_pushcfunction(L, Some(lua_native_unhook));
    ffi::lua_setglobal(L, c"unhook".as_ptr());

    // ---- ptr(addr) ----
    ffi::lua_pushcfunction(L, Some(lua_ptr));
    ffi::lua_setglobal(L, c"ptr".as_ptr());
}

unsafe fn set_cfn(
    L: *mut ffi::lua_State,
    name: &std::ffi::CStr,
    f: unsafe extern "C" fn(*mut ffi::lua_State) -> std::os::raw::c_int,
) {
    ffi::lua_pushcfunction(L, Some(f));
    ffi::lua_setfield(L, -2, name.as_ptr());
}

fn lua_arg_addr(L: *mut ffi::lua_State, idx: i32) -> u64 {
    unsafe {
        let tp = ffi::lua_type(L, idx);
        if tp == ffi::LUA_TLIGHTUSERDATA as i32 {
            ffi::lua_touserdata(L, idx) as u64
        } else {
            ffi::lua_tointeger_ex(L, idx) as u64
        }
    }
}

// ============================================================================
// ptr(addr) → lightuserdata
// ============================================================================

unsafe extern "C" fn lua_ptr(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let addr = lua_arg_addr(L, 1);
    ffi::lua_pushlightuserdata(L, addr as *mut std::ffi::c_void);
    1
}

// ============================================================================
// Module API
// ============================================================================

/// Module.findExportByName(moduleName, symbolName) → lightuserdata | nil
unsafe extern "C" fn lua_module_find_export(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let mod_c = ffi::lua_tostring_ex(L, 1);
    let sym_c = ffi::lua_tostring_ex(L, 2);
    if sym_c.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let sym = std::ffi::CStr::from_ptr(sym_c).to_string_lossy();
    let mod_name = if mod_c.is_null() {
        None
    } else {
        Some(std::ffi::CStr::from_ptr(mod_c).to_string_lossy().into_owned())
    };

    let addr = if let Some(ref m) = mod_name {
        crate::jsapi::module::module_dlsym(m, &sym) as u64
    } else {
        // 无模块名: dlsym(RTLD_DEFAULT, sym)
        let csym = std::ffi::CString::new(sym.as_ref()).unwrap_or_default();
        libc::dlsym(libc::RTLD_DEFAULT, csym.as_ptr()) as u64
    };

    if addr == 0 {
        ffi::lua_pushnil(L);
    } else {
        ffi::lua_pushlightuserdata(L, addr as *mut std::ffi::c_void);
    }
    1
}

/// Module.findBaseAddress(moduleName) → lightuserdata | nil
unsafe extern "C" fn lua_module_find_base(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let mod_c = ffi::lua_tostring_ex(L, 1);
    if mod_c.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let mod_name = std::ffi::CStr::from_ptr(mod_c).to_string_lossy();
    let addr = crate::jsapi::module::find_module_base(&mod_name);
    if addr == 0 {
        ffi::lua_pushnil(L);
    } else {
        ffi::lua_pushlightuserdata(L, addr as *mut std::ffi::c_void);
    }
    1
}

/// Module.enumerateModules() → {{name=, base=, size=, path=}, ...}
unsafe extern "C" fn lua_module_enumerate(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let modules = crate::jsapi::module::enumerate_modules_from_maps();
    ffi::lua_createtable(L, modules.len() as i32, 0);
    for (i, m) in modules.iter().enumerate() {
        ffi::lua_createtable(L, 0, 4);
        let cs = std::ffi::CString::new(m.name.as_str()).unwrap_or_default();
        ffi::lua_pushstring(L, cs.as_ptr());
        ffi::lua_setfield(L, -2, c"name".as_ptr());
        ffi::lua_pushlightuserdata(L, m.base as *mut std::ffi::c_void);
        ffi::lua_setfield(L, -2, c"base".as_ptr());
        ffi::lua_pushinteger(L, m.size as ffi::lua_Integer);
        ffi::lua_setfield(L, -2, c"size".as_ptr());
        let ps = std::ffi::CString::new(m.path.as_str()).unwrap_or_default();
        ffi::lua_pushstring(L, ps.as_ptr());
        ffi::lua_setfield(L, -2, c"path".as_ptr());
        ffi::lua_rawseti(L, -2, (i + 1) as ffi::lua_Integer);
    }
    1
}

// ============================================================================
// Memory API
// ============================================================================

macro_rules! lua_mem_read {
    ($name:ident, $ty:ty) => {
        unsafe extern "C" fn $name(L: *mut ffi::lua_State) -> std::os::raw::c_int {
            let addr = lua_arg_addr(L, 1);
            if addr == 0 {
                ffi::lua_pushinteger(L, 0);
                return 1;
            }
            let val = std::ptr::read_unaligned(addr as *const $ty);
            ffi::lua_pushinteger(L, val as ffi::lua_Integer);
            1
        }
    };
}

lua_mem_read!(lua_mem_read_u8, u8);
lua_mem_read!(lua_mem_read_u16, u16);
lua_mem_read!(lua_mem_read_u32, u32);
lua_mem_read!(lua_mem_read_u64, u64);

unsafe extern "C" fn lua_mem_read_cstring(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let addr = lua_arg_addr(L, 1);
    if addr == 0 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let max_len = if ffi::lua_gettop(L) >= 2 {
        ffi::lua_tointeger_ex(L, 2) as usize
    } else {
        4096
    };
    let ptr = addr as *const u8;
    let mut len = 0usize;
    while len < max_len {
        if *ptr.add(len) == 0 { break; }
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    ffi::lua_pushlstring(L, slice.as_ptr() as *const _, len);
    1
}

macro_rules! lua_mem_write {
    ($name:ident, $ty:ty) => {
        unsafe extern "C" fn $name(L: *mut ffi::lua_State) -> std::os::raw::c_int {
            let addr = lua_arg_addr(L, 1);
            let val = ffi::lua_tointeger_ex(L, 2) as $ty;
            if addr != 0 {
                std::ptr::write_unaligned(addr as *mut $ty, val);
            }
            0
        }
    };
}

lua_mem_write!(lua_mem_write_u8, u8);
lua_mem_write!(lua_mem_write_u16, u16);
lua_mem_write!(lua_mem_write_u32, u32);
lua_mem_write!(lua_mem_write_u64, u64);

// ============================================================================
// Native hook API
// ============================================================================

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// native hook 注册表: target_addr → bytecode
static NATIVE_HOOK_REGISTRY: Mutex<Option<HashMap<u64, (Vec<u8>, bool)>>> = Mutex::new(None);

fn init_native_registry() {
    let mut reg = NATIVE_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if reg.is_none() {
        *reg = Some(HashMap::new());
    }
}

/// hook(addr, callback) — native function hook (replace mode)
unsafe extern "C" fn lua_native_hook(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let addr = lua_arg_addr(L, 1);
    if addr == 0 || !ffi::lua_isfunction_ex(L, 2) {
        ffi::luaL_error(L, c"hook(addr, callback): addr and function required".as_ptr());
        return 0;
    }

    // dump callback
    ffi::lua_pushvalue(L, 2);
    let mut bytecode: Vec<u8> = Vec::new();
    extern "C" fn writer(
        _L: *mut ffi::lua_State, p: *const std::ffi::c_void, sz: usize, ud: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int {
        let buf = unsafe { &mut *(ud as *mut Vec<u8>) };
        buf.extend_from_slice(unsafe { std::slice::from_raw_parts(p as *const u8, sz) });
        0
    }
    let ret = ffi::lua_dump(L, Some(writer), &mut bytecode as *mut _ as *mut _, 0);
    ffi::lua_pop(L, 1);
    if ret != 0 || bytecode.is_empty() {
        ffi::luaL_error(L, c"hook: failed to dump callback".as_ptr());
        return 0;
    }

    init_native_registry();
    {
        let mut reg = NATIVE_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(map) = reg.as_mut() {
            map.insert(addr, (bytecode, true));
        }
    }

    // 安装 hook (replace mode, stealth=0)
    use crate::ffi::hook as hook_ffi;
    let trampoline = hook_ffi::hook_replace(
        addr as *mut std::ffi::c_void,
        Some(native_lua_callback),
        addr as *mut std::ffi::c_void,
        0,
    );
    if trampoline.is_null() {
        let mut reg = NATIVE_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(map) = reg.as_mut() { map.remove(&addr); }
        ffi::luaL_error(L, c"hook: hook_replace failed".as_ptr());
        return 0;
    }

    crate::jsapi::console::output_message(&format!("[lua] native hook installed: {:#x}", addr));
    ffi::lua_pushboolean(L, 1);
    1
}

/// unhook(addr) — remove native hook
unsafe extern "C" fn lua_native_unhook(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let addr = lua_arg_addr(L, 1);
    if addr == 0 {
        ffi::lua_pushboolean(L, 0);
        return 1;
    }
    use crate::ffi::hook as hook_ffi;
    hook_ffi::hook_remove(addr as *mut std::ffi::c_void);
    let mut reg = NATIVE_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = reg.as_mut() { map.remove(&addr); }
    ffi::lua_pushboolean(L, 1);
    1
}

/// native hook 回调 — 从 hook engine thunk 调用，per-thread Lua 执行
unsafe extern "C" fn native_lua_callback(
    ctx_ptr: *mut crate::ffi::hook::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() { return; }
    let target_addr = user_data as u64;

    let entry = {
        let reg = NATIVE_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        reg.as_ref().and_then(|m| m.get(&target_addr).cloned())
    };
    let (bytecode, is_raw) = match entry {
        Some(e) => e,
        None => return,
    };

    let tls = match super::get_thread_lua_state() {
        Some(t) => t,
        None => return,
    };
    let func_ref = match super::ensure_hook_loaded(tls, target_addr, &bytecode, is_raw) {
        Ok(r) => r,
        Err(_) => return,
    };

    let L = tls.state.as_ptr();
    let ctx = &mut *ctx_ptr;

    // push callback
    ffi::lua_rawgeti(L, ffi::LUA_REGISTRYINDEX, func_ref as ffi::lua_Integer);

    // push ctx table: {x0..x30, sp, pc, lr, d0..d7, callOriginal}
    ffi::lua_createtable(L, 0, 8);

    // x0-x7 (常用寄存器)
    for i in 0..8u32 {
        ffi::lua_pushinteger(L, ctx.x[i as usize] as ffi::lua_Integer);
        let name = std::ffi::CString::new(format!("x{}", i)).unwrap();
        ffi::lua_setfield(L, -2, name.as_ptr());
    }
    ffi::lua_pushinteger(L, ctx.sp as ffi::lua_Integer);
    ffi::lua_setfield(L, -2, c"sp".as_ptr());
    ffi::lua_pushinteger(L, ctx.pc as ffi::lua_Integer);
    ffi::lua_setfield(L, -2, c"pc".as_ptr());
    ffi::lua_pushinteger(L, ctx.x[30] as ffi::lua_Integer);
    ffi::lua_setfield(L, -2, c"lr".as_ptr());

    // callOriginal()
    ffi::lua_pushlightuserdata(L, ctx_ptr as *mut std::ffi::c_void);
    ffi::lua_pushcclosure(L, Some(lua_call_original_native), 1);
    ffi::lua_setfield(L, -2, c"callOriginal".as_ptr());

    // callback(ctx)
    if ffi::lua_pcall(L, 1, 1, 0) != ffi::LUA_OK as i32 {
        let err = ffi::lua_tostring_ex(L, -1);
        if !err.is_null() {
            let e = std::ffi::CStr::from_ptr(err).to_string_lossy();
            crate::jsapi::console::output_message(&format!("[lua] native hook error: {}", e));
        }
        ffi::lua_pop(L, 1);
        return;
    }

    // 如果 callback 返回了值，写入 x0
    if !ffi::lua_isnil(L, -1) {
        ctx.x[0] = ffi::lua_tointeger_ex(L, -1) as u64;
    }
    ffi::lua_pop(L, 1);
}

/// ctx.callOriginal() — 调用被 hook 的原始函数
unsafe extern "C" fn lua_call_original_native(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let ctx_ptr = ffi::lua_touserdata(L, super::api::lua_upvalueindex(1))
        as *mut crate::ffi::hook::HookContext;
    if ctx_ptr.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let ctx = &*ctx_ptr;
    if ctx.trampoline.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    // 通过 trampoline 调用原始函数
    type TrampolineFn = unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64;
    let f: TrampolineFn = std::mem::transmute(ctx.trampoline);
    let ret = f(ctx.x[0], ctx.x[1], ctx.x[2], ctx.x[3], ctx.x[4], ctx.x[5], ctx.x[6], ctx.x[7]);
    ffi::lua_pushinteger(L, ret as ffi::lua_Integer);
    1
}

// ============================================================================
// Java API
// ============================================================================

unsafe extern "C" fn lua_java_hook(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 4 {
        ffi::luaL_error(L, c"Java.hook requires 4 args: class, method, sig, callback".as_ptr());
        return 0;
    }
    let class_c = ffi::lua_tostring_ex(L, 1);
    let method_c = ffi::lua_tostring_ex(L, 2);
    let sig_c = ffi::lua_tostring_ex(L, 3);
    if class_c.is_null() || method_c.is_null() || sig_c.is_null() {
        ffi::luaL_error(L, c"Java.hook: first 3 args must be strings".as_ptr());
        return 0;
    }
    let class_name = std::ffi::CStr::from_ptr(class_c).to_string_lossy().into_owned();
    let method_name = std::ffi::CStr::from_ptr(method_c).to_string_lossy().into_owned();
    let sig = std::ffi::CStr::from_ptr(sig_c).to_string_lossy().into_owned();
    if !ffi::lua_isfunction_ex(L, 4) {
        ffi::luaL_error(L, c"Java.hook: arg4 must be a function".as_ptr());
        return 0;
    }
    ffi::lua_pushvalue(L, 4);
    let mut bytecode: Vec<u8> = Vec::new();
    extern "C" fn writer(
        _L: *mut ffi::lua_State, p: *const std::ffi::c_void, sz: usize, ud: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int {
        let buf = unsafe { &mut *(ud as *mut Vec<u8>) };
        buf.extend_from_slice(unsafe { std::slice::from_raw_parts(p as *const u8, sz) });
        0
    }
    let ret = ffi::lua_dump(L, Some(writer), &mut bytecode as *mut _ as *mut _, 0);
    ffi::lua_pop(L, 1);
    if ret != 0 || bytecode.is_empty() {
        ffi::luaL_error(L, c"Java.hook: failed to dump callback".as_ptr());
        return 0;
    }
    use crate::jsapi::java::java_hook_api::lua_install::install_lua_hook_inner;
    match install_lua_hook_inner(&class_name, &method_name, &sig, bytecode, true) {
        Ok(()) => {
            crate::jsapi::console::output_message(&format!(
                "[lua] hook installed: {}.{}{}", class_name, method_name, sig
            ));
            ffi::lua_pushboolean(L, 1);
            1
        }
        Err(e) => {
            let cs = std::ffi::CString::new(format!("Java.hook failed: {}", e)).unwrap_or_default();
            ffi::luaL_error(L, cs.as_ptr());
            0
        }
    }
}

unsafe extern "C" fn lua_java_unhook(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 3 {
        ffi::luaL_error(L, c"Java.unhook requires 3 args".as_ptr());
        return 0;
    }
    let class_c = ffi::lua_tostring_ex(L, 1);
    let method_c = ffi::lua_tostring_ex(L, 2);
    let sig_c = ffi::lua_tostring_ex(L, 3);
    if class_c.is_null() || method_c.is_null() || sig_c.is_null() {
        ffi::luaL_error(L, c"Java.unhook: args must be strings".as_ptr());
        return 0;
    }
    let cn = std::ffi::CStr::from_ptr(class_c).to_string_lossy();
    let mn = std::ffi::CStr::from_ptr(method_c).to_string_lossy();
    let sig = std::ffi::CStr::from_ptr(sig_c).to_string_lossy();
    let js_cmd = format!(
        "Java.unhook(\"{}\",\"{}\",\"{}\")",
        cn.replace('"', "\\\""), mn.replace('"', "\\\""), sig.replace('"', "\\\""),
    );
    match crate::load_script(&js_cmd) {
        Ok(_) => { ffi::lua_pushboolean(L, 1); }
        Err(e) => {
            let cs = std::ffi::CString::new(format!("unhook failed: {}", e)).unwrap_or_default();
            ffi::luaL_error(L, cs.as_ptr());
        }
    }
    1
}

unsafe extern "C" fn lua_jstring(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let s = ffi::lua_tostring_ex(L, 1);
    if s.is_null() { ffi::lua_pushnil(L); return 1; }
    let env = super::api::get_current_env();
    if env.is_null() {
        match crate::jsapi::java::jni_core::get_thread_env() {
            Ok(e) => {
                let jstr = super::api::lua_string_to_jstring(L, 1, e);
                if jstr != 0 { ffi::lua_pushlightuserdata(L, jstr as *mut std::ffi::c_void); }
                else { ffi::lua_pushnil(L); }
            }
            Err(_) => ffi::lua_pushnil(L),
        }
    } else {
        let e = env as crate::jsapi::java::jni_core::JniEnv;
        let jstr = super::api::lua_string_to_jstring(L, 1, e);
        if jstr != 0 { ffi::lua_pushlightuserdata(L, jstr as *mut std::ffi::c_void); }
        else { ffi::lua_pushnil(L); }
    }
    1
}

pub fn cleanup_master_state() {
    let mut guard = MASTER_STATE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}
