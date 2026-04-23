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
        register_java_api(&state);
    }
    *guard = Some(state);
    Ok(())
}

/// 加载并执行 Lua 脚本
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

unsafe fn register_java_api(state: &LuaState) {
    let L = state.as_ptr();
    ffi::lua_createtable(L, 0, 1);
    ffi::lua_pushcfunction(L, Some(lua_java_hook));
    ffi::lua_setfield(L, -2, c"hook".as_ptr());
    ffi::lua_setglobal(L, c"Java".as_ptr());
}

/// Java.hook(class, method, sig, callback_fn)
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

    // dump callback function → 裸函数字节码
    ffi::lua_pushvalue(L, 4);
    let mut bytecode: Vec<u8> = Vec::new();
    extern "C" fn writer(
        _L: *mut ffi::lua_State,
        p: *const std::ffi::c_void,
        sz: usize,
        ud: *mut std::ffi::c_void,
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
                "[lua] hook installed: {}.{}{}",
                class_name, method_name, sig
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

pub fn cleanup_master_state() {
    let mut guard = MASTER_STATE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}
