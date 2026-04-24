use super::ffi;
use super::state::LuaState;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

const REF_KIND_NONE: u8 = 0;
const REF_KIND_JNI_LOCAL: u8 = 1;
const REF_KIND_RAW_MIRROR: u8 = 2;
static CALLBACK_LOG_MARK: AtomicU64 = AtomicU64::new(0);
static JNEW_DIAG_BITS: AtomicU64 = AtomicU64::new(0);
static SHARED_VALUES: OnceLock<RwLock<HashMap<String, SharedValue>>> = OnceLock::new();
static SHARED_COUNTERS: OnceLock<RwLock<HashMap<String, Arc<AtomicI64>>>> = OnceLock::new();
static JSTRING_GLOBAL_CACHE: OnceLock<RwLock<HashMap<Vec<u8>, usize>>> = OnceLock::new();
static ART_CARD_TABLE_OFFSET: AtomicUsize = AtomicUsize::new(0);
static QUICK_ENTRYPOINTS_OFFSET: AtomicUsize = AtomicUsize::new(0);
static STRING_CLASS_MIRROR: AtomicUsize = AtomicUsize::new(0);
const ART_CARD_TABLE_OFFSET_FAILED: usize = usize::MAX;
const QUICK_ENTRYPOINTS_OFFSET_FAILED: usize = usize::MAX;
const ART_CARD_DIRTY: u8 = 0x70;
const ART_CARD_SHIFT: u32 = 10;
const MIRROR_STRING_COUNT_OFFSET: u64 = 8;
const MIRROR_STRING_VALUE_OFFSET: u64 = 16;
const DEFAULT_FAST_STRING_MAX_CHARS: usize = 4096;
const JSTRING_GLOBAL_CACHE_MAX: usize = 1024;
const LUA_AUTO_ARRAY_MAX_LEN: usize = 65536;
const LUA_FAST_HELPERS: &str = r#"
local __raw_jcall = jcall
local __raw_jnew = jnew
local __raw_jget = jget
local __raw_jset = jset

function jmethod(handle)
    return function(...)
        return __raw_jcall(handle, ...)
    end
end

function jctor(handle)
    return function(...)
        return __raw_jnew(handle, ...)
    end
end

function jfield(handle)
    return {
        get = function(obj)
            return __raw_jget(handle, obj)
        end,
        set = function(obj, value)
            return __raw_jset(handle, obj, value)
        end
    }
end

function jobject(obj, bind)
    return setmetatable({ __jptr = obj, __bind = bind }, {
        __index = function(t, k)
            if k == "__jptr" then return obj end
            local b = bind and bind[k] or nil
            if type(b) == "function" then
                return function(_, ...)
                    return b(obj, ...)
                end
            end
            if type(b) == "table" and b.get then
                return b.get(obj)
            end
            return nil
        end,
        __newindex = function(t, k, v)
            local b = bind and bind[k] or nil
            if type(b) == "table" and b.set then
                return b.set(obj, v)
            end
            rawset(t, k, v)
        end
    })
end

jconstructor = jctor
jwrap = jobject
"#;

#[derive(Clone)]
enum SharedValue {
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Ptr(u64),
}

// 当前 callback 线程的 JNIEnv 和引用形态 (JNI local ref / quick raw mirror)。
std::thread_local! {
    static CURRENT_ENV: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CURRENT_REF_KIND: std::cell::Cell<u8> = const { std::cell::Cell::new(REF_KIND_NONE) };
    static CURRENT_LOCAL_REFS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static FAST_ORIG_REQUESTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static QUICK_ORIG_RESULT: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

pub(crate) fn set_current_env(env: *const std::ffi::c_void) {
    CURRENT_ENV.with(|c| c.set(env as usize));
    CURRENT_REF_KIND.with(|c| {
        c.set(if env.is_null() {
            REF_KIND_NONE
        } else {
            REF_KIND_JNI_LOCAL
        })
    });
}

pub(crate) fn set_current_raw_mirror_env(env: *const std::ffi::c_void) {
    CURRENT_ENV.with(|c| c.set(env as usize));
    CURRENT_REF_KIND.with(|c| {
        c.set(if env.is_null() {
            REF_KIND_NONE
        } else {
            REF_KIND_RAW_MIRROR
        })
    });
}

pub(crate) fn clear_current_env() {
    CURRENT_ENV.with(|c| c.set(0));
    CURRENT_REF_KIND.with(|c| c.set(REF_KIND_NONE));
    CURRENT_LOCAL_REFS.with(|c| c.set(0));
}

pub(crate) fn get_current_env() -> *const std::ffi::c_void {
    CURRENT_ENV.with(|c| c.get() as *const std::ffi::c_void)
}

pub(crate) fn set_current_local_refs(local_refs: *mut Vec<*mut std::ffi::c_void>) {
    CURRENT_LOCAL_REFS.with(|c| c.set(local_refs as usize));
}

unsafe fn push_current_local_ref(local_ref: *mut std::ffi::c_void) -> bool {
    if local_ref.is_null() {
        return false;
    }
    CURRENT_LOCAL_REFS.with(|c| {
        let ptr = c.get() as *mut Vec<*mut std::ffi::c_void>;
        if ptr.is_null() {
            false
        } else {
            (*ptr).push(local_ref);
            true
        }
    })
}

fn jnew_diag_once(bit: u64, msg: &str) {
    let mask = 1u64 << bit;
    if JNEW_DIAG_BITS.fetch_or(mask, Ordering::AcqRel) & mask == 0 {
        crate::jsapi::console::output_message(msg);
    }
}

fn get_current_ref_context() -> (*const std::ffi::c_void, u8) {
    let env = CURRENT_ENV.with(|c| c.get() as *const std::ffi::c_void);
    let kind = CURRENT_REF_KIND.with(|c| c.get());
    (env, kind)
}

pub(crate) fn clear_fast_orig_requested() {
    FAST_ORIG_REQUESTED.with(|c| c.set(false));
}

pub(crate) fn mark_fast_orig_requested() {
    FAST_ORIG_REQUESTED.with(|c| c.set(true));
}

pub(crate) fn take_fast_orig_requested() -> bool {
    FAST_ORIG_REQUESTED.with(|c| {
        let v = c.get();
        c.set(false);
        v
    })
}

pub(crate) fn clear_quick_orig_result() {
    QUICK_ORIG_RESULT.with(|c| c.set(None));
}

pub(crate) fn set_quick_orig_result(raw: u64) {
    QUICK_ORIG_RESULT.with(|c| c.set(Some(raw)));
}

pub(crate) fn take_quick_orig_result() -> Option<u64> {
    QUICK_ORIG_RESULT.with(|c| {
        let v = c.get();
        c.set(None);
        v
    })
}

pub(crate) unsafe fn register_lua_apis(state: &LuaState) {
    state.register_fn("print", Some(lua_print));
    state.register_fn("jcall", Some(lua_jcall));
    state.register_fn("jnew", Some(lua_jnew));
    state.register_fn("$new", Some(lua_jnew));
    state.register_fn("jget", Some(lua_jget));
    state.register_fn("jset", Some(lua_jset));
    state.register_fn("jstr", Some(lua_jstr));
    state.register_fn("jstr_fast", Some(lua_jstr_fast));
    state.register_fn("shared_get", Some(lua_shared_get));
    state.register_fn("shared_set", Some(lua_shared_set));
    state.register_fn("shared_add", Some(lua_shared_add));
    state.register_fn("shared_inc", Some(lua_shared_inc));
    state.register_fn("shared_del", Some(lua_shared_del));
    state.register_fn("callback_count", Some(lua_callback_count));
    state.register_fn("callback_log_mark", Some(lua_callback_log_mark));
    if let Err(err) = state.dostring(LUA_FAST_HELPERS) {
        crate::jsapi::console::output_message(&format!("[lua] failed to install fast helpers: {}", err));
    }
}

pub(crate) fn reset_callback_log_mark() {
    CALLBACK_LOG_MARK.store(0, Ordering::Release);
}

#[inline]
pub(crate) fn lua_upvalueindex(i: i32) -> i32 {
    ffi::LUA_REGISTRYINDEX - i
}

/// Lua print() → console callback
unsafe extern "C" fn lua_print(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let n = ffi::lua_gettop(L);
    let mut parts = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let tp = ffi::lua_type(L, i);
        if tp == ffi::LUA_TSTRING as i32 {
            let s = ffi::lua_tostring_ex(L, i);
            if !s.is_null() {
                parts.push(std::ffi::CStr::from_ptr(s).to_string_lossy().into_owned());
            } else {
                parts.push("nil".to_string());
            }
        } else if tp == ffi::LUA_TLIGHTUSERDATA as i32 {
            // Keep print() side-effect free in hook callbacks. Use jstr_fast()
            // for known java.lang.String values, or jstr() for the slow fallback.
            let ptr = ffi::lua_touserdata(L, i) as u64;
            parts.push(format!("0x{:x}", ptr));
        } else {
            match tp as u32 {
                ffi::LUA_TNIL => parts.push("nil".to_string()),
                ffi::LUA_TBOOLEAN => {
                    let b = ffi::lua_toboolean(L, i);
                    parts.push(if b != 0 { "true" } else { "false" }.to_string());
                }
                ffi::LUA_TNUMBER => {
                    if ffi::lua_isinteger(L, i) != 0 {
                        let n = ffi::lua_tointeger_ex(L, i);
                        parts.push(format!("{}", n));
                    } else {
                        let n = ffi::lua_tonumber_ex(L, i);
                        parts.push(format!("{}", n));
                    }
                }
                _ => parts.push(format!("<{}>", lua_typename_str(tp))),
            }
        }
    }
    let msg = parts.join("\t");
    crate::jsapi::console::output_message(&msg);
    0
}

unsafe fn lua_typename_str(tp: i32) -> &'static str {
    match tp as u32 {
        ffi::LUA_TNIL => "nil",
        ffi::LUA_TBOOLEAN => "boolean",
        ffi::LUA_TNUMBER => "number",
        ffi::LUA_TSTRING => "string",
        ffi::LUA_TTABLE => "table",
        ffi::LUA_TFUNCTION => "function",
        ffi::LUA_TUSERDATA => "userdata",
        ffi::LUA_TLIGHTUSERDATA => "lightuserdata",
        ffi::LUA_TTHREAD => "thread",
        _ => "unknown",
    }
}

/// jstr_fast(obj[, maxChars]) — decode a known java.lang.String by reading ART mirror memory.
/// This avoids JNI and Object.toString(); callers must only pass real String objects.
unsafe extern "C" fn lua_jstr_fast(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 1 || ffi::lua_type(L, 1) != ffi::LUA_TLIGHTUSERDATA as i32 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let ptr = ffi::lua_touserdata(L, 1) as u64;
    let max_chars = if ffi::lua_gettop(L) >= 2 && ffi::lua_type(L, 2) == ffi::LUA_TNUMBER as i32 {
        (ffi::lua_tointeger_ex(L, 2).max(1) as usize).min(1 << 20)
    } else {
        DEFAULT_FAST_STRING_MAX_CHARS
    };
    match fast_read_java_string_unchecked(ptr, max_chars) {
        Some(s) => {
            let cs = std::ffi::CString::new(s).unwrap_or_default();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        None => ffi::lua_pushnil(L),
    }
    1
}

/// jstr(obj) — slow general conversion. Fast-decodes java.lang.String first,
/// otherwise falls back to JNI Object.toString().
unsafe extern "C" fn lua_jstr(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 1 || ffi::lua_type(L, 1) != ffi::LUA_TLIGHTUSERDATA as i32 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let ptr = ffi::lua_touserdata(L, 1) as u64;
    if ptr == 0 {
        ffi::lua_pushstring(L, c"null".as_ptr());
        return 1;
    }
    if let Some(s) = fast_read_java_string_checked(ptr, DEFAULT_FAST_STRING_MAX_CHARS) {
        let cs = std::ffi::CString::new(s).unwrap_or_default();
        ffi::lua_pushstring(L, cs.as_ptr());
        return 1;
    }
    let (env, ref_kind) = get_current_ref_context();
    if env.is_null() || ref_kind == REF_KIND_NONE {
        ffi::lua_pushnil(L);
        return 1;
    }
    let result = match local_ref_from_lua_obj(env, ptr, ref_kind) {
        Some((local, delete_local)) => {
            let result = jni_tostring(local as u64, env);
            if delete_local {
                delete_local_ref(env, local);
            }
            result
        }
        None => None,
    };
    match result {
        Some(s) => {
            let cs = std::ffi::CString::new(s).unwrap_or_default();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        None => ffi::lua_pushnil(L),
    }
    1
}

unsafe fn fast_read_java_string_checked(obj: u64, max_chars: usize) -> Option<String> {
    if obj == 0 {
        return Some("null".to_string());
    }
    if !is_java_string_object(obj) {
        return None;
    }
    fast_read_java_string_unchecked(obj, max_chars)
}

unsafe fn fast_read_java_string_unchecked(obj: u64, max_chars: usize) -> Option<String> {
    if obj == 0 {
        return Some("null".to_string());
    }
    let count = std::ptr::read_unaligned((obj + MIRROR_STRING_COUNT_OFFSET) as *const i32);
    let length = ((count as u32) >> 1) as usize;
    if length > max_chars {
        return None;
    }
    let value_addr = obj.checked_add(MIRROR_STRING_VALUE_OFFSET)?;
    if (count as u32 & 1) == 0 {
        let bytes = std::slice::from_raw_parts(value_addr as *const u8, length);
        if bytes.iter().all(|&b| b < 0x80) {
            Some(String::from_utf8_lossy(bytes).into_owned())
        } else {
            Some(
                bytes
                    .iter()
                    .map(|&b| char::from_u32(b as u32).unwrap_or('\u{fffd}'))
                    .collect(),
            )
        }
    } else {
        let chars = std::slice::from_raw_parts(value_addr as *const u16, length);
        Some(String::from_utf16_lossy(chars))
    }
}

unsafe fn is_java_string_object(obj: u64) -> bool {
    let Some(string_class) = get_string_class_mirror() else {
        return false;
    };
    let class_ref = std::ptr::read_unaligned(obj as *const u32) as u64;
    class_ref == (string_class & 0xffff_ffff)
}

unsafe fn get_string_class_mirror() -> Option<u64> {
    let cached = STRING_CLASS_MIRROR.load(Ordering::Acquire) as u64;
    if cached != 0 {
        return Some(cached);
    }
    let env = get_current_env();
    if env.is_null() {
        return None;
    }
    let vtable = *(env as *const *const usize);
    type FindClassFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    let find_class: FindClassFn = std::mem::transmute(*vtable.add(6));
    let cls = find_class(env, c"java/lang/String".as_ptr());
    if cls.is_null() {
        let _ = jni_exception_check_and_clear(env);
        return None;
    }
    let mirror = crate::jsapi::java::decode_jobject_raw(env as crate::jsapi::java::jni_core::JniEnv, cls)?;
    delete_local_ref(env, cls);
    if mirror != 0 {
        STRING_CLASS_MIRROR.store(mirror as usize, Ordering::Release);
        Some(mirror)
    } else {
        None
    }
}

/// jcall(handle, receiver, ...) — direct ART quick-code call from a quick Lua callback.
///
/// Handles are created on the JS cold path with Java.luaFastMethod().
unsafe extern "C" fn lua_jcall(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 1 || ffi::lua_type(L, 1) != ffi::LUA_TNUMBER as i32 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let handle = ffi::lua_tointeger_ex(L, 1) as u64;
    let Some(method) = crate::jsapi::java::java_lua_fast_api::get_lua_fast_method(handle) else {
        ffi::lua_pushnil(L);
        return 1;
    };

    let mut receiver = 0u64;
    let mut first_arg = 2i32;
    if !method.is_static {
        if ffi::lua_gettop(L) < 2 || ffi::lua_type(L, 2) != ffi::LUA_TLIGHTUSERDATA as i32 {
            ffi::lua_pushnil(L);
            return 1;
        }
        receiver = ffi::lua_touserdata(L, 2) as u64;
        first_arg = 3;
    }

    if ffi::lua_gettop(L) < first_arg + method.param_types.len() as i32 - 1 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let mut args = Vec::with_capacity(method.param_types.len());
    let env = get_current_env() as crate::jsapi::java::jni_core::JniEnv;
    for (i, sig) in method.param_types.iter().enumerate() {
        args.push(lua_to_lua_fast_arg(L, first_arg + i as i32, sig.as_str(), env));
    }

    match crate::jsapi::java::java_lua_fast_api::invoke_lua_fast_method(&method, receiver, &args) {
        Ok(raw) => push_return_value(L, raw, method.return_type, std::ptr::null_mut()),
        Err(_) => ffi::lua_pushnil(L),
    }
    1
}

/// jnew(handle, ...) — allocate an object and call a pre-resolved constructor.
///
/// Handles are created on the JS cold path with Java.luaFastConstructor().
unsafe extern "C" fn lua_jnew(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 1 || ffi::lua_type(L, 1) != ffi::LUA_TNUMBER as i32 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let handle = ffi::lua_tointeger_ex(L, 1) as u64;
    let Some(ctor) = crate::jsapi::java::java_lua_fast_api::get_lua_fast_constructor(handle) else {
        ffi::lua_pushnil(L);
        return 1;
    };
    if ffi::lua_gettop(L) < ctor.param_types.len() as i32 + 1 {
        ffi::lua_pushnil(L);
        return 1;
    }

    let env = get_current_env() as crate::jsapi::java::jni_core::JniEnv;
    if env.is_null() {
        jnew_diag_once(0, "[lua jnew] current JNIEnv is null");
        ffi::lua_pushnil(L);
        return 1;
    }

    let allocation = if ctor.class_mirror != 0 {
        match alloc_object_quick(ctor.class_mirror) {
            Some(raw) => {
                jnew_diag_once(7, "[lua jnew] using ART quick allocation path");
                let local_obj = raw_mirror_to_local_ref(env as *const std::ffi::c_void, raw as *mut std::ffi::c_void);
                if local_obj.is_null() {
                    jnew_diag_once(8, "[lua jnew] quick allocation NewLocalRef failed");
                    ffi::lua_pushnil(L);
                    return 1;
                }
                Some((raw, local_obj))
            }
            None => alloc_object_jni_raw(env, ctor.class_global_ref as *mut std::ffi::c_void),
        }
    } else {
        alloc_object_jni_raw(env, ctor.class_global_ref as *mut std::ffi::c_void)
    };
    let Some((raw_obj, local_obj)) = allocation else {
        ffi::lua_pushnil(L);
        return 1;
    };
    if !(0x0100_0000..=0x0000_0080_0000_0000).contains(&raw_obj) {
        jnew_diag_once(6, "[lua jnew] decoded object pointer rejected by sanity check");
        if !local_obj.is_null() {
            delete_local_ref(env as *const std::ffi::c_void, local_obj);
        }
        ffi::lua_pushnil(L);
        return 1;
    }

    let mut args = Vec::with_capacity(ctor.param_types.len());
    for (i, sig) in ctor.param_types.iter().enumerate() {
        args.push(lua_to_lua_fast_arg(L, 2 + i as i32, sig.as_str(), env));
    }

    if let Err(msg) = crate::jsapi::java::java_lua_fast_api::invoke_lua_fast_constructor(&ctor, raw_obj, &args) {
        jnew_diag_once(3, &format!("[lua jnew] constructor call failed: {}", msg));
        if !local_obj.is_null() {
            delete_local_ref(env as *const std::ffi::c_void, local_obj);
        }
        ffi::lua_pushnil(L);
        return 1;
    }
    if !push_current_local_ref(local_obj) {
        jnew_diag_once(4, "[lua jnew] callback local-ref scope unavailable");
        delete_local_ref(env as *const std::ffi::c_void, local_obj);
        ffi::lua_pushnil(L);
        return 1;
    }
    ffi::lua_pushlightuserdata(L, raw_obj as *mut std::ffi::c_void);
    1
}

/// jget(fieldHandle, receiver) — direct primitive instance field read.
unsafe extern "C" fn lua_jget(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 2
        || ffi::lua_type(L, 1) != ffi::LUA_TNUMBER as i32
        || ffi::lua_type(L, 2) != ffi::LUA_TLIGHTUSERDATA as i32
    {
        ffi::lua_pushnil(L);
        return 1;
    }
    let handle = ffi::lua_tointeger_ex(L, 1) as u64;
    let Some(field) = crate::jsapi::java::java_lua_fast_api::get_lua_fast_field(handle) else {
        ffi::lua_pushnil(L);
        return 1;
    };
    if field.is_static || !is_fast_primitive_field_type(field.value_type) {
        ffi::lua_pushnil(L);
        return 1;
    }
    let receiver = ffi::lua_touserdata(L, 2) as u64;
    let Some(raw) = crate::lua::callback::with_current_quick_runnable(|_| {
        read_fast_instance_field(receiver, field.offset, field.value_type)
    }) else {
        ffi::lua_pushnil(L);
        return 1;
    };
    match raw {
        Some(v) => push_return_value(L, v, field.value_type, std::ptr::null_mut()),
        None => ffi::lua_pushnil(L),
    }
    1
}

/// jset(fieldHandle, receiver, value) — direct primitive instance field write.
unsafe extern "C" fn lua_jset(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    if ffi::lua_gettop(L) < 3
        || ffi::lua_type(L, 1) != ffi::LUA_TNUMBER as i32
        || ffi::lua_type(L, 2) != ffi::LUA_TLIGHTUSERDATA as i32
    {
        ffi::lua_pushboolean(L, 0);
        return 1;
    }
    let handle = ffi::lua_tointeger_ex(L, 1) as u64;
    let Some(field) = crate::jsapi::java::java_lua_fast_api::get_lua_fast_field(handle) else {
        ffi::lua_pushboolean(L, 0);
        return 1;
    };
    if field.is_static || !is_fast_primitive_field_type(field.value_type) {
        ffi::lua_pushboolean(L, 0);
        return 1;
    }
    let receiver = ffi::lua_touserdata(L, 2) as u64;
    let Some(raw) = lua_to_fast_field_value(L, 3, field.jni_sig.as_str()) else {
        ffi::lua_pushboolean(L, 0);
        return 1;
    };
    let ok = crate::lua::callback::with_current_quick_runnable(|thread| {
        write_fast_instance_field(thread as u64, receiver, field.offset, field.value_type, raw)
    })
    .flatten()
    .unwrap_or(false);
    ffi::lua_pushboolean(L, if ok { 1 } else { 0 });
    1
}

#[inline]
unsafe fn is_fast_primitive_field_type(value_type: u8) -> bool {
    matches!(
        value_type,
        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'['
    )
}

unsafe fn lua_to_fast_field_value(L: *mut ffi::lua_State, idx: i32, type_sig: &str) -> Option<u64> {
    let value_type = type_sig.as_bytes().first().copied().unwrap_or(b'L');
    if matches!(value_type, b'L' | b'[') {
        return Some(lua_to_jvalue(
            L,
            idx,
            Some(type_sig),
            get_current_env() as crate::jsapi::java::jni_core::JniEnv,
        ));
    }
    Some(lua_to_jvalue(
        L,
        idx,
        Some(std::str::from_utf8_unchecked(std::slice::from_ref(&value_type))),
        get_current_env() as crate::jsapi::java::jni_core::JniEnv,
    ))
}

unsafe fn read_fast_instance_field(obj: u64, offset: u32, value_type: u8) -> Option<u64> {
    if obj == 0 || offset == 0 {
        return None;
    }
    let addr = obj.checked_add(offset as u64)?;
    Some(match value_type {
        b'Z' => (std::ptr::read_volatile(addr as *const u8) != 0) as u64,
        b'B' => std::ptr::read_volatile(addr as *const i8) as u64,
        b'C' => std::ptr::read_volatile(addr as *const u16) as u64,
        b'S' => std::ptr::read_volatile(addr as *const i16) as u64,
        b'I' => std::ptr::read_volatile(addr as *const i32) as u64,
        b'J' => std::ptr::read_volatile(addr as *const i64) as u64,
        b'F' => std::ptr::read_volatile(addr as *const u32) as u64,
        b'D' => std::ptr::read_volatile(addr as *const u64),
        b'L' | b'[' => std::ptr::read_volatile(addr as *const u32) as u64,
        _ => return None,
    })
}

unsafe fn write_fast_instance_field(thread: u64, obj: u64, offset: u32, value_type: u8, raw: u64) -> Option<bool> {
    if obj == 0 || offset == 0 {
        return None;
    }
    let addr = obj.checked_add(offset as u64)?;
    match value_type {
        b'Z' => std::ptr::write_volatile(addr as *mut u8, if raw != 0 { 1 } else { 0 }),
        b'B' => std::ptr::write_volatile(addr as *mut i8, raw as i8),
        b'C' => std::ptr::write_volatile(addr as *mut u16, raw as u16),
        b'S' => std::ptr::write_volatile(addr as *mut i16, raw as i16),
        b'I' => std::ptr::write_volatile(addr as *mut i32, raw as i32),
        b'J' => std::ptr::write_volatile(addr as *mut i64, raw as i64),
        b'F' => std::ptr::write_volatile(addr as *mut u32, raw as u32),
        b'D' => std::ptr::write_volatile(addr as *mut u64, raw),
        b'L' | b'[' => {
            std::ptr::write_volatile(addr as *mut u32, raw as u32);
            if raw != 0 {
                mark_art_card(thread, obj)?;
            }
        }
        _ => return None,
    }
    Some(true)
}

unsafe fn mark_art_card(thread: u64, holder: u64) -> Option<()> {
    let offset = get_art_card_table_offset(thread)?;
    let card_table = std::ptr::read_volatile((thread as usize + offset) as *const u64);
    if card_table == 0 {
        return None;
    }
    let card = card_table.checked_add(holder >> ART_CARD_SHIFT)?;
    std::ptr::write_volatile(card as *mut u8, ART_CARD_DIRTY);
    Some(())
}

unsafe fn get_art_card_table_offset(thread: u64) -> Option<usize> {
    let cached = ART_CARD_TABLE_OFFSET.load(Ordering::Acquire);
    if cached == ART_CARD_TABLE_OFFSET_FAILED {
        return None;
    }
    if cached != 0 {
        return Some(cached);
    }

    let env = get_current_env() as u64;
    if env == 0 || thread == 0 {
        ART_CARD_TABLE_OFFSET.store(ART_CARD_TABLE_OFFSET_FAILED, Ordering::Release);
        return None;
    }
    let env_stripped = env & crate::jsapi::java::PAC_STRIP_MASK;
    for off in (144usize..384usize).step_by(8) {
        let v = std::ptr::read_volatile((thread as usize + off) as *const u64);
        if (v & crate::jsapi::java::PAC_STRIP_MASK) == env_stripped {
            let card_off = off.checked_sub(7 * 8)?;
            ART_CARD_TABLE_OFFSET.store(card_off, Ordering::Release);
            return Some(card_off);
        }
    }

    // Modern Android arm64 places tlsPtr_.card_table at Thread+0x90. Keep this
    // fallback for quick callbacks where the current env is unavailable.
    ART_CARD_TABLE_OFFSET.store(0x90, Ordering::Release);
    Some(0x90)
}

unsafe extern "C" fn lua_shared_get(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let Some(key) = lua_string_arg(L, 1) else {
        ffi::lua_pushnil(L);
        return 1;
    };
    if let Some(counter) = shared_counters()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
    {
        ffi::lua_pushinteger(L, counter.load(Ordering::Acquire) as ffi::lua_Integer);
        return 1;
    }
    let value = shared_values()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned();
    match value {
        Some(v) => push_shared_value(L, v),
        None => ffi::lua_pushnil(L),
    }
    1
}

unsafe extern "C" fn lua_shared_set(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let Some(key) = lua_string_arg(L, 1) else {
        ffi::lua_pushboolean(L, 0);
        return 1;
    };
    if ffi::lua_isnil(L, 2) {
        shared_values().write().unwrap_or_else(|e| e.into_inner()).remove(&key);
        shared_counters()
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
        ffi::lua_pushboolean(L, 1);
        return 1;
    }
    let Some(value) = lua_to_shared_value(L, 2) else {
        ffi::lua_pushboolean(L, 0);
        return 1;
    };
    if let SharedValue::Int(v) = value {
        if let Some(counter) = shared_counters()
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned()
        {
            counter.store(v, Ordering::Release);
            ffi::lua_pushboolean(L, 1);
            return 1;
        }
        shared_values()
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, SharedValue::Int(v));
    } else {
        shared_counters()
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
        shared_values()
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, value);
    }
    ffi::lua_pushboolean(L, 1);
    1
}

unsafe extern "C" fn lua_shared_inc(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    lua_shared_add_inner(L, 1)
}

unsafe extern "C" fn lua_shared_add(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let delta = if ffi::lua_gettop(L) >= 2 && ffi::lua_type(L, 2) == ffi::LUA_TNUMBER as i32 {
        ffi::lua_tointeger_ex(L, 2) as i64
    } else {
        1
    };
    lua_shared_add_inner(L, delta)
}

unsafe fn lua_shared_add_inner(L: *mut ffi::lua_State, delta: i64) -> std::os::raw::c_int {
    let Some(key) = lua_string_arg(L, 1) else {
        ffi::lua_pushnil(L);
        return 1;
    };
    let counter = get_or_create_shared_counter(&key);
    let new_value = counter.fetch_add(delta, Ordering::AcqRel).wrapping_add(delta);
    ffi::lua_pushinteger(L, new_value as ffi::lua_Integer);
    1
}

unsafe extern "C" fn lua_shared_del(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let Some(key) = lua_string_arg(L, 1) else {
        ffi::lua_pushboolean(L, 0);
        return 1;
    };
    shared_values().write().unwrap_or_else(|e| e.into_inner()).remove(&key);
    shared_counters()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&key);
    ffi::lua_pushboolean(L, 1);
    1
}

fn shared_values() -> &'static RwLock<HashMap<String, SharedValue>> {
    SHARED_VALUES.get_or_init(|| RwLock::new(HashMap::new()))
}

fn shared_counters() -> &'static RwLock<HashMap<String, Arc<AtomicI64>>> {
    SHARED_COUNTERS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn get_or_create_shared_counter(key: &str) -> Arc<AtomicI64> {
    if let Some(counter) = shared_counters()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(key)
        .cloned()
    {
        return counter;
    }
    let mut counters = shared_counters().write().unwrap_or_else(|e| e.into_inner());
    counters
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(AtomicI64::new(0)))
        .clone()
}

unsafe fn lua_string_arg(L: *mut ffi::lua_State, idx: i32) -> Option<String> {
    if ffi::lua_gettop(L) < idx || ffi::lua_type(L, idx) != ffi::LUA_TSTRING as i32 {
        return None;
    }
    let s = ffi::lua_tostring_ex(L, idx);
    if s.is_null() {
        return None;
    }
    Some(std::ffi::CStr::from_ptr(s).to_string_lossy().into_owned())
}

unsafe fn lua_to_shared_value(L: *mut ffi::lua_State, idx: i32) -> Option<SharedValue> {
    match ffi::lua_type(L, idx) as u32 {
        ffi::LUA_TBOOLEAN => Some(SharedValue::Bool(ffi::lua_toboolean(L, idx) != 0)),
        ffi::LUA_TNUMBER => {
            if ffi::lua_isinteger(L, idx) != 0 {
                Some(SharedValue::Int(ffi::lua_tointeger_ex(L, idx) as i64))
            } else {
                Some(SharedValue::Float(ffi::lua_tonumber_ex(L, idx) as f64))
            }
        }
        ffi::LUA_TSTRING => {
            let s = ffi::lua_tostring_ex(L, idx);
            if s.is_null() {
                None
            } else {
                Some(SharedValue::String(
                    std::ffi::CStr::from_ptr(s).to_string_lossy().into_owned(),
                ))
            }
        }
        ffi::LUA_TLIGHTUSERDATA => Some(SharedValue::Ptr(ffi::lua_touserdata(L, idx) as u64)),
        _ => None,
    }
}

unsafe fn push_shared_value(L: *mut ffi::lua_State, value: SharedValue) {
    match value {
        SharedValue::Bool(v) => ffi::lua_pushboolean(L, if v { 1 } else { 0 }),
        SharedValue::Int(v) => ffi::lua_pushinteger(L, v as ffi::lua_Integer),
        SharedValue::Float(v) => ffi::lua_pushnumber(L, v as ffi::lua_Number),
        SharedValue::String(v) => {
            let cs = std::ffi::CString::new(v).unwrap_or_default();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        SharedValue::Ptr(v) => ffi::lua_pushlightuserdata(L, v as *mut std::ffi::c_void),
    }
}

unsafe extern "C" fn lua_callback_count(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let (total, _, _, _, _, _, _, _) = super::callback_stats();
    ffi::lua_pushinteger(L, total as ffi::lua_Integer);
    1
}

unsafe extern "C" fn lua_callback_log_mark(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let step = if ffi::lua_gettop(L) >= 1 && ffi::lua_type(L, 1) == ffi::LUA_TNUMBER as i32 {
        ffi::lua_tointeger_ex(L, 1).max(1) as u64
    } else {
        10000
    };
    let (total, _, _, _, _, _, _, _) = super::callback_stats();
    let mark = (total / step) * step;
    if mark == 0 {
        ffi::lua_pushnil(L);
        return 1;
    }
    let mut prev = CALLBACK_LOG_MARK.load(Ordering::Acquire);
    while mark > prev {
        match CALLBACK_LOG_MARK.compare_exchange(prev, mark, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                ffi::lua_pushinteger(L, mark as ffi::lua_Integer);
                return 1;
            }
            Err(v) => prev = v,
        }
    }
    ffi::lua_pushnil(L);
    1
}

unsafe fn local_ref_from_lua_obj(
    env: *const std::ffi::c_void,
    obj: u64,
    ref_kind: u8,
) -> Option<(*mut std::ffi::c_void, bool)> {
    if obj == 0 || env.is_null() {
        return None;
    }
    match ref_kind {
        REF_KIND_JNI_LOCAL => {
            let local = new_jni_local_ref(env, obj as *mut std::ffi::c_void);
            if local.is_null() {
                None
            } else {
                Some((local, true))
            }
        }
        REF_KIND_RAW_MIRROR => {
            let local = raw_mirror_to_local_ref(env, obj as *mut std::ffi::c_void);
            if local.is_null() {
                None
            } else {
                Some((local, true))
            }
        }
        _ => None,
    }
}

unsafe fn new_jni_local_ref(env: *const std::ffi::c_void, obj: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    if env.is_null() || obj.is_null() {
        return std::ptr::null_mut();
    }
    let vtable = *(env as *const *const usize);
    type NewLocalRefFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    let new_local_ref: NewLocalRefFn = std::mem::transmute(*vtable.add(25));
    let local = new_local_ref(env, obj);
    if jni_exception_check_and_clear(env) {
        return std::ptr::null_mut();
    }
    local
}

unsafe fn raw_mirror_to_local_ref(env: *const std::ffi::c_void, raw: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    if env.is_null() || raw.is_null() {
        return std::ptr::null_mut();
    }

    type ArtNewLocalRefFn = unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    static ART_NEW_LOCAL_REF: OnceLock<Option<ArtNewLocalRefFn>> = OnceLock::new();

    let local = if let Some(add_ref) = *ART_NEW_LOCAL_REF.get_or_init(|| {
        let sym = crate::jsapi::module::libart_dlsym("_ZN3art9JNIEnvExt11NewLocalRefEPNS_6mirror6ObjectE");
        if sym.is_null() {
            None
        } else {
            Some(std::mem::transmute(sym))
        }
    }) {
        add_ref(env as *mut std::ffi::c_void, raw)
    } else {
        std::ptr::null_mut()
    };
    if jni_exception_check_and_clear(env) {
        return std::ptr::null_mut();
    }
    local
}

unsafe fn delete_local_ref(env: *const std::ffi::c_void, obj: *mut std::ffi::c_void) {
    if env.is_null() || obj.is_null() {
        return;
    }
    let vtable = *(env as *const *const usize);
    type DeleteLocalRefFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void);
    let del_local: DeleteLocalRefFn = std::mem::transmute(*vtable.add(23));
    del_local(env, obj);
}

unsafe fn alloc_object(env: *const std::ffi::c_void, cls: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
    if env.is_null() || cls.is_null() {
        return std::ptr::null_mut();
    }
    let vtable = *(env as *const *const usize);
    type AllocObjectFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    let alloc_object: AllocObjectFn = std::mem::transmute(*vtable.add(27));
    let obj = alloc_object(env, cls);
    if jni_exception_check_and_clear(env) {
        return std::ptr::null_mut();
    }
    obj
}

unsafe fn alloc_object_jni_raw(
    env: crate::jsapi::java::jni_core::JniEnv,
    cls: *mut std::ffi::c_void,
) -> Option<(u64, *mut std::ffi::c_void)> {
    let local_obj = alloc_object(env as *const std::ffi::c_void, cls);
    if local_obj.is_null() {
        jnew_diag_once(1, "[lua jnew] AllocObject failed");
        return None;
    }
    let Some(raw_obj) = crate::jsapi::java::decode_jobject_raw(env, local_obj)
        .or_else(|| decode_jni_local_ref_via_irt(env as *const std::ffi::c_void, local_obj))
    else {
        jnew_diag_once(
            2,
            &format!(
                "[lua jnew] DecodeJObject failed for AllocObject result local={:#x}",
                local_obj as usize
            ),
        );
        delete_local_ref(env as *const std::ffi::c_void, local_obj);
        return None;
    };
    Some((raw_obj, local_obj))
}

unsafe fn alloc_object_quick(class_mirror: u64) -> Option<u64> {
    if class_mirror == 0 {
        return None;
    }
    crate::lua::callback::with_current_quick_runnable(|thread| {
        let entry = quick_entrypoint(thread as usize, QUICK_ALLOC_OBJECT_INITIALIZED_INDEX)?;
        let raw = call_quick_alloc_object(entry as usize, thread as usize, class_mirror as usize) as u64;
        if raw == 0 {
            None
        } else {
            Some(raw)
        }
    })?
}

const QUICK_ENTRYPOINT_COUNT: usize = 174;
const QUICK_ALLOC_OBJECT_INITIALIZED_INDEX: usize = 6;
const QUICK_JNI_METHOD_START_INDEX: usize = 45;
const QUICK_JNI_METHOD_END_INDEX: usize = 46;
const QUICK_SCAN_LIMIT: usize = 16384;
const QUICK_MIN_LIBART_POINTERS: usize = 40;

unsafe fn quick_entrypoint(thread: usize, index: usize) -> Option<u64> {
    if thread == 0 || index >= QUICK_ENTRYPOINT_COUNT {
        return None;
    }
    let cached = QUICK_ENTRYPOINTS_OFFSET.load(Ordering::Acquire);
    if cached == QUICK_ENTRYPOINTS_OFFSET_FAILED {
        return None;
    }
    if cached != 0 {
        let off = cached - 1;
        let entry = std::ptr::read_volatile((thread + off + index * 8) as *const u64);
        return crate::jsapi::module::is_in_libart(entry).then_some(entry);
    }

    let max_off = QUICK_SCAN_LIMIT.saturating_sub(QUICK_ENTRYPOINT_COUNT * 8);
    for off in (0..=max_off).step_by(8) {
        let base = (thread + off) as *const u64;
        let start = std::ptr::read_volatile(base.add(QUICK_JNI_METHOD_START_INDEX));
        let end = std::ptr::read_volatile(base.add(QUICK_JNI_METHOD_END_INDEX));
        if !crate::jsapi::module::is_in_libart(start) || !crate::jsapi::module::is_in_libart(end) {
            continue;
        }
        if off < 16 {
            continue;
        }
        let prev0 = std::ptr::read_volatile((thread + off - 16) as *const u64);
        let prev1 = std::ptr::read_volatile((thread + off - 8) as *const u64);
        if !crate::jsapi::module::is_in_libart(prev0) || !crate::jsapi::module::is_in_libart(prev1) {
            continue;
        }

        let mut libart_ptrs = 0usize;
        for i in 0..QUICK_ENTRYPOINT_COUNT {
            if crate::jsapi::module::is_in_libart(std::ptr::read_volatile(base.add(i))) {
                libart_ptrs += 1;
            }
        }
        if libart_ptrs < QUICK_MIN_LIBART_POINTERS {
            continue;
        }

        QUICK_ENTRYPOINTS_OFFSET.store(off + 1, Ordering::Release);
        jnew_diag_once(
            9,
            &format!(
                "[lua jnew] quick entrypoints base Thread+0x{:x}, libart_ptrs={}",
                off, libart_ptrs
            ),
        );
        let entry = std::ptr::read_volatile(base.add(index));
        return crate::jsapi::module::is_in_libart(entry).then_some(entry);
    }

    QUICK_ENTRYPOINTS_OFFSET.store(QUICK_ENTRYPOINTS_OFFSET_FAILED, Ordering::Release);
    None
}

#[cfg(target_arch = "aarch64")]
unsafe fn call_quick_alloc_object(entry: usize, thread: usize, klass: usize) -> usize {
    let mut ret = klass;
    core::arch::asm!(
        "str x19, [sp, #-16]!",
        "mov x19, x10",
        "blr x11",
        "ldr x19, [sp], #16",
        in("x10") thread,
        in("x11") entry,
        inlateout("x0") ret,
        clobber_abi("C"),
    );
    ret
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn call_quick_alloc_object(entry: usize, _thread: usize, klass: usize) -> usize {
    let f: unsafe extern "C" fn(usize) -> usize = std::mem::transmute(entry);
    f(klass)
}

pub(crate) unsafe fn decode_jni_local_ref_via_irt(
    env: *const std::ffi::c_void,
    obj: *mut std::ffi::c_void,
) -> Option<u64> {
    if env.is_null() || obj.is_null() {
        return None;
    }
    let uref = obj as usize;
    if (uref & 0x3) != 1 {
        if (uref & 0x7) == 0 {
            return Some(uref as u64);
        }
        return None;
    }

    // Some modern ART builds use an IrtEntry pointer with the low kind bits
    // ORed in. IrtEntry is { u32 serial; u32 references[3] } on release ART.
    let slot = uref & !0x3;
    if slot > 0x10000 {
        let first = std::ptr::read_unaligned(slot as *const u32) as usize;
        if first < 3 {
            let raw = std::ptr::read_unaligned((slot + 4 + first * 4) as *const u32) as u64;
            if raw != 0 {
                return Some(raw);
            }
        } else {
            let raw = first as u64;
            if raw != 0 {
                return Some(raw);
            }
        }
    }

    // AOSP JNIEnvExt layout on 64-bit ART:
    // JNIEnv + self_ + vm_ + local_ref_cookie_ + padding + locals_.
    let locals_base = (env as usize).checked_add(32)?;

    // Android 10+ IRT encoding: serial in bits [2..4), index from bit 4.
    let modern_index = uref >> 4;
    let modern_serial = (uref >> 2) & 0x3;
    if let Some(raw) = decode_irt_entry(locals_base + 16, modern_index, modern_serial) {
        return Some(raw);
    }

    // Older ART encoding: index in bits [2..18), serial from bit 20.
    let old_index = (uref >> 2) & 0xffff;
    let old_serial = (uref >> 20) & 0x3;
    decode_irt_entry(locals_base + 8, old_index, old_serial)
}

unsafe fn decode_irt_entry(table_ptr_addr: usize, index: usize, serial: usize) -> Option<u64> {
    if index > 0x100000 || serial >= 3 {
        return None;
    }
    let table = std::ptr::read_unaligned(table_ptr_addr as *const usize);
    if table == 0 {
        return None;
    }
    let entry = table.checked_add(index.checked_mul(16)?)?;
    let entry_serial = std::ptr::read_unaligned(entry as *const u32) as usize;
    if entry_serial != serial {
        return None;
    }
    let raw = std::ptr::read_unaligned((entry + 4 + serial * 4) as *const u32) as u64;
    if raw == 0 {
        None
    } else {
        Some(raw)
    }
}

unsafe fn jni_exception_check_and_clear(env: *const std::ffi::c_void) -> bool {
    if env.is_null() {
        return false;
    }
    let vtable = *(env as *const *const usize);
    type ExceptionCheckFn = unsafe extern "C" fn(*const std::ffi::c_void) -> u8;
    type ExceptionClearFn = unsafe extern "C" fn(*const std::ffi::c_void);
    let exc_check: ExceptionCheckFn = std::mem::transmute(*vtable.add(228));
    let exc_clear: ExceptionClearFn = std::mem::transmute(*vtable.add(17));
    if exc_check(env) != 0 {
        exc_clear(env);
        true
    } else {
        false
    }
}

unsafe fn jni_tostring(obj: u64, env: *const std::ffi::c_void) -> Option<String> {
    if obj == 0 || env.is_null() {
        return None;
    }
    let vtable = *(env as *const *const usize);

    type IsInstanceOfFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void) -> u8;
    type FindClassFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    type GetStringUtfCharsFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *mut u8) -> *const std::os::raw::c_char;
    type ReleaseStringUtfCharsFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *const std::os::raw::c_char);

    let obj_ptr = obj as *mut std::ffi::c_void;
    let is_instance: IsInstanceOfFn = std::mem::transmute(*vtable.add(32));
    let find_class: FindClassFn = std::mem::transmute(*vtable.add(6));

    let string_class = find_class(env, c"java/lang/String".as_ptr());
    if string_class.is_null() {
        let _ = jni_exception_check_and_clear(env);
        return try_tostring_via_method(env, vtable, obj_ptr);
    }

    if is_instance(env, obj_ptr, string_class) != 0 {
        delete_local_ref(env, string_class);
        let get_str: GetStringUtfCharsFn = std::mem::transmute(*vtable.add(169));
        let rel_str: ReleaseStringUtfCharsFn = std::mem::transmute(*vtable.add(170));
        let chars = get_str(env, obj_ptr, std::ptr::null_mut());
        if chars.is_null() {
            let _ = jni_exception_check_and_clear(env);
            return None;
        }
        let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().into_owned();
        rel_str(env, obj_ptr, chars);
        return Some(s);
    }
    delete_local_ref(env, string_class);

    try_tostring_via_method(env, vtable, obj_ptr)
}

unsafe fn try_tostring_via_method(
    env: *const std::ffi::c_void,
    vtable: *const usize,
    obj_ptr: *mut std::ffi::c_void,
) -> Option<String> {
    type GetObjectClassFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    type GetMethodIdFn = unsafe extern "C" fn(
        *const std::ffi::c_void,
        *mut std::ffi::c_void,
        *const std::os::raw::c_char,
        *const std::os::raw::c_char,
    ) -> *mut std::ffi::c_void;
    type CallObjectMethodAFn = unsafe extern "C" fn(
        *const std::ffi::c_void,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
        *const std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    type GetStringUtfCharsFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *mut u8) -> *const std::os::raw::c_char;
    type ReleaseStringUtfCharsFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, *const std::os::raw::c_char);

    let get_obj_class: GetObjectClassFn = std::mem::transmute(*vtable.add(31));
    let get_method_id: GetMethodIdFn = std::mem::transmute(*vtable.add(33));
    let call_obj_method: CallObjectMethodAFn = std::mem::transmute(*vtable.add(36));
    let get_str: GetStringUtfCharsFn = std::mem::transmute(*vtable.add(169));
    let rel_str: ReleaseStringUtfCharsFn = std::mem::transmute(*vtable.add(170));

    let cls = get_obj_class(env, obj_ptr);
    if cls.is_null() {
        let _ = jni_exception_check_and_clear(env);
        return None;
    }

    let mid = get_method_id(env, cls, c"toString".as_ptr(), c"()Ljava/lang/String;".as_ptr());
    delete_local_ref(env, cls);
    if mid.is_null() {
        let _ = jni_exception_check_and_clear(env);
        return None;
    }

    let str_obj = call_obj_method(env, obj_ptr, mid, std::ptr::null());
    if str_obj.is_null() {
        let _ = jni_exception_check_and_clear(env);
        return None;
    }

    let chars = get_str(env, str_obj, std::ptr::null_mut());
    if chars.is_null() {
        delete_local_ref(env, str_obj);
        let _ = jni_exception_check_and_clear(env);
        return None;
    }

    let s = std::ffi::CStr::from_ptr(chars).to_string_lossy().into_owned();
    rel_str(env, str_obj, chars);
    delete_local_ref(env, str_obj);
    Some(s)
}

/// self:orig() — 原始参数调用原始方法
/// self:orig(a1, a2, ...) — 自定义参数调用原始方法
/// 注意: `:` 语法会把 self 作为第一个参数传入 (Lua stack index 1)
/// upvalue 1 = lightuserdata (CallbackContext*)
pub(crate) unsafe extern "C" fn lua_call_original(L: *mut ffi::lua_State) -> std::os::raw::c_int {
    let ctx_ptr = ffi::lua_touserdata(L, lua_upvalueindex(1));
    if ctx_ptr.is_null() {
        ffi::lua_pushnil(L);
        return 1;
    }
    let cb_ctx = &*(ctx_ptr as *const super::callback::CallbackContext);

    // stack: [self, arg1, arg2, ...]
    // self:orig() → nargs=1 (只有 self), 用原始参数
    // self:orig(a,b) → nargs=3 (self + 2 args), 用自定义参数
    let nargs = ffi::lua_gettop(L);
    let user_arg_count = nargs - 1; // 减去 self

    let (this_obj, jargs_ptr, jargs_buf) = if user_arg_count > 0 && user_arg_count as usize == cb_ctx.param_count {
        // 自定义参数: Lua → JNI jvalue 转换
        let mut jargs: Vec<u64> = Vec::with_capacity(cb_ctx.param_count);
        for i in 0..cb_ctx.param_count {
            let lua_idx = (i + 2) as i32; // stack index 2, 3, ...
            let type_sig = cb_ctx.param_types.get(i).map(|s| s.as_str());
            jargs.push(lua_to_jvalue(L, lua_idx, type_sig, cb_ctx.env));
        }
        (cb_ctx.this_obj, jargs.as_ptr() as *const std::ffi::c_void, Some(jargs))
    } else {
        // 原始参数: 对齐 JS $orig，调用瞬间从 HookContext 寄存器重建，
        // 避免在高频/GC 下使用进入 callback 时缓存的旧引用。
        let hook_ctx = if cb_ctx.hook_ctx_ptr.is_null() {
            std::ptr::null()
        } else {
            cb_ctx.hook_ctx_ptr as *const crate::ffi::hook::HookContext
        };
        if hook_ctx.is_null() {
            (cb_ctx.this_obj, cb_ctx.jargs_ptr, None)
        } else {
            let hook_ctx_ref = unsafe { &*hook_ctx };
            let jargs = crate::jsapi::java::callback::build_jargs_from_registers(
                hook_ctx_ref,
                cb_ctx.param_count,
                &cb_ctx.param_types,
            );
            let this_obj = if cb_ctx.is_static { 0 } else { hook_ctx_ref.x[1] };
            let jargs_ptr = if cb_ctx.param_count > 0 {
                jargs.as_ptr() as *const std::ffi::c_void
            } else {
                std::ptr::null()
            };
            (this_obj, jargs_ptr, Some(jargs))
        }
    };

    if cb_ctx.use_blr && cb_ctx.quick_trampoline != 0 {
        let thread_id = crate::current_thread_id_u64();
        let can_fast_orig = !cb_ctx.hook_ctx_ptr.is_null()
            && crate::jsapi::java::callback::prepare_fast_orig_router_frame(
                cb_ctx.env,
                &*(cb_ctx.hook_ctx_ptr as *const crate::ffi::hook::HookContext),
                cb_ctx.is_static,
                cb_ctx.param_count,
                &cb_ctx.param_types,
            );
        if can_fast_orig
            && unsafe { crate::ffi::hook::fast_orig_set(thread_id, cb_ctx.art_method, cb_ctx.quick_trampoline) } == 0
        {
            mark_fast_orig_requested();
            ffi::lua_pushnil(L);
            return 1;
        }
    }

    let ret = crate::jsapi::java::callback::invoke_original_jni(
        cb_ctx.env,
        cb_ctx.art_method,
        cb_ctx.class_global_ref,
        this_obj,
        cb_ctx.return_type,
        cb_ctx.is_static,
        jargs_ptr,
        cb_ctx.quick_trampoline,
        cb_ctx.use_blr,
    );

    // 保持 jargs_buf 存活到 invoke 完成
    drop(jargs_buf);

    push_return_value(L, ret, cb_ctx.return_type, cb_ctx.env);
    1
}

/// Lua 值 → JNI/quick jvalue (u64).
///
/// In normal JNI callback mode, object values stay as JNI refs. In quick Lua
/// callback mode, newly-created Java objects are decoded to raw mirror pointers
/// because ART quick code expects managed object pointers, not jobject handles.
pub(crate) unsafe fn lua_to_jvalue(
    L: *mut ffi::lua_State,
    idx: i32,
    type_sig: Option<&str>,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> u64 {
    if ffi::lua_isnil(L, idx) {
        return 0;
    }
    let sig = type_sig.unwrap_or("L");
    match sig.as_bytes()[0] {
        b'Z' => lua_to_bool(L, idx) as u64,
        b'B' => lua_to_integer(L, idx) as i8 as u64,
        b'C' => lua_to_char(L, idx) as u64,
        b'S' => lua_to_integer(L, idx) as i16 as u64,
        b'I' => lua_to_integer(L, idx) as i32 as u64,
        b'J' => lua_to_integer(L, idx) as u64,
        b'F' => (lua_to_number(L, idx) as f32).to_bits() as u64,
        b'D' => lua_to_number(L, idx).to_bits(),
        b'L' | b'[' => {
            let tp = ffi::lua_type(L, idx);
            if tp == ffi::LUA_TLIGHTUSERDATA as i32 {
                ffi::lua_touserdata(L, idx) as u64
            } else if sig.as_bytes()[0] == b'[' && tp == ffi::LUA_TTABLE as i32 && !env.is_null() {
                let local = lua_table_to_java_array_local(L, idx, sig, env);
                if local.is_null() {
                    return 0;
                }
                let _ = push_current_local_ref(local);
                let (_, ref_kind) = get_current_ref_context();
                if ref_kind == REF_KIND_RAW_MIRROR {
                    crate::jsapi::java::decode_jobject_raw(env, local)
                        .or_else(|| decode_jni_local_ref_via_irt(env as *const std::ffi::c_void, local))
                        .unwrap_or(0)
                } else {
                    local as u64
                }
            } else if tp == ffi::LUA_TSTRING as i32 && !env.is_null() {
                lua_string_to_object_jvalue(L, idx, env)
            } else if tp == ffi::LUA_TNUMBER as i32 {
                ffi::lua_tointeger_ex(L, idx) as u64
            } else if tp == ffi::LUA_TBOOLEAN as i32 {
                lua_to_bool(L, idx) as u64
            } else {
                0
            }
        }
        _ => ffi::lua_tointeger_ex(L, idx) as u64,
    }
}

unsafe fn lua_to_lua_fast_arg(
    L: *mut ffi::lua_State,
    idx: i32,
    type_sig: &str,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> crate::jsapi::java::java_lua_fast_api::LuaFastArg {
    let is_object = matches!(type_sig.as_bytes().first().copied(), Some(b'L' | b'['));
    if type_sig.as_bytes().first().copied() == Some(b'[')
        && ffi::lua_type(L, idx) == ffi::LUA_TTABLE as i32
        && !env.is_null()
    {
        let local = lua_table_to_java_array_local(L, idx, type_sig, env);
        if !local.is_null() {
            let _ = push_current_local_ref(local);
            return crate::jsapi::java::java_lua_fast_api::LuaFastArg::JniRef { env, object: local };
        }
    }
    if is_object && ffi::lua_type(L, idx) == ffi::LUA_TSTRING as i32 && !env.is_null() {
        let (_, ref_kind) = get_current_ref_context();
        if ref_kind == REF_KIND_RAW_MIRROR {
            if let Some(global) = lua_string_to_cached_jstring_global(L, idx, env) {
                return crate::jsapi::java::java_lua_fast_api::LuaFastArg::JniRef { env, object: global };
            } else {
                let local = lua_string_to_jstring_local(L, idx, env);
                if !local.is_null() {
                    let _ = push_current_local_ref(local);
                    return crate::jsapi::java::java_lua_fast_api::LuaFastArg::JniRef { env, object: local };
                }
            }
        }
    }

    crate::jsapi::java::java_lua_fast_api::LuaFastArg::Raw(lua_to_jvalue(L, idx, Some(type_sig), env))
}

unsafe fn lua_to_bool(L: *mut ffi::lua_State, idx: i32) -> bool {
    match ffi::lua_type(L, idx) as u32 {
        ffi::LUA_TBOOLEAN => ffi::lua_toboolean(L, idx) != 0,
        ffi::LUA_TNUMBER => ffi::lua_tointeger_ex(L, idx) != 0,
        ffi::LUA_TSTRING => {
            let s = ffi::lua_tostring_ex(L, idx);
            if s.is_null() {
                false
            } else {
                let v = std::ffi::CStr::from_ptr(s).to_string_lossy();
                v == "true" || v == "1"
            }
        }
        _ => false,
    }
}

unsafe fn lua_to_integer(L: *mut ffi::lua_State, idx: i32) -> i64 {
    match ffi::lua_type(L, idx) as u32 {
        ffi::LUA_TBOOLEAN => ffi::lua_toboolean(L, idx) as i64,
        ffi::LUA_TNUMBER | ffi::LUA_TSTRING => ffi::lua_tointeger_ex(L, idx) as i64,
        ffi::LUA_TLIGHTUSERDATA => ffi::lua_touserdata(L, idx) as i64,
        _ => 0,
    }
}

unsafe fn lua_to_number(L: *mut ffi::lua_State, idx: i32) -> f64 {
    match ffi::lua_type(L, idx) as u32 {
        ffi::LUA_TBOOLEAN => ffi::lua_toboolean(L, idx) as f64,
        ffi::LUA_TNUMBER | ffi::LUA_TSTRING => ffi::lua_tonumber_ex(L, idx),
        _ => 0.0,
    }
}

unsafe fn lua_to_char(L: *mut ffi::lua_State, idx: i32) -> u16 {
    if ffi::lua_type(L, idx) == ffi::LUA_TSTRING as i32 {
        let s = ffi::lua_tostring_ex(L, idx);
        if !s.is_null() {
            return std::ffi::CStr::from_ptr(s)
                .to_string_lossy()
                .chars()
                .next()
                .map(|c| c as u16)
                .unwrap_or(0);
        }
    }
    lua_to_integer(L, idx) as u16
}

unsafe fn lua_table_to_java_array_local(
    L: *mut ffi::lua_State,
    idx: i32,
    type_sig: &str,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> *mut std::ffi::c_void {
    if env.is_null() || !type_sig.starts_with('[') || ffi::lua_type(L, idx) != ffi::LUA_TTABLE as i32 {
        return std::ptr::null_mut();
    }
    let abs_idx = ffi::lua_absindex(L, idx);
    let len = ffi::lua_rawlen(L, abs_idx) as usize;
    if len > LUA_AUTO_ARRAY_MAX_LEN {
        return std::ptr::null_mut();
    }
    let component_sig = &type_sig[1..];
    match component_sig.as_bytes().first().copied() {
        Some(b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D') => {
            lua_table_to_primitive_array_local(L, abs_idx, component_sig.as_bytes()[0], len, env)
        }
        Some(b'L' | b'[') => lua_table_to_object_array_local(L, abs_idx, component_sig, len, env),
        _ => std::ptr::null_mut(),
    }
}

unsafe fn lua_table_to_primitive_array_local(
    L: *mut ffi::lua_State,
    table_idx: i32,
    component: u8,
    len: usize,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> *mut std::ffi::c_void {
    let vtable = *(env as *const *const usize);
    let jlen = len as i32;
    match component {
        b'Z' => {
            type NewArrayFn = unsafe extern "C" fn(*const std::ffi::c_void, i32) -> *mut std::ffi::c_void;
            type SetRegionFn =
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, i32, *const u8);
            let new_array: NewArrayFn = std::mem::transmute(*vtable.add(175));
            let set_region: SetRegionFn = std::mem::transmute(*vtable.add(207));
            let array = new_array(env as *const std::ffi::c_void, jlen);
            if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                return std::ptr::null_mut();
            }
            let values = lua_table_to_vec(L, table_idx, len, |L, i| lua_to_bool(L, i) as u8);
            set_region(env as *const std::ffi::c_void, array, 0, jlen, values.as_ptr());
            if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                delete_local_ref(env as *const std::ffi::c_void, array);
                return std::ptr::null_mut();
            }
            array
        }
        b'B' => {
            type NewArrayFn = unsafe extern "C" fn(*const std::ffi::c_void, i32) -> *mut std::ffi::c_void;
            type SetRegionFn =
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, i32, *const i8);
            let new_array: NewArrayFn = std::mem::transmute(*vtable.add(176));
            let set_region: SetRegionFn = std::mem::transmute(*vtable.add(208));
            let array = new_array(env as *const std::ffi::c_void, jlen);
            if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                return std::ptr::null_mut();
            }
            let values = lua_table_to_vec(L, table_idx, len, |L, i| lua_to_integer(L, i) as i8);
            set_region(env as *const std::ffi::c_void, array, 0, jlen, values.as_ptr());
            if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                delete_local_ref(env as *const std::ffi::c_void, array);
                return std::ptr::null_mut();
            }
            array
        }
        b'C' => {
            type NewArrayFn = unsafe extern "C" fn(*const std::ffi::c_void, i32) -> *mut std::ffi::c_void;
            type SetRegionFn =
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, i32, *const u16);
            let new_array: NewArrayFn = std::mem::transmute(*vtable.add(177));
            let set_region: SetRegionFn = std::mem::transmute(*vtable.add(209));
            let array = new_array(env as *const std::ffi::c_void, jlen);
            if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                return std::ptr::null_mut();
            }
            let values = lua_table_to_vec(L, table_idx, len, |L, i| lua_to_char(L, i));
            set_region(env as *const std::ffi::c_void, array, 0, jlen, values.as_ptr());
            if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                delete_local_ref(env as *const std::ffi::c_void, array);
                return std::ptr::null_mut();
            }
            array
        }
        b'S' => {
            type NewArrayFn = unsafe extern "C" fn(*const std::ffi::c_void, i32) -> *mut std::ffi::c_void;
            type SetRegionFn =
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, i32, *const i16);
            let new_array: NewArrayFn = std::mem::transmute(*vtable.add(178));
            let set_region: SetRegionFn = std::mem::transmute(*vtable.add(210));
            let array = new_array(env as *const std::ffi::c_void, jlen);
            if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                return std::ptr::null_mut();
            }
            let values = lua_table_to_vec(L, table_idx, len, |L, i| lua_to_integer(L, i) as i16);
            set_region(env as *const std::ffi::c_void, array, 0, jlen, values.as_ptr());
            if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                delete_local_ref(env as *const std::ffi::c_void, array);
                return std::ptr::null_mut();
            }
            array
        }
        b'I' => {
            type NewArrayFn = unsafe extern "C" fn(*const std::ffi::c_void, i32) -> *mut std::ffi::c_void;
            type SetRegionFn =
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, i32, *const i32);
            let new_array: NewArrayFn = std::mem::transmute(*vtable.add(179));
            let set_region: SetRegionFn = std::mem::transmute(*vtable.add(211));
            let array = new_array(env as *const std::ffi::c_void, jlen);
            if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                return std::ptr::null_mut();
            }
            let values = lua_table_to_vec(L, table_idx, len, |L, i| lua_to_integer(L, i) as i32);
            set_region(env as *const std::ffi::c_void, array, 0, jlen, values.as_ptr());
            if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                delete_local_ref(env as *const std::ffi::c_void, array);
                return std::ptr::null_mut();
            }
            array
        }
        b'J' => {
            type NewArrayFn = unsafe extern "C" fn(*const std::ffi::c_void, i32) -> *mut std::ffi::c_void;
            type SetRegionFn =
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, i32, *const i64);
            let new_array: NewArrayFn = std::mem::transmute(*vtable.add(180));
            let set_region: SetRegionFn = std::mem::transmute(*vtable.add(212));
            let array = new_array(env as *const std::ffi::c_void, jlen);
            if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                return std::ptr::null_mut();
            }
            let values = lua_table_to_vec(L, table_idx, len, |L, i| lua_to_integer(L, i) as i64);
            set_region(env as *const std::ffi::c_void, array, 0, jlen, values.as_ptr());
            if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                delete_local_ref(env as *const std::ffi::c_void, array);
                return std::ptr::null_mut();
            }
            array
        }
        b'F' => {
            type NewArrayFn = unsafe extern "C" fn(*const std::ffi::c_void, i32) -> *mut std::ffi::c_void;
            type SetRegionFn =
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, i32, *const f32);
            let new_array: NewArrayFn = std::mem::transmute(*vtable.add(181));
            let set_region: SetRegionFn = std::mem::transmute(*vtable.add(213));
            let array = new_array(env as *const std::ffi::c_void, jlen);
            if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                return std::ptr::null_mut();
            }
            let values = lua_table_to_vec(L, table_idx, len, |L, i| lua_to_number(L, i) as f32);
            set_region(env as *const std::ffi::c_void, array, 0, jlen, values.as_ptr());
            if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                delete_local_ref(env as *const std::ffi::c_void, array);
                return std::ptr::null_mut();
            }
            array
        }
        b'D' => {
            type NewArrayFn = unsafe extern "C" fn(*const std::ffi::c_void, i32) -> *mut std::ffi::c_void;
            type SetRegionFn =
                unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, i32, *const f64);
            let new_array: NewArrayFn = std::mem::transmute(*vtable.add(182));
            let set_region: SetRegionFn = std::mem::transmute(*vtable.add(214));
            let array = new_array(env as *const std::ffi::c_void, jlen);
            if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                return std::ptr::null_mut();
            }
            let values = lua_table_to_vec(L, table_idx, len, |L, i| lua_to_number(L, i) as f64);
            set_region(env as *const std::ffi::c_void, array, 0, jlen, values.as_ptr());
            if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
                delete_local_ref(env as *const std::ffi::c_void, array);
                return std::ptr::null_mut();
            }
            array
        }
        _ => std::ptr::null_mut(),
    }
}

unsafe fn lua_table_to_vec<T>(
    L: *mut ffi::lua_State,
    table_idx: i32,
    len: usize,
    mut convert: impl FnMut(*mut ffi::lua_State, i32) -> T,
) -> Vec<T> {
    let mut values = Vec::with_capacity(len);
    for i in 1..=len {
        ffi::lua_geti(L, table_idx, i as ffi::lua_Integer);
        values.push(convert(L, -1));
        ffi::lua_pop(L, 1);
    }
    values
}

unsafe fn lua_table_to_object_array_local(
    L: *mut ffi::lua_State,
    table_idx: i32,
    component_sig: &str,
    len: usize,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> *mut std::ffi::c_void {
    let component_class = find_array_component_class(env, component_sig);
    if component_class.is_null() {
        return std::ptr::null_mut();
    }
    let vtable = *(env as *const *const usize);
    type NewObjectArrayFn = unsafe extern "C" fn(
        *const std::ffi::c_void,
        i32,
        *mut std::ffi::c_void,
        *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    type SetObjectArrayElementFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void, i32, *mut std::ffi::c_void);
    let new_object_array: NewObjectArrayFn = std::mem::transmute(*vtable.add(172));
    let set_object_array_element: SetObjectArrayElementFn = std::mem::transmute(*vtable.add(174));
    let array = new_object_array(
        env as *const std::ffi::c_void,
        len as i32,
        component_class,
        std::ptr::null_mut(),
    );
    delete_local_ref(env as *const std::ffi::c_void, component_class);
    if array.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
        return std::ptr::null_mut();
    }

    for i in 1..=len {
        ffi::lua_geti(L, table_idx, i as ffi::lua_Integer);
        let elem = lua_value_to_object_array_element(L, -1, component_sig, env);
        ffi::lua_pop(L, 1);
        if elem.is_null() {
            continue;
        }
        set_object_array_element(env as *const std::ffi::c_void, array, (i - 1) as i32, elem);
        let had_exception = jni_exception_check_and_clear(env as *const std::ffi::c_void);
        delete_local_ref(env as *const std::ffi::c_void, elem);
        if had_exception {
            delete_local_ref(env as *const std::ffi::c_void, array);
            return std::ptr::null_mut();
        }
    }
    array
}

unsafe fn lua_value_to_object_array_element(
    L: *mut ffi::lua_State,
    idx: i32,
    component_sig: &str,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> *mut std::ffi::c_void {
    match ffi::lua_type(L, idx) as u32 {
        ffi::LUA_TNIL => std::ptr::null_mut(),
        ffi::LUA_TLIGHTUSERDATA => {
            let (_, ref_kind) = get_current_ref_context();
            local_ref_from_lua_obj(
                env as *const std::ffi::c_void,
                ffi::lua_touserdata(L, idx) as u64,
                ref_kind,
            )
            .map(|(local, _)| local)
            .unwrap_or(std::ptr::null_mut())
        }
        ffi::LUA_TSTRING if component_sig.starts_with('L') => lua_string_to_jstring_local(L, idx, env),
        ffi::LUA_TTABLE if component_sig.starts_with('[') => lua_table_to_java_array_local(L, idx, component_sig, env),
        _ => std::ptr::null_mut(),
    }
}

unsafe fn find_array_component_class(
    env: crate::jsapi::java::jni_core::JniEnv,
    component_sig: &str,
) -> *mut std::ffi::c_void {
    if env.is_null() {
        return std::ptr::null_mut();
    }
    let name = if component_sig.starts_with('[') {
        component_sig.to_string()
    } else if component_sig.starts_with('L') && component_sig.ends_with(';') {
        component_sig[1..component_sig.len() - 1].to_string()
    } else {
        return std::ptr::null_mut();
    };
    let Ok(cs) = std::ffi::CString::new(name) else {
        return std::ptr::null_mut();
    };
    let vtable = *(env as *const *const usize);
    type FindClassFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    let find_class: FindClassFn = std::mem::transmute(*vtable.add(6));
    let cls = find_class(env as *const std::ffi::c_void, cs.as_ptr());
    if cls.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
        std::ptr::null_mut()
    } else {
        cls
    }
}

unsafe fn lua_string_to_object_jvalue(
    L: *mut ffi::lua_State,
    idx: i32,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> u64 {
    let local = lua_string_to_jstring_local(L, idx, env);
    if local.is_null() {
        return 0;
    }
    let _ = push_current_local_ref(local);

    let (_, ref_kind) = get_current_ref_context();
    if ref_kind == REF_KIND_RAW_MIRROR {
        crate::jsapi::java::decode_jobject_raw(env, local)
            .or_else(|| decode_jni_local_ref_via_irt(env as *const std::ffi::c_void, local))
            .unwrap_or(0)
    } else {
        local as u64
    }
}

/// Lua string → Java String (NewStringUTF)
pub(crate) unsafe fn lua_string_to_jstring(
    L: *mut ffi::lua_State,
    idx: i32,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> u64 {
    lua_string_to_jstring_local(L, idx, env) as u64
}

unsafe fn lua_string_to_jstring_local(
    L: *mut ffi::lua_State,
    idx: i32,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> *mut std::ffi::c_void {
    let s = ffi::lua_tostring_ex(L, idx);
    if s.is_null() || env.is_null() {
        return std::ptr::null_mut();
    }
    let vtable = *(env as *const *const usize);
    type NewStringUtfFn =
        unsafe extern "C" fn(*const std::ffi::c_void, *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    let new_string: NewStringUtfFn = std::mem::transmute(*vtable.add(167));
    let local = new_string(env as *const std::ffi::c_void, s);
    if jni_exception_check_and_clear(env as *const std::ffi::c_void) {
        return std::ptr::null_mut();
    }
    local
}

unsafe fn lua_string_to_cached_jstring_global(
    L: *mut ffi::lua_State,
    idx: i32,
    env: crate::jsapi::java::jni_core::JniEnv,
) -> Option<*mut std::ffi::c_void> {
    let s = ffi::lua_tostring_ex(L, idx);
    if s.is_null() || env.is_null() {
        return None;
    }
    let key = std::ffi::CStr::from_ptr(s).to_bytes().to_vec();
    let cache = JSTRING_GLOBAL_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Some(cached) = cache.read().ok()?.get(&key).copied() {
        return Some(cached as *mut std::ffi::c_void);
    }

    let mut guard = cache.write().ok()?;
    if let Some(cached) = guard.get(&key).copied() {
        return Some(cached as *mut std::ffi::c_void);
    }
    if guard.len() >= JSTRING_GLOBAL_CACHE_MAX {
        return None;
    }

    let local = lua_string_to_jstring_local(L, idx, env);
    if local.is_null() {
        return None;
    }
    let vtable = *(env as *const *const usize);
    type NewGlobalRefFn = unsafe extern "C" fn(*const std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    let new_global_ref: NewGlobalRefFn = std::mem::transmute(*vtable.add(21));
    let global = new_global_ref(env as *const std::ffi::c_void, local);
    delete_local_ref(env as *const std::ffi::c_void, local);
    if global.is_null() || jni_exception_check_and_clear(env as *const std::ffi::c_void) {
        return None;
    }
    guard.insert(key, global as usize);
    Some(global)
}

unsafe fn push_return_value(
    L: *mut ffi::lua_State,
    raw: u64,
    return_type: u8,
    env: crate::jsapi::java::jni_core::JniEnv,
) {
    match return_type {
        b'V' => ffi::lua_pushnil(L),
        b'Z' => ffi::lua_pushboolean(L, if raw != 0 { 1 } else { 0 }),
        b'B' => ffi::lua_pushinteger(L, raw as i8 as ffi::lua_Integer),
        b'C' => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            let cs = std::ffi::CString::new(s).unwrap();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        b'S' => ffi::lua_pushinteger(L, raw as i16 as ffi::lua_Integer),
        b'I' => ffi::lua_pushinteger(L, raw as i32 as ffi::lua_Integer),
        b'J' => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
        b'F' => ffi::lua_pushnumber(L, f32::from_bits(raw as u32) as ffi::lua_Number),
        b'D' => ffi::lua_pushnumber(L, f64::from_bits(raw) as ffi::lua_Number),
        b'L' | b'[' => {
            if raw == 0 {
                ffi::lua_pushnil(L);
            } else {
                ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
            }
        }
        _ => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
    }
}

/// 将 JNI 参数推入 Lua 栈 (根据类型签名)
/// - String → Lua string (via GetStringUTFChars)
/// - Object (Ljava/lang/Object;) → 自动 toString, 失败则 lightuserdata
/// - 其他对象 → lightuserdata
pub(crate) unsafe fn push_jni_arg(
    L: *mut ffi::lua_State,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
    env: *const std::ffi::c_void,
) {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => {
            ffi::lua_pushinteger(L, raw as ffi::lua_Integer);
            return;
        }
    };
    match sig.as_bytes()[0] {
        b'Z' => ffi::lua_pushboolean(L, if raw != 0 { 1 } else { 0 }),
        b'B' => ffi::lua_pushinteger(L, raw as i8 as ffi::lua_Integer),
        b'C' => {
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            let cs = std::ffi::CString::new(s).unwrap();
            ffi::lua_pushstring(L, cs.as_ptr());
        }
        b'S' => ffi::lua_pushinteger(L, raw as i16 as ffi::lua_Integer),
        b'I' => ffi::lua_pushinteger(L, raw as i32 as ffi::lua_Integer),
        b'J' => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
        b'F' => {
            let f = f32::from_bits(fp_raw as u32);
            ffi::lua_pushnumber(L, f as f64);
        }
        b'D' => {
            let d = f64::from_bits(fp_raw);
            ffi::lua_pushnumber(L, d);
        }
        b'L' | b'[' => {
            if raw == 0 {
                ffi::lua_pushnil(L);
            } else {
                ffi::lua_pushlightuserdata(L, raw as *mut std::ffi::c_void);
            }
        }
        _ => ffi::lua_pushinteger(L, raw as ffi::lua_Integer),
    }
}
