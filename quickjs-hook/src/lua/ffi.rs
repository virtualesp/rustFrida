#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]

mod bindings {
    #![allow(
        non_upper_case_globals,
        non_camel_case_types,
        non_snake_case,
        dead_code,
        unused_imports
    )]
    include!(concat!(env!("OUT_DIR"), "/lua_bindings.rs"));
}

pub use bindings::*;

#[inline]
pub unsafe fn lua_pop(L: *mut lua_State, n: i32) {
    lua_settop(L, -(n) - 1);
}

#[inline]
pub unsafe fn lua_newtable(L: *mut lua_State) {
    lua_createtable(L, 0, 0);
}

#[inline]
pub unsafe fn lua_pushcfunction(L: *mut lua_State, f: lua_CFunction) {
    lua_pushcclosure(L, f, 0);
}

#[inline]
pub unsafe fn lua_pcall(L: *mut lua_State, nargs: i32, nresults: i32, msgh: i32) -> i32 {
    lua_pcallk(L, nargs, nresults, msgh, 0, None)
}

#[inline]
pub unsafe fn lua_isnil(L: *mut lua_State, idx: i32) -> bool {
    lua_type(L, idx) == LUA_TNIL as i32
}

#[inline]
pub unsafe fn lua_isnil_or_none(L: *mut lua_State, idx: i32) -> bool {
    let t = lua_type(L, idx);
    t == LUA_TNIL as i32 || t == LUA_TNONE as i32
}

#[inline]
pub unsafe fn lua_isboolean_ex(L: *mut lua_State, idx: i32) -> bool {
    lua_type(L, idx) == LUA_TBOOLEAN as i32
}

#[inline]
pub unsafe fn lua_istable_ex(L: *mut lua_State, idx: i32) -> bool {
    lua_type(L, idx) == LUA_TTABLE as i32
}

#[inline]
pub unsafe fn lua_isfunction_ex(L: *mut lua_State, idx: i32) -> bool {
    lua_type(L, idx) == LUA_TFUNCTION as i32
}

#[inline]
pub unsafe fn lua_tointeger_ex(L: *mut lua_State, idx: i32) -> lua_Integer {
    lua_tointegerx(L, idx, std::ptr::null_mut())
}

#[inline]
pub unsafe fn lua_tonumber_ex(L: *mut lua_State, idx: i32) -> lua_Number {
    lua_tonumberx(L, idx, std::ptr::null_mut())
}

#[inline]
pub unsafe fn lua_tostring_ex(L: *mut lua_State, idx: i32) -> *const std::os::raw::c_char {
    lua_tolstring(L, idx, std::ptr::null_mut())
}
