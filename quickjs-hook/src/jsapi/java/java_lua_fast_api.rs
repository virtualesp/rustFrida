//! Java.luaFastMethod() backend used by Lua high-frequency callbacks.
//!
//! This is intentionally fast-only: registration rejects methods that do not
//! currently have an independent quick-code entrypoint. Slow/reflection/JNI
//! calls stay in the JS callback path.

use crate::ffi;
use crate::jsapi::callback_util::{
    extract_string_arg, js_u64_to_js_number_or_bigint, set_js_u64_property, throw_internal_error, throw_type_error,
};
use crate::jsapi::console::output_verbose;
use crate::value::JSValue;
use std::ffi::CString;
use std::sync::{Mutex, OnceLock};

use super::art_method::*;
use super::callback::{get_return_type_from_sig, parse_jni_param_types};
use super::jni_core::*;
use super::reflect::{decode_field_id, find_class_safe};
use super::safe_mem::{refresh_mem_regions, safe_read_u32};

#[derive(Clone)]
pub(crate) struct LuaFastMethod {
    pub(crate) art_method: u64,
    pub(crate) is_static: bool,
    pub(crate) return_type: u8,
    shorty: CString,
    pub(crate) param_types: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct LuaFastConstructor {
    pub(crate) class_global_ref: u64,
    pub(crate) class_mirror: u64,
    pub(crate) art_method: u64,
    shorty: CString,
    pub(crate) param_types: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct LuaFastField {
    #[allow(dead_code)]
    pub(crate) art_field: u64,
    pub(crate) offset: u32,
    pub(crate) is_static: bool,
    pub(crate) value_type: u8,
    #[allow(dead_code)]
    pub(crate) jni_sig: String,
    #[allow(dead_code)]
    pub(crate) class_name: String,
    #[allow(dead_code)]
    pub(crate) field_name: String,
}

#[derive(Clone, Copy)]
pub(crate) enum LuaFastArg {
    Raw(u64),
    JniRef { env: JniEnv, object: *mut std::ffi::c_void },
}

static LUA_FAST_METHODS: OnceLock<Mutex<Vec<LuaFastMethod>>> = OnceLock::new();
static LUA_FAST_CONSTRUCTORS: OnceLock<Mutex<Vec<LuaFastConstructor>>> = OnceLock::new();
static LUA_FAST_FIELDS: OnceLock<Mutex<Vec<LuaFastField>>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
enum RequestedCompileKind {
    Auto,
    Fast,
    Baseline,
    Optimized,
}

impl RequestedCompileKind {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "fast" => Some(Self::Fast),
            "baseline" => Some(Self::Baseline),
            "optimized" | "opt" => Some(Self::Optimized),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Fast => "fast",
            Self::Baseline => "baseline",
            Self::Optimized => "optimized",
        }
    }

    fn sequence(self) -> &'static [u32] {
        match self {
            // Mirrors ART's JitAtFirstUse behavior: fast first, then baseline.
            Self::Auto => &[1, 2, 3],
            Self::Fast => &[1],
            Self::Baseline => &[2],
            Self::Optimized => &[3],
        }
    }
}

struct CompileResult {
    before: u64,
    after: u64,
    success: bool,
    compiled: bool,
    kind: &'static str,
    message: String,
}

fn lua_fast_methods() -> &'static Mutex<Vec<LuaFastMethod>> {
    LUA_FAST_METHODS.get_or_init(|| Mutex::new(Vec::new()))
}

fn lua_fast_constructors() -> &'static Mutex<Vec<LuaFastConstructor>> {
    LUA_FAST_CONSTRUCTORS.get_or_init(|| Mutex::new(Vec::new()))
}

fn lua_fast_fields() -> &'static Mutex<Vec<LuaFastField>> {
    LUA_FAST_FIELDS.get_or_init(|| Mutex::new(Vec::new()))
}

fn make_shorty(sig: &str) -> CString {
    let return_sig = sig
        .rsplit_once(')')
        .map(|(_, ret)| ret)
        .filter(|ret| !ret.is_empty())
        .unwrap_or("V");
    let mut shorty = Vec::with_capacity(sig.len() + 1);
    shorty.push(shorty_char(return_sig));
    for param in parse_jni_param_types(sig) {
        shorty.push(shorty_char(param.as_str()));
    }
    CString::new(shorty).unwrap_or_else(|_| CString::new("V").unwrap())
}

fn shorty_char(type_sig: &str) -> u8 {
    match type_sig.as_bytes().first().copied().unwrap_or(b'V') {
        b'L' | b'[' => b'L',
        ch => ch,
    }
}

pub(crate) fn get_lua_fast_method(handle: u64) -> Option<LuaFastMethod> {
    if handle == 0 {
        return None;
    }
    let methods = lua_fast_methods().lock().unwrap_or_else(|e| e.into_inner());
    methods.get((handle - 1) as usize).cloned()
}

pub(crate) fn get_lua_fast_constructor(handle: u64) -> Option<LuaFastConstructor> {
    if handle == 0 {
        return None;
    }
    let constructors = lua_fast_constructors().lock().unwrap_or_else(|e| e.into_inner());
    constructors.get((handle - 1) as usize).cloned()
}

pub(crate) fn get_lua_fast_field(handle: u64) -> Option<LuaFastField> {
    if handle == 0 {
        return None;
    }
    let fields = lua_fast_fields().lock().unwrap_or_else(|e| e.into_inner());
    fields.get((handle - 1) as usize).cloned()
}

unsafe fn is_lua_fast_field_type(sig: &str) -> bool {
    matches!(
        sig.as_bytes().first().copied(),
        Some(b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' | b'L' | b'[')
    )
}

unsafe fn parse_lua_fast_options(
    ctx: *mut ffi::JSContext,
    argc: i32,
    argv: *mut ffi::JSValue,
    opt_index: i32,
) -> Result<(bool, RequestedCompileKind), ffi::JSValue> {
    if argc <= opt_index {
        return Ok((false, RequestedCompileKind::Auto));
    }
    let opt = JSValue(*argv.add(opt_index as usize));
    if opt.is_bool() {
        return Ok((opt.to_bool().unwrap_or(false), RequestedCompileKind::Auto));
    }
    if opt.is_string() {
        let Some(kind_s) = opt.to_string(ctx) else {
            return Ok((false, RequestedCompileKind::Auto));
        };
        let Some(kind) = RequestedCompileKind::from_str(kind_s.as_str()) else {
            return Err(throw_type_error(ctx, b"invalid compile kind\0"));
        };
        return Ok((true, kind));
    }
    if opt.is_object() {
        let compile_val = opt.get_property(ctx, "compile");
        let should_compile = compile_val.to_bool().unwrap_or(false);
        compile_val.free(ctx);

        let kind_val = opt.get_property(ctx, "kind");
        let kind = if kind_val.is_string() {
            let kind_s = kind_val.to_string(ctx).unwrap_or_else(|| "auto".to_string());
            let Some(kind) = RequestedCompileKind::from_str(kind_s.as_str()) else {
                kind_val.free(ctx);
                return Err(throw_type_error(ctx, b"invalid compile kind\0"));
            };
            kind
        } else {
            RequestedCompileKind::Auto
        };
        kind_val.free(ctx);
        return Ok((should_compile, kind));
    }
    Ok((false, RequestedCompileKind::Auto))
}

pub(crate) unsafe extern "C" fn js_java_lua_fast_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_type_error(
            ctx,
            b"luaFastMethod(class, method, sig[, options]) requires at least 3 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg 2 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str, false)
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let (art_method, is_static) = match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
        Ok(v) => v,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let (should_compile, compile_kind) = match parse_lua_fast_options(ctx, argc, argv, 3) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    let mut entry_point = read_entry_point(art_method, spec.entry_point_offset);
    if is_art_quick_entrypoint(entry_point, &bridge) && should_compile {
        let compile = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, compile_kind);
        entry_point = compile.after;
        crate::jsapi::console::output_verbose(&format!(
            "[luaFastMethod] compile {}.{}{} kind={} success={} before={:#x} after={:#x} msg={}",
            class_name,
            method_name,
            actual_sig,
            compile.kind,
            compile.success,
            compile.before,
            compile.after,
            compile.message
        ));
    }
    if is_art_quick_entrypoint(entry_point, &bridge) {
        return throw_internal_error(
            ctx,
            format!(
                "luaFastMethod rejected {}.{}{}: no independent quick entrypoint (entry={:#x})",
                class_name, method_name, actual_sig, entry_point
            ),
        );
    }

    let method = LuaFastMethod {
        art_method,
        is_static,
        return_type: get_return_type_from_sig(&actual_sig),
        shorty: make_shorty(&actual_sig),
        param_types: parse_jni_param_types(&actual_sig),
    };
    let mut methods = lua_fast_methods().lock().unwrap_or_else(|e| e.into_inner());
    methods.push(method);
    js_u64_to_js_number_or_bigint(ctx, methods.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_lua_fast_constructor(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_type_error(
            ctx,
            b"luaFastConstructor(class, sig[, options]) requires at least 2 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    if get_return_type_from_sig(&sig_str) != b'V' {
        return throw_type_error(ctx, b"constructor signature must return void\0");
    }

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    let (art_method, is_static) = match resolve_art_method(env, &class_name, "<init>", &sig_str, false) {
        Ok(v) => v,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    if is_static {
        return throw_internal_error(
            ctx,
            format!("constructor resolved as static: {}{}", class_name, sig_str),
        );
    }

    let (should_compile, compile_kind) = match parse_lua_fast_options(ctx, argc, argv, 2) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    let mut entry_point = read_entry_point(art_method, spec.entry_point_offset);
    if is_art_quick_entrypoint(entry_point, &bridge) && should_compile {
        let compile = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, compile_kind);
        entry_point = compile.after;
        crate::jsapi::console::output_verbose(&format!(
            "[luaFastConstructor] compile {}.<init>{} kind={} success={} before={:#x} after={:#x} msg={}",
            class_name, sig_str, compile.kind, compile.success, compile.before, compile.after, compile.message
        ));
    }
    if is_art_quick_entrypoint(entry_point, &bridge) {
        return throw_internal_error(
            ctx,
            format!(
                "luaFastConstructor rejected {}.<init>{}: no independent quick entrypoint (entry={:#x})",
                class_name, sig_str, entry_point
            ),
        );
    }

    let class_global_ref = match create_class_global_ref(env, &class_name) {
        Ok(v) => v,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let class_mirror = super::decode_global_jobject_raw(env, class_global_ref).unwrap_or(0);
    output_verbose(&format!(
        "[lua fast ctor] {}.<init>{} class_global={:#x} class_mirror={:#x}",
        class_name, sig_str, class_global_ref as usize, class_mirror
    ));
    let constructor = LuaFastConstructor {
        class_global_ref: class_global_ref as u64,
        class_mirror,
        art_method,
        shorty: make_shorty(&sig_str),
        param_types: parse_jni_param_types(&sig_str),
    };
    let mut constructors = lua_fast_constructors().lock().unwrap_or_else(|e| e.into_inner());
    constructors.push(constructor);
    js_u64_to_js_number_or_bigint(ctx, constructors.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_lua_fast_field(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return throw_type_error(
            ctx,
            b"luaFastField(class, field[, sig]) requires at least 2 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let field_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let requested_sig = if argc >= 3 {
        let sig_arg = JSValue(*argv.add(2));
        if !sig_arg.is_undefined() && !sig_arg.is_null() {
            match extract_string_arg(ctx, sig_arg, b"arg 2 must be string\0") {
                Ok(s) => Some(s),
                Err(e) => return e,
            }
        } else {
            None
        }
    } else {
        None
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let Some(spec) = get_art_field_spec() else {
        return throw_internal_error(ctx, "unsupported ArtField layout".to_string());
    };

    cache_fields_for_class(env, &class_name);
    let (jni_sig, field_id, is_static) = {
        let guard = FIELD_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let Some(cache) = guard.as_ref() else {
            return throw_internal_error(ctx, format!("field cache unavailable for {}", class_name));
        };
        let Some(fields) = cache.get(&class_name) else {
            return throw_internal_error(ctx, format!("fields unavailable for {}", class_name));
        };
        let Some(info) = fields.get(&field_name) else {
            return throw_internal_error(ctx, format!("field not found: {}.{}", class_name, field_name));
        };
        (info.jni_sig.clone(), info.field_id, info.is_static)
    };

    if let Some(sig) = requested_sig.as_ref() {
        if sig != &jni_sig {
            return throw_type_error(ctx, b"field signature mismatch\0");
        }
    }
    if is_static {
        return throw_type_error(ctx, b"luaFastField only supports instance fields\0");
    }
    if !is_lua_fast_field_type(&jni_sig) {
        return throw_type_error(ctx, b"luaFastField only supports primitive/object instance fields\0");
    }

    let cls = find_class_safe(env, &class_name);
    if cls.is_null() {
        return throw_internal_error(ctx, format!("class not found: {}", class_name));
    }
    let art_field = decode_field_id(env, cls, field_id as u64, is_static);
    jni_check_exc(env);
    if art_field == 0 {
        return throw_internal_error(ctx, format!("failed to decode field id: {}.{}", class_name, field_name));
    }
    refresh_mem_regions();
    let offset = safe_read_u32(art_field + spec.offset_offset as u64);
    if offset == 0 {
        return throw_internal_error(ctx, format!("invalid field offset: {}.{}", class_name, field_name));
    }

    let field = LuaFastField {
        art_field,
        offset,
        is_static,
        value_type: jni_sig.as_bytes()[0],
        jni_sig,
        class_name,
        field_name,
    };
    let mut fields = lua_fast_fields().lock().unwrap_or_else(|e| e.into_inner());
    fields.push(field);
    js_u64_to_js_number_or_bigint(ctx, fields.len() as u64)
}

pub(crate) unsafe extern "C" fn js_java_compile_method(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return throw_type_error(
            ctx,
            b"compileMethod(class, method, sig[, kind]) requires at least 3 arguments\0",
        );
    }

    let class_name = match extract_string_arg(ctx, JSValue(*argv), b"arg 0 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let method_name = match extract_string_arg(ctx, JSValue(*argv.add(1)), b"arg 1 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sig_str = match extract_string_arg(ctx, JSValue(*argv.add(2)), b"arg 2 must be string\0") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str, false)
    };
    let kind = if argc >= 4 {
        if let Some(s) = JSValue(*argv.add(3)).to_string(ctx) {
            match RequestedCompileKind::from_str(s.as_str()) {
                Some(k) => k,
                None => return throw_type_error(ctx, b"invalid compile kind\0"),
            }
        } else {
            RequestedCompileKind::Auto
        }
    } else {
        RequestedCompileKind::Auto
    };

    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let (art_method, _is_static) = match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
        Ok(v) => v,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let spec = get_art_method_spec(env, art_method);
    let bridge = find_art_bridge_functions(env, spec.entry_point_offset);
    let result = compile_art_method_to_quick(env, art_method, spec.entry_point_offset, bridge, kind);

    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    obj_v.set_property(ctx, "success", JSValue::bool(result.success));
    obj_v.set_property(ctx, "compiled", JSValue::bool(result.compiled));
    obj_v.set_property(ctx, "kind", JSValue::string(ctx, result.kind));
    obj_v.set_property(ctx, "message", JSValue::string(ctx, &result.message));
    set_js_u64_property(ctx, obj, "artMethod", art_method);
    set_js_u64_property(ctx, obj, "before", result.before);
    set_js_u64_property(ctx, obj, "after", result.after);
    obj
}

pub(crate) unsafe extern "C" fn js_java_jit_info(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let _env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };
    let Some(info) = probe_jit_runtime_info() else {
        return throw_internal_error(ctx, "JIT runtime info unavailable".to_string());
    };

    let obj = ffi::JS_NewObject(ctx);
    let obj_v = JSValue(obj);
    set_js_u64_property(ctx, obj, "runtime", info.runtime);
    set_js_u64_property(ctx, obj, "javaVmOffset", info.java_vm_offset as u64);
    set_js_u64_property(ctx, obj, "jitOffset", info.jit_offset as u64);
    set_js_u64_property(ctx, obj, "jitCodeCacheOffset", info.jit_code_cache_offset as u64);
    set_js_u64_property(ctx, obj, "directJit", info.direct_jit);
    set_js_u64_property(ctx, obj, "runtimeJitCodeCache", info.runtime_jit_code_cache);
    set_js_u64_property(ctx, obj, "directGetCodeCache", info.direct_get_code_cache);
    set_js_u64_property(ctx, obj, "foundJit", info.found_jit);
    obj_v.set_property(ctx, "message", JSValue::string(ctx, &info.message));
    obj
}

unsafe fn compile_art_method_to_quick(
    env: JniEnv,
    art_method: u64,
    entry_point_offset: usize,
    bridge: &ArtBridgeFunctions,
    kind: RequestedCompileKind,
) -> CompileResult {
    let before = read_entry_point(art_method, entry_point_offset);
    if !is_art_quick_entrypoint(before, bridge) {
        return CompileResult {
            before,
            after: before,
            success: true,
            compiled: false,
            kind: "already-quick",
            message: "method already has independent quick code".to_string(),
        };
    }

    let Some(jit) = find_jit_instance() else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Jit* not found".to_string(),
        };
    };
    let Some(thread) = current_art_thread(env) else {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Thread::Current() unavailable".to_string(),
        };
    };
    let compile_sym = crate::jsapi::module::libart_dlsym(
        "_ZN3art3jit3Jit13CompileMethodEPNS_9ArtMethodEPNS_6ThreadENS_15CompilationKindEb",
    );
    if compile_sym.is_null() {
        return CompileResult {
            before,
            after: before,
            success: false,
            compiled: false,
            kind: kind.label(),
            message: "Jit::CompileMethod symbol not found".to_string(),
        };
    }

    type CompileMethodFn =
        unsafe extern "C" fn(this: u64, method: u64, thread: u64, compilation_kind: u32, prejit: u8) -> u8;
    let compile_method: CompileMethodFn = std::mem::transmute(compile_sym);

    let mut last_kind = kind.label();
    let mut saw_compile_success = false;
    for k in kind.sequence() {
        last_kind = match *k {
            1 => "fast",
            2 => "baseline",
            3 => "optimized",
            _ => "unknown",
        };
        let ok = compile_method(jit, art_method, thread, *k, 0) != 0;
        let after = read_entry_point(art_method, entry_point_offset);
        if ok {
            saw_compile_success = true;
        }
        if !is_art_quick_entrypoint(after, bridge) {
            return CompileResult {
                before,
                after,
                success: true,
                compiled: true,
                kind: last_kind,
                message: format!("Jit::CompileMethod({}) succeeded", last_kind),
            };
        }
    }

    let after = read_entry_point(art_method, entry_point_offset);
    CompileResult {
        before,
        after,
        success: false,
        compiled: saw_compile_success,
        kind: last_kind,
        message: if saw_compile_success {
            "JIT reported success but entrypoint is still a shared ART bridge".to_string()
        } else {
            "Jit::CompileMethod returned false".to_string()
        },
    }
}

unsafe fn current_art_thread(env: JniEnv) -> Option<u64> {
    let sym = crate::jsapi::module::libart_dlsym("_ZN3art6Thread7CurrentEv");
    if !sym.is_null() {
        type ThreadCurrentFn = unsafe extern "C" fn() -> u64;
        let thread_current: ThreadCurrentFn = std::mem::transmute(sym);
        let thread = thread_current() & super::PAC_STRIP_MASK;
        if thread != 0 {
            return Some(thread);
        }
    }
    if !env.is_null() {
        let thread = *((env as usize + 8) as *const u64) & super::PAC_STRIP_MASK;
        if thread != 0 {
            return Some(thread);
        }
    }
    None
}

unsafe fn create_class_global_ref(env: JniEnv, class_name: &str) -> Result<*mut std::ffi::c_void, String> {
    let cls = find_class_safe(env, class_name);
    if cls.is_null() {
        let _ = jni_check_exc(env);
        return Err(format!("class not found: {}", class_name));
    }
    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let global = new_global_ref(env, cls);
    delete_local_ref(env, cls);
    if jni_check_exc(env) || global.is_null() {
        return Err(format!("NewGlobalRef failed for {}", class_name));
    }
    Ok(global)
}

type ArtMethodInvokeFn = unsafe extern "C" fn(
    method: *mut std::ffi::c_void,
    thread: *mut std::ffi::c_void,
    args: *mut u32,
    args_size: u32,
    result: *mut u64,
    shorty: *const std::os::raw::c_char,
);

static ART_METHOD_INVOKE: OnceLock<Option<ArtMethodInvokeFn>> = OnceLock::new();

pub(crate) unsafe fn invoke_lua_fast_method(
    method: &LuaFastMethod,
    receiver: u64,
    args: &[LuaFastArg],
) -> Result<u64, String> {
    if !method.is_static && receiver == 0 {
        return Err("jcall instance receiver is null".to_string());
    }
    if args.len() != method.param_types.len() {
        return Err(format!(
            "jcall argument count mismatch: expected {}, got {}",
            method.param_types.len(),
            args.len()
        ));
    }

    let Some(ret) = crate::lua::callback::with_current_quick_runnable(|thread| {
        let Some(invoke) = art_method_invoke() else {
            return Err("ArtMethod::Invoke symbol not found".to_string());
        };
        let mut invoke_args = Vec::with_capacity(1 + method.param_types.len() * 2);
        if !method.is_static {
            push_art_invoke_arg(&mut invoke_args, "L", receiver);
        }

        for (i, type_sig) in method.param_types.iter().enumerate() {
            let raw = match resolve_lua_fast_arg(args[i], type_sig.as_str()) {
                Ok(raw) => raw,
                Err(msg) => return Err(msg),
            };
            push_art_invoke_arg(&mut invoke_args, type_sig.as_str(), raw);
        }

        let mut result = 0u64;
        invoke(
            method.art_method as *mut std::ffi::c_void,
            thread,
            invoke_args.as_mut_ptr(),
            (invoke_args.len() * std::mem::size_of::<u32>()) as u32,
            &mut result as *mut u64,
            method.shorty.as_ptr(),
        );
        Ok(result)
    }) else {
        return Err("jcall is only available inside quick Lua callbacks".to_string());
    };
    ret
}

pub(crate) unsafe fn invoke_lua_fast_constructor(
    ctor: &LuaFastConstructor,
    receiver: u64,
    args: &[LuaFastArg],
) -> Result<(), String> {
    if receiver == 0 {
        return Err("jnew receiver allocation returned null".to_string());
    }
    if args.len() != ctor.param_types.len() {
        return Err(format!(
            "jnew argument count mismatch: expected {}, got {}",
            ctor.param_types.len(),
            args.len()
        ));
    }

    let Some(ret) = crate::lua::callback::with_current_quick_runnable(|thread| {
        let Some(invoke) = art_method_invoke() else {
            return Err("ArtMethod::Invoke symbol not found".to_string());
        };
        let mut invoke_args = Vec::with_capacity(1 + ctor.param_types.len() * 2);
        push_art_invoke_arg(&mut invoke_args, "L", receiver);

        for (i, type_sig) in ctor.param_types.iter().enumerate() {
            let raw = match resolve_lua_fast_arg(args[i], type_sig.as_str()) {
                Ok(raw) => raw,
                Err(msg) => return Err(msg),
            };
            push_art_invoke_arg(&mut invoke_args, type_sig.as_str(), raw);
        }

        let mut result = 0u64;
        invoke(
            ctor.art_method as *mut std::ffi::c_void,
            thread,
            invoke_args.as_mut_ptr(),
            (invoke_args.len() * std::mem::size_of::<u32>()) as u32,
            &mut result as *mut u64,
            ctor.shorty.as_ptr(),
        );
        Ok(())
    }) else {
        return Err("jnew is only available inside quick Lua callbacks".to_string());
    };
    ret
}

unsafe fn art_method_invoke() -> Option<ArtMethodInvokeFn> {
    *ART_METHOD_INVOKE.get_or_init(|| {
        let sym = crate::jsapi::module::libart_dlsym("_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc");
        if sym.is_null() {
            None
        } else {
            Some(std::mem::transmute(sym))
        }
    })
}

fn push_art_invoke_arg(out: &mut Vec<u32>, type_sig: &str, raw: u64) {
    match type_sig.as_bytes().first().copied() {
        Some(b'J' | b'D') => {
            out.push(raw as u32);
            out.push((raw >> 32) as u32);
        }
        Some(b'F') => out.push(raw as u32),
        Some(b'L' | b'[') => out.push(raw as u32),
        _ => out.push(raw as u32),
    }
}

unsafe fn resolve_lua_fast_arg(arg: LuaFastArg, type_sig: &str) -> Result<u64, String> {
    match arg {
        LuaFastArg::Raw(raw) => Ok(raw),
        LuaFastArg::JniRef { env, object } => {
            if !matches!(type_sig.as_bytes().first().copied(), Some(b'L' | b'[')) {
                return Ok(object as u64);
            }
            super::decode_jobject_raw(env, object)
                .or_else(|| crate::lua::api::decode_jni_local_ref_via_irt(env as *const std::ffi::c_void, object))
                .or_else(|| super::decode_global_jobject_raw(env, object))
                .ok_or_else(|| "failed to decode JNI ref for quick call".to_string())
        }
    }
}
