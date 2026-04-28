use crate::jsapi::java::jni_core::{
    jni_check_exc, CallBooleanMethodAFn, CallIntMethodAFn, CallObjectMethodAFn, DeleteLocalRefFn, GetArrayLengthFn,
    GetMethodIdFn, GetObjectArrayElementFn, GetStringUtfCharsFn, JniEnv, PopLocalFrameFn, PushLocalFrameFn,
    ReleaseStringUtfCharsFn, JNI_CALL_BOOLEAN_METHOD_A, JNI_CALL_INT_METHOD_A, JNI_CALL_OBJECT_METHOD_A,
    JNI_DELETE_LOCAL_REF, JNI_GET_ARRAY_LENGTH, JNI_GET_METHOD_ID, JNI_GET_OBJECT_ARRAY_ELEMENT,
    JNI_GET_STRING_UTF_CHARS, JNI_POP_LOCAL_FRAME, JNI_PUSH_LOCAL_FRAME, JNI_RELEASE_STRING_UTF_CHARS,
};
use std::collections::{BTreeSet, VecDeque};
use std::ffi::{c_void, CStr, CString};

pub(super) fn java_class_to_descriptor(class_name: &str) -> Result<String, String> {
    let trimmed = class_name.trim();
    if trimmed.is_empty() {
        return Err("empty Java class name".to_string());
    }
    if trimmed.starts_with('[') {
        validate_descriptor(trimmed, false)?;
        return Ok(trimmed.to_string());
    }
    if trimmed.ends_with("[]") {
        return java_array_type_to_descriptor(trimmed);
    }
    if trimmed.starts_with('L') && trimmed.ends_with(';') {
        return Ok(trimmed.to_string());
    }
    if trimmed.contains('/') {
        return Ok(format!("L{};", trimmed.trim_matches(';')));
    }
    Ok(format!("L{};", trimmed.replace('.', "/")))
}

fn validate_descriptor(desc: &str, allow_void: bool) -> Result<(), String> {
    let mut pos = 0usize;
    parse_descriptor_at(desc, &mut pos, allow_void)?;
    if pos != desc.len() {
        return Err(format!("invalid descriptor '{}': trailing input", desc));
    }
    Ok(())
}

fn primitive_descriptor(type_name: &str, allow_void: bool) -> Option<&'static str> {
    match type_name {
        "void" | "V" if allow_void => Some("V"),
        "boolean" | "Z" => Some("Z"),
        "byte" | "B" => Some("B"),
        "char" | "C" => Some("C"),
        "short" | "S" => Some("S"),
        "int" | "I" => Some("I"),
        "long" | "J" => Some("J"),
        "float" | "F" => Some("F"),
        "double" | "D" => Some("D"),
        _ => None,
    }
}

fn java_array_type_to_descriptor(type_name: &str) -> Result<String, String> {
    let mut base = type_name.trim();
    let mut dims = 0usize;
    while let Some(stripped) = base.strip_suffix("[]") {
        dims += 1;
        base = stripped.trim();
    }
    if dims == 0 {
        return Err(format!("not an array type '{}'", type_name));
    }
    if base.is_empty() {
        return Err(format!("invalid array type '{}'", type_name));
    }
    let base_desc = if let Some(desc) = primitive_descriptor(base, false) {
        desc.to_string()
    } else {
        java_class_to_descriptor(base)?
    };
    if base_desc == "V" {
        return Err("void[] is not a valid Java array type".to_string());
    }
    let mut out = String::with_capacity(dims + base_desc.len());
    for _ in 0..dims {
        out.push('[');
    }
    out.push_str(&base_desc);
    Ok(out)
}

pub(super) fn parse_method_signature(sig: &str) -> Result<(Vec<String>, String), String> {
    let bytes = sig.as_bytes();
    if bytes.first().copied() != Some(b'(') {
        return Err(format!("invalid method signature '{}': missing '('", sig));
    }

    let mut params = Vec::new();
    let mut pos = 1usize;
    while pos < bytes.len() && bytes[pos] != b')' {
        let start = pos;
        parse_descriptor_at(sig, &mut pos, false)?;
        params.push(sig[start..pos].to_string());
    }
    if pos >= bytes.len() || bytes[pos] != b')' {
        return Err(format!("invalid method signature '{}': missing ')'", sig));
    }
    pos += 1;
    let ret_start = pos;
    parse_descriptor_at(sig, &mut pos, true)?;
    if pos != bytes.len() {
        return Err(format!("invalid method signature '{}': trailing input", sig));
    }
    Ok((params, sig[ret_start..pos].to_string()))
}

pub(super) fn parse_method_params_signature(sig: &str) -> Result<Vec<String>, String> {
    let bytes = sig.as_bytes();
    if bytes.first().copied() != Some(b'(') {
        return Err(format!("invalid method parameter signature '{}': missing '('", sig));
    }

    let mut params = Vec::new();
    let mut pos = 1usize;
    while pos < bytes.len() && bytes[pos] != b')' {
        let start = pos;
        parse_descriptor_at(sig, &mut pos, false)?;
        params.push(sig[start..pos].to_string());
    }
    if pos >= bytes.len() || bytes[pos] != b')' {
        return Err(format!("invalid method parameter signature '{}': missing ')'", sig));
    }
    pos += 1;
    if pos != bytes.len() {
        return Err(format!("invalid method parameter signature '{}': trailing input", sig));
    }
    Ok(params)
}

pub(super) fn parse_call_params(sig: &str) -> Result<Vec<String>, String> {
    match parse_method_signature(sig) {
        Ok((params, _)) => Ok(params),
        Err(_) => parse_method_params_signature(sig),
    }
}

pub(super) fn build_params_sig(params: &[String]) -> String {
    let mut sig = String::from("(");
    for param in params {
        sig.push_str(param);
    }
    sig.push(')');
    sig
}

fn parse_descriptor_at(sig: &str, pos: &mut usize, allow_void: bool) -> Result<(), String> {
    let bytes = sig.as_bytes();
    if *pos >= bytes.len() {
        return Err("unexpected end of descriptor".to_string());
    }
    match bytes[*pos] {
        b'V' if allow_void => {
            *pos += 1;
            Ok(())
        }
        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
            *pos += 1;
            Ok(())
        }
        b'L' => {
            *pos += 1;
            while *pos < bytes.len() && bytes[*pos] != b';' {
                *pos += 1;
            }
            if *pos >= bytes.len() {
                return Err("unterminated object descriptor".to_string());
            }
            *pos += 1;
            Ok(())
        }
        b'[' => {
            while *pos < bytes.len() && bytes[*pos] == b'[' {
                *pos += 1;
            }
            parse_descriptor_at(sig, pos, false)
        }
        other => Err(format!("invalid descriptor char '{}'", other as char)),
    }
}

pub(super) fn descriptor_word_count(desc: &str) -> u16 {
    if desc == "J" || desc == "D" {
        2
    } else {
        1
    }
}

pub(super) fn descriptor_list_word_count(descs: &[String]) -> Result<u16, String> {
    let mut total = 0u16;
    for desc in descs {
        total = total
            .checked_add(descriptor_word_count(desc))
            .ok_or_else(|| "too many dex registers".to_string())?;
    }
    Ok(total)
}

pub(super) fn build_method_sig(params: &[String], return_type: &str) -> String {
    let mut sig = String::from("(");
    for param in params {
        sig.push_str(param);
    }
    sig.push(')');
    sig.push_str(return_type);
    sig
}

pub(super) fn return_is_object(return_type: &str) -> bool {
    return_type.starts_with('L') || return_type.starts_with('[')
}

pub(super) fn common_value_descriptor_with_env(
    left: Option<String>,
    right: Option<String>,
    env: JniEnv,
) -> Result<Option<String>, String> {
    match (left, right) {
        (Some(left), Some(right)) if left == right => Ok(Some(left)),
        (Some(left), Some(right)) if return_is_object(&left) && return_is_object(&right) => {
            Ok(Some(common_reference_descriptor(env, &left, &right)))
        }
        (Some(desc), None) | (None, Some(desc)) if return_is_object(&desc) => Ok(Some(desc)),
        (None, None) => Ok(None),
        (Some(left), Some(right)) => Err(format!(
            "ternary branch types are not compatible: {} and {}",
            left, right
        )),
        (Some(desc), None) | (None, Some(desc)) => Err(format!("ternary null branch cannot be assigned to {}", desc)),
    }
}

fn common_reference_descriptor(env: JniEnv, left: &str, right: &str) -> String {
    if left == right {
        return left.to_string();
    }
    if left.starts_with('[') || right.starts_with('[') {
        return common_array_reference_descriptor(env, left, right);
    }
    common_object_descriptor(env, left, right).unwrap_or_else(|| "Ljava/lang/Object;".to_string())
}

fn common_array_reference_descriptor(env: JniEnv, left: &str, right: &str) -> String {
    if left == right {
        return left.to_string();
    }
    if left.starts_with('[') && right.starts_with('[') {
        if let Some(common_array) = common_covariant_array_descriptor(env, left, right) {
            return common_array;
        }
    }
    match (left, right) {
        ("Ljava/lang/Object;", _) | (_, "Ljava/lang/Object;") => "Ljava/lang/Object;".to_string(),
        ("Ljava/lang/Cloneable;", array) | (array, "Ljava/lang/Cloneable;") if array.starts_with('[') => {
            "Ljava/lang/Cloneable;".to_string()
        }
        ("Ljava/io/Serializable;", array) | (array, "Ljava/io/Serializable;") if array.starts_with('[') => {
            "Ljava/io/Serializable;".to_string()
        }
        _ => "Ljava/lang/Object;".to_string(),
    }
}

fn common_covariant_array_descriptor(env: JniEnv, left: &str, right: &str) -> Option<String> {
    let left_component = array_component_descriptor(left).ok()?;
    let right_component = array_component_descriptor(right).ok()?;
    if left_component == right_component {
        return Some(format!("[{}", left_component));
    }
    if return_is_object(&left_component) && return_is_object(&right_component) {
        return Some(format!(
            "[{}",
            common_reference_descriptor(env, &left_component, &right_component)
        ));
    }
    None
}

pub(super) fn descriptor_is_interface(env: JniEnv, desc: &str) -> bool {
    if env.is_null() || !return_is_object(desc) || desc.starts_with('[') {
        return false;
    }
    let Ok(class_name) = descriptor_to_java_class_name(desc) else {
        return false;
    };
    unsafe {
        let cls = crate::jsapi::java::reflect::find_class_safe(env, &class_name);
        if cls.is_null() {
            return false;
        }
        let result = class_is_interface(env, cls);
        delete_local_ref(env, cls);
        result
    }
}

pub(super) fn object_assignability_score(env: JniEnv, src: &str, dst: &str) -> Option<u16> {
    if src == dst {
        return Some(0);
    }
    if !return_is_object(src) || !return_is_object(dst) {
        return None;
    }
    if src.starts_with('[') || dst.starts_with('[') {
        return array_assignability_score(env, src, dst);
    }
    if dst == "Ljava/lang/Object;" {
        return Some(1024);
    }
    if env.is_null() {
        return None;
    }
    let src_name = descriptor_to_java_class_name(src).ok()?;
    unsafe {
        let src_cls = crate::jsapi::java::reflect::find_class_safe(env, &src_name);
        if src_cls.is_null() {
            return None;
        }
        let interfaces_mid = class_get_interfaces_method_id(env);
        let src_types = class_type_closure(env, src_cls, interfaces_mid);
        delete_local_ref(env, src_cls);
        src_types
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate.desc == dst)
            .map(|(index, candidate)| assignability_candidate_score(index, candidate))
    }
}

pub(super) struct ResolvedFieldSpec {
    pub(super) declaring_type: String,
    pub(super) field_type: String,
    pub(super) is_static: bool,
}

pub(super) fn resolve_field_with_env(
    env: JniEnv,
    class_type: &str,
    field_name: &str,
    expected_static: Option<bool>,
) -> Result<ResolvedFieldSpec, String> {
    if env.is_null() || !return_is_object(class_type) || class_type.starts_with('[') {
        return Err(format!(
            "field {} cannot be resolved from non-class descriptor {}",
            field_name, class_type
        ));
    }
    let class_name = descriptor_to_java_class_name(class_type)?;
    unsafe { resolve_field_with_reflection(env, &class_name, field_name, expected_static) }
}

unsafe fn resolve_field_with_reflection(
    env: JniEnv,
    class_name: &str,
    field_name: &str,
    expected_static: Option<bool>,
) -> Result<ResolvedFieldSpec, String> {
    let cls = crate::jsapi::java::reflect::find_class_safe(env, class_name);
    if cls.is_null() {
        return Err(format!(
            "class not found while resolving field {}.{}",
            class_name, field_name
        ));
    }

    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let push_frame: PushLocalFrameFn = jni_fn!(env, PushLocalFrameFn, JNI_PUSH_LOCAL_FRAME);
    let pop_frame: PopLocalFrameFn = jni_fn!(env, PopLocalFrameFn, JNI_POP_LOCAL_FRAME);

    if push_frame(env, 256) < 0 {
        delete_local_ref(env, cls);
        return Err("PushLocalFrame failed while resolving field".to_string());
    }

    let class_cls = crate::jsapi::java::reflect::find_class_safe(env, "java.lang.Class");
    let field_cls = crate::jsapi::java::reflect::find_class_safe(env, "java.lang.reflect.Field");
    if class_cls.is_null() || field_cls.is_null() {
        pop_frame(env, std::ptr::null_mut());
        delete_local_ref(env, cls);
        return Err("reflection classes not found while resolving field".to_string());
    }

    let get_declared_fields_mid =
        class_method_id_from_class_ref(env, class_cls, "getDeclaredFields", "()[Ljava/lang/reflect/Field;")?;
    let get_fields_mid = class_method_id_from_class_ref(env, class_cls, "getFields", "()[Ljava/lang/reflect/Field;")?;
    let get_superclass_mid = class_method_id_from_class_ref(env, class_cls, "getSuperclass", "()Ljava/lang/Class;")?;
    let field_get_name_mid = class_method_id_from_class_ref(env, field_cls, "getName", "()Ljava/lang/String;")?;

    let mut current = cls;
    loop {
        if let Some(spec) = find_matching_field_in_array(
            env,
            call_obj(env, current, get_declared_fields_mid, std::ptr::null()),
            field_name,
            expected_static,
            field_get_name_mid,
        )? {
            pop_frame(env, std::ptr::null_mut());
            delete_local_ref(env, cls);
            return Ok(spec);
        }
        let super_cls = call_obj(env, current, get_superclass_mid, std::ptr::null());
        if jni_check_exc(env) || super_cls.is_null() {
            break;
        }
        current = super_cls;
    }

    if let Some(spec) = find_matching_field_in_array(
        env,
        call_obj(env, cls, get_fields_mid, std::ptr::null()),
        field_name,
        expected_static,
        field_get_name_mid,
    )? {
        pop_frame(env, std::ptr::null_mut());
        delete_local_ref(env, cls);
        return Ok(spec);
    }

    pop_frame(env, std::ptr::null_mut());
    delete_local_ref(env, cls);
    Err(format!(
        "field {}.{} not found; use explicit typed field syntax if reflection cannot resolve it",
        class_name, field_name
    ))
}

unsafe fn find_matching_field_in_array(
    env: JniEnv,
    array: *mut c_void,
    field_name: &str,
    expected_static: Option<bool>,
    field_get_name_mid: *mut c_void,
) -> Result<Option<ResolvedFieldSpec>, String> {
    if array.is_null() || jni_check_exc(env) {
        return Ok(None);
    }
    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn = jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let len = get_arr_len(env, array);
    if jni_check_exc(env) || len <= 0 {
        return Ok(None);
    }
    for i in 0..len {
        let field = get_arr_elem(env, array, i);
        if field.is_null() || jni_check_exc(env) {
            continue;
        }
        let Some(name) = reflected_field_name(env, field, field_get_name_mid) else {
            continue;
        };
        if name != field_name {
            continue;
        }
        let spec = reflected_field_spec(env, field)?;
        if expected_static
            .map(|is_static| is_static != spec.is_static)
            .unwrap_or(false)
        {
            continue;
        }
        return Ok(Some(spec));
    }
    Ok(None)
}

unsafe fn reflected_field_name(env: JniEnv, field: *mut c_void, field_get_name_mid: *mut c_void) -> Option<String> {
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn = jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let name_jstr = call_obj(env, field, field_get_name_mid, std::ptr::null());
    if name_jstr.is_null() || jni_check_exc(env) {
        return None;
    }
    let chars = get_str(env, name_jstr, std::ptr::null_mut());
    if chars.is_null() || jni_check_exc(env) {
        return None;
    }
    let value = CStr::from_ptr(chars).to_string_lossy().to_string();
    rel_str(env, name_jstr, chars);
    Some(value)
}

unsafe fn reflected_field_spec(env: JniEnv, field: *mut c_void) -> Result<ResolvedFieldSpec, String> {
    let field_cls = crate::jsapi::java::reflect::find_class_safe(env, "java.lang.reflect.Field");
    if field_cls.is_null() {
        return Err("java.lang.reflect.Field not found".to_string());
    }
    let get_type_mid = class_method_id_from_class_ref(env, field_cls, "getType", "()Ljava/lang/Class;")?;
    let get_declaring_class_mid =
        class_method_id_from_class_ref(env, field_cls, "getDeclaringClass", "()Ljava/lang/Class;")?;
    let get_modifiers_mid = class_method_id_from_class_ref(env, field_cls, "getModifiers", "()I")?;
    delete_local_ref(env, field_cls);

    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let call_int: CallIntMethodAFn = jni_fn!(env, CallIntMethodAFn, JNI_CALL_INT_METHOD_A);
    let type_cls = call_obj(env, field, get_type_mid, std::ptr::null());
    let declaring_cls = call_obj(env, field, get_declaring_class_mid, std::ptr::null());
    let modifiers = call_int(env, field, get_modifiers_mid, std::ptr::null());
    if jni_check_exc(env) || type_cls.is_null() || declaring_cls.is_null() {
        return Err("failed to read reflected field metadata".to_string());
    }
    let type_name = crate::jsapi::java::try_get_class_name(env as u64, type_cls as u64)
        .ok_or_else(|| "failed to resolve reflected field type".to_string())?;
    let declaring_name = crate::jsapi::java::try_get_class_name(env as u64, declaring_cls as u64)
        .ok_or_else(|| "failed to resolve reflected field declaring class".to_string())?;
    Ok(ResolvedFieldSpec {
        declaring_type: java_class_to_descriptor(&declaring_name)?,
        field_type: java_class_to_descriptor_or_primitive(&type_name)?,
        is_static: (modifiers & 0x0008) != 0,
    })
}

unsafe fn class_method_id_from_class_ref(
    env: JniEnv,
    cls: *mut c_void,
    name: &str,
    sig: &str,
) -> Result<*mut c_void, String> {
    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let name = CString::new(name).map_err(|_| format!("invalid method name {}", name))?;
    let sig = CString::new(sig).map_err(|_| format!("invalid method signature {}", sig))?;
    let mid = get_mid(env, cls, name.as_ptr(), sig.as_ptr());
    if mid.is_null() || jni_check_exc(env) {
        Err(format!(
            "reflection method {}{} not found",
            name.to_string_lossy(),
            sig.to_string_lossy()
        ))
    } else {
        Ok(mid)
    }
}

fn array_assignability_score(env: JniEnv, src: &str, dst: &str) -> Option<u16> {
    if src == dst {
        return Some(0);
    }
    if !src.starts_with('[') {
        return None;
    }
    if dst.starts_with('[') {
        let src_component = array_component_descriptor(src).ok()?;
        let dst_component = array_component_descriptor(dst).ok()?;
        if src_component == dst_component {
            return Some(0);
        }
        if return_is_object(&src_component) && return_is_object(&dst_component) {
            return object_assignability_score(env, &src_component, &dst_component)
                .map(|score| score.saturating_add(16));
        }
        return None;
    }
    match dst {
        "Ljava/lang/Object;" => Some(512),
        "Ljava/lang/Cloneable;" | "Ljava/io/Serializable;" => Some(384),
        _ => None,
    }
}

fn assignability_candidate_score(index: usize, candidate: &TypeCandidate) -> u16 {
    let base = (index as u16).saturating_add(1).saturating_mul(16);
    if is_low_priority_interface(&candidate.desc) {
        base.saturating_add(256)
    } else {
        base
    }
}

fn common_object_descriptor(env: JniEnv, left: &str, right: &str) -> Option<String> {
    if env.is_null() || left.starts_with('[') || right.starts_with('[') {
        return None;
    }
    let left_name = descriptor_to_java_class_name(left).ok()?;
    let right_name = descriptor_to_java_class_name(right).ok()?;
    unsafe {
        let left_cls = crate::jsapi::java::reflect::find_class_safe(env, &left_name);
        if left_cls.is_null() {
            return None;
        }
        let right_cls = crate::jsapi::java::reflect::find_class_safe(env, &right_name);
        if right_cls.is_null() {
            delete_local_ref(env, left_cls);
            return None;
        }

        let interfaces_mid = class_get_interfaces_method_id(env);
        let left_types = class_type_closure(env, left_cls, interfaces_mid);
        let right_types = class_type_closure(env, right_cls, interfaces_mid);
        let common = pick_common_type(&left_types, &right_types);

        delete_local_ref(env, left_cls);
        delete_local_ref(env, right_cls);
        common
    }
}

#[derive(Clone)]
struct TypeCandidate {
    desc: String,
    is_interface: bool,
}

unsafe fn class_type_closure(env: JniEnv, cls: *mut c_void, interfaces_mid: Option<*mut c_void>) -> Vec<TypeCandidate> {
    let mut refs = Vec::new();
    let mut descriptors = Vec::new();
    let mut seen = BTreeSet::new();
    let mut current = cls;

    loop {
        push_type_candidate(env, current, false, &mut descriptors, &mut seen);
        collect_interface_types(env, current, interfaces_mid, &mut refs, &mut descriptors, &mut seen);

        let Some(super_cls) = crate::jsapi::java::try_get_superclass(env as u64, current as u64) else {
            break;
        };
        let super_cls = super_cls as *mut c_void;
        refs.push(super_cls);
        current = super_cls;
    }

    for local_ref in refs {
        delete_local_ref(env, local_ref);
    }
    descriptors
}

unsafe fn collect_interface_types(
    env: JniEnv,
    cls: *mut c_void,
    interfaces_mid: Option<*mut c_void>,
    refs: &mut Vec<*mut c_void>,
    descriptors: &mut Vec<TypeCandidate>,
    seen: &mut BTreeSet<String>,
) {
    let Some(interfaces_mid) = interfaces_mid else {
        return;
    };
    let Some(array) = get_interfaces_array(env, cls, interfaces_mid) else {
        return;
    };

    let get_arr_len: GetArrayLengthFn = jni_fn!(env, GetArrayLengthFn, JNI_GET_ARRAY_LENGTH);
    let get_arr_elem: GetObjectArrayElementFn = jni_fn!(env, GetObjectArrayElementFn, JNI_GET_OBJECT_ARRAY_ELEMENT);
    let len = get_arr_len(env, array);
    if jni_check_exc(env) || len <= 0 {
        delete_local_ref(env, array);
        return;
    }

    let mut queue = VecDeque::new();
    for i in 0..len {
        let iface = get_arr_elem(env, array, i);
        if jni_check_exc(env) || iface.is_null() {
            continue;
        }
        refs.push(iface);
        queue.push_back(iface);
    }
    delete_local_ref(env, array);

    while let Some(iface) = queue.pop_front() {
        if !push_type_candidate(env, iface, true, descriptors, seen) {
            continue;
        }
        let Some(parent_array) = get_interfaces_array(env, iface, interfaces_mid) else {
            continue;
        };
        let parent_len = get_arr_len(env, parent_array);
        if jni_check_exc(env) || parent_len <= 0 {
            delete_local_ref(env, parent_array);
            continue;
        }
        for i in 0..parent_len {
            let parent_iface = get_arr_elem(env, parent_array, i);
            if jni_check_exc(env) || parent_iface.is_null() {
                continue;
            }
            refs.push(parent_iface);
            queue.push_back(parent_iface);
        }
        delete_local_ref(env, parent_array);
    }
}

unsafe fn push_type_candidate(
    env: JniEnv,
    cls: *mut c_void,
    is_interface: bool,
    descriptors: &mut Vec<TypeCandidate>,
    seen: &mut BTreeSet<String>,
) -> bool {
    let Some(name) = crate::jsapi::java::try_get_class_name(env as u64, cls as u64) else {
        return false;
    };
    let Ok(desc) = java_class_to_descriptor(&name) else {
        return false;
    };
    if !seen.insert(desc.clone()) {
        return false;
    }
    descriptors.push(TypeCandidate { desc, is_interface });
    true
}

fn pick_common_type(left: &[TypeCandidate], right: &[TypeCandidate]) -> Option<String> {
    let right_descs: BTreeSet<&str> = right.iter().map(|candidate| candidate.desc.as_str()).collect();
    left.iter()
        .find(|candidate| {
            candidate.is_interface
                && !is_low_priority_interface(&candidate.desc)
                && right_descs.contains(candidate.desc.as_str())
        })
        .or_else(|| {
            left.iter().find(|candidate| {
                candidate.is_interface
                    && candidate.desc != "Ljava/lang/Object;"
                    && right_descs.contains(candidate.desc.as_str())
            })
        })
        .or_else(|| {
            left.iter()
                .find(|candidate| !candidate.is_interface && right_descs.contains(candidate.desc.as_str()))
        })
        .map(|candidate| candidate.desc.clone())
}

fn is_low_priority_interface(desc: &str) -> bool {
    matches!(
        desc,
        "Ljava/lang/Cloneable;" | "Ljava/io/Serializable;" | "Ljava/lang/Comparable;"
    )
}

unsafe fn class_is_interface(env: JniEnv, cls: *mut c_void) -> bool {
    let Some(is_interface_mid) = class_is_interface_method_id(env) else {
        return false;
    };
    let call_bool: CallBooleanMethodAFn = jni_fn!(env, CallBooleanMethodAFn, JNI_CALL_BOOLEAN_METHOD_A);
    let result = call_bool(env, cls, is_interface_mid, std::ptr::null());
    !jni_check_exc(env) && result != 0
}

unsafe fn class_get_interfaces_method_id(env: JniEnv) -> Option<*mut c_void> {
    class_method_id(env, "getInterfaces", "()[Ljava/lang/Class;")
}

unsafe fn class_is_interface_method_id(env: JniEnv) -> Option<*mut c_void> {
    class_method_id(env, "isInterface", "()Z")
}

unsafe fn class_method_id(env: JniEnv, name: &str, sig: &str) -> Option<*mut c_void> {
    let class_cls = crate::jsapi::java::reflect::find_class_safe(env, "java.lang.Class");
    if class_cls.is_null() {
        return None;
    }

    let get_mid: GetMethodIdFn = jni_fn!(env, GetMethodIdFn, JNI_GET_METHOD_ID);
    let name = CString::new(name).ok()?;
    let sig = CString::new(sig).ok()?;
    let mid = get_mid(env, class_cls, name.as_ptr(), sig.as_ptr());
    let failed = mid.is_null() || jni_check_exc(env);
    delete_local_ref(env, class_cls);
    if failed {
        None
    } else {
        Some(mid)
    }
}

unsafe fn get_interfaces_array(env: JniEnv, cls: *mut c_void, interfaces_mid: *mut c_void) -> Option<*mut c_void> {
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let array = call_obj(env, cls, interfaces_mid, std::ptr::null());
    if array.is_null() || jni_check_exc(env) {
        None
    } else {
        Some(array)
    }
}

unsafe fn delete_local_ref(env: JniEnv, obj: *mut c_void) {
    if env.is_null() || obj.is_null() {
        return;
    }
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    delete_local_ref(env, obj);
}

pub(super) fn array_component_descriptor(array_desc: &str) -> Result<String, String> {
    array_desc
        .strip_prefix('[')
        .map(|desc| desc.to_string())
        .ok_or_else(|| format!("expected array descriptor, got {}", array_desc))
}

pub(super) fn descriptor_to_java_class_name(desc: &str) -> Result<String, String> {
    let Some(class_desc) = desc.strip_prefix('L').and_then(|value| value.strip_suffix(';')) else {
        return Err(format!(
            "method overload resolution requires object class, got {}",
            desc
        ));
    };
    Ok(class_desc.replace('/', "."))
}

pub(super) fn java_class_to_descriptor_or_primitive(type_name: &str) -> Result<String, String> {
    let trimmed = type_name.trim();
    if trimmed.starts_with('[') {
        validate_descriptor(trimmed, false)?;
        return Ok(trimmed.to_string());
    }
    if trimmed.ends_with("[]") {
        return java_array_type_to_descriptor(trimmed);
    }
    if let Some(value) = primitive_descriptor(trimmed, true) {
        return Ok(value.to_string());
    }
    java_class_to_descriptor(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_value_descriptor_keeps_null_typed_as_reference() {
        let env = std::ptr::null_mut();
        assert_eq!(
            common_value_descriptor_with_env(Some("[[I".to_string()), None, env).unwrap(),
            Some("[[I".to_string())
        );
        assert_eq!(
            common_value_descriptor_with_env(None, Some("Ljava/lang/String;".to_string()), env).unwrap(),
            Some("Ljava/lang/String;".to_string())
        );
    }

    #[test]
    fn common_value_descriptor_preserves_covariant_array_types() {
        let env = std::ptr::null_mut();
        assert_eq!(
            common_value_descriptor_with_env(
                Some("[Ljava/lang/String;".to_string()),
                Some("[Ljava/lang/Object;".to_string()),
                env
            )
            .unwrap(),
            Some("[Ljava/lang/Object;".to_string())
        );
        assert_eq!(
            common_value_descriptor_with_env(
                Some("[[Ljava/lang/String;".to_string()),
                Some("[[Ljava/lang/Object;".to_string()),
                env
            )
            .unwrap(),
            Some("[[Ljava/lang/Object;".to_string())
        );
    }

    #[test]
    fn common_value_descriptor_falls_back_for_incompatible_primitive_arrays() {
        let env = std::ptr::null_mut();
        assert_eq!(
            common_value_descriptor_with_env(Some("[I".to_string()), Some("[J".to_string()), env).unwrap(),
            Some("Ljava/lang/Object;".to_string())
        );
    }
}
