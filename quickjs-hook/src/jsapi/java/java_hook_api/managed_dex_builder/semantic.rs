use std::collections::BTreeMap;

use super::dsl::{
    DslCallKind, DslCallStmt, DslCatch, DslCondition, DslFieldStmt, DslIntBinOp, DslOrigArgs, DslProgram, DslStmt,
    DslTarget, DslUnaryOp, DslValue,
};
use super::{
    array_component_descriptor, common_value_descriptor_with_env, java_class_to_descriptor,
    java_class_to_descriptor_or_primitive, object_assignability_score, resolve_call_proto_with_arg_types,
    resolve_constructor_proto_with_arg_types, resolve_field_with_env, return_is_object,
};
use crate::jsapi::java::jni_core::JniEnv;

struct DslSemanticContext {
    env: JniEnv,
    this_descriptor: Option<String>,
    arg_descriptors: Vec<String>,
    target_return_type: String,
    local_descriptors: BTreeMap<String, String>,
    target_narrow_types: BTreeMap<DslTargetKey, Option<String>>,
    last_descriptor: Option<String>,
    result_descriptor: Option<String>,
    loop_depth: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum DslTargetKey {
    This,
    Arg(usize),
    Local(String),
}

fn dsl_target_key(target: &DslTarget) -> Option<DslTargetKey> {
    match target {
        DslTarget::This => Some(DslTargetKey::This),
        DslTarget::Arg(index) => Some(DslTargetKey::Arg(*index)),
        DslTarget::Local(name) => Some(DslTargetKey::Local(name.clone())),
        DslTarget::Last | DslTarget::Result => None,
    }
}

fn dsl_target_label(target: &DslTarget) -> String {
    match target {
        DslTarget::This => "this".to_string(),
        DslTarget::Arg(index) => format!("arg{}", index),
        DslTarget::Local(name) => name.clone(),
        DslTarget::Last => "last".to_string(),
        DslTarget::Result => "result".to_string(),
    }
}

fn value_descriptor_assignable_to(src: &str, dst: &str) -> bool {
    src == dst || (return_is_object(src) && return_is_object(dst))
}

fn int_literal_assignable_to_descriptor(value: i16, dst: &str) -> bool {
    match dst {
        "B" => i8::try_from(value).is_ok(),
        "S" | "I" => true,
        "C" => value >= 0,
        _ => false,
    }
}

fn value_assignable_to_descriptor(value: &DslValue, src: &str, dst: &str) -> bool {
    value_descriptor_assignable_to(src, dst)
        || matches!(value, DslValue::Int(n) if int_literal_assignable_to_descriptor(*n, dst))
}

fn value_descriptor_assignable_to_strict(env: JniEnv, src: &str, dst: &str) -> bool {
    src == dst || object_assignability_score(env, src, dst).is_some()
}

fn value_assignable_to_descriptor_strict(env: JniEnv, value: &DslValue, src: &str, dst: &str) -> bool {
    value_descriptor_assignable_to_strict(env, src, dst)
        || matches!(value, DslValue::Int(n) if int_literal_assignable_to_descriptor(*n, dst))
}

fn descriptor_is_string(desc: Option<&str>) -> bool {
    desc == Some("Ljava/lang/String;")
}

fn nonnull_key_for_value(value: &DslValue) -> Option<DslTargetKey> {
    let DslValue::Target(target) = value else {
        return None;
    };
    dsl_target_key(target)
}

fn condition_facts_when_true(condition: &DslCondition) -> Vec<(DslTargetKey, Option<String>)> {
    match condition {
        DslCondition::Null { value, invert: true } => nonnull_key_for_value(value)
            .into_iter()
            .map(|key| (key, None))
            .collect(),
        DslCondition::InstanceOf { value, class_name } => nonnull_key_for_value(value)
            .into_iter()
            .map(|key| {
                (
                    key,
                    Some(java_class_to_descriptor(class_name).unwrap_or_else(|_| class_name.clone())),
                )
            })
            .collect(),
        DslCondition::And(left, right) => {
            let mut facts = condition_facts_when_true(left);
            facts.extend(condition_facts_when_true(right));
            facts
        }
        DslCondition::Not(condition) => condition_facts_when_false(condition),
        _ => Vec::new(),
    }
}

fn condition_facts_when_false(condition: &DslCondition) -> Vec<(DslTargetKey, Option<String>)> {
    match condition {
        DslCondition::Null { value, invert: false } => nonnull_key_for_value(value)
            .into_iter()
            .map(|key| (key, None))
            .collect(),
        DslCondition::Or(left, right) => {
            let mut facts = condition_facts_when_false(left);
            facts.extend(condition_facts_when_false(right));
            facts
        }
        DslCondition::Not(condition) => condition_facts_when_true(condition),
        _ => Vec::new(),
    }
}

impl DslSemanticContext {
    fn new(
        env: JniEnv,
        is_static: bool,
        target_type: String,
        target_params: Vec<String>,
        target_return_type: String,
    ) -> Self {
        Self {
            env,
            this_descriptor: if is_static { None } else { Some(target_type) },
            arg_descriptors: target_params,
            target_return_type,
            local_descriptors: BTreeMap::new(),
            target_narrow_types: BTreeMap::new(),
            last_descriptor: None,
            result_descriptor: None,
            loop_depth: 0,
        }
    }

    fn record_last_descriptor(&mut self, descriptor: String) {
        self.last_descriptor = Some(descriptor);
    }

    fn record_result_descriptor(&mut self, descriptor: String) {
        self.result_descriptor = Some(descriptor);
    }

    fn record_value_descriptor(&mut self, descriptor: &str) {
        if return_is_object(descriptor) {
            self.record_last_descriptor(descriptor.to_string());
        } else if descriptor != "V" {
            self.record_result_descriptor(descriptor.to_string());
        }
    }

    fn is_string_concat_operands(&self, left: &DslValue, right: &DslValue) -> Result<bool, String> {
        let left_desc = self.infer_value_descriptor(left)?;
        let right_desc = self.infer_value_descriptor(right)?;
        Ok(descriptor_is_string(left_desc.as_deref()) || descriptor_is_string(right_desc.as_deref()))
    }

    fn validate_int_arg(&mut self, value: &DslValue, label: &str) -> Result<(), String> {
        self.validate_value_inner(value, false)?;
        let Some(desc) = self.infer_value_descriptor(value)? else {
            return Err(format!("{} cannot be null/void", label));
        };
        if !value_assignable_to_descriptor(value, &desc, "I") {
            return Err(format!("{} must be int, got {}", label, desc));
        }
        Ok(())
    }

    fn validate_direct_buffer_arg(&mut self, value: &DslValue, label: &str) -> Result<(), String> {
        self.validate_value_inner(value, false)?;
        let Some(desc) = self.infer_value_descriptor(value)? else {
            return Err(format!("{} cannot be null/void", label));
        };
        if !value_assignable_to_descriptor_strict(self.env, value, &desc, "Ljava/nio/ByteBuffer;") {
            return Err(format!("{} must be java.nio.ByteBuffer, got {}", label, desc));
        }
        Ok(())
    }

    fn resolve_target_descriptor(&self, target: &DslTarget) -> Result<String, String> {
        if let Some(key) = dsl_target_key(target) {
            if let Some(Some(desc)) = self.target_narrow_types.get(&key) {
                return Ok(desc.clone());
            }
        }
        match target {
            DslTarget::This => self
                .this_descriptor
                .clone()
                .ok_or_else(|| "static target has no this descriptor".to_string()),
            DslTarget::Arg(index) => self
                .arg_descriptors
                .get(*index)
                .cloned()
                .ok_or_else(|| format!("argument {} does not exist", index)),
            DslTarget::Local(name) => self
                .local_descriptors
                .get(name)
                .cloned()
                .ok_or_else(|| format!("local '{}' is not declared", name)),
            DslTarget::Last => self
                .last_descriptor
                .clone()
                .ok_or_else(|| "last has no known object type yet".to_string()),
            DslTarget::Result => self
                .result_descriptor
                .clone()
                .ok_or_else(|| "result has no known primitive type yet".to_string()),
        }
    }

    fn resolve_member_class_type(
        &self,
        explicit_class_name: Option<&str>,
        target: Option<&DslTarget>,
        receiver: Option<&DslValue>,
    ) -> Result<String, String> {
        if let Some(class_name) = explicit_class_name {
            return java_class_to_descriptor(class_name);
        }
        if let Some(receiver) = receiver {
            let Some(desc) = self.infer_value_descriptor(receiver)? else {
                return Err("receiver class cannot be inferred from null/void expression".to_string());
            };
            if !desc.starts_with('L') || !desc.ends_with(';') {
                return Err(format!(
                    "receiver class can only be inferred from object expressions, got {}",
                    desc
                ));
            }
            return Ok(desc);
        }
        let Some(target) = target else {
            return Err("static member access requires an explicit class name".to_string());
        };
        let desc = self.resolve_target_descriptor(target)?;
        if !desc.starts_with('L') || !desc.ends_with(';') {
            return Err(format!(
                "target class can only be inferred from object locals/args, got {}",
                desc
            ));
        }
        Ok(desc)
    }

    fn infer_value_descriptor(&self, value: &DslValue) -> Result<Option<String>, String> {
        match value {
            DslValue::Target(target) => self.resolve_target_descriptor(target).map(Some),
            DslValue::String(_) => Ok(Some("Ljava/lang/String;".to_string())),
            DslValue::Int(_)
            | DslValue::ArrayLength(_)
            | DslValue::DirectBufferCapacity { .. }
            | DslValue::DirectBufferGetU8 { .. } => {
                Ok(Some("I".to_string()))
            }
            DslValue::IntBinOp { op, left, right } => {
                if *op == DslIntBinOp::Add {
                    let left_desc = self.infer_value_descriptor(left)?;
                    let right_desc = self.infer_value_descriptor(right)?;
                    if descriptor_is_string(left_desc.as_deref()) || descriptor_is_string(right_desc.as_deref()) {
                        return Ok(Some("Ljava/lang/String;".to_string()));
                    }
                }
                Ok(Some("I".to_string()))
            }
            DslValue::DefaultValue { type_name } => java_class_to_descriptor_or_primitive(type_name).map(Some),
            DslValue::UnaryOp { op, .. } => match op {
                DslUnaryOp::Neg | DslUnaryOp::BitNot => Ok(Some("I".to_string())),
                DslUnaryOp::BoolNot => Ok(Some("Z".to_string())),
            },
            DslValue::Ternary {
                then_value, else_value, ..
            } => {
                let then_desc = self.infer_value_descriptor(then_value)?;
                let else_desc = self.infer_value_descriptor(else_value)?;
                common_value_descriptor_with_env(then_desc, else_desc, self.env)
            }
            DslValue::Bool(_) => Ok(Some("Z".to_string())),
            DslValue::Null => Ok(None),
            DslValue::OrigCall(_) => {
                if self.target_return_type == "V" {
                    Ok(None)
                } else {
                    Ok(Some(self.target_return_type.clone()))
                }
            }
            DslValue::Call(stmt) => {
                let class_type = self.resolve_member_class_type(
                    stmt.class_name.as_deref(),
                    stmt.target.as_ref(),
                    stmt.receiver.as_deref(),
                )?;
                let arg_types = self.infer_call_arg_descriptors(stmt)?;
                let (_, return_type, _) =
                    resolve_call_proto_with_arg_types(self.env, stmt, &class_type, Some(&arg_types))?;
                if return_type == "V" {
                    Ok(None)
                } else {
                    Ok(Some(return_type))
                }
            }
            DslValue::NewObject { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
            DslValue::NewArray { array_type_name, .. } => {
                java_class_to_descriptor_or_primitive(array_type_name).map(Some)
            }
            DslValue::FieldGet { stmt, is_static } => self.resolve_field_descriptor(stmt, *is_static).map(Some),
            DslValue::Cast { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
            DslValue::ArrayGet { type_name, array, .. } => match type_name {
                Some(type_name) => java_class_to_descriptor_or_primitive(type_name).map(Some),
                None => {
                    let Some(array_desc) = self.infer_value_descriptor(array)? else {
                        return Ok(None);
                    };
                    array_component_descriptor(&array_desc).map(Some)
                }
            },
            DslValue::ArrayLiteral { elements } => self.infer_array_literal_descriptor(elements),
        }
    }

    fn infer_array_literal_descriptor(&self, elements: &[DslValue]) -> Result<Option<String>, String> {
        let mut component = None;
        let mut saw_null_before_type = false;
        for element in elements {
            let element_desc = self.infer_value_descriptor(element)?;
            match (&component, element_desc) {
                (None, Some(desc)) => {
                    if saw_null_before_type && !return_is_object(&desc) {
                        return Err(format!("array literal null element cannot be assigned to {}", desc));
                    }
                    component = Some(desc);
                }
                (None, None) => {
                    saw_null_before_type = true;
                }
                (Some(_), desc) => {
                    component = common_value_descriptor_with_env(component, desc, self.env)?;
                }
            }
        }
        let Some(component) = component else {
            return Ok(None);
        };
        Ok(Some(format!("[{}", component)))
    }

    fn is_known_nonnull_target(&self, target: &DslTarget) -> bool {
        matches!(target, DslTarget::This)
            || dsl_target_key(target)
                .map(|key| self.target_narrow_types.contains_key(&key))
                .unwrap_or(false)
    }

    fn validate_receiver_nonnull(&self, stmt: &DslCallStmt, class_type: &str) -> Result<(), String> {
        if stmt.kind == DslCallKind::Static || !return_is_object(class_type) {
            return Ok(());
        }
        if stmt.receiver.is_some() {
            return Ok(());
        }
        let Some(target) = stmt.target.as_ref() else {
            return Ok(());
        };
        if self.is_known_nonnull_target(target) {
            return Ok(());
        }
        Err(format!(
            "receiver '{}' may be null before calling {}.{}; guard it with '{} != null' first",
            dsl_target_label(target),
            stmt.class_label(),
            stmt.method_name,
            dsl_target_label(target)
        ))
    }

    fn validate_value(&mut self, value: &DslValue) -> Result<(), String> {
        self.validate_value_inner(value, false)
    }

    fn validate_value_for_expected(
        &mut self,
        value: &DslValue,
        expected_desc: &str,
        require_nonnull_receiver: bool,
    ) -> Result<(), String> {
        if let DslValue::ArrayLiteral { elements } = value {
            return self.validate_array_literal_for_expected(elements, expected_desc, require_nonnull_receiver);
        }
        self.validate_value_inner(value, require_nonnull_receiver)?;
        if let Some(value_desc) = self.infer_value_descriptor(value)? {
            if !value_assignable_to_descriptor(value, &value_desc, expected_desc) {
                return Err(format!(
                    "value type mismatch: cannot assign {} to {}",
                    value_desc, expected_desc
                ));
            }
        } else if !return_is_object(expected_desc) {
            return Err(format!(
                "value type mismatch: cannot assign null/void to {}",
                expected_desc
            ));
        }
        Ok(())
    }

    fn validate_array_literal_for_expected(
        &mut self,
        elements: &[DslValue],
        expected_desc: &str,
        require_nonnull_receiver: bool,
    ) -> Result<(), String> {
        if !expected_desc.starts_with('[') {
            return Err(format!("array literal cannot be assigned to {}", expected_desc));
        }
        let component_desc = array_component_descriptor(expected_desc)?;
        for element in elements {
            if matches!(element, DslValue::Null) {
                if !return_is_object(&component_desc) {
                    return Err(format!(
                        "array literal null element cannot be assigned to {}",
                        component_desc
                    ));
                }
                continue;
            }
            self.validate_value_for_expected(element, &component_desc, require_nonnull_receiver)?;
        }
        Ok(())
    }

    fn validate_bool_condition_value(&mut self, value: &DslValue) -> Result<(), String> {
        self.validate_value_inner(value, true)?;
        let Some(desc) = self.infer_value_descriptor(value)? else {
            return Err("boolean condition requires boolean, got null/void".to_string());
        };
        if desc != "Z" {
            return Err(format!("boolean condition requires boolean, got {}", desc));
        }
        Ok(())
    }

    fn validate_value_inner(&mut self, value: &DslValue, require_nonnull_receiver: bool) -> Result<(), String> {
        match value {
            DslValue::Target(target) => {
                self.resolve_target_descriptor(target)?;
            }
            DslValue::String(_) | DslValue::Int(_) | DslValue::Bool(_) | DslValue::Null => {}
            DslValue::DefaultValue { type_name } => {
                let desc = java_class_to_descriptor_or_primitive(type_name)?;
                if desc == "V" {
                    return Err("default local value cannot have void type".to_string());
                }
                if matches!(desc.as_str(), "J" | "D") {
                    return Err(format!("default local value for {} is not supported yet", desc));
                }
            }
            DslValue::UnaryOp { op, value } => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
                let Some(desc) = self.infer_value_descriptor(value)? else {
                    return Err("unary expression type cannot be inferred".to_string());
                };
                match op {
                    DslUnaryOp::Neg | DslUnaryOp::BitNot if desc != "I" => {
                        return Err(format!("int unary expression requires int, got {}", desc));
                    }
                    DslUnaryOp::BoolNot if desc != "Z" => {
                        return Err(format!("boolean unary expression requires boolean, got {}", desc));
                    }
                    _ => {}
                }
            }
            DslValue::ArrayLength(value) => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
            }
            DslValue::IntBinOp { op, left, right } => {
                self.validate_value_inner(left, require_nonnull_receiver)?;
                self.validate_value_inner(right, require_nonnull_receiver)?;
                if *op == DslIntBinOp::Add && self.is_string_concat_operands(left, right)? {
                    return Ok(());
                }
                let Some(left_desc) = self.infer_value_descriptor(left)? else {
                    return Err("int binary expression requires int, got null/void".to_string());
                };
                let Some(right_desc) = self.infer_value_descriptor(right)? else {
                    return Err("int binary expression requires int, got null/void".to_string());
                };
                if left_desc != "I" || right_desc != "I" {
                    return Err(format!(
                        "int binary expression requires int operands, got {} and {}",
                        left_desc, right_desc
                    ));
                }
            }
            DslValue::Ternary {
                condition,
                then_value,
                else_value,
            } => {
                self.validate_condition(condition)?;
                let true_facts = condition_facts_when_true(condition);
                self.validate_with_target_facts(&true_facts, |ctx| {
                    ctx.validate_value_inner(then_value, require_nonnull_receiver)
                })?;
                let false_facts = condition_facts_when_false(condition);
                self.validate_with_target_facts(&false_facts, |ctx| {
                    ctx.validate_value_inner(else_value, require_nonnull_receiver)
                })?;
                let _ = self.infer_value_descriptor(value)?;
            }
            DslValue::DirectBufferCapacity { buffer } => {
                self.validate_value_inner(buffer, require_nonnull_receiver)?;
                let Some(buffer_desc) = self.infer_value_descriptor(buffer)? else {
                    return Err("dbbCapacity() buffer cannot be null/void".to_string());
                };
                if !value_assignable_to_descriptor_strict(
                    self.env,
                    buffer,
                    &buffer_desc,
                    "Ljava/nio/ByteBuffer;",
                ) {
                    return Err(format!(
                        "dbbCapacity() buffer must be java.nio.ByteBuffer, got {}",
                        buffer_desc
                    ));
                }
            }
            DslValue::DirectBufferGetU8 { buffer, offset } => {
                self.validate_direct_buffer_arg(buffer, "dbbGetU8() buffer")?;
                self.validate_int_arg(offset, "dbbGetU8() offset")?;
            }
            DslValue::Cast { value, class_name } => {
                self.validate_value_inner(value, require_nonnull_receiver)?;
                java_class_to_descriptor(class_name)?;
            }
            DslValue::ArrayGet { array, index, .. } => {
                self.validate_value_inner(array, require_nonnull_receiver)?;
                self.validate_value_inner(index, require_nonnull_receiver)?;
                if self.infer_value_descriptor(array)?.is_none() {
                    return Err("array element type cannot be inferred; use arr[index: Type]".to_string());
                }
            }
            DslValue::ArrayLiteral { elements } => {
                if elements.is_empty() {
                    return Err(
                        "empty array literal type cannot be inferred; assign from new Type[](size)".to_string(),
                    );
                }
                for element in elements {
                    self.validate_value_inner(element, require_nonnull_receiver)?;
                }
                let Some(array_desc) = self.infer_array_literal_descriptor(elements)? else {
                    return Err("array literal type cannot be inferred from null-only elements".to_string());
                };
                let component = array_component_descriptor(&array_desc)?;
                for element in elements {
                    if let Some(element_desc) = self.infer_value_descriptor(element)? {
                        if !value_assignable_to_descriptor(element, &element_desc, &component) {
                            return Err(format!(
                                "array literal element type mismatch: cannot store {} in {}",
                                element_desc, component
                            ));
                        }
                    } else if !return_is_object(&component) {
                        return Err(format!(
                            "array literal element type mismatch: cannot store null in {}",
                            component
                        ));
                    }
                }
            }
            DslValue::OrigCall(args) => {
                if self.target_return_type == "V" {
                    return Err("void orig() cannot be used as a value".to_string());
                }
                self.validate_orig_args(args)?;
            }
            DslValue::NewObject {
                class_name,
                ctor_sig,
                args,
            } => {
                java_class_to_descriptor(class_name)?;
                let arg_types = args
                    .iter()
                    .map(|arg| self.infer_value_descriptor(arg))
                    .collect::<Result<Vec<_>, _>>()?;
                let (params, full_sig) =
                    resolve_constructor_proto_with_arg_types(self.env, class_name, ctor_sig.as_deref(), &arg_types)?;
                if params.len() != args.len() {
                    return Err(format!(
                        "{}.<init>{} expects {} explicit args, got {}",
                        class_name,
                        full_sig,
                        params.len(),
                        args.len()
                    ));
                }
                for arg in args {
                    self.validate_value_inner(arg, require_nonnull_receiver)?;
                }
            }
            DslValue::NewArray { array_type_name, size } => {
                let desc = java_class_to_descriptor_or_primitive(array_type_name)?;
                if !desc.starts_with('[') {
                    return Err(format!("new array requires an array type, got '{}'", array_type_name));
                }
                self.validate_value_inner(size, require_nonnull_receiver)?;
                if self.infer_value_descriptor(size)?.as_deref() != Some("I") {
                    return Err("new array size must be int".to_string());
                }
            }
            DslValue::Call(stmt) => {
                if let Some(receiver) = &stmt.receiver {
                    self.validate_value_inner(receiver, require_nonnull_receiver)?;
                }
                self.validate_call_inner(stmt, require_nonnull_receiver)?;
            }
            DslValue::FieldGet { stmt, is_static } => {
                if let Some(receiver) = &stmt.receiver {
                    self.validate_value_inner(receiver, require_nonnull_receiver)?;
                }
                self.validate_field(stmt, *is_static)?;
            }
        }
        Ok(())
    }

    fn validate_condition(&mut self, condition: &DslCondition) -> Result<(), String> {
        match condition {
            DslCondition::Const(_) => {}
            DslCondition::Null { value, .. } => {
                self.validate_value(value)?;
            }
            DslCondition::Bool { value } => {
                self.validate_bool_condition_value(value)?;
            }
            DslCondition::Cmp { left, right, .. } => {
                self.validate_value(left)?;
                self.validate_value(right)?;
            }
            DslCondition::InstanceOf { value, class_name } => {
                self.validate_value(value)?;
                java_class_to_descriptor(class_name)?;
            }
            DslCondition::And(left, right) => {
                self.validate_condition(left)?;
                let facts = condition_facts_when_true(left);
                self.validate_with_target_facts(&facts, |ctx| ctx.validate_condition(right))?;
            }
            DslCondition::Or(left, right) => {
                self.validate_condition(left)?;
                let facts = condition_facts_when_false(left);
                self.validate_with_target_facts(&facts, |ctx| ctx.validate_condition(right))?;
            }
            DslCondition::Not(condition) => self.validate_condition(condition)?,
        }
        Ok(())
    }

    fn validate_call(&mut self, stmt: &DslCallStmt) -> Result<(), String> {
        self.validate_call_inner(stmt, false)
    }

    fn validate_call_inner(&mut self, stmt: &DslCallStmt, require_nonnull_receiver: bool) -> Result<(), String> {
        if stmt.target.is_some() && stmt.receiver.is_some() {
            return Err("method call cannot use both target and receiver expression".to_string());
        }
        if stmt.kind == DslCallKind::Static && stmt.receiver.is_some() {
            return Err("static method call cannot use a receiver expression".to_string());
        }
        if stmt.null_safe && stmt.kind == DslCallKind::Static {
            return Err("null-safe call is only valid for instance/interface methods".to_string());
        }
        if stmt.null_safe && stmt.target.is_none() && stmt.receiver.is_none() {
            return Err("null-safe call requires a receiver".to_string());
        }
        let class_type = self.resolve_member_class_type(
            stmt.class_name.as_deref(),
            stmt.target.as_ref(),
            stmt.receiver.as_deref(),
        )?;
        let arg_types = self.infer_call_arg_descriptors(stmt)?;
        let (params, _, full_sig) = resolve_call_proto_with_arg_types(self.env, stmt, &class_type, Some(&arg_types))?;
        if require_nonnull_receiver {
            self.validate_receiver_nonnull(stmt, &class_type)?;
        }
        if let Some(receiver) = &stmt.receiver {
            self.validate_value_inner(receiver, require_nonnull_receiver)?;
        }
        if params.len() != stmt.args.len() {
            return Err(format!(
                "{}.{}{} expects {} explicit args, got {}",
                stmt.class_label(),
                stmt.method_name,
                full_sig,
                params.len(),
                stmt.args.len()
            ));
        }
        for (arg, param) in stmt.args.iter().zip(&params) {
            self.validate_value_for_expected(arg, param, require_nonnull_receiver)?;
        }
        Ok(())
    }

    fn infer_call_arg_descriptors(&self, stmt: &DslCallStmt) -> Result<Vec<Option<String>>, String> {
        stmt.args
            .iter()
            .map(|arg| self.infer_value_descriptor(arg))
            .collect::<Result<Vec<_>, _>>()
    }

    fn resolve_field_descriptor(&self, stmt: &DslFieldStmt, is_static: bool) -> Result<String, String> {
        if !stmt.type_name.is_empty() {
            return java_class_to_descriptor_or_primitive(&stmt.type_name);
        }
        let class_type = self.resolve_member_class_type(
            stmt.class_name.as_deref(),
            stmt.target.as_ref(),
            stmt.receiver.as_deref(),
        )?;
        resolve_field_with_env(self.env, &class_type, &stmt.field_name, Some(is_static)).map(|field| field.field_type)
    }

    fn validate_field(&mut self, stmt: &DslFieldStmt, is_static: bool) -> Result<(), String> {
        if stmt.target.is_some() && stmt.receiver.is_some() {
            return Err("field access cannot use both target and receiver expression".to_string());
        }
        self.resolve_member_class_type(
            stmt.class_name.as_deref(),
            stmt.target.as_ref(),
            stmt.receiver.as_deref(),
        )?;
        if let Some(receiver) = &stmt.receiver {
            self.validate_value(receiver)?;
        }
        let descriptor = self.resolve_field_descriptor(stmt, is_static)?;
        if let Some(value) = &stmt.value {
            self.validate_value_for_expected(value, &descriptor, false)?;
            if let Some(value_desc) = self.infer_value_descriptor(value)? {
                if !value_assignable_to_descriptor(value, &value_desc, &descriptor) {
                    return Err(format!(
                        "field '{}' type mismatch: cannot assign {} to {}",
                        stmt.field_name, value_desc, descriptor
                    ));
                }
            } else if !return_is_object(&descriptor) {
                return Err(format!(
                    "field '{}' type mismatch: cannot assign null/void to {}",
                    stmt.field_name, descriptor
                ));
            }
        }
        Ok(())
    }

    fn validate_orig_args(&mut self, args: &DslOrigArgs) -> Result<(), String> {
        let DslOrigArgs::Values(values) = args else {
            return Ok(());
        };
        if values.len() != self.arg_descriptors.len() {
            return Err(format!(
                "orig(...) expects {} argument(s), got {}",
                self.arg_descriptors.len(),
                values.len()
            ));
        }
        let expected_descriptors = self.arg_descriptors.clone();
        for (index, (value, expected_desc)) in values.iter().zip(&expected_descriptors).enumerate() {
            self.validate_value_for_expected(value, expected_desc, false)?;
            if let Some(value_desc) = self.infer_value_descriptor(value)? {
                if !value_assignable_to_descriptor_strict(self.env, value, &value_desc, expected_desc) {
                    return Err(format!(
                        "orig(arg{}) type mismatch: cannot pass {} as {}",
                        index, value_desc, expected_desc
                    ));
                }
            } else if !return_is_object(expected_desc) {
                return Err(format!(
                    "orig(arg{}) type mismatch: cannot pass null/void as {}",
                    index, expected_desc
                ));
            }
        }
        Ok(())
    }

    fn validate_stmts(&mut self, stmts: &[DslStmt]) -> Result<(), String> {
        for stmt in stmts {
            self.validate_stmt(stmt)?;
        }
        Ok(())
    }

    fn validate_stmts_with_nonnull_value(&mut self, value: &DslValue, stmts: &[DslStmt]) -> Result<(), String> {
        let Some(key) = nonnull_key_for_value(value) else {
            return self.validate_stmts(stmts);
        };
        self.validate_with_target_facts(&[(key, None)], |ctx| ctx.validate_stmts(stmts))
    }

    fn validate_with_target_facts<F>(&mut self, facts: &[(DslTargetKey, Option<String>)], f: F) -> Result<(), String>
    where
        F: FnOnce(&mut Self) -> Result<(), String>,
    {
        let previous = facts
            .iter()
            .map(|(key, desc)| {
                let old = self.target_narrow_types.insert(key.clone(), desc.clone());
                (key.clone(), old)
            })
            .collect::<Vec<_>>();
        let result = f(self);
        for (key, old) in previous.into_iter().rev() {
            if let Some(old) = old {
                self.target_narrow_types.insert(key, old);
            } else {
                self.target_narrow_types.remove(&key);
            }
        }
        result
    }

    fn validate_stmt(&mut self, stmt: &DslStmt) -> Result<(), String> {
        match stmt {
            DslStmt::Block(stmts) => self.validate_stmts(stmts)?,
            DslStmt::Let { name, type_name, value } => {
                let descriptor = if let Some(type_name) = type_name {
                    let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
                    self.validate_value_for_expected(value, &descriptor, false)?;
                    if let Some(value_desc) = self.infer_value_descriptor(value)? {
                        if !value_assignable_to_descriptor(value, &value_desc, &descriptor) {
                            return Err(format!(
                                "local '{}' type mismatch: cannot assign {} to {}",
                                name, value_desc, descriptor
                            ));
                        }
                    } else if !return_is_object(&descriptor) {
                        return Err(format!(
                            "local '{}' type mismatch: cannot assign null/void to {}",
                            name, descriptor
                        ));
                    }
                    descriptor
                } else {
                    self.validate_value(value)?;
                    self.infer_value_descriptor(value)?
                        .ok_or_else(|| format!("local '{}' type cannot be inferred", name))?
                };
                self.local_descriptors.entry(name.clone()).or_insert(descriptor);
            }
            DslStmt::Assign { name, value } => {
                let Some(descriptor) = self.local_descriptors.get(name).cloned() else {
                    return Err(format!("local '{}' is not declared", name));
                };
                self.validate_value_for_expected(value, &descriptor, false)?;
                if let Some(value_desc) = self.infer_value_descriptor(value)? {
                    if !value_assignable_to_descriptor(value, &value_desc, &descriptor) {
                        return Err(format!(
                            "local '{}' type mismatch: cannot assign {} to {}",
                            name, value_desc, descriptor
                        ));
                    }
                } else if !return_is_object(&descriptor) {
                    return Err(format!(
                        "local '{}' type mismatch: cannot assign null/void to {}",
                        name, descriptor
                    ));
                }
            }
            DslStmt::LetOrig { name, type_name, args } => {
                if self.target_return_type == "V" {
                    return Err("void orig() cannot be assigned to a local".to_string());
                }
                let descriptor = if let Some(type_name) = type_name {
                    let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
                    if !value_descriptor_assignable_to(&self.target_return_type, &descriptor) {
                        return Err(format!(
                            "orig() return type {} cannot be assigned to {}",
                            self.target_return_type, descriptor
                        ));
                    }
                    descriptor
                } else {
                    self.target_return_type.clone()
                };
                self.validate_orig_args(args)?;
                self.local_descriptors.entry(name.clone()).or_insert(descriptor);
            }
            DslStmt::New {
                class_name,
                ctor_sig,
                args,
            } => {
                self.validate_value(&DslValue::NewObject {
                    class_name: class_name.clone(),
                    ctor_sig: ctor_sig.clone(),
                    args: args.clone(),
                })?;
                self.record_last_descriptor(java_class_to_descriptor(class_name)?);
            }
            DslStmt::NewArray { array_type_name, size } => {
                let desc = java_class_to_descriptor_or_primitive(array_type_name)?;
                if !desc.starts_with('[') {
                    return Err(format!("new array requires an array type, got '{}'", array_type_name));
                }
                self.validate_value(size)?;
                self.record_last_descriptor(desc);
            }
            DslStmt::Call(stmt) => {
                self.validate_call(stmt)?;
                let class_type = self.resolve_member_class_type(
                    stmt.class_name.as_deref(),
                    stmt.target.as_ref(),
                    stmt.receiver.as_deref(),
                )?;
                let arg_types = self.infer_call_arg_descriptors(stmt)?;
                let (_, return_type, _) =
                    resolve_call_proto_with_arg_types(self.env, stmt, &class_type, Some(&arg_types))?;
                self.record_value_descriptor(&return_type);
            }
            DslStmt::Cast { value, class_name } => {
                self.validate_value(value)?;
                self.record_last_descriptor(java_class_to_descriptor(class_name)?);
            }
            DslStmt::ArrayLength { array } => {
                self.validate_value(array)?;
                self.record_result_descriptor("I".to_string());
            }
            DslStmt::ArrayGet {
                array,
                index,
                type_name,
            } => {
                self.validate_value(array)?;
                self.validate_value(index)?;
                if let Some(type_name) = type_name {
                    let component = java_class_to_descriptor_or_primitive(type_name)?;
                    self.record_value_descriptor(&component);
                } else if self.infer_value_descriptor(array)?.is_none() {
                    return Err("array element type cannot be inferred; use arr[index: Type]".to_string());
                } else {
                    let array_desc = self
                        .infer_value_descriptor(array)?
                        .ok_or_else(|| "array element type cannot be inferred; use arr[index: Type]".to_string())?;
                    let component = array_component_descriptor(&array_desc)?;
                    self.record_value_descriptor(&component);
                }
            }
            DslStmt::ArrayPut {
                array,
                index,
                type_name,
                value,
            } => {
                self.validate_value(array)?;
                self.validate_value(index)?;
                let component = if let Some(type_name) = type_name {
                    java_class_to_descriptor_or_primitive(type_name)?
                } else {
                    let array_desc = self
                        .infer_value_descriptor(array)?
                        .ok_or_else(|| "array element type cannot be inferred; use arr[index: Type]".to_string())?;
                    array_component_descriptor(&array_desc)?
                };
                self.validate_value_for_expected(value, &component, false)?;
            }
            DslStmt::ArrayUpdate {
                array,
                index,
                type_name,
                value,
                ..
            } => {
                self.validate_value(array)?;
                self.validate_value(index)?;
                self.validate_value(value)?;
                let component = if let Some(type_name) = type_name {
                    java_class_to_descriptor_or_primitive(type_name)?
                } else {
                    let array_desc = self
                        .infer_value_descriptor(array)?
                        .ok_or_else(|| "array element type cannot be inferred; use arr[index: int]".to_string())?;
                    array_component_descriptor(&array_desc)?
                };
                if component != "I" {
                    return Err(format!(
                        "array compound assignment requires int element, got {}",
                        component
                    ));
                }
                if self.infer_value_descriptor(value)?.as_deref() != Some("I") {
                    return Err("array compound assignment rhs must be int".to_string());
                }
            }
            DslStmt::FieldRead { stmt, is_static } => {
                self.validate_field(stmt, *is_static)?;
                let descriptor = self.resolve_field_descriptor(stmt, *is_static)?;
                self.record_value_descriptor(&descriptor);
            }
            DslStmt::FieldWrite { stmt, is_static } => {
                self.validate_field(stmt, *is_static)?;
            }
            DslStmt::FieldUpdate {
                stmt, is_static, value, ..
            } => {
                self.validate_field(stmt, *is_static)?;
                self.validate_value(value)?;
                let descriptor = self.resolve_field_descriptor(stmt, *is_static)?;
                if descriptor != "I" {
                    return Err(format!(
                        "field '{}' compound assignment requires int field, got {}",
                        stmt.field_name, descriptor
                    ));
                }
                if self.infer_value_descriptor(value)?.as_deref() != Some("I") {
                    return Err(format!(
                        "field '{}' compound assignment rhs must be int",
                        stmt.field_name
                    ));
                }
            }
            DslStmt::IfNull {
                value,
                invert,
                then_stmts,
                else_stmts,
            } => {
                self.validate_value(value)?;
                if *invert {
                    self.validate_stmts_with_nonnull_value(value, then_stmts)?;
                    self.validate_stmts(else_stmts)?;
                } else {
                    self.validate_stmts(then_stmts)?;
                    self.validate_stmts_with_nonnull_value(value, else_stmts)?;
                }
            }
            DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            } => {
                self.validate_bool_condition_value(value)?;
                self.validate_stmts(then_stmts)?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::IfInstanceOf {
                value,
                class_name,
                then_stmts,
                else_stmts,
            } => {
                self.validate_value(value)?;
                let ty = java_class_to_descriptor(class_name)?;
                let facts = nonnull_key_for_value(value)
                    .into_iter()
                    .map(|key| (key, Some(ty.clone())))
                    .collect::<Vec<_>>();
                self.validate_with_target_facts(&facts, |ctx| ctx.validate_stmts(then_stmts))?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::IfCmp {
                left,
                right,
                then_stmts,
                else_stmts,
                ..
            } => {
                self.validate_value(left)?;
                self.validate_value(right)?;
                self.validate_stmts(then_stmts)?;
                self.validate_stmts(else_stmts)?;
            }
            DslStmt::Switch {
                value,
                cases,
                default_stmts,
            } => {
                self.validate_value(value)?;
                for (_, stmts) in cases {
                    self.validate_stmts(stmts)?;
                }
                if let Some(stmts) = default_stmts {
                    self.validate_stmts(stmts)?;
                }
            }
            DslStmt::TryCatch { try_stmts, catches } => {
                self.validate_catch_order(catches)?;
                self.validate_stmts(try_stmts)?;
                for catch in catches {
                    self.validate_catch_block(catch)?;
                }
            }
            DslStmt::While { condition, body_stmts } => {
                self.validate_condition(condition)?;
                let facts = condition_facts_when_true(condition);
                self.loop_depth += 1;
                let result = self.validate_with_target_facts(&facts, |ctx| ctx.validate_stmts(body_stmts));
                self.loop_depth -= 1;
                result?;
            }
            DslStmt::DoWhile { body_stmts, condition } => {
                self.loop_depth += 1;
                let result = self.validate_stmts(body_stmts);
                self.loop_depth -= 1;
                result?;
                self.validate_condition(condition)?;
            }
            DslStmt::For {
                init_stmts,
                condition,
                update_stmts,
                body_stmts,
            } => {
                for stmt in init_stmts {
                    self.validate_stmt(stmt)?;
                }
                let facts = if let Some(condition) = condition {
                    self.validate_condition(condition)?;
                    condition_facts_when_true(condition)
                } else {
                    Vec::new()
                };
                self.loop_depth += 1;
                let result = self.validate_with_target_facts(&facts, |ctx| ctx.validate_stmts(body_stmts));
                let update_result: Result<(), String> = if result.is_ok() {
                    for stmt in update_stmts {
                        self.validate_stmt(stmt).map_err(|err| format!("for update: {}", err))?;
                    }
                    Ok(())
                } else {
                    Ok(())
                };
                self.loop_depth -= 1;
                result?;
                update_result?;
            }
            DslStmt::Break | DslStmt::Continue => {
                if self.loop_depth == 0 {
                    return Err("break/continue can only be used inside a loop".to_string());
                }
            }
            DslStmt::Count { name } => {
                if name.is_empty() {
                    return Err("count() name must not be empty".to_string());
                }
            }
            DslStmt::Send { name, value } => {
                if name.is_empty() {
                    return Err("send() channel name must not be empty".to_string());
                }
                let Some(value_desc) = self.infer_value_descriptor(value)? else {
                    return Err("send() value cannot be null; use an int or java.lang.String".to_string());
                };
                if value_desc != "I" && value_desc != "Ljava/lang/String;" {
                    return Err(format!(
                        "send() value must be int or java.lang.String, got {}",
                        value_desc
                    ));
                }
            }
            DslStmt::DirectBufferFill {
                buffer,
                offset,
                length,
                value,
            } => {
                self.validate_direct_buffer_arg(buffer, "dbbFill() buffer")?;
                self.validate_int_arg(offset, "dbbFill() offset")?;
                self.validate_int_arg(length, "dbbFill() length")?;
                self.validate_int_arg(value, "dbbFill() value")?;
            }
            DslStmt::DirectBufferCopyFromByteArray {
                buffer,
                dst_offset,
                src,
                src_offset,
                length,
            } => {
                self.validate_direct_buffer_arg(buffer, "dbbCopyFromByteArray() buffer")?;
                self.validate_int_arg(dst_offset, "dbbCopyFromByteArray() dstOffset")?;
                self.validate_value_inner(src, false)?;
                let Some(src_desc) = self.infer_value_descriptor(src)? else {
                    return Err("dbbCopyFromByteArray() src cannot be null/void".to_string());
                };
                if src_desc != "[B" {
                    return Err(format!(
                        "dbbCopyFromByteArray() src must be byte[], got {}",
                        src_desc
                    ));
                }
                self.validate_int_arg(src_offset, "dbbCopyFromByteArray() srcOffset")?;
                self.validate_int_arg(length, "dbbCopyFromByteArray() length")?;
            }
            DslStmt::DirectBufferCopyToByteArray {
                buffer,
                src_offset,
                dst,
                dst_offset,
                length,
            } => {
                self.validate_direct_buffer_arg(buffer, "dbbCopyToByteArray() buffer")?;
                self.validate_int_arg(src_offset, "dbbCopyToByteArray() srcOffset")?;
                self.validate_value_inner(dst, false)?;
                let Some(dst_desc) = self.infer_value_descriptor(dst)? else {
                    return Err("dbbCopyToByteArray() dst cannot be null/void".to_string());
                };
                if dst_desc != "[B" {
                    return Err(format!("dbbCopyToByteArray() dst must be byte[], got {}", dst_desc));
                }
                self.validate_int_arg(dst_offset, "dbbCopyToByteArray() dstOffset")?;
                self.validate_int_arg(length, "dbbCopyToByteArray() length")?;
            }
            DslStmt::ReturnOrig { args } => self.validate_orig_args(args)?,
            DslStmt::ReturnValue { value } => {
                if let Some(value) = value {
                    let expected_desc = self.target_return_type.clone();
                    self.validate_value_for_expected(value, &expected_desc, false)?;
                    if let Some(value_desc) = self.infer_value_descriptor(value)? {
                        if !value_assignable_to_descriptor_strict(
                            self.env,
                            value,
                            &value_desc,
                            &self.target_return_type,
                        ) {
                            return Err(format!(
                                "return type mismatch: cannot return {} from {} method",
                                value_desc, self.target_return_type
                            ));
                        }
                    } else if !return_is_object(&self.target_return_type) && self.target_return_type != "V" {
                        return Err(format!(
                            "return type mismatch: cannot return null/void from {} method",
                            self.target_return_type
                        ));
                    }
                } else if self.target_return_type != "V" {
                    return Err(format!(
                        "return type mismatch: non-void method {} requires a value",
                        self.target_return_type
                    ));
                }
            }
            DslStmt::Throw { value } => {
                self.validate_value(value)?;
                if let Some(desc) = self.infer_value_descriptor(value)? {
                    if !return_is_object(&desc) {
                        return Err(format!("throw value must be an object, got {}", desc));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_catch_block(&mut self, catch: &DslCatch) -> Result<(), String> {
        let catch_descriptor = java_class_to_descriptor(&catch.catch_type)?;
        if !return_is_object(&catch_descriptor) {
            return Err(format!("catch type must be an object, got {}", catch_descriptor));
        }
        if object_assignability_score(self.env, &catch_descriptor, "Ljava/lang/Throwable;").is_none() {
            return Err(format!("catch type must extend Throwable, got {}", catch_descriptor));
        }
        if let Some(existing) = self.local_descriptors.get(&catch.catch_name) {
            if existing != &catch_descriptor {
                return Err(format!(
                    "catch local '{}' type mismatch: existing {}, catch {}",
                    catch.catch_name, existing, catch_descriptor
                ));
            }
        } else {
            self.local_descriptors
                .insert(catch.catch_name.clone(), catch_descriptor);
        }
        self.validate_stmts(&catch.catch_stmts)
    }

    fn validate_catch_order(&self, catches: &[DslCatch]) -> Result<(), String> {
        let mut previous = Vec::<(&DslCatch, String)>::new();
        for catch in catches {
            let catch_descriptor = java_class_to_descriptor(&catch.catch_type)?;
            for (prev, prev_descriptor) in &previous {
                if object_assignability_score(self.env, &catch_descriptor, prev_descriptor).is_some() {
                    return Err(format!(
                        "catch({}) is unreachable because earlier catch({}) also matches {}; put the more specific catch first",
                        catch.catch_type, prev.catch_type, catch.catch_type
                    ));
                }
            }
            previous.push((catch, catch_descriptor));
        }
        Ok(())
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn validate_semantics(
    env: JniEnv,
    program: &DslProgram,
    is_static: bool,
    target_type: String,
    target_params: Vec<String>,
    target_return_type: String,
) -> Result<BTreeMap<String, String>, String> {
    let mut ctx = DslSemanticContext::new(env, is_static, target_type, target_params, target_return_type);
    ctx.validate_stmts(&program.stmts)?;
    Ok(ctx.local_descriptors)
}
