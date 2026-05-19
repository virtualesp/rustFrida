use std::collections::{BTreeMap, BTreeSet};

use super::dex_ir::DexLabel;
use super::dsl::{
    DslCallKind, DslCallStmt, DslCatch, DslCondition, DslFieldStmt, DslIntBinOp, DslOrigArgs, DslProgram, DslStmt,
    DslTarget, DslUnaryOp, DslValue,
};
use super::{
    array_component_descriptor, common_value_descriptor_with_env, descriptor_is_interface, descriptor_list_word_count,
    descriptor_word_count, java_class_to_descriptor, java_class_to_descriptor_or_primitive, parse_call_params,
    parse_method_signature, resolve_call_proto_with_arg_types, resolve_constructor_proto_with_arg_types,
    resolve_field_with_env, return_is_object, value_kind_from_descriptor, DexIntBinOp, DexIntLit16Op, DexIntLit8Op,
    DexIrBuilder, FieldRef, GeneratedCounter, GeneratedMessageChannel, GeneratedStringLiteral, IfCmpOp, IrCatchHandler,
    MethodRef, ValueKind,
};
use crate::jsapi::java::jni_core::JniEnv;

pub(super) const BASE_LOCAL_REG_COUNT: u16 = 5;
const REG_RESULT: u8 = 0;
const REG_LAST_OBJECT: u8 = 1;
const REG_LOOP_LIMIT: u8 = 2;
const REG_TMP0: u8 = 3;
const REG_TMP1: u8 = 4;

pub(super) struct HelperParamLayout {
    this_reg: Option<u8>,
    this_descriptor: Option<String>,
    arg_regs: Vec<u8>,
    arg_descriptors: Vec<String>,
    local_regs: BTreeMap<String, LocalSlot>,
}

#[derive(Clone)]
pub(super) struct LocalSlot {
    reg: u8,
    descriptor: String,
}

#[derive(Clone)]
pub(super) struct DslBuildContext {
    env: JniEnv,
    generated_type: String,
    pub(super) string_literals: Vec<GeneratedStringLiteral>,
    pub(super) counters: Vec<GeneratedCounter>,
    pub(super) message_channels: Vec<GeneratedMessageChannel>,
    pub(super) uses_direct_buffer_helpers: bool,
    int_expr_scratch_base: u16,
    int_expr_scratch_count: u16,
    array_literal_scratch_base: u16,
    array_literal_scratch_count: u16,
    array_literal_depth: u16,
    invoke_scratch_base: u16,
    invoke_frame_words: u16,
    invoke_frame_count: u16,
    invoke_depth: u16,
    managed_guard_enabled: bool,
    target_narrow_types: BTreeMap<DslTargetKey, String>,
    last_descriptor: Option<String>,
    result_descriptor: Option<String>,
    orig_emit: Option<OrigEmitContext>,
}

#[derive(Clone)]
struct OrigEmitContext {
    is_static: bool,
    local_count: u16,
    ins_size: u16,
    orig_backup: MethodRef,
    return_type: String,
}

#[derive(Clone, Copy)]
struct InvokeScratchFrame {
    range_base: u16,
    stage_base: u16,
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

fn dsl_value_target_key(value: &DslValue) -> Option<DslTargetKey> {
    let DslValue::Target(target) = value else {
        return None;
    };
    dsl_target_key(target)
}

impl DslBuildContext {
    pub(super) fn new(
        env: JniEnv,
        generated_type: String,
        int_expr_scratch_base: u16,
        int_expr_scratch_count: u16,
        array_literal_scratch_base: u16,
        array_literal_scratch_count: u16,
        invoke_scratch_base: u16,
        invoke_frame_words: u16,
        invoke_frame_count: u16,
    ) -> Self {
        Self {
            env,
            generated_type,
            string_literals: Vec::new(),
            counters: Vec::new(),
            message_channels: Vec::new(),
            uses_direct_buffer_helpers: false,
            int_expr_scratch_base,
            int_expr_scratch_count,
            array_literal_scratch_base,
            array_literal_scratch_count,
            array_literal_depth: 0,
            invoke_scratch_base,
            invoke_frame_words,
            invoke_frame_count,
            invoke_depth: 0,
            managed_guard_enabled: true,
            target_narrow_types: BTreeMap::new(),
            last_descriptor: None,
            result_descriptor: None,
            orig_emit: None,
        }
    }

    pub(super) fn set_orig_emit_context(
        &mut self,
        is_static: bool,
        local_count: u16,
        ins_size: u16,
        orig_backup: MethodRef,
        return_type: String,
    ) {
        self.orig_emit = Some(OrigEmitContext {
            is_static,
            local_count,
            ins_size,
            orig_backup,
            return_type,
        });
    }

    pub(super) fn set_managed_guard_enabled(&mut self, enabled: bool) {
        self.managed_guard_enabled = enabled;
    }

    fn int_expr_scratch_reg(&self, index: u16) -> Result<u8, String> {
        if index >= self.int_expr_scratch_count {
            return Err(format!(
                "int expression requires scratch register {}, only {} reserved",
                index + 1,
                self.int_expr_scratch_count
            ));
        }
        checked_reg(self.int_expr_scratch_base + index, "int expression scratch register")
    }

    fn enter_array_literal(&mut self) -> Result<u8, String> {
        if self.array_literal_depth >= self.array_literal_scratch_count {
            return Err(format!(
                "array literal nesting depth {} exceeds reserved scratch registers {}",
                self.array_literal_depth + 1,
                self.array_literal_scratch_count
            ));
        }
        let reg = checked_reg(
            self.array_literal_scratch_base
                .checked_add(self.array_literal_depth)
                .ok_or_else(|| "too many dex registers".to_string())?,
            "array literal scratch register",
        )?;
        self.array_literal_depth += 1;
        Ok(reg)
    }

    fn leave_array_literal(&mut self) {
        self.array_literal_depth = self.array_literal_depth.saturating_sub(1);
    }

    fn enter_invoke_frame(&mut self) -> Result<InvokeScratchFrame, String> {
        if self.invoke_depth >= self.invoke_frame_count {
            return Err(format!(
                "invoke nesting depth {} exceeds reserved scratch frames {}",
                self.invoke_depth + 1,
                self.invoke_frame_count
            ));
        }
        let frame_span = self
            .invoke_frame_words
            .checked_mul(2)
            .ok_or_else(|| "too many dex registers".to_string())?;
        let frame_offset = self
            .invoke_depth
            .checked_mul(frame_span)
            .ok_or_else(|| "too many dex registers".to_string())?;
        let range_base = self
            .invoke_scratch_base
            .checked_add(frame_offset)
            .ok_or_else(|| "too many dex registers".to_string())?;
        let stage_base = range_base
            .checked_add(self.invoke_frame_words)
            .ok_or_else(|| "too many dex registers".to_string())?;
        self.invoke_depth += 1;
        Ok(InvokeScratchFrame { range_base, stage_base })
    }

    fn leave_invoke_frame(&mut self) {
        self.invoke_depth = self.invoke_depth.saturating_sub(1);
    }

    fn string_literal_field(&mut self, value: &str) -> FieldRef {
        if let Some(existing) = self.string_literals.iter().find(|lit| lit.value == value) {
            return FieldRef::new(
                self.generated_type.clone(),
                "Ljava/lang/String;".to_string(),
                existing.field_name.clone(),
            );
        }
        let field_name = format!("__rf_str{}", self.string_literals.len());
        self.string_literals.push(GeneratedStringLiteral {
            field_name: field_name.clone(),
            value: value.to_string(),
        });
        FieldRef::new(
            self.generated_type.clone(),
            "Ljava/lang/String;".to_string(),
            field_name,
        )
    }

    fn counter_field(&mut self, name: &str) -> FieldRef {
        if let Some(existing) = self.counters.iter().find(|counter| counter.name == name) {
            return FieldRef::new(
                self.generated_type.clone(),
                "I".to_string(),
                existing.field_name.clone(),
            );
        }
        let field_name = format!("__rf_counter{}", self.counters.len());
        self.counters.push(GeneratedCounter {
            name: name.to_string(),
            field_name: field_name.clone(),
        });
        FieldRef::new(self.generated_type.clone(), "I".to_string(), field_name)
    }

    fn message_channel_code(&mut self, name: &str) -> i32 {
        if let Some(existing) = self.message_channels.iter().find(|channel| channel.name == name) {
            return existing.code;
        }
        let code = (self.message_channels.len() + 1) as i32;
        self.message_channels.push(GeneratedMessageChannel {
            name: name.to_string(),
            code,
        });
        code
    }

    fn message_send_method(&self) -> MethodRef {
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_send".to_string(),
            "V".to_string(),
            vec!["I".to_string(), "I".to_string()],
        )
    }

    fn message_send_string_method(&self) -> MethodRef {
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_send_str".to_string(),
            "V".to_string(),
            vec!["I".to_string(), "Ljava/lang/String;".to_string()],
        )
    }

    fn direct_buffer_fill_method(&mut self) -> MethodRef {
        self.uses_direct_buffer_helpers = true;
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_dbb_fill".to_string(),
            "I".to_string(),
            vec![
                "Ljava/nio/ByteBuffer;".to_string(),
                "I".to_string(),
                "I".to_string(),
                "I".to_string(),
            ],
        )
    }

    fn direct_buffer_copy_from_byte_array_method(&mut self) -> MethodRef {
        self.uses_direct_buffer_helpers = true;
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_dbb_copy_from_byte_array".to_string(),
            "I".to_string(),
            vec![
                "Ljava/nio/ByteBuffer;".to_string(),
                "I".to_string(),
                "[B".to_string(),
                "I".to_string(),
                "I".to_string(),
            ],
        )
    }

    fn direct_buffer_copy_to_byte_array_method(&mut self) -> MethodRef {
        self.uses_direct_buffer_helpers = true;
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_dbb_copy_to_byte_array".to_string(),
            "I".to_string(),
            vec![
                "Ljava/nio/ByteBuffer;".to_string(),
                "I".to_string(),
                "[B".to_string(),
                "I".to_string(),
                "I".to_string(),
            ],
        )
    }

    fn direct_buffer_capacity_method(&mut self) -> MethodRef {
        self.uses_direct_buffer_helpers = true;
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_dbb_capacity".to_string(),
            "I".to_string(),
            vec!["Ljava/nio/ByteBuffer;".to_string()],
        )
    }

    fn direct_buffer_get_u8_method(&mut self) -> MethodRef {
        self.uses_direct_buffer_helpers = true;
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_dbb_get_u8".to_string(),
            "I".to_string(),
            vec!["Ljava/nio/ByteBuffer;".to_string(), "I".to_string()],
        )
    }

    pub(super) fn guard_enter_method(&self) -> MethodRef {
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_guard_enter".to_string(),
            "V".to_string(),
            Vec::new(),
        )
    }

    pub(super) fn guard_leave_method(&self) -> MethodRef {
        MethodRef::new(
            self.generated_type.clone(),
            "__rf_guard_leave".to_string(),
            "V".to_string(),
            Vec::new(),
        )
    }

    fn with_target_narrow_type<F>(&mut self, key: DslTargetKey, descriptor: String, f: F) -> Result<bool, String>
    where
        F: FnOnce(&mut Self) -> Result<bool, String>,
    {
        self.with_target_narrow_types(&[(key, descriptor)], f)
    }

    fn with_target_narrow_types<F, R>(&mut self, facts: &[(DslTargetKey, String)], f: F) -> Result<R, String>
    where
        F: FnOnce(&mut Self) -> Result<R, String>,
    {
        let previous = facts
            .iter()
            .map(|(key, descriptor)| {
                let old = self.target_narrow_types.insert(key.clone(), descriptor.clone());
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
}

pub(super) fn precollect_string_literals(program: &DslProgram, dsl_ctx: &mut DslBuildContext) {
    collect_stmt_strings(&program.stmts, dsl_ctx);
}

fn collect_stmt_strings(stmts: &[DslStmt], dsl_ctx: &mut DslBuildContext) {
    for stmt in stmts {
        match stmt {
            DslStmt::Block(stmts) => collect_stmt_strings(stmts, dsl_ctx),
            DslStmt::Let { value, .. } | DslStmt::Assign { value, .. } | DslStmt::Throw { value } => {
                collect_value_strings(value, dsl_ctx)
            }
            DslStmt::LetOrig { args, .. } | DslStmt::ReturnOrig { args } => collect_orig_arg_strings(args, dsl_ctx),
            DslStmt::New { args, .. } => collect_values_strings(args, dsl_ctx),
            DslStmt::NewArray { size, .. }
            | DslStmt::Cast { value: size, .. }
            | DslStmt::ArrayLength { array: size } => collect_value_strings(size, dsl_ctx),
            DslStmt::Call(call) => collect_call_strings(call, dsl_ctx),
            DslStmt::Send { name, value } => {
                dsl_ctx.message_channel_code(name);
                collect_value_strings(value, dsl_ctx);
            }
            DslStmt::DirectBufferFill {
                buffer,
                offset,
                length,
                value,
            } => {
                dsl_ctx.uses_direct_buffer_helpers = true;
                collect_value_strings(buffer, dsl_ctx);
                collect_value_strings(offset, dsl_ctx);
                collect_value_strings(length, dsl_ctx);
                collect_value_strings(value, dsl_ctx);
            }
            DslStmt::DirectBufferCopyFromByteArray {
                buffer,
                dst_offset,
                src,
                src_offset,
                length,
            } => {
                dsl_ctx.uses_direct_buffer_helpers = true;
                collect_value_strings(buffer, dsl_ctx);
                collect_value_strings(dst_offset, dsl_ctx);
                collect_value_strings(src, dsl_ctx);
                collect_value_strings(src_offset, dsl_ctx);
                collect_value_strings(length, dsl_ctx);
            }
            DslStmt::DirectBufferCopyToByteArray {
                buffer,
                src_offset,
                dst,
                dst_offset,
                length,
            } => {
                dsl_ctx.uses_direct_buffer_helpers = true;
                collect_value_strings(buffer, dsl_ctx);
                collect_value_strings(src_offset, dsl_ctx);
                collect_value_strings(dst, dsl_ctx);
                collect_value_strings(dst_offset, dsl_ctx);
                collect_value_strings(length, dsl_ctx);
            }
            DslStmt::ArrayGet { array, index, .. } => {
                collect_value_strings(array, dsl_ctx);
                collect_value_strings(index, dsl_ctx);
            }
            DslStmt::ArrayPut {
                array, index, value, ..
            }
            | DslStmt::ArrayUpdate {
                array, index, value, ..
            } => {
                collect_value_strings(array, dsl_ctx);
                collect_value_strings(index, dsl_ctx);
                collect_value_strings(value, dsl_ctx);
            }
            DslStmt::FieldRead { stmt, .. } | DslStmt::FieldWrite { stmt, .. } => {
                collect_field_stmt_strings(stmt, dsl_ctx)
            }
            DslStmt::FieldUpdate { stmt, value, .. } => {
                collect_field_stmt_strings(stmt, dsl_ctx);
                collect_value_strings(value, dsl_ctx);
            }
            DslStmt::IfNull {
                value,
                then_stmts,
                else_stmts,
                ..
            }
            | DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            }
            | DslStmt::IfInstanceOf {
                value,
                then_stmts,
                else_stmts,
                ..
            } => {
                collect_value_strings(value, dsl_ctx);
                collect_stmt_strings(then_stmts, dsl_ctx);
                collect_stmt_strings(else_stmts, dsl_ctx);
            }
            DslStmt::IfCmp {
                left,
                right,
                then_stmts,
                else_stmts,
                ..
            } => {
                collect_value_strings(left, dsl_ctx);
                collect_value_strings(right, dsl_ctx);
                collect_stmt_strings(then_stmts, dsl_ctx);
                collect_stmt_strings(else_stmts, dsl_ctx);
            }
            DslStmt::Switch {
                value,
                cases,
                default_stmts,
            } => {
                collect_value_strings(value, dsl_ctx);
                for (_, stmts) in cases {
                    collect_stmt_strings(stmts, dsl_ctx);
                }
                if let Some(stmts) = default_stmts {
                    collect_stmt_strings(stmts, dsl_ctx);
                }
            }
            DslStmt::TryCatch { try_stmts, catches } => {
                collect_stmt_strings(try_stmts, dsl_ctx);
                for catch in catches {
                    collect_stmt_strings(&catch.catch_stmts, dsl_ctx);
                }
            }
            DslStmt::While { condition, body_stmts } | DslStmt::DoWhile { body_stmts, condition } => {
                collect_condition_strings(condition, dsl_ctx);
                collect_stmt_strings(body_stmts, dsl_ctx);
            }
            DslStmt::For {
                init_stmts,
                condition,
                update_stmts,
                body_stmts,
            } => {
                collect_stmt_strings(init_stmts, dsl_ctx);
                if let Some(condition) = condition {
                    collect_condition_strings(condition, dsl_ctx);
                }
                collect_stmt_strings(update_stmts, dsl_ctx);
                collect_stmt_strings(body_stmts, dsl_ctx);
            }
            DslStmt::ReturnValue { value } => {
                if let Some(value) = value {
                    collect_value_strings(value, dsl_ctx);
                }
            }
            DslStmt::Break | DslStmt::Continue | DslStmt::Count { .. } => {}
        }
    }
}

fn collect_value_strings(value: &DslValue, dsl_ctx: &mut DslBuildContext) {
    match value {
        DslValue::String(value) => {
            dsl_ctx.string_literal_field(value);
        }
        DslValue::DefaultValue { .. } => {}
        DslValue::UnaryOp { value, .. }
        | DslValue::Cast { value, .. }
        | DslValue::ArrayLength(value)
        | DslValue::NewArray { size: value, .. } => collect_value_strings(value, dsl_ctx),
        DslValue::IntBinOp { left, right, .. }
        | DslValue::ArrayGet {
            array: left,
            index: right,
            ..
        } => {
            collect_value_strings(left, dsl_ctx);
            collect_value_strings(right, dsl_ctx);
        }
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => {
            collect_condition_strings(condition, dsl_ctx);
            collect_value_strings(then_value, dsl_ctx);
            collect_value_strings(else_value, dsl_ctx);
        }
        DslValue::OrigCall(args) => collect_orig_arg_strings(args, dsl_ctx),
        DslValue::DirectBufferCapacity { buffer } => {
            dsl_ctx.uses_direct_buffer_helpers = true;
            collect_value_strings(buffer, dsl_ctx);
        }
        DslValue::DirectBufferGetU8 { buffer, offset } => {
            dsl_ctx.uses_direct_buffer_helpers = true;
            collect_value_strings(buffer, dsl_ctx);
            collect_value_strings(offset, dsl_ctx);
        }
        DslValue::Call(call) => collect_call_strings(call, dsl_ctx),
        DslValue::NewObject { args, .. } | DslValue::ArrayLiteral { elements: args } => {
            collect_values_strings(args, dsl_ctx)
        }
        DslValue::FieldGet { stmt, .. } => collect_field_stmt_strings(stmt, dsl_ctx),
        DslValue::Target(_) | DslValue::Int(_) | DslValue::Bool(_) | DslValue::Null => {}
    }
}

fn collect_values_strings(values: &[DslValue], dsl_ctx: &mut DslBuildContext) {
    for value in values {
        collect_value_strings(value, dsl_ctx);
    }
}

fn collect_call_strings(call: &DslCallStmt, dsl_ctx: &mut DslBuildContext) {
    if let Some(receiver) = &call.receiver {
        collect_value_strings(receiver, dsl_ctx);
    }
    collect_values_strings(&call.args, dsl_ctx);
}

fn collect_field_stmt_strings(stmt: &DslFieldStmt, dsl_ctx: &mut DslBuildContext) {
    if let Some(receiver) = &stmt.receiver {
        collect_value_strings(receiver, dsl_ctx);
    }
    if let Some(value) = &stmt.value {
        collect_value_strings(value, dsl_ctx);
    }
}

fn collect_orig_arg_strings(args: &DslOrigArgs, dsl_ctx: &mut DslBuildContext) {
    if let DslOrigArgs::Values(values) = args {
        collect_values_strings(values, dsl_ctx);
    }
}

fn collect_condition_strings(condition: &DslCondition, dsl_ctx: &mut DslBuildContext) {
    match condition {
        DslCondition::Null { value, .. } | DslCondition::InstanceOf { value, .. } | DslCondition::Bool { value } => {
            collect_value_strings(value, dsl_ctx)
        }
        DslCondition::Cmp { left, right, .. } => {
            collect_value_strings(left, dsl_ctx);
            collect_value_strings(right, dsl_ctx);
        }
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            collect_condition_strings(left, dsl_ctx);
            collect_condition_strings(right, dsl_ctx);
        }
        DslCondition::Not(condition) => collect_condition_strings(condition, dsl_ctx),
        DslCondition::Const(_) => {}
    }
}

fn condition_narrow_facts_when_true(condition: &DslCondition) -> Result<Vec<(DslTargetKey, String)>, String> {
    match condition {
        DslCondition::InstanceOf { value, class_name } => {
            let Some(key) = dsl_value_target_key(value) else {
                return Ok(Vec::new());
            };
            Ok(vec![(key, java_class_to_descriptor(class_name)?)])
        }
        DslCondition::And(left, right) => {
            let mut facts = condition_narrow_facts_when_true(left)?;
            facts.extend(condition_narrow_facts_when_true(right)?);
            Ok(facts)
        }
        DslCondition::Not(condition) => condition_narrow_facts_when_false(condition),
        _ => Ok(Vec::new()),
    }
}

fn condition_narrow_facts_when_false(condition: &DslCondition) -> Result<Vec<(DslTargetKey, String)>, String> {
    match condition {
        DslCondition::Or(left, right) => {
            let mut facts = condition_narrow_facts_when_false(left)?;
            facts.extend(condition_narrow_facts_when_false(right)?);
            Ok(facts)
        }
        DslCondition::Not(condition) => condition_narrow_facts_when_true(condition),
        _ => Ok(Vec::new()),
    }
}

pub(super) fn helper_param_layout(
    is_static: bool,
    target_type: &str,
    target_params: &[String],
    local_count: u16,
    local_slots: BTreeMap<String, LocalSlot>,
) -> Result<HelperParamLayout, String> {
    let mut next = local_count;
    let this_reg = if is_static {
        None
    } else {
        let reg = checked_reg(next, "this register")?;
        next += descriptor_word_count(target_type);
        Some(reg)
    };
    let this_descriptor = if is_static { None } else { Some(target_type.to_string()) };
    let mut arg_regs = Vec::with_capacity(target_params.len());
    for param in target_params {
        let reg = checked_reg(next, "argument register")?;
        next += descriptor_word_count(param);
        arg_regs.push(reg);
    }
    Ok(HelperParamLayout {
        this_reg,
        this_descriptor,
        arg_regs,
        arg_descriptors: target_params.to_vec(),
        local_regs: local_slots,
    })
}

fn checked_reg(reg: u16, what: &str) -> Result<u8, String> {
    if reg > u8::MAX as u16 {
        return Err(format!("{} out of dex register range: v{}", what, reg));
    }
    Ok(reg as u8)
}

fn emit_copy_value(ir: &mut DexIrBuilder, dst: u8, src: u8, descriptor: &str) -> Result<(), String> {
    if dst == src {
        return Ok(());
    }
    let kind = value_kind_from_descriptor(descriptor)?;
    ir.move_from16(dst, src as u16, kind);
    Ok(())
}

fn emit_copy_object_if_needed(ir: &mut DexIrBuilder, reg: u8, temp: u8) -> u8 {
    if reg <= 0x0f {
        reg
    } else {
        ir.move_from16(temp, reg as u16, ValueKind::Object);
        temp
    }
}

fn emit_copy_field_value_if_needed(ir: &mut DexIrBuilder, reg: u8, temp: u8, kind: ValueKind) -> u8 {
    if reg <= 0x0f {
        reg
    } else {
        ir.move_from16(temp, reg as u16, kind);
        temp
    }
}

fn emit_new_object(
    ir: &mut DexIrBuilder,
    class_name: &str,
    ctor_sig: Option<&str>,
    args: &[DslValue],
    sink: &FieldRef,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<MethodRef, String> {
    let new_type = java_class_to_descriptor(class_name)?;
    let arg_types = infer_value_descriptors(args, layout, dsl_ctx)?;
    let (params, full_sig) = resolve_constructor_proto_with_arg_types(dsl_ctx.env, class_name, ctor_sig, &arg_types)?;
    if params.len() != args.len() {
        return Err(format!(
            "{}.<init>{} expects {} explicit args, got {}",
            class_name,
            full_sig,
            params.len(),
            args.len()
        ));
    }
    let ctor = MethodRef::new(new_type.clone(), "<init>", "V", params.clone());
    ir.new_instance(REG_LAST_OBJECT, new_type);
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Direct,
        ctor.clone(),
        Some((REG_LAST_OBJECT, "Ljava/lang/Object;")),
        &params,
        args,
        layout,
        dsl_ctx,
    )?;
    ir.sput_object(REG_LAST_OBJECT, sink.clone());
    Ok(ctor)
}

fn emit_new_object_value(
    ir: &mut DexIrBuilder,
    class_name: &str,
    ctor_sig: Option<&str>,
    args: &[DslValue],
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let new_type = java_class_to_descriptor(class_name)?;
    if !value_descriptor_assignable_to(&new_type, expected_type) {
        return Err(format!(
            "new expression type {} cannot be passed as {}",
            new_type, expected_type
        ));
    }
    let arg_types = infer_value_descriptors(args, layout, dsl_ctx)?;
    let (params, full_sig) = resolve_constructor_proto_with_arg_types(dsl_ctx.env, class_name, ctor_sig, &arg_types)?;
    if params.len() != args.len() {
        return Err(format!(
            "{}.<init>{} expects {} explicit args, got {}",
            class_name,
            full_sig,
            params.len(),
            args.len()
        ));
    }
    let ctor = MethodRef::new(new_type.clone(), "<init>", "V", params.clone());
    ir.new_instance(dst, new_type);
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Direct,
        ctor,
        Some((dst, "Ljava/lang/Object;")),
        &params,
        args,
        layout,
        dsl_ctx,
    )?;
    Ok(dst)
}

fn emit_discard_result(ir: &mut DexIrBuilder, return_type: &str) -> Result<(), String> {
    match return_type {
        "V" => {}
        "J" | "D" => ir.move_result_wide(REG_RESULT),
        ret if return_is_object(ret) => ir.move_result_object(REG_LAST_OBJECT),
        "Z" | "B" | "C" | "S" | "I" | "F" => ir.move_result(REG_RESULT),
        other => return Err(format!("unsupported call return type '{}'", other)),
    }
    Ok(())
}

fn emit_move_result_value(ir: &mut DexIrBuilder, return_type: &str, dst: u8) -> Result<u8, String> {
    match return_type {
        "V" => Err("void call cannot be used as a value".to_string()),
        "J" | "D" => {
            ir.move_result_wide(dst);
            Ok(dst)
        }
        ret if return_is_object(ret) => {
            ir.move_result_object(dst);
            Ok(dst)
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.move_result(dst);
            Ok(dst)
        }
        other => Err(format!("unsupported call return type '{}'", other)),
    }
}

fn emit_call_value(
    ir: &mut DexIrBuilder,
    stmt: &DslCallStmt,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let arg_types = infer_call_arg_descriptors(stmt, layout, dsl_ctx)?;
    let (params, return_type, full_sig) =
        resolve_call_proto_with_arg_types(dsl_ctx.env, stmt, &class_type, Some(&arg_types))?;
    if return_type == "V" {
        return Err(format!(
            "{}.{}{} returns void and cannot be used as a value",
            stmt.class_label(),
            stmt.method_name,
            full_sig
        ));
    }
    if !value_descriptor_assignable_to(&return_type, expected_type) {
        return Err(format!(
            "call expression return type {} cannot be passed as {}",
            return_type, expected_type
        ));
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
    let method = MethodRef::new(
        class_type.clone(),
        stmt.method_name.clone(),
        return_type.clone(),
        params.clone(),
    );
    let receiver = emit_call_receiver(ir, stmt, &class_type, layout, dsl_ctx)?;
    let invoke_kind = resolve_managed_invoke_kind(dsl_ctx.env, stmt.kind, &class_type);
    if stmt.null_safe {
        return emit_null_safe_call_value(
            ir,
            invoke_kind,
            method,
            receiver,
            &params,
            &stmt.args,
            &return_type,
            dst,
            layout,
            dsl_ctx,
        );
    }
    emit_invoke_with_values(ir, invoke_kind, method, receiver, &params, &stmt.args, layout, dsl_ctx)?;
    emit_move_result_value(ir, &return_type, dst)
}

fn emit_null_safe_default(ir: &mut DexIrBuilder, return_type: &str, dst: u8) -> Result<(), String> {
    match return_type {
        "V" => Err("void null-safe call cannot be used as a value".to_string()),
        "J" | "D" => Err("wide null-safe call result is not supported yet".to_string()),
        ret if return_is_object(ret) => {
            ir.const4(dst, 0);
            Ok(())
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.const4(dst, 0);
            Ok(())
        }
        other => Err(format!("unsupported null-safe call return type '{}'", other)),
    }
}

fn emit_null_safe_call_value(
    ir: &mut DexIrBuilder,
    invoke_kind: ManagedInvokeKind,
    method: MethodRef,
    receiver: Option<(u8, &str)>,
    params: &[String],
    args: &[DslValue],
    return_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let Some((receiver_reg, receiver_desc)) = receiver else {
        return Err("null-safe call requires a receiver".to_string());
    };
    if matches!(invoke_kind, ManagedInvokeKind::Static) {
        return Err("null-safe call is only valid for instance/interface methods".to_string());
    }
    let null_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_eqz(receiver_reg, null_label);
    emit_invoke_with_values(
        ir,
        invoke_kind,
        method,
        Some((receiver_reg, receiver_desc)),
        params,
        args,
        layout,
        dsl_ctx,
    )?;
    emit_move_result_value(ir, return_type, dst)?;
    ir.goto16(done_label);
    ir.bind(null_label)?;
    emit_null_safe_default(ir, return_type, dst)?;
    ir.bind(done_label)?;
    Ok(dst)
}

fn emit_field_get_value(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    is_static: bool,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let (declaring_type, field_type) = resolve_field_ref_parts(dsl_ctx.env, stmt, is_static, &class_type)?;
    if !value_descriptor_assignable_to(&field_type, expected_type) {
        return Err(format!(
            "field expression type {} cannot be passed as {}",
            field_type, expected_type
        ));
    }
    let field = FieldRef::new(declaring_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    if is_static {
        ir.sget(dst, field, kind);
    } else {
        let obj = emit_field_receiver(ir, stmt, layout, dsl_ctx)?;
        ir.iget(dst, obj, field, kind);
    }
    Ok(dst)
}

fn emit_cast_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    class_name: &str,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let ty = java_class_to_descriptor(class_name)?;
    if !return_is_object(expected_type) {
        return Err(format!("cast expression cannot be passed as {}", expected_type));
    }
    let src = emit_load_value(ir, value, "Ljava/lang/Object;", dst, layout, dsl_ctx)?;
    let reg = emit_copy_object_if_needed(ir, src, dst);
    ir.check_cast(reg, ty);
    if reg != dst {
        ir.move_from16(dst, reg as u16, ValueKind::Object);
    }
    Ok(dst)
}

fn emit_load_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    expected_type: &str,
    temp_reg: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    match value {
        DslValue::Target(target) => resolve_target_reg(target, layout),
        DslValue::String(value) => {
            if !return_is_object(expected_type) {
                return Err(format!("string literal cannot be passed as {}", expected_type));
            }
            let field = dsl_ctx.string_literal_field(value);
            ir.sget(temp_reg, field, ValueKind::Object);
            Ok(temp_reg)
        }
        DslValue::Int(value) => {
            if matches!(expected_type, "J" | "D") {
                return Err("wide integer literals are not supported in managed DSL yet".to_string());
            }
            ir.const16(temp_reg, *value);
            Ok(temp_reg)
        }
        DslValue::Bool(value) => {
            if expected_type != "Z" {
                return Err(format!("boolean literal cannot be passed as {}", expected_type));
            }
            ir.const4(temp_reg, if *value { 1 } else { 0 });
            Ok(temp_reg)
        }
        DslValue::Null => {
            if !return_is_object(expected_type) {
                return Err(format!("null cannot be passed as {}", expected_type));
            }
            ir.const4(temp_reg, 0);
            Ok(temp_reg)
        }
        DslValue::DefaultValue { type_name } => {
            let desc = java_class_to_descriptor_or_primitive(type_name)?;
            if desc == "V" {
                return Err("default value cannot be void".to_string());
            }
            if !value_descriptor_assignable_to(&desc, expected_type) {
                return Err(format!("default {} cannot be passed as {}", desc, expected_type));
            }
            match desc.as_str() {
                "J" | "D" => Err(format!("default value for {} is not supported yet", desc)),
                desc if return_is_object(desc) || matches!(desc, "Z" | "B" | "C" | "S" | "I" | "F") => {
                    ir.const4(temp_reg, 0);
                    Ok(temp_reg)
                }
                other => Err(format!("unsupported default value type {}", other)),
            }
        }
        DslValue::UnaryOp { op, value } => emit_unary_value(ir, *op, value, expected_type, temp_reg, layout, dsl_ctx),
        DslValue::IntBinOp { op, left, right } => {
            if *op == DslIntBinOp::Add && is_string_concat_operands(left, right, layout, dsl_ctx)? {
                if !value_descriptor_assignable_to("Ljava/lang/String;", expected_type) {
                    return Err(format!("string concat cannot be passed as {}", expected_type));
                }
                return emit_string_concat_value(ir, value, expected_type, temp_reg, layout, dsl_ctx);
            }
            if expected_type != "I" {
                return Err(format!("int expression cannot be passed as {}", expected_type));
            }
            emit_int_binop_value(ir, *op, left, right, temp_reg, layout, dsl_ctx)
        }
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => emit_ternary_value(
            ir,
            condition,
            then_value,
            else_value,
            expected_type,
            temp_reg,
            layout,
            dsl_ctx,
        ),
        DslValue::OrigCall(args) => emit_orig_value(ir, args, expected_type, temp_reg, layout, dsl_ctx),
        DslValue::DirectBufferCapacity { buffer } => {
            if expected_type != "I" {
                return Err(format!("dbbCapacity expression cannot be passed as {}", expected_type));
            }
            emit_direct_buffer_capacity_value(ir, buffer, temp_reg, layout, dsl_ctx)
        }
        DslValue::DirectBufferGetU8 { buffer, offset } => {
            if expected_type != "I" {
                return Err(format!("dbbGetU8 expression cannot be passed as {}", expected_type));
            }
            emit_direct_buffer_get_u8_value(ir, buffer, offset, temp_reg, layout, dsl_ctx)
        }
        DslValue::Call(stmt) => emit_call_value(ir, stmt, expected_type, temp_reg, layout, dsl_ctx),
        DslValue::NewObject {
            class_name,
            ctor_sig,
            args,
        } => emit_new_object_value(
            ir,
            class_name,
            ctor_sig.as_deref(),
            args,
            expected_type,
            temp_reg,
            layout,
            dsl_ctx,
        ),
        DslValue::NewArray { array_type_name, size } => {
            emit_new_array_value(ir, array_type_name, size, expected_type, temp_reg, layout, dsl_ctx)
        }
        DslValue::FieldGet { stmt, is_static } => {
            emit_field_get_value(ir, stmt, *is_static, expected_type, temp_reg, layout, dsl_ctx)
        }
        DslValue::Cast { value, class_name } => {
            emit_cast_value(ir, value, class_name, expected_type, temp_reg, layout, dsl_ctx)
        }
        DslValue::ArrayLength(array) => {
            if expected_type != "I" {
                return Err(format!("arrayLength expression cannot be passed as {}", expected_type));
            }
            emit_array_length_value(ir, array, temp_reg, layout, dsl_ctx)
        }
        DslValue::ArrayGet {
            array,
            index,
            type_name,
        } => {
            let component_type = resolve_array_component_type(array, type_name.as_deref(), layout, dsl_ctx)?;
            if !value_descriptor_assignable_to(&component_type, expected_type) {
                return Err(format!(
                    "aget expression type {} cannot be passed as {}",
                    component_type, expected_type
                ));
            }
            emit_array_get_value(ir, array, index, &component_type, temp_reg, layout, dsl_ctx)
        }
        DslValue::ArrayLiteral { elements } => {
            emit_array_literal_value(ir, elements, expected_type, temp_reg, layout, dsl_ctx)
        }
    }
}

fn value_descriptor_assignable_to(src: &str, dst: &str) -> bool {
    src == dst || (return_is_object(src) && return_is_object(dst))
}

fn descriptor_is_string(desc: Option<&str>) -> bool {
    desc == Some("Ljava/lang/String;")
}

fn is_string_concat_operands(
    left: &DslValue,
    right: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<bool, String> {
    let left_desc = infer_value_descriptor(left, layout, dsl_ctx)?;
    let right_desc = infer_value_descriptor(right, layout, dsl_ctx)?;
    Ok(descriptor_is_string(left_desc.as_deref()) || descriptor_is_string(right_desc.as_deref()))
}

fn emit_ternary_value(
    ir: &mut DexIrBuilder,
    condition: &DslCondition,
    then_value: &DslValue,
    else_value: &DslValue,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    if matches!(expected_type, "J" | "D") {
        return Err("wide ternary result is not supported yet".to_string());
    }
    if expected_type == "V" {
        return Err("void ternary result is not supported".to_string());
    }
    let then_label = ir.new_label();
    let else_label = ir.new_label();
    let done_label = ir.new_label();
    emit_condition_branch(ir, condition, then_label, else_label, layout, dsl_ctx)?;
    ir.bind(then_label)?;
    let then_facts = condition_narrow_facts_when_true(condition)?;
    let then_reg = dsl_ctx.with_target_narrow_types(&then_facts, |dsl_ctx| {
        emit_load_value(ir, then_value, expected_type, dst, layout, dsl_ctx)
    })?;
    emit_copy_value(ir, dst, then_reg, expected_type)?;
    ir.goto16(done_label);
    ir.bind(else_label)?;
    let else_facts = condition_narrow_facts_when_false(condition)?;
    let else_reg = dsl_ctx.with_target_narrow_types(&else_facts, |dsl_ctx| {
        emit_load_value(ir, else_value, expected_type, dst, layout, dsl_ctx)
    })?;
    emit_copy_value(ir, dst, else_reg, expected_type)?;
    ir.bind(done_label)?;
    Ok(dst)
}

fn emit_condition_branch(
    ir: &mut DexIrBuilder,
    condition: &DslCondition,
    true_label: DexLabel,
    false_label: DexLabel,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    match condition {
        DslCondition::Const(true) => ir.goto16(true_label),
        DslCondition::Const(false) => ir.goto16(false_label),
        DslCondition::Bool { value } => {
            let reg = emit_load_cmp_value(ir, value, "Z", REG_TMP0, layout, dsl_ctx)?;
            ir.if_eqz(reg, false_label);
            ir.goto16(true_label);
        }
        DslCondition::Null { value, invert } => {
            let reg = emit_load_value(ir, value, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
            let obj = emit_copy_object_if_needed(ir, reg, REG_TMP1);
            if *invert {
                ir.if_eqz(obj, false_label);
                ir.goto16(true_label);
            } else {
                ir.if_eqz(obj, true_label);
                ir.goto16(false_label);
            }
        }
        DslCondition::Cmp { op, left, right } => {
            let expected_type = cmp_expected_type(left, right, layout, dsl_ctx)?;
            let left_reg = emit_load_cmp_value(ir, left, expected_type, REG_TMP0, layout, dsl_ctx)?;
            let right_reg = emit_load_cmp_value(ir, right, expected_type, REG_TMP1, layout, dsl_ctx)?;
            ir.if_cmp(*op, left_reg, right_reg, true_label);
            ir.goto16(false_label);
        }
        DslCondition::InstanceOf { value, class_name } => {
            let ty = java_class_to_descriptor(class_name)?;
            let src = emit_load_value(ir, value, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
            let obj = emit_copy_object_if_needed(ir, src, REG_TMP1);
            ir.instance_of(REG_TMP0, obj, ty);
            ir.if_eqz(REG_TMP0, false_label);
            ir.goto16(true_label);
        }
        DslCondition::And(left, right) => {
            let right_label = ir.new_label();
            emit_condition_branch(ir, left, right_label, false_label, layout, dsl_ctx)?;
            ir.bind(right_label)?;
            let facts = condition_narrow_facts_when_true(left)?;
            dsl_ctx.with_target_narrow_types(&facts, |dsl_ctx| {
                emit_condition_branch(ir, right, true_label, false_label, layout, dsl_ctx)
            })?;
        }
        DslCondition::Or(left, right) => {
            let right_label = ir.new_label();
            emit_condition_branch(ir, left, true_label, right_label, layout, dsl_ctx)?;
            ir.bind(right_label)?;
            let facts = condition_narrow_facts_when_false(left)?;
            dsl_ctx.with_target_narrow_types(&facts, |dsl_ctx| {
                emit_condition_branch(ir, right, true_label, false_label, layout, dsl_ctx)
            })?;
        }
        DslCondition::Not(condition) => {
            emit_condition_branch(ir, condition, false_label, true_label, layout, dsl_ctx)?;
        }
    }
    Ok(())
}

fn dex_int_binop(op: DslIntBinOp) -> DexIntBinOp {
    match op {
        DslIntBinOp::Add => DexIntBinOp::Add,
        DslIntBinOp::Sub => DexIntBinOp::Sub,
        DslIntBinOp::Mul => DexIntBinOp::Mul,
        DslIntBinOp::Div => DexIntBinOp::Div,
        DslIntBinOp::Rem => DexIntBinOp::Rem,
        DslIntBinOp::And => DexIntBinOp::And,
        DslIntBinOp::Or => DexIntBinOp::Or,
        DslIntBinOp::Xor => DexIntBinOp::Xor,
        DslIntBinOp::Shl => DexIntBinOp::Shl,
        DslIntBinOp::Shr => DexIntBinOp::Shr,
        DslIntBinOp::Ushr => DexIntBinOp::Ushr,
    }
}

fn emit_unary_value(
    ir: &mut DexIrBuilder,
    op: DslUnaryOp,
    value: &DslValue,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    emit_unary_value_with_scratch(ir, op, value, expected_type, dst, 0, layout, dsl_ctx)
}

fn emit_unary_value_with_scratch(
    ir: &mut DexIrBuilder,
    op: DslUnaryOp,
    value: &DslValue,
    expected_type: &str,
    dst: u8,
    scratch_index: u16,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    match op {
        DslUnaryOp::Neg => {
            if expected_type != "I" {
                return Err(format!("int unary expression cannot be passed as {}", expected_type));
            }
            let src = emit_int_expr_value(ir, value, dst, scratch_index, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit8(DexIntLit8Op::Rsub, dst, dst, 0);
            Ok(dst)
        }
        DslUnaryOp::BitNot => {
            if expected_type != "I" {
                return Err(format!("int unary expression cannot be passed as {}", expected_type));
            }
            let src = emit_int_expr_value(ir, value, dst, scratch_index, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit8(DexIntLit8Op::Xor, dst, dst, -1);
            Ok(dst)
        }
        DslUnaryOp::BoolNot => {
            if expected_type != "Z" {
                return Err(format!(
                    "boolean unary expression cannot be passed as {}",
                    expected_type
                ));
            }
            let src = emit_load_value(ir, value, "Z", dst, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit8(DexIntLit8Op::Xor, dst, dst, 1);
            Ok(dst)
        }
    }
}

fn emit_int_binop_value(
    ir: &mut DexIrBuilder,
    op: DslIntBinOp,
    left: &DslValue,
    right: &DslValue,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    emit_int_binop_expr(ir, op, left, right, dst, 0, layout, dsl_ctx)
}

fn emit_string_concat_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    if !return_is_object(expected_type) {
        return Err(format!("string concat cannot be passed as {}", expected_type));
    }
    let string_desc = "Ljava/lang/String;".to_string();
    let builder_desc = "Ljava/lang/StringBuilder;".to_string();
    let builder_ctor = MethodRef::new(builder_desc.clone(), "<init>", "V", Vec::new());
    let builder_reg = REG_TMP1;

    ir.new_instance(builder_reg, builder_desc.clone());
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Direct,
        builder_ctor,
        Some((builder_reg, builder_desc.as_str())),
        &[],
        &[],
        layout,
        dsl_ctx,
    )?;

    let mut operands = Vec::new();
    collect_string_concat_operands(value, layout, dsl_ctx, &mut operands)?;
    for operand in operands {
        let operand_desc = infer_value_descriptor(operand, layout, dsl_ctx)?;
        let append_param = string_builder_append_param(operand_desc.as_deref())?;
        let append = MethodRef::new(
            builder_desc.clone(),
            "append",
            builder_desc.clone(),
            vec![append_param.clone()],
        );
        let args = [operand.clone()];
        emit_invoke_with_values(
            ir,
            ManagedInvokeKind::Virtual,
            append,
            Some((builder_reg, builder_desc.as_str())),
            &[append_param],
            &args,
            layout,
            dsl_ctx,
        )?;
        ir.move_result_object(builder_reg);
    }

    let to_string = MethodRef::new(builder_desc.clone(), "toString", string_desc, Vec::new());
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Virtual,
        to_string,
        Some((builder_reg, builder_desc.as_str())),
        &[],
        &[],
        layout,
        dsl_ctx,
    )?;
    ir.move_result_object(dst);
    Ok(dst)
}

fn collect_string_concat_operands<'a>(
    value: &'a DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
    out: &mut Vec<&'a DslValue>,
) -> Result<(), String> {
    if let DslValue::IntBinOp {
        op: DslIntBinOp::Add,
        left,
        right,
    } = value
    {
        if is_string_concat_operands(left, right, layout, dsl_ctx)? {
            collect_string_concat_operands(left, layout, dsl_ctx, out)?;
            collect_string_concat_operands(right, layout, dsl_ctx, out)?;
            return Ok(());
        }
    }
    out.push(value);
    Ok(())
}

fn string_builder_append_param(desc: Option<&str>) -> Result<String, String> {
    let param = match desc {
        None | Some("Ljava/lang/String;") => "Ljava/lang/String;",
        Some("Z") => "Z",
        Some("C") => "C",
        Some("I") => "I",
        Some("F") => "F",
        Some("J") => "J",
        Some("D") => "D",
        Some(desc) if return_is_object(desc) => "Ljava/lang/Object;",
        Some("B" | "S") => "I",
        Some(other) => return Err(format!("string concat does not support operand type {}", other)),
    };
    Ok(param.to_string())
}

fn emit_int_expr_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    dst: u8,
    scratch_index: u16,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    match value {
        DslValue::IntBinOp { op, left, right } => {
            emit_int_binop_expr(ir, *op, left, right, dst, scratch_index, layout, dsl_ctx)
        }
        DslValue::UnaryOp {
            op: op @ (DslUnaryOp::Neg | DslUnaryOp::BitNot),
            value,
        } => emit_unary_value_with_scratch(ir, *op, value, "I", dst, scratch_index, layout, dsl_ctx),
        _ => emit_load_value(ir, value, "I", dst, layout, dsl_ctx),
    }
}

fn emit_int_binop_expr(
    ir: &mut DexIrBuilder,
    op: DslIntBinOp,
    left: &DslValue,
    right: &DslValue,
    dst: u8,
    scratch_index: u16,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    if let Some((lit_op, literal)) = right_lit8_op(op, right) {
        let src = emit_int_expr_value(ir, left, dst, scratch_index, layout, dsl_ctx)?;
        if src != dst {
            ir.move_from16(dst, src as u16, ValueKind::Narrow);
        }
        ir.int_binop_lit8(lit_op, dst, dst, literal);
        return Ok(dst);
    }
    if dst <= 0x0f {
        if let Some((lit_op, literal)) = right_lit16_op(op, right) {
            let src = emit_int_expr_value(ir, left, dst, scratch_index, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit16(lit_op, dst, dst, literal);
            return Ok(dst);
        }
    }
    if let Some((lit_op, literal)) = left_lit8_op(op, left) {
        let src = emit_int_expr_value(ir, right, dst, scratch_index, layout, dsl_ctx)?;
        if src != dst {
            ir.move_from16(dst, src as u16, ValueKind::Narrow);
        }
        ir.int_binop_lit8(lit_op, dst, dst, literal);
        return Ok(dst);
    }
    if dst <= 0x0f {
        if let Some((lit_op, literal)) = left_lit16_op(op, left) {
            let src = emit_int_expr_value(ir, right, dst, scratch_index, layout, dsl_ctx)?;
            if src != dst {
                ir.move_from16(dst, src as u16, ValueKind::Narrow);
            }
            ir.int_binop_lit16(lit_op, dst, dst, literal);
            return Ok(dst);
        }
    }
    let left_dst = dsl_ctx.int_expr_scratch_reg(scratch_index)?;
    let left_reg = emit_int_expr_value(ir, left, left_dst, scratch_index, layout, dsl_ctx)?;
    if left_reg != left_dst {
        ir.move_from16(left_dst, left_reg as u16, ValueKind::Narrow);
    }
    let right_index = scratch_index
        .checked_add(1)
        .ok_or_else(|| "too many int expression scratch registers".to_string())?;
    let right_dst = dsl_ctx.int_expr_scratch_reg(right_index)?;
    let right_reg = emit_int_expr_value(ir, right, right_dst, right_index, layout, dsl_ctx)?;
    if right_reg != right_dst {
        ir.move_from16(right_dst, right_reg as u16, ValueKind::Narrow);
    }
    ir.int_binop(dex_int_binop(op), dst, left_dst, right_dst);
    Ok(dst)
}

fn right_lit8_op(op: DslIntBinOp, right: &DslValue) -> Option<(DexIntLit8Op, i8)> {
    let literal = value_i8_literal(right)?;
    let lit_op = match op {
        DslIntBinOp::Add => DexIntLit8Op::Add,
        DslIntBinOp::Sub => return literal.checked_neg().map(|negated| (DexIntLit8Op::Add, negated)),
        DslIntBinOp::Mul => DexIntLit8Op::Mul,
        DslIntBinOp::Div => DexIntLit8Op::Div,
        DslIntBinOp::Rem => DexIntLit8Op::Rem,
        DslIntBinOp::And => DexIntLit8Op::And,
        DslIntBinOp::Or => DexIntLit8Op::Or,
        DslIntBinOp::Xor => DexIntLit8Op::Xor,
        DslIntBinOp::Shl => DexIntLit8Op::Shl,
        DslIntBinOp::Shr => DexIntLit8Op::Shr,
        DslIntBinOp::Ushr => DexIntLit8Op::Ushr,
    };
    Some((lit_op, literal))
}

fn right_lit16_op(op: DslIntBinOp, right: &DslValue) -> Option<(DexIntLit16Op, i16)> {
    let literal = value_i16_literal(right)?;
    let lit_op = match op {
        DslIntBinOp::Add => DexIntLit16Op::Add,
        DslIntBinOp::Sub => return literal.checked_neg().map(|negated| (DexIntLit16Op::Add, negated)),
        DslIntBinOp::Mul => DexIntLit16Op::Mul,
        DslIntBinOp::Div => DexIntLit16Op::Div,
        DslIntBinOp::Rem => DexIntLit16Op::Rem,
        DslIntBinOp::And => DexIntLit16Op::And,
        DslIntBinOp::Or => DexIntLit16Op::Or,
        DslIntBinOp::Xor => DexIntLit16Op::Xor,
        DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => return None,
    };
    Some((lit_op, literal))
}

fn left_lit8_op(op: DslIntBinOp, left: &DslValue) -> Option<(DexIntLit8Op, i8)> {
    let literal = value_i8_literal(left)?;
    let lit_op = match op {
        DslIntBinOp::Add => DexIntLit8Op::Add,
        DslIntBinOp::Sub => DexIntLit8Op::Rsub,
        DslIntBinOp::Mul => DexIntLit8Op::Mul,
        DslIntBinOp::And => DexIntLit8Op::And,
        DslIntBinOp::Or => DexIntLit8Op::Or,
        DslIntBinOp::Xor => DexIntLit8Op::Xor,
        DslIntBinOp::Div | DslIntBinOp::Rem | DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => return None,
    };
    Some((lit_op, literal))
}

fn left_lit16_op(op: DslIntBinOp, left: &DslValue) -> Option<(DexIntLit16Op, i16)> {
    let literal = value_i16_literal(left)?;
    let lit_op = match op {
        DslIntBinOp::Add => DexIntLit16Op::Add,
        DslIntBinOp::Sub => DexIntLit16Op::Rsub,
        DslIntBinOp::Mul => DexIntLit16Op::Mul,
        DslIntBinOp::And => DexIntLit16Op::And,
        DslIntBinOp::Or => DexIntLit16Op::Or,
        DslIntBinOp::Xor => DexIntLit16Op::Xor,
        DslIntBinOp::Div | DslIntBinOp::Rem | DslIntBinOp::Shl | DslIntBinOp::Shr | DslIntBinOp::Ushr => return None,
    };
    Some((lit_op, literal))
}

fn value_i8_literal(value: &DslValue) -> Option<i8> {
    let DslValue::Int(value) = value else {
        return None;
    };
    (*value).try_into().ok()
}

fn value_i16_literal(value: &DslValue) -> Option<i16> {
    let DslValue::Int(value) = value else {
        return None;
    };
    Some(*value)
}

fn infer_value_descriptor(
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<Option<String>, String> {
    match value {
        DslValue::Target(target) => resolve_target_descriptor(target, layout, dsl_ctx).map(Some),
        DslValue::String(_) => Ok(Some("Ljava/lang/String;".to_string())),
        DslValue::Int(_)
        | DslValue::ArrayLength(_)
        | DslValue::DirectBufferCapacity { .. }
        | DslValue::DirectBufferGetU8 { .. } => Ok(Some("I".to_string())),
        DslValue::IntBinOp { op, left, right } => {
            if *op == DslIntBinOp::Add && is_string_concat_operands(left, right, layout, dsl_ctx)? {
                return Ok(Some("Ljava/lang/String;".to_string()));
            }
            Ok(Some("I".to_string()))
        }
        DslValue::DefaultValue { type_name } => java_class_to_descriptor_or_primitive(type_name).map(Some),
        DslValue::UnaryOp { op, .. } => match op {
            DslUnaryOp::Neg | DslUnaryOp::BitNot => Ok(Some("I".to_string())),
            DslUnaryOp::BoolNot => Ok(Some("Z".to_string())),
        },
        DslValue::Bool(_) => Ok(Some("Z".to_string())),
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => {
            let then_facts = condition_narrow_facts_when_true(condition)?;
            let mut then_ctx = dsl_ctx.clone();
            let then_desc = then_ctx.with_target_narrow_types(&then_facts, |dsl_ctx| {
                infer_value_descriptor(then_value, layout, dsl_ctx)
            })?;
            let else_facts = condition_narrow_facts_when_false(condition)?;
            let mut else_ctx = dsl_ctx.clone();
            let else_desc = else_ctx.with_target_narrow_types(&else_facts, |dsl_ctx| {
                infer_value_descriptor(else_value, layout, dsl_ctx)
            })?;
            common_value_descriptor_with_env(then_desc, else_desc, dsl_ctx.env)
        }
        DslValue::Null => Ok(None),
        DslValue::OrigCall(_) => {
            let Some(orig_ctx) = dsl_ctx.orig_emit.as_ref() else {
                return Err("orig() is not available in this helper".to_string());
            };
            if orig_ctx.return_type == "V" {
                Ok(None)
            } else {
                Ok(Some(orig_ctx.return_type.clone()))
            }
        }
        DslValue::Call(stmt) => {
            if let Ok((_, return_type)) = parse_method_signature(&stmt.sig) {
                if return_type == "V" {
                    Ok(None)
                } else {
                    Ok(Some(return_type))
                }
            } else {
                let class_type = resolve_member_class_type(
                    stmt.class_name.as_deref(),
                    stmt.target.as_ref(),
                    stmt.receiver.as_deref(),
                    layout,
                    dsl_ctx,
                )?;
                let arg_types = infer_call_arg_descriptors(stmt, layout, dsl_ctx)?;
                let (_, return_type, _) =
                    resolve_call_proto_with_arg_types(dsl_ctx.env, stmt, &class_type, Some(&arg_types))?;
                if return_type == "V" {
                    Ok(None)
                } else {
                    Ok(Some(return_type))
                }
            }
        }
        DslValue::NewObject { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
        DslValue::NewArray { array_type_name, .. } => java_class_to_descriptor_or_primitive(array_type_name).map(Some),
        DslValue::FieldGet { stmt, is_static } => {
            let class_type = resolve_member_class_type(
                stmt.class_name.as_deref(),
                stmt.target.as_ref(),
                stmt.receiver.as_deref(),
                layout,
                dsl_ctx,
            )?;
            resolve_field_type(dsl_ctx.env, stmt, *is_static, &class_type).map(Some)
        }
        DslValue::Cast { class_name, .. } => java_class_to_descriptor(class_name).map(Some),
        DslValue::ArrayGet { type_name, array, .. } => match type_name {
            Some(type_name) => java_class_to_descriptor_or_primitive(type_name).map(Some),
            None => {
                let Some(array_desc) = infer_value_descriptor(array, layout, dsl_ctx)? else {
                    return Ok(None);
                };
                array_component_descriptor(&array_desc).map(Some)
            }
        },
        DslValue::ArrayLiteral { elements } => infer_array_literal_descriptor(elements, layout, dsl_ctx),
    }
}

fn infer_array_literal_descriptor(
    elements: &[DslValue],
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<Option<String>, String> {
    let mut component = None;
    let mut saw_null_before_type = false;
    for element in elements {
        let element_desc = infer_value_descriptor(element, layout, dsl_ctx)?;
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
                component = common_value_descriptor_with_env(component, desc, dsl_ctx.env)?;
            }
        }
    }
    let Some(component) = component else {
        return Ok(None);
    };
    Ok(Some(format!("[{}", component)))
}

fn resolve_array_component_type(
    array: &DslValue,
    explicit_type_name: Option<&str>,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<String, String> {
    if let Some(type_name) = explicit_type_name {
        return java_class_to_descriptor_or_primitive(type_name);
    }
    let Some(array_desc) = infer_value_descriptor(array, layout, dsl_ctx)? else {
        return Err("array element type cannot be inferred; use arr[index: Type]".to_string());
    };
    array_component_descriptor(&array_desc)
}

fn emit_array_length_value(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let array_reg = emit_load_value(ir, array, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
    let array_reg = emit_copy_object_if_needed(ir, array_reg, REG_TMP1);
    let dst = if dst <= 0x0f { dst } else { REG_TMP0 };
    ir.array_length(dst, array_reg);
    Ok(dst)
}

fn emit_array_literal_value(
    ir: &mut DexIrBuilder,
    elements: &[DslValue],
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let array_type = if expected_type.starts_with('[') {
        expected_type.to_string()
    } else {
        infer_array_literal_descriptor(elements, layout, dsl_ctx)?
            .ok_or_else(|| "array literal type cannot be inferred from context or elements".to_string())?
    };
    if !array_type.starts_with('[') {
        return Err(format!("array literal cannot be passed as {}", expected_type));
    }
    let component_type = array_component_descriptor(&array_type)?;
    let kind = value_kind_from_descriptor(&component_type)?;
    let array_reg = dsl_ctx.enter_array_literal()?;
    let result = emit_array_literal_value_in_reg(
        ir,
        elements,
        &array_type,
        &component_type,
        kind,
        array_reg,
        dst,
        layout,
        dsl_ctx,
    );
    dsl_ctx.leave_array_literal();
    result
}

fn emit_array_literal_value_in_reg(
    ir: &mut DexIrBuilder,
    elements: &[DslValue],
    array_type: &str,
    component_type: &str,
    kind: ValueKind,
    array_reg: u8,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let len = i16::try_from(elements.len()).map_err(|_| "array literal is too large".to_string())?;
    if (0..=7).contains(&len) {
        ir.const4(REG_TMP0, len as i8);
    } else {
        ir.const16(REG_TMP0, len);
    }
    ir.new_array(array_reg, REG_TMP0, array_type.to_string());

    for (index, element) in elements.iter().enumerate() {
        let value_reg = emit_array_literal_element(ir, element, component_type, kind, array_reg, layout, dsl_ctx)?;
        let index = i16::try_from(index).map_err(|_| "array literal is too large".to_string())?;
        if (0..=7).contains(&index) {
            ir.const4(REG_TMP0, index as i8);
        } else {
            ir.const16(REG_TMP0, index);
        }
        ir.aput(value_reg, array_reg, REG_TMP0, kind);
    }

    if array_reg != dst {
        ir.move_from16(dst, array_reg as u16, ValueKind::Object);
    }
    Ok(dst)
}

fn emit_array_literal_element(
    ir: &mut DexIrBuilder,
    element: &DslValue,
    component_type: &str,
    kind: ValueKind,
    array_reg: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    match element {
        DslValue::String(value) => {
            if !return_is_object(component_type) {
                return Err(format!("string literal cannot be stored in {}", component_type));
            }
            let field = dsl_ctx.string_literal_field(value);
            ir.sget(REG_TMP1, field, ValueKind::Object);
            Ok(REG_TMP1)
        }
        DslValue::Int(value) => {
            match component_type {
                "B" if i8::try_from(*value).is_err() => {
                    return Err(format!("int literal {} cannot be stored in byte", value));
                }
                "C" if *value < 0 => {
                    return Err(format!("int literal {} cannot be stored in char", value));
                }
                "B" | "C" | "S" | "I" => {}
                _ => {
                    return Err(format!("int literal cannot be stored in {}", component_type));
                }
            }
            ir.const16(REG_TMP1, *value);
            Ok(REG_TMP1)
        }
        DslValue::Bool(value) => {
            if component_type != "Z" {
                return Err(format!("boolean literal cannot be stored in {}", component_type));
            }
            ir.const4(REG_TMP1, if *value { 1 } else { 0 });
            Ok(REG_TMP1)
        }
        DslValue::Null => {
            if !return_is_object(component_type) {
                return Err(format!("null cannot be stored in {}", component_type));
            }
            ir.const4(REG_TMP1, 0);
            Ok(REG_TMP1)
        }
        _ => {
            let reg = emit_load_value(ir, element, component_type, REG_TMP1, layout, dsl_ctx)?;
            if reg == array_reg {
                return Err("array literal element cannot use the destination array register".to_string());
            }
            if reg == REG_TMP0 {
                ir.move_from16(REG_TMP1, REG_TMP0 as u16, kind);
                Ok(REG_TMP1)
            } else {
                Ok(reg)
            }
        }
    }
}

fn emit_array_get_value(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    component_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let array_reg = emit_load_value(ir, array, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
    let array_reg = emit_copy_object_if_needed(ir, array_reg, REG_TMP1);
    let index_reg = emit_load_value(ir, index, "I", REG_TMP0, layout, dsl_ctx)?;
    let index_reg = emit_copy_field_value_if_needed(ir, index_reg, REG_TMP0, ValueKind::Narrow);
    let kind = value_kind_from_descriptor(component_type)?;
    ir.aget(dst, array_reg, index_reg, kind);
    Ok(dst)
}

fn resolve_target_reg(target: &DslTarget, layout: &HelperParamLayout) -> Result<u8, String> {
    match target {
        DslTarget::This => layout
            .this_reg
            .ok_or_else(|| "static target has no this register".to_string()),
        DslTarget::Arg(index) => layout
            .arg_regs
            .get(*index)
            .copied()
            .ok_or_else(|| format!("argument {} does not exist", index)),
        DslTarget::Last => Ok(REG_LAST_OBJECT),
        DslTarget::Result => Ok(REG_RESULT),
        DslTarget::Local(name) => layout
            .local_regs
            .get(name)
            .map(|slot| slot.reg)
            .ok_or_else(|| format!("local '{}' is not declared", name)),
    }
}

fn resolve_target_descriptor(
    target: &DslTarget,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<String, String> {
    if let Some(key) = dsl_target_key(target) {
        if let Some(descriptor) = dsl_ctx.target_narrow_types.get(&key) {
            return Ok(descriptor.clone());
        }
    }
    match target {
        DslTarget::This => layout
            .this_descriptor
            .clone()
            .ok_or_else(|| "static target has no this descriptor".to_string()),
        DslTarget::Arg(index) => layout
            .arg_descriptors
            .get(*index)
            .cloned()
            .ok_or_else(|| format!("argument {} does not exist", index)),
        DslTarget::Local(name) => layout
            .local_regs
            .get(name)
            .map(|slot| slot.descriptor.clone())
            .ok_or_else(|| format!("local '{}' is not declared", name)),
        DslTarget::Last => dsl_ctx
            .last_descriptor
            .clone()
            .ok_or_else(|| "last has no known object type yet".to_string()),
        DslTarget::Result => dsl_ctx
            .result_descriptor
            .clone()
            .ok_or_else(|| "result has no known primitive type yet".to_string()),
    }
}

fn resolve_member_class_type(
    explicit_class_name: Option<&str>,
    target: Option<&DslTarget>,
    receiver: Option<&DslValue>,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<String, String> {
    if let Some(class_name) = explicit_class_name {
        return java_class_to_descriptor(class_name);
    }
    if let Some(receiver) = receiver {
        let Some(desc) = infer_value_descriptor(receiver, layout, dsl_ctx)? else {
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
    let desc = resolve_target_descriptor(target, layout, dsl_ctx)?;
    if !desc.starts_with('L') || !desc.ends_with(';') {
        return Err(format!(
            "target class can only be inferred from object locals/args, got {}",
            desc
        ));
    }
    Ok(desc)
}

fn emit_call_receiver<'a>(
    ir: &mut DexIrBuilder,
    stmt: &DslCallStmt,
    class_type: &'a str,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<Option<(u8, &'a str)>, String> {
    if stmt.kind == DslCallKind::Static {
        return Ok(None);
    }
    if stmt.target.is_some() && stmt.receiver.is_some() {
        return Err("method call cannot use both target and receiver expression".to_string());
    }
    if let Some(target) = stmt.target.as_ref() {
        return resolve_target_reg(target, layout).map(|reg| Some((reg, class_type)));
    }
    if let Some(receiver) = stmt.receiver.as_ref() {
        let reg = emit_load_value(ir, receiver, "Ljava/lang/Object;", REG_LAST_OBJECT, layout, dsl_ctx)?;
        return Ok(Some((reg, class_type)));
    }
    Err("instance method call requires a target or receiver expression".to_string())
}

fn emit_field_receiver(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    if stmt.target.is_some() && stmt.receiver.is_some() {
        return Err("field access cannot use both target and receiver expression".to_string());
    }
    if let Some(target) = stmt.target.as_ref() {
        return Ok(emit_copy_object_if_needed(
            ir,
            resolve_target_reg(target, layout)?,
            REG_TMP1,
        ));
    }
    if let Some(receiver) = stmt.receiver.as_ref() {
        let reg = emit_load_value(ir, receiver, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
        return Ok(emit_copy_object_if_needed(ir, reg, REG_TMP1));
    }
    Err("instance field access requires a target or receiver expression".to_string())
}

fn emit_field_read(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    layout: &HelperParamLayout,
    is_static: bool,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let (declaring_type, field_type) = resolve_field_ref_parts(dsl_ctx.env, stmt, is_static, &class_type)?;
    let field = FieldRef::new(declaring_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    let dst = if matches!(kind, ValueKind::Object) {
        REG_LAST_OBJECT
    } else {
        REG_RESULT
    };
    if is_static {
        ir.sget(dst, field, kind);
    } else {
        let obj = emit_field_receiver(ir, stmt, layout, dsl_ctx)?;
        ir.iget(dst, obj, field, kind);
    }
    dsl_ctx.record_value_descriptor(&field_type);
    Ok(())
}

fn emit_field_write(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    layout: &HelperParamLayout,
    is_static: bool,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let (declaring_type, field_type) = resolve_field_ref_parts(dsl_ctx.env, stmt, is_static, &class_type)?;
    let field = FieldRef::new(declaring_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    let Some(value) = &stmt.value else {
        return Err("field write requires a value".to_string());
    };
    let raw_src = emit_load_value(ir, value, &field_type, REG_TMP0, layout, dsl_ctx)?;
    let src = emit_copy_field_value_if_needed(ir, raw_src, REG_TMP0, kind);
    if is_static {
        ir.sput(src, field, kind);
    } else {
        let obj = emit_field_receiver(ir, stmt, layout, dsl_ctx)?;
        ir.iput(src, obj, field, kind);
    }
    Ok(())
}

fn emit_field_update(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    is_static: bool,
    op: DslIntBinOp,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let (declaring_type, field_type) = resolve_field_ref_parts(dsl_ctx.env, stmt, is_static, &class_type)?;
    if field_type != "I" {
        return Err(format!(
            "field '{}' compound assignment requires int field, got {}",
            stmt.field_name, field_type
        ));
    }
    let rhs = emit_load_value(ir, value, "I", REG_LOOP_LIMIT, layout, dsl_ctx)?;
    if rhs != REG_LOOP_LIMIT {
        ir.move_from16(REG_LOOP_LIMIT, rhs as u16, ValueKind::Narrow);
    }
    let field = FieldRef::new(declaring_type, field_type, stmt.field_name.clone());
    if is_static {
        ir.sget(REG_RESULT, field.clone(), ValueKind::Narrow);
        ir.int_binop(dex_int_binop(op), REG_RESULT, REG_RESULT, REG_LOOP_LIMIT);
        ir.sput(REG_RESULT, field, ValueKind::Narrow);
    } else {
        let obj = emit_field_receiver(ir, stmt, layout, dsl_ctx)?;
        ir.iget(REG_RESULT, obj, field.clone(), ValueKind::Narrow);
        ir.int_binop(dex_int_binop(op), REG_RESULT, REG_RESULT, REG_LOOP_LIMIT);
        ir.iput(REG_RESULT, obj, field, ValueKind::Narrow);
    }
    Ok(())
}

fn resolve_field_type(env: JniEnv, stmt: &DslFieldStmt, is_static: bool, class_type: &str) -> Result<String, String> {
    if !stmt.type_name.is_empty() {
        return java_class_to_descriptor_or_primitive(&stmt.type_name);
    }
    resolve_field_with_env(env, class_type, &stmt.field_name, Some(is_static)).map(|field| field.field_type)
}

fn resolve_field_ref_parts(
    env: JniEnv,
    stmt: &DslFieldStmt,
    is_static: bool,
    class_type: &str,
) -> Result<(String, String), String> {
    if !stmt.type_name.is_empty() {
        return Ok((
            class_type.to_string(),
            java_class_to_descriptor_or_primitive(&stmt.type_name)?,
        ));
    }
    let field = resolve_field_with_env(env, class_type, &stmt.field_name, Some(is_static))?;
    Ok((field.declaring_type, field.field_type))
}

fn emit_let(
    ir: &mut DexIrBuilder,
    name: &str,
    type_name: Option<&str>,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let Some(slot) = layout.local_regs.get(name) else {
        return Err(format!("local '{}' is not allocated", name));
    };
    if let Some(type_name) = type_name {
        let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
        if slot.descriptor != descriptor {
            return Err(format!(
                "local '{}' type mismatch: declared {}, emitted {}",
                name, slot.descriptor, descriptor
            ));
        }
    }
    let src = emit_load_value(ir, value, &slot.descriptor, REG_TMP0, layout, dsl_ctx)?;
    emit_copy_value(ir, slot.reg, src, &slot.descriptor)?;
    Ok(())
}

fn emit_assign(
    ir: &mut DexIrBuilder,
    name: &str,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let Some(slot) = layout.local_regs.get(name) else {
        return Err(format!("local '{}' is not allocated", name));
    };
    let src = emit_load_value(ir, value, &slot.descriptor, REG_TMP0, layout, dsl_ctx)?;
    emit_copy_value(ir, slot.reg, src, &slot.descriptor)?;
    Ok(())
}

fn emit_let_orig(
    ir: &mut DexIrBuilder,
    name: &str,
    type_name: Option<&str>,
    args: &DslOrigArgs,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<(), String> {
    if emit_ctx.return_type == "V" {
        return Err("void orig() cannot be assigned to a local".to_string());
    }
    let slot = emit_ctx
        .layout
        .local_regs
        .get(name)
        .ok_or_else(|| format!("local '{}' is not allocated", name))?;
    let descriptor = if let Some(type_name) = type_name {
        java_class_to_descriptor_or_primitive(type_name)?
    } else {
        slot.descriptor.clone()
    };
    if slot.descriptor != descriptor {
        return Err(format!(
            "local '{}' type mismatch: declared {}, emitted {}",
            name, slot.descriptor, descriptor
        ));
    }
    if !value_descriptor_assignable_to(emit_ctx.return_type, &slot.descriptor) {
        return Err(format!(
            "orig() return type {} cannot be assigned to {}",
            emit_ctx.return_type, slot.descriptor
        ));
    }
    emit_orig_invoke(ir, args, emit_ctx)?;
    emit_move_result_value(ir, emit_ctx.return_type, slot.reg)?;
    Ok(())
}

fn emit_if_null(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    invert: bool,
    then_stmts: &[DslStmt],
    else_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let reg = emit_load_value(
        ir,
        value,
        "Ljava/lang/Object;",
        REG_TMP0,
        emit_ctx.layout,
        emit_ctx.dsl_ctx,
    )?;
    let else_label = ir.new_label();
    let done_label = ir.new_label();
    if invert {
        ir.if_eqz(reg, else_label);
    } else {
        ir.if_nez(reg, else_label);
    }

    let then_returns = emit_statements(ir, then_stmts, emit_ctx)?;
    if !then_returns {
        ir.goto16(done_label);
    }
    ir.bind(else_label)?;
    let else_returns = emit_statements(ir, else_stmts, emit_ctx)?;
    ir.bind(done_label)?;
    Ok(then_returns && else_returns)
}

fn emit_if_bool(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    then_stmts: &[DslStmt],
    else_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let reg = emit_load_cmp_value(ir, value, "Z", REG_TMP0, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let else_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_eqz(reg, else_label);

    let then_returns = emit_statements(ir, then_stmts, emit_ctx)?;
    if !then_returns {
        ir.goto16(done_label);
    }
    ir.bind(else_label)?;
    let else_returns = emit_statements(ir, else_stmts, emit_ctx)?;
    ir.bind(done_label)?;
    Ok(then_returns && else_returns)
}

fn cmp_expected_type(
    left: &DslValue,
    right: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<&'static str, String> {
    let left_desc = infer_cmp_descriptor(left, layout, dsl_ctx)?;
    let right_desc = infer_cmp_descriptor(right, layout, dsl_ctx)?;
    if left_desc == Some("Z") || right_desc == Some("Z") {
        Ok("Z")
    } else if left_desc == Some("I") || right_desc == Some("I") {
        Ok("I")
    } else {
        Ok("Ljava/lang/Object;")
    }
}

fn infer_cmp_descriptor(
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<Option<&'static str>, String> {
    let Some(desc) = infer_value_descriptor(value, layout, dsl_ctx)? else {
        return Ok(None);
    };
    Ok(match desc.as_str() {
        "I" => Some("I"),
        "Z" => Some("Z"),
        _ => None,
    })
}

fn emit_load_cmp_value(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    expected_type: &str,
    temp_reg: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let reg = emit_load_value(ir, value, expected_type, temp_reg, layout, dsl_ctx)?;
    if reg <= 0x0f {
        return Ok(reg);
    }
    let kind = value_kind_from_descriptor(expected_type)?;
    ir.move_from16(temp_reg, reg as u16, kind);
    Ok(temp_reg)
}

fn emit_if_cmp(
    ir: &mut DexIrBuilder,
    op: IfCmpOp,
    left: &DslValue,
    right: &DslValue,
    then_stmts: &[DslStmt],
    else_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let expected_type = cmp_expected_type(left, right, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let left_reg = emit_load_cmp_value(ir, left, expected_type, REG_TMP0, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let right_reg = emit_load_cmp_value(ir, right, expected_type, REG_TMP1, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let else_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_cmp(op.invert(), left_reg, right_reg, else_label);

    let then_returns = emit_statements(ir, then_stmts, emit_ctx)?;
    if !then_returns {
        ir.goto16(done_label);
    }
    ir.bind(else_label)?;
    let else_returns = emit_statements(ir, else_stmts, emit_ctx)?;
    ir.bind(done_label)?;
    Ok(then_returns && else_returns)
}

fn emit_switch(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    cases: &[(i16, Vec<DslStmt>)],
    default_stmts: Option<&[DslStmt]>,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    if cases.is_empty() {
        return Err("switch requires at least one case".to_string());
    }
    let mut seen = BTreeSet::new();
    for (literal, _) in cases {
        if !seen.insert(*literal) {
            return Err(format!("duplicate switch case {}", literal));
        }
    }

    let switch_reg = emit_load_cmp_value(ir, value, "I", REG_TMP0, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    let default_label = ir.new_label();
    let done_label = ir.new_label();
    let case_labels = cases.iter().map(|_| ir.new_label()).collect::<Vec<_>>();

    let mut label_by_key = BTreeMap::new();
    for ((literal, _), label) in cases.iter().zip(case_labels.iter()) {
        label_by_key.insert(*literal, *label);
    }
    let min_key = *seen
        .iter()
        .next()
        .ok_or_else(|| "switch requires at least one case".to_string())?;
    let max_key = *seen
        .iter()
        .next_back()
        .ok_or_else(|| "switch requires at least one case".to_string())?;
    let range_len = (max_key as i32 - min_key as i32 + 1) as usize;
    if range_len <= cases.len() * 2 {
        let targets = (min_key..=max_key)
            .map(|key| *label_by_key.get(&key).unwrap_or(&default_label))
            .collect::<Vec<_>>();
        ir.packed_switch(switch_reg, min_key as i32, targets, default_label);
    } else {
        let keys = seen.iter().map(|key| *key as i32).collect::<Vec<_>>();
        let targets = seen
            .iter()
            .map(|key| *label_by_key.get(key).unwrap_or(&default_label))
            .collect::<Vec<_>>();
        ir.sparse_switch(switch_reg, keys, targets, default_label);
    }

    ir.bind(default_label)?;
    let default_returns = if let Some(stmts) = default_stmts {
        emit_statements(ir, stmts, emit_ctx)?
    } else {
        false
    };
    if !default_returns {
        ir.goto16(done_label);
    }

    let mut cases_all_return = true;
    for ((_, stmts), label) in cases.iter().zip(case_labels.iter()) {
        ir.bind(*label)?;
        let case_returns = emit_statements(ir, stmts, emit_ctx)?;
        if !case_returns {
            ir.goto16(done_label);
        }
        cases_all_return &= case_returns;
    }

    ir.bind(done_label)?;
    Ok(default_stmts.is_some() && default_returns && cases_all_return)
}

fn emit_while(
    ir: &mut DexIrBuilder,
    condition: &DslCondition,
    body_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let condition_label = ir.new_label();
    let body_label = ir.new_label();
    let done_label = ir.new_label();

    ir.bind(condition_label)?;
    emit_condition_branch(ir, condition, body_label, done_label, emit_ctx.layout, emit_ctx.dsl_ctx)?;

    ir.bind(body_label)?;
    emit_ctx.loop_stack.push(LoopLabels {
        break_label: done_label,
        continue_label: condition_label,
    });

    let facts = condition_narrow_facts_when_true(condition)?;
    let body_returns = if facts.is_empty() {
        emit_statements(ir, body_stmts, emit_ctx)?
    } else {
        let layout = emit_ctx.layout;
        let is_static = emit_ctx.is_static;
        let local_count = emit_ctx.local_count;
        let ins_size = emit_ctx.ins_size;
        let target = emit_ctx.target;
        let orig_backup = emit_ctx.orig_backup;
        let target_is_interface = emit_ctx.target_is_interface;
        let return_type = emit_ctx.return_type;
        let sink = emit_ctx.sink;
        let loop_stack = emit_ctx.loop_stack.clone();
        emit_ctx.dsl_ctx.with_target_narrow_types(&facts, |dsl_ctx| {
            let mut narrowed_ctx = EmitContext {
                layout,
                dsl_ctx,
                is_static,
                local_count,
                ins_size,
                target,
                orig_backup,
                target_is_interface,
                return_type,
                sink,
                loop_stack,
            };
            emit_statements(ir, body_stmts, &mut narrowed_ctx)
        })?
    };
    emit_ctx.loop_stack.pop();

    if !body_returns {
        ir.goto16(condition_label);
    }
    ir.bind(done_label)?;
    Ok(false)
}

fn emit_do_while(
    ir: &mut DexIrBuilder,
    body_stmts: &[DslStmt],
    condition: &DslCondition,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let body_label = ir.new_label();
    let condition_label = ir.new_label();
    let done_label = ir.new_label();

    ir.bind(body_label)?;
    emit_ctx.loop_stack.push(LoopLabels {
        break_label: done_label,
        continue_label: condition_label,
    });
    let _body_returns = emit_statements(ir, body_stmts, emit_ctx)?;
    emit_ctx.loop_stack.pop();

    ir.bind(condition_label)?;
    emit_condition_branch(ir, condition, body_label, done_label, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    ir.bind(done_label)?;
    Ok(false)
}

fn emit_for(
    ir: &mut DexIrBuilder,
    init_stmts: &[DslStmt],
    condition: Option<&DslCondition>,
    update_stmts: &[DslStmt],
    body_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    emit_statements(ir, init_stmts, emit_ctx)?;

    let condition_label = ir.new_label();
    let body_label = ir.new_label();
    let update_label = ir.new_label();
    let done_label = ir.new_label();

    ir.bind(condition_label)?;
    if let Some(condition) = condition {
        emit_condition_branch(ir, condition, body_label, done_label, emit_ctx.layout, emit_ctx.dsl_ctx)?;
    } else {
        ir.goto16(body_label);
    }

    ir.bind(body_label)?;
    emit_ctx.loop_stack.push(LoopLabels {
        break_label: done_label,
        continue_label: update_label,
    });

    let facts = condition
        .map(condition_narrow_facts_when_true)
        .transpose()?
        .unwrap_or_default();
    let body_returns = if facts.is_empty() {
        emit_statements(ir, body_stmts, emit_ctx)?
    } else {
        let layout = emit_ctx.layout;
        let is_static = emit_ctx.is_static;
        let local_count = emit_ctx.local_count;
        let ins_size = emit_ctx.ins_size;
        let target = emit_ctx.target;
        let orig_backup = emit_ctx.orig_backup;
        let target_is_interface = emit_ctx.target_is_interface;
        let return_type = emit_ctx.return_type;
        let sink = emit_ctx.sink;
        let loop_stack = emit_ctx.loop_stack.clone();
        emit_ctx.dsl_ctx.with_target_narrow_types(&facts, |dsl_ctx| {
            let mut narrowed_ctx = EmitContext {
                layout,
                dsl_ctx,
                is_static,
                local_count,
                ins_size,
                target,
                orig_backup,
                target_is_interface,
                return_type,
                sink,
                loop_stack,
            };
            emit_statements(ir, body_stmts, &mut narrowed_ctx)
        })?
    };
    emit_ctx.loop_stack.pop();

    if !body_returns {
        ir.goto16(update_label);
    }
    ir.bind(update_label)?;
    let update_returns = emit_statements(ir, update_stmts, emit_ctx)?;
    if !update_returns {
        ir.goto16(condition_label);
    }
    ir.bind(done_label)?;
    Ok(false)
}

fn emit_cast(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    class_name: &str,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let ty = java_class_to_descriptor(class_name)?;
    let src = emit_load_value(ir, value, "Ljava/lang/Object;", REG_LAST_OBJECT, layout, dsl_ctx)?;
    let reg = emit_copy_object_if_needed(ir, src, REG_LAST_OBJECT);
    ir.check_cast(reg, ty);
    if reg != REG_LAST_OBJECT {
        ir.move_from16(REG_LAST_OBJECT, reg as u16, ValueKind::Object);
    }
    dsl_ctx.record_last_descriptor(java_class_to_descriptor(class_name)?);
    Ok(())
}

fn emit_new_array(
    ir: &mut DexIrBuilder,
    array_type_name: &str,
    size: &DslValue,
    sink: &FieldRef,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let array_type = java_class_to_descriptor_or_primitive(array_type_name)?;
    if !array_type.starts_with('[') {
        return Err(format!("newArray requires an array type, got '{}'", array_type_name));
    }
    let size_reg = emit_load_value(ir, size, "I", REG_TMP0, layout, dsl_ctx)?;
    let size_reg = emit_copy_field_value_if_needed(ir, size_reg, REG_TMP0, ValueKind::Narrow);
    ir.new_array(REG_LAST_OBJECT, size_reg, array_type);
    ir.sput_object(REG_LAST_OBJECT, sink.clone());
    dsl_ctx.record_last_descriptor(java_class_to_descriptor_or_primitive(array_type_name)?);
    Ok(())
}

fn emit_new_array_value(
    ir: &mut DexIrBuilder,
    array_type_name: &str,
    size: &DslValue,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let array_type = java_class_to_descriptor_or_primitive(array_type_name)?;
    if !array_type.starts_with('[') {
        return Err(format!("newArray requires an array type, got '{}'", array_type_name));
    }
    if !value_descriptor_assignable_to(&array_type, expected_type) {
        return Err(format!(
            "new array expression type {} cannot be passed as {}",
            array_type, expected_type
        ));
    }
    let size_reg = emit_load_value(ir, size, "I", REG_TMP0, layout, dsl_ctx)?;
    let size_reg = emit_copy_field_value_if_needed(ir, size_reg, REG_TMP0, ValueKind::Narrow);
    ir.new_array(dst, size_reg, array_type);
    Ok(dst)
}

fn emit_array_length_stmt(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let _ = emit_array_length_value(ir, array, REG_RESULT, layout, dsl_ctx)?;
    dsl_ctx.record_result_descriptor("I".to_string());
    Ok(())
}

fn emit_array_get_stmt(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    type_name: Option<&str>,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let component_type = resolve_array_component_type(array, type_name, layout, dsl_ctx)?;
    let kind = value_kind_from_descriptor(&component_type)?;
    let dst = if matches!(kind, ValueKind::Object) {
        REG_LAST_OBJECT
    } else {
        REG_RESULT
    };
    let _ = emit_array_get_value(ir, array, index, &component_type, dst, layout, dsl_ctx)?;
    dsl_ctx.record_value_descriptor(&component_type);
    Ok(())
}

fn emit_array_put(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    type_name: Option<&str>,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let component_type = resolve_array_component_type(array, type_name, layout, dsl_ctx)?;
    let kind = value_kind_from_descriptor(&component_type)?;
    let array_reg = emit_load_value(ir, array, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
    let array_reg = emit_copy_object_if_needed(ir, array_reg, REG_TMP1);
    let index_reg = emit_load_value(ir, index, "I", REG_TMP0, layout, dsl_ctx)?;
    let index_reg = emit_copy_field_value_if_needed(ir, index_reg, REG_TMP0, ValueKind::Narrow);
    let value_temp = if matches!(kind, ValueKind::Object) && array_reg != REG_LAST_OBJECT {
        REG_LAST_OBJECT
    } else if matches!(kind, ValueKind::Object) {
        REG_TMP1
    } else {
        REG_LOOP_LIMIT
    };
    let value_reg = emit_load_value(ir, value, &component_type, value_temp, layout, dsl_ctx)?;
    let value_reg = emit_copy_field_value_if_needed(ir, value_reg, value_temp, kind);
    ir.aput(value_reg, array_reg, index_reg, kind);
    Ok(())
}

fn emit_array_update(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    type_name: Option<&str>,
    op: DslIntBinOp,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let component_type = resolve_array_component_type(array, type_name, layout, dsl_ctx)?;
    if component_type != "I" {
        return Err(format!(
            "array compound assignment requires int element, got {}",
            component_type
        ));
    }
    let rhs = emit_load_value(ir, value, "I", REG_LOOP_LIMIT, layout, dsl_ctx)?;
    if rhs != REG_LOOP_LIMIT {
        ir.move_from16(REG_LOOP_LIMIT, rhs as u16, ValueKind::Narrow);
    }
    let array_reg = emit_load_value(ir, array, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
    let array_reg = emit_copy_object_if_needed(ir, array_reg, REG_TMP1);
    let index_reg = emit_load_value(ir, index, "I", REG_TMP0, layout, dsl_ctx)?;
    let index_reg = emit_copy_field_value_if_needed(ir, index_reg, REG_TMP0, ValueKind::Narrow);
    ir.aget(REG_RESULT, array_reg, index_reg, ValueKind::Narrow);
    ir.int_binop(dex_int_binop(op), REG_RESULT, REG_RESULT, REG_LOOP_LIMIT);
    ir.aput(REG_RESULT, array_reg, index_reg, ValueKind::Narrow);
    Ok(())
}

fn emit_if_instance_of(
    ir: &mut DexIrBuilder,
    value: &DslValue,
    class_name: &str,
    then_stmts: &[DslStmt],
    else_stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    let ty = java_class_to_descriptor(class_name)?;
    let src = emit_load_value(
        ir,
        value,
        "Ljava/lang/Object;",
        REG_TMP1,
        emit_ctx.layout,
        emit_ctx.dsl_ctx,
    )?;
    let obj = emit_copy_object_if_needed(ir, src, REG_TMP1);
    ir.instance_of(REG_TMP0, obj, ty.clone());

    let else_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_eqz(REG_TMP0, else_label);

    let then_returns = if let Some(key) = dsl_value_target_key(value) {
        emit_ctx.dsl_ctx.with_target_narrow_type(key, ty.clone(), |dsl_ctx| {
            let mut narrowed_ctx = EmitContext {
                layout: emit_ctx.layout,
                dsl_ctx,
                is_static: emit_ctx.is_static,
                local_count: emit_ctx.local_count,
                ins_size: emit_ctx.ins_size,
                target: emit_ctx.target,
                orig_backup: emit_ctx.orig_backup,
                target_is_interface: emit_ctx.target_is_interface,
                return_type: emit_ctx.return_type,
                sink: emit_ctx.sink,
                loop_stack: emit_ctx.loop_stack.clone(),
            };
            emit_statements(ir, then_stmts, &mut narrowed_ctx)
        })?
    } else {
        emit_statements(ir, then_stmts, emit_ctx)?
    };
    if !then_returns {
        ir.goto16(done_label);
    }
    ir.bind(else_label)?;
    let else_returns = emit_statements(ir, else_stmts, emit_ctx)?;
    ir.bind(done_label)?;
    Ok(then_returns && else_returns)
}

#[derive(Clone, Copy)]
enum ManagedInvokeKind {
    Direct,
    Virtual,
    Interface,
    Static,
}

fn resolve_managed_invoke_kind(env: JniEnv, requested: DslCallKind, class_type: &str) -> ManagedInvokeKind {
    match requested {
        DslCallKind::Virtual if descriptor_is_interface(env, class_type) => ManagedInvokeKind::Interface,
        DslCallKind::Virtual => ManagedInvokeKind::Virtual,
        DslCallKind::Interface => ManagedInvokeKind::Interface,
        DslCallKind::Static => ManagedInvokeKind::Static,
    }
}

fn infer_call_arg_descriptors(
    stmt: &DslCallStmt,
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<Vec<Option<String>>, String> {
    infer_value_descriptors(&stmt.args, layout, dsl_ctx)
}

fn infer_value_descriptors(
    values: &[DslValue],
    layout: &HelperParamLayout,
    dsl_ctx: &DslBuildContext,
) -> Result<Vec<Option<String>>, String> {
    values
        .iter()
        .map(|value| infer_value_descriptor(value, layout, dsl_ctx))
        .collect::<Result<Vec<_>, _>>()
}

fn emit_invoke_with_values(
    ir: &mut DexIrBuilder,
    kind: ManagedInvokeKind,
    method: MethodRef,
    receiver: Option<(u8, &str)>,
    params: &[String],
    args: &[DslValue],
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let frame = dsl_ctx.enter_invoke_frame()?;
    let result = emit_invoke_with_values_in_frame(ir, kind, method, receiver, params, args, layout, dsl_ctx, frame);
    dsl_ctx.leave_invoke_frame();
    result
}

fn emit_invoke_with_values_in_frame(
    ir: &mut DexIrBuilder,
    kind: ManagedInvokeKind,
    method: MethodRef,
    receiver: Option<(u8, &str)>,
    params: &[String],
    args: &[DslValue],
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
    frame: InvokeScratchFrame,
) -> Result<(), String> {
    let has_wide = params.iter().any(|param| matches!(param.as_str(), "J" | "D"));
    let mut regs = Vec::new();
    if let Some((receiver_reg, _)) = receiver {
        regs.push(receiver_reg);
    }

    let simple_35c = args.is_empty() && !has_wide && regs.len() <= 5 && regs.iter().all(|reg| *reg <= 0x0f);
    if simple_35c {
        match kind {
            ManagedInvokeKind::Direct => ir.invoke_direct(regs, method),
            ManagedInvokeKind::Virtual => ir.invoke_virtual(regs, method),
            ManagedInvokeKind::Interface => ir.invoke_interface(regs, method),
            ManagedInvokeKind::Static => ir.invoke_static(regs, method),
        }
        return Ok(());
    }

    let mut range_next = frame.range_base;
    let mut stage_next = frame.stage_base;
    let receiver_dst = if let Some((_, _)) = receiver {
        let range_dst = checked_reg(range_next, "range receiver register")?;
        let stage_dst = checked_reg(stage_next, "stage receiver register")?;
        range_next += 1;
        stage_next += 1;
        Some((range_dst, stage_dst))
    } else {
        None
    };
    let mut arg_dsts = Vec::with_capacity(args.len());
    for (idx, _) in args.iter().enumerate() {
        let range_dst = checked_reg(range_next, "range argument register")?;
        let stage_dst = checked_reg(stage_next, "stage argument register")?;
        arg_dsts.push((range_dst, stage_dst));
        let words = descriptor_word_count(&params[idx]);
        range_next = range_next
            .checked_add(words)
            .ok_or_else(|| "too many dex registers".to_string())?;
        stage_next = stage_next
            .checked_add(words)
            .ok_or_else(|| "too many dex registers".to_string())?;
    }

    if let Some((receiver_reg, receiver_desc)) = receiver {
        let (_, stage_dst) = receiver_dst.ok_or_else(|| "missing stage receiver register".to_string())?;
        emit_copy_value(ir, stage_dst, receiver_reg, receiver_desc)?;
    }
    for (idx, arg) in args.iter().enumerate() {
        let (_, stage_dst) = arg_dsts[idx];
        let src = emit_load_value(ir, arg, &params[idx], stage_dst, layout, dsl_ctx)?;
        emit_copy_value(ir, stage_dst, src, &params[idx])?;
    }

    if let Some((_, receiver_desc)) = receiver {
        let (range_dst, stage_dst) = receiver_dst.ok_or_else(|| "missing range receiver register".to_string())?;
        emit_copy_value(ir, range_dst, stage_dst, receiver_desc)?;
    }
    for (idx, _) in args.iter().enumerate() {
        let (range_dst, stage_dst) = arg_dsts[idx];
        emit_copy_value(ir, range_dst, stage_dst, &params[idx])?;
    }

    let arg_words = range_next
        .checked_sub(frame.range_base)
        .ok_or_else(|| "invalid range invoke register layout".to_string())?;
    if arg_words > dsl_ctx.invoke_frame_words {
        return Err(format!(
            "invoke requires {} words, reserved frame has {}",
            arg_words, dsl_ctx.invoke_frame_words
        ));
    }
    if arg_words > u8::MAX as u16 {
        return Err(format!("too many invoke argument words: {}", arg_words));
    }
    match kind {
        ManagedInvokeKind::Direct => ir.invoke_direct_range(frame.range_base, arg_words as u8, method),
        ManagedInvokeKind::Virtual => ir.invoke_virtual_range(frame.range_base, arg_words as u8, method),
        ManagedInvokeKind::Interface => ir.invoke_interface_range(frame.range_base, arg_words as u8, method),
        ManagedInvokeKind::Static => ir.invoke_static_range(frame.range_base, arg_words as u8, method),
    }
    Ok(())
}

fn emit_call(
    ir: &mut DexIrBuilder,
    stmt: &DslCallStmt,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<MethodRef, String> {
    let class_type = resolve_member_class_type(
        stmt.class_name.as_deref(),
        stmt.target.as_ref(),
        stmt.receiver.as_deref(),
        layout,
        dsl_ctx,
    )?;
    let arg_types = infer_call_arg_descriptors(stmt, layout, dsl_ctx)?;
    let (params, return_type, full_sig) =
        resolve_call_proto_with_arg_types(dsl_ctx.env, stmt, &class_type, Some(&arg_types))?;
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
    let method = MethodRef::new(
        class_type.clone(),
        stmt.method_name.clone(),
        return_type.clone(),
        params.clone(),
    );

    let receiver = stmt
        .target
        .as_ref()
        .map(|target| resolve_target_reg(target, layout).map(|reg| (reg, class_type.as_str())))
        .transpose()?;
    let invoke_kind = resolve_managed_invoke_kind(dsl_ctx.env, stmt.kind, &class_type);
    if stmt.null_safe {
        let Some((receiver_reg, receiver_desc)) = receiver else {
            return Err("null-safe call requires a receiver".to_string());
        };
        if matches!(invoke_kind, ManagedInvokeKind::Static) {
            return Err("null-safe call is only valid for instance/interface methods".to_string());
        }
        let done_label = ir.new_label();
        ir.if_eqz(receiver_reg, done_label);
        emit_invoke_with_values(
            ir,
            invoke_kind,
            method.clone(),
            Some((receiver_reg, receiver_desc)),
            &params,
            &stmt.args,
            layout,
            dsl_ctx,
        )?;
        emit_discard_result(ir, &return_type)?;
        ir.bind(done_label)?;
        return Ok(method);
    }
    emit_invoke_with_values(
        ir,
        invoke_kind,
        method.clone(),
        receiver,
        &params,
        &stmt.args,
        layout,
        dsl_ctx,
    )?;
    emit_discard_result(ir, &return_type)?;
    dsl_ctx.record_value_descriptor(&return_type);
    Ok(method)
}

fn invoke_arg_words(has_receiver: bool, params: &[String]) -> Result<u16, String> {
    let mut words = if has_receiver { 1u16 } else { 0u16 };
    words = words
        .checked_add(descriptor_list_word_count(params)?)
        .ok_or_else(|| "too many dex registers".to_string())?;
    Ok(words)
}

pub(super) fn program_max_invoke_words(
    program: &DslProgram,
    target_params: &[String],
    is_static: bool,
) -> Result<u16, String> {
    statements_max_invoke_words(&program.stmts, target_params, is_static)
}

pub(super) fn program_max_invoke_depth(program: &DslProgram) -> u16 {
    statements_max_invoke_depth(&program.stmts)
}

pub(super) fn program_int_expr_scratch_count(program: &DslProgram) -> u16 {
    statements_int_expr_scratch_count(&program.stmts)
}

pub(super) fn program_array_literal_scratch_count(program: &DslProgram) -> u16 {
    statements_array_literal_scratch_count(&program.stmts)
}

fn statements_max_invoke_depth(stmts: &[DslStmt]) -> u16 {
    stmts.iter().map(stmt_max_invoke_depth).max().unwrap_or(0)
}

fn stmt_max_invoke_depth(stmt: &DslStmt) -> u16 {
    match stmt {
        DslStmt::Block(stmts) => statements_max_invoke_depth(stmts),
        DslStmt::Let { value, .. }
        | DslStmt::Assign { value, .. }
        | DslStmt::NewArray { size: value, .. }
        | DslStmt::Cast { value, .. }
        | DslStmt::ArrayLength { array: value }
        | DslStmt::Throw { value } => value_max_invoke_depth(value),
        DslStmt::LetOrig { args, .. } | DslStmt::ReturnOrig { args } => orig_args_max_invoke_depth(args),
        DslStmt::New { args, .. } => 1 + values_max_invoke_depth(args),
        DslStmt::Call(stmt) => call_stmt_max_invoke_depth(stmt),
        DslStmt::ArrayGet { array, index, .. } => value_max_invoke_depth(array).max(value_max_invoke_depth(index)),
        DslStmt::ArrayPut {
            array, index, value, ..
        } => value_max_invoke_depth(array)
            .max(value_max_invoke_depth(index))
            .max(value_max_invoke_depth(value)),
        DslStmt::ArrayUpdate {
            array, index, value, ..
        } => value_max_invoke_depth(array)
            .max(value_max_invoke_depth(index))
            .max(value_max_invoke_depth(value)),
        DslStmt::FieldRead { stmt, .. } => field_stmt_max_invoke_depth(stmt),
        DslStmt::FieldWrite { stmt, .. } => field_stmt_max_invoke_depth(stmt),
        DslStmt::FieldUpdate { stmt, value, .. } => {
            field_stmt_max_invoke_depth(stmt).max(value_max_invoke_depth(value))
        }
        DslStmt::IfNull {
            value,
            then_stmts,
            else_stmts,
            ..
        }
        | DslStmt::IfBool {
            value,
            then_stmts,
            else_stmts,
            ..
        }
        | DslStmt::IfInstanceOf {
            value,
            then_stmts,
            else_stmts,
            ..
        } => value_max_invoke_depth(value)
            .max(statements_max_invoke_depth(then_stmts))
            .max(statements_max_invoke_depth(else_stmts)),
        DslStmt::IfCmp {
            left,
            right,
            then_stmts,
            else_stmts,
            ..
        } => value_max_invoke_depth(left)
            .max(value_max_invoke_depth(right))
            .max(statements_max_invoke_depth(then_stmts))
            .max(statements_max_invoke_depth(else_stmts)),
        DslStmt::Switch {
            value,
            cases,
            default_stmts,
        } => {
            let mut depth = value_max_invoke_depth(value);
            for (_, stmts) in cases {
                depth = depth.max(statements_max_invoke_depth(stmts));
            }
            if let Some(stmts) = default_stmts {
                depth = depth.max(statements_max_invoke_depth(stmts));
            }
            depth
        }
        DslStmt::TryCatch { try_stmts, catches } => statements_max_invoke_depth(try_stmts).max(
            catches
                .iter()
                .map(|catch| statements_max_invoke_depth(&catch.catch_stmts))
                .max()
                .unwrap_or(0),
        ),
        DslStmt::While { condition, body_stmts } | DslStmt::DoWhile { condition, body_stmts } => {
            condition_max_invoke_depth(condition).max(statements_max_invoke_depth(body_stmts))
        }
        DslStmt::For {
            init_stmts,
            condition,
            update_stmts,
            body_stmts,
        } => statements_max_invoke_depth(init_stmts)
            .max(condition.as_ref().map(condition_max_invoke_depth).unwrap_or(0))
            .max(statements_max_invoke_depth(update_stmts))
            .max(statements_max_invoke_depth(body_stmts)),
        DslStmt::Send { value, .. } => 1 + value_max_invoke_depth(value),
        DslStmt::DirectBufferFill {
            buffer,
            offset,
            length,
            value,
        } => {
            1 + value_max_invoke_depth(buffer)
                .max(value_max_invoke_depth(offset))
                .max(value_max_invoke_depth(length))
                .max(value_max_invoke_depth(value))
        }
        DslStmt::DirectBufferCopyFromByteArray {
            buffer,
            dst_offset,
            src,
            src_offset,
            length,
        } => {
            1 + value_max_invoke_depth(buffer)
                .max(value_max_invoke_depth(dst_offset))
                .max(value_max_invoke_depth(src))
                .max(value_max_invoke_depth(src_offset))
                .max(value_max_invoke_depth(length))
        }
        DslStmt::DirectBufferCopyToByteArray {
            buffer,
            src_offset,
            dst,
            dst_offset,
            length,
        } => {
            1 + value_max_invoke_depth(buffer)
                .max(value_max_invoke_depth(src_offset))
                .max(value_max_invoke_depth(dst))
                .max(value_max_invoke_depth(dst_offset))
                .max(value_max_invoke_depth(length))
        }
        DslStmt::Break | DslStmt::Continue | DslStmt::Count { .. } => 0,
        DslStmt::ReturnValue { value } => value.as_ref().map(value_max_invoke_depth).unwrap_or(0),
    }
}

fn field_stmt_max_invoke_depth(stmt: &DslFieldStmt) -> u16 {
    stmt.receiver
        .as_deref()
        .map(value_max_invoke_depth)
        .unwrap_or(0)
        .max(stmt.value.as_ref().map(value_max_invoke_depth).unwrap_or(0))
}

fn call_stmt_max_invoke_depth(stmt: &DslCallStmt) -> u16 {
    1 + stmt
        .receiver
        .as_deref()
        .map(value_max_invoke_depth)
        .unwrap_or(0)
        .max(values_max_invoke_depth(&stmt.args))
}

fn values_max_invoke_depth(values: &[DslValue]) -> u16 {
    values.iter().map(value_max_invoke_depth).max().unwrap_or(0)
}

fn value_max_invoke_depth(value: &DslValue) -> u16 {
    match value {
        DslValue::Call(stmt) => call_stmt_max_invoke_depth(stmt),
        DslValue::NewObject { args, .. } => 1 + values_max_invoke_depth(args),
        DslValue::NewArray { size, .. } => value_max_invoke_depth(size),
        DslValue::OrigCall(args) => orig_args_max_invoke_depth(args),
        DslValue::UnaryOp { value, .. } | DslValue::Cast { value, .. } | DslValue::ArrayLength(value) => {
            value_max_invoke_depth(value)
        }
        DslValue::DirectBufferCapacity { buffer } => 1 + value_max_invoke_depth(buffer),
        DslValue::DirectBufferGetU8 { buffer, offset } => {
            1 + value_max_invoke_depth(buffer).max(value_max_invoke_depth(offset))
        }
        DslValue::IntBinOp { op, left, right } => {
            let nested = value_max_invoke_depth(left).max(value_max_invoke_depth(right));
            if *op == DslIntBinOp::Add {
                1 + nested
            } else {
                nested
            }
        }
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => condition_max_invoke_depth(condition)
            .max(value_max_invoke_depth(then_value))
            .max(value_max_invoke_depth(else_value)),
        DslValue::FieldGet { stmt, .. } => field_stmt_max_invoke_depth(stmt),
        DslValue::ArrayGet { array, index, .. } => value_max_invoke_depth(array).max(value_max_invoke_depth(index)),
        DslValue::ArrayLiteral { elements } => values_max_invoke_depth(elements),
        DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Bool(_)
        | DslValue::Null
        | DslValue::DefaultValue { .. } => 0,
    }
}

fn condition_max_invoke_depth(condition: &DslCondition) -> u16 {
    match condition {
        DslCondition::Const(_) => 0,
        DslCondition::Null { value, .. } | DslCondition::Bool { value } | DslCondition::InstanceOf { value, .. } => {
            value_max_invoke_depth(value)
        }
        DslCondition::Cmp { left, right, .. } => value_max_invoke_depth(left).max(value_max_invoke_depth(right)),
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            condition_max_invoke_depth(left).max(condition_max_invoke_depth(right))
        }
        DslCondition::Not(condition) => condition_max_invoke_depth(condition),
    }
}

fn orig_args_max_invoke_depth(args: &DslOrigArgs) -> u16 {
    match args {
        DslOrigArgs::Original => 1,
        DslOrigArgs::Values(values) => 1 + values_max_invoke_depth(values),
    }
}

fn statements_int_expr_scratch_count(stmts: &[DslStmt]) -> u16 {
    stmts.iter().map(stmt_int_expr_scratch_count).max().unwrap_or(0)
}

fn stmt_int_expr_scratch_count(stmt: &DslStmt) -> u16 {
    match stmt {
        DslStmt::Block(stmts) => statements_int_expr_scratch_count(stmts),
        DslStmt::Let { value, .. } | DslStmt::Assign { value, .. } => value_int_expr_scratch_count(value),
        DslStmt::LetOrig { args, .. } | DslStmt::ReturnOrig { args } => orig_args_int_expr_scratch_count(args),
        DslStmt::New { args, .. } => values_int_expr_scratch_count(args),
        DslStmt::NewArray { size, .. } => value_int_expr_scratch_count(size),
        DslStmt::Call(stmt) => stmt
            .receiver
            .as_ref()
            .map(|receiver| value_int_expr_scratch_count(receiver))
            .unwrap_or(0)
            .max(values_int_expr_scratch_count(&stmt.args)),
        DslStmt::Cast { value, .. } | DslStmt::ArrayLength { array: value } => value_int_expr_scratch_count(value),
        DslStmt::ArrayGet { array, index, .. } => {
            value_int_expr_scratch_count(array).max(value_int_expr_scratch_count(index))
        }
        DslStmt::ArrayPut {
            array, index, value, ..
        } => value_int_expr_scratch_count(array)
            .max(value_int_expr_scratch_count(index))
            .max(value_int_expr_scratch_count(value)),
        DslStmt::ArrayUpdate {
            array, index, value, ..
        } => value_int_expr_scratch_count(array)
            .max(value_int_expr_scratch_count(index))
            .max(value_int_expr_scratch_count(value)),
        DslStmt::FieldRead { .. } => 0,
        DslStmt::FieldWrite { stmt, .. } => stmt.value.as_ref().map(value_int_expr_scratch_count).unwrap_or(0),
        DslStmt::FieldUpdate { stmt, value, .. } => stmt
            .receiver
            .as_deref()
            .map(value_int_expr_scratch_count)
            .unwrap_or(0)
            .max(value_int_expr_scratch_count(value)),
        DslStmt::IfNull {
            value,
            then_stmts,
            else_stmts,
            ..
        }
        | DslStmt::IfBool {
            value,
            then_stmts,
            else_stmts,
        }
        | DslStmt::IfInstanceOf {
            value,
            then_stmts,
            else_stmts,
            ..
        } => value_int_expr_scratch_count(value)
            .max(statements_int_expr_scratch_count(then_stmts))
            .max(statements_int_expr_scratch_count(else_stmts)),
        DslStmt::IfCmp {
            left,
            right,
            then_stmts,
            else_stmts,
            ..
        } => value_int_expr_scratch_count(left)
            .max(value_int_expr_scratch_count(right))
            .max(statements_int_expr_scratch_count(then_stmts))
            .max(statements_int_expr_scratch_count(else_stmts)),
        DslStmt::Switch {
            value,
            cases,
            default_stmts,
        } => {
            let mut count = value_int_expr_scratch_count(value);
            for (_, stmts) in cases {
                count = count.max(statements_int_expr_scratch_count(stmts));
            }
            if let Some(stmts) = default_stmts {
                count = count.max(statements_int_expr_scratch_count(stmts));
            }
            count
        }
        DslStmt::TryCatch { try_stmts, catches } => statements_int_expr_scratch_count(try_stmts).max(
            catches
                .iter()
                .map(|catch| statements_int_expr_scratch_count(&catch.catch_stmts))
                .max()
                .unwrap_or(0),
        ),
        DslStmt::While { condition, body_stmts } | DslStmt::DoWhile { condition, body_stmts } => {
            condition_int_expr_scratch_count(condition).max(statements_int_expr_scratch_count(body_stmts))
        }
        DslStmt::For {
            init_stmts,
            condition,
            update_stmts,
            body_stmts,
        } => statements_int_expr_scratch_count(init_stmts)
            .max(condition.as_ref().map(condition_int_expr_scratch_count).unwrap_or(0))
            .max(statements_int_expr_scratch_count(update_stmts))
            .max(statements_int_expr_scratch_count(body_stmts)),
        DslStmt::Send { value, .. } => value_int_expr_scratch_count(value),
        DslStmt::DirectBufferFill {
            buffer,
            offset,
            length,
            value,
        } => value_int_expr_scratch_count(buffer)
            .max(value_int_expr_scratch_count(offset))
            .max(value_int_expr_scratch_count(length))
            .max(value_int_expr_scratch_count(value)),
        DslStmt::DirectBufferCopyFromByteArray {
            buffer,
            dst_offset,
            src,
            src_offset,
            length,
        } => value_int_expr_scratch_count(buffer)
            .max(value_int_expr_scratch_count(dst_offset))
            .max(value_int_expr_scratch_count(src))
            .max(value_int_expr_scratch_count(src_offset))
            .max(value_int_expr_scratch_count(length)),
        DslStmt::DirectBufferCopyToByteArray {
            buffer,
            src_offset,
            dst,
            dst_offset,
            length,
        } => value_int_expr_scratch_count(buffer)
            .max(value_int_expr_scratch_count(src_offset))
            .max(value_int_expr_scratch_count(dst))
            .max(value_int_expr_scratch_count(dst_offset))
            .max(value_int_expr_scratch_count(length)),
        DslStmt::Break | DslStmt::Continue | DslStmt::Count { .. } => 0,
        DslStmt::ReturnValue { value } => value.as_ref().map(value_int_expr_scratch_count).unwrap_or(0),
        DslStmt::Throw { value } => value_int_expr_scratch_count(value),
    }
}

fn orig_args_int_expr_scratch_count(args: &DslOrigArgs) -> u16 {
    match args {
        DslOrigArgs::Original => 0,
        DslOrigArgs::Values(values) => values_int_expr_scratch_count(values),
    }
}

fn values_int_expr_scratch_count(values: &[DslValue]) -> u16 {
    values.iter().map(value_int_expr_scratch_count).max().unwrap_or(0)
}

fn value_int_expr_scratch_count(value: &DslValue) -> u16 {
    match value {
        DslValue::IntBinOp { op, left, right } => {
            if right_lit8_op(*op, right).is_some() {
                return value_int_expr_scratch_count(left);
            }
            if left_lit8_op(*op, left).is_some() {
                return value_int_expr_scratch_count(right);
            }
            let left_count = value_int_expr_scratch_count(left).max(1);
            let right_count = 1 + value_int_expr_scratch_count(right).max(1);
            left_count.max(right_count)
        }
        DslValue::UnaryOp { value, .. } => value_int_expr_scratch_count(value),
        DslValue::OrigCall(args) => orig_args_int_expr_scratch_count(args),
        DslValue::NewObject { args, .. } => values_int_expr_scratch_count(args),
        DslValue::NewArray { size, .. } => value_int_expr_scratch_count(size),
        DslValue::Call(stmt) => stmt
            .receiver
            .as_ref()
            .map(|receiver| value_int_expr_scratch_count(receiver))
            .unwrap_or(0)
            .max(values_int_expr_scratch_count(&stmt.args)),
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => condition_int_expr_scratch_count(condition)
            .max(value_int_expr_scratch_count(then_value))
            .max(value_int_expr_scratch_count(else_value)),
        DslValue::Cast { value, .. }
        | DslValue::ArrayLength(value)
        | DslValue::DirectBufferCapacity { buffer: value } => value_int_expr_scratch_count(value),
        DslValue::DirectBufferGetU8 { buffer, offset } => {
            value_int_expr_scratch_count(buffer).max(value_int_expr_scratch_count(offset))
        }
        DslValue::ArrayGet { array, index, .. } => {
            value_int_expr_scratch_count(array).max(value_int_expr_scratch_count(index))
        }
        DslValue::ArrayLiteral { elements } => values_int_expr_scratch_count(elements),
        DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Bool(_)
        | DslValue::Null
        | DslValue::DefaultValue { .. }
        | DslValue::FieldGet { .. } => 0,
    }
}

fn condition_int_expr_scratch_count(condition: &DslCondition) -> u16 {
    match condition {
        DslCondition::Const(_) => 0,
        DslCondition::Null { value, .. } | DslCondition::Bool { value } | DslCondition::InstanceOf { value, .. } => {
            value_int_expr_scratch_count(value)
        }
        DslCondition::Cmp { left, right, .. } => {
            value_int_expr_scratch_count(left).max(value_int_expr_scratch_count(right))
        }
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            condition_int_expr_scratch_count(left).max(condition_int_expr_scratch_count(right))
        }
        DslCondition::Not(condition) => condition_int_expr_scratch_count(condition),
    }
}

fn statements_array_literal_scratch_count(stmts: &[DslStmt]) -> u16 {
    stmts.iter().map(stmt_array_literal_scratch_count).max().unwrap_or(0)
}

fn stmt_array_literal_scratch_count(stmt: &DslStmt) -> u16 {
    match stmt {
        DslStmt::Block(stmts) => statements_array_literal_scratch_count(stmts),
        DslStmt::Let { value, .. }
        | DslStmt::Assign { value, .. }
        | DslStmt::NewArray { size: value, .. }
        | DslStmt::Cast { value, .. }
        | DslStmt::ArrayLength { array: value }
        | DslStmt::Throw { value } => value_array_literal_scratch_count(value),
        DslStmt::LetOrig { args, .. } | DslStmt::ReturnOrig { args } => orig_args_array_literal_scratch_count(args),
        DslStmt::New { args, .. } => values_array_literal_scratch_count(args),
        DslStmt::Call(stmt) => call_stmt_array_literal_scratch_count(stmt),
        DslStmt::ArrayGet { array, index, .. } => {
            value_array_literal_scratch_count(array).max(value_array_literal_scratch_count(index))
        }
        DslStmt::ArrayPut {
            array, index, value, ..
        }
        | DslStmt::ArrayUpdate {
            array, index, value, ..
        } => value_array_literal_scratch_count(array)
            .max(value_array_literal_scratch_count(index))
            .max(value_array_literal_scratch_count(value)),
        DslStmt::FieldRead { stmt, .. } | DslStmt::FieldWrite { stmt, .. } => {
            field_stmt_array_literal_scratch_count(stmt)
        }
        DslStmt::FieldUpdate { stmt, value, .. } => {
            field_stmt_array_literal_scratch_count(stmt).max(value_array_literal_scratch_count(value))
        }
        DslStmt::IfNull {
            value,
            then_stmts,
            else_stmts,
            ..
        }
        | DslStmt::IfBool {
            value,
            then_stmts,
            else_stmts,
        }
        | DslStmt::IfInstanceOf {
            value,
            then_stmts,
            else_stmts,
            ..
        } => value_array_literal_scratch_count(value)
            .max(statements_array_literal_scratch_count(then_stmts))
            .max(statements_array_literal_scratch_count(else_stmts)),
        DslStmt::IfCmp {
            left,
            right,
            then_stmts,
            else_stmts,
            ..
        } => value_array_literal_scratch_count(left)
            .max(value_array_literal_scratch_count(right))
            .max(statements_array_literal_scratch_count(then_stmts))
            .max(statements_array_literal_scratch_count(else_stmts)),
        DslStmt::Switch {
            value,
            cases,
            default_stmts,
        } => {
            let mut count = value_array_literal_scratch_count(value);
            for (_, stmts) in cases {
                count = count.max(statements_array_literal_scratch_count(stmts));
            }
            if let Some(stmts) = default_stmts {
                count = count.max(statements_array_literal_scratch_count(stmts));
            }
            count
        }
        DslStmt::TryCatch { try_stmts, catches } => {
            let mut count = statements_array_literal_scratch_count(try_stmts);
            for catch in catches {
                count = count.max(statements_array_literal_scratch_count(&catch.catch_stmts));
            }
            count
        }
        DslStmt::While { condition, body_stmts } | DslStmt::DoWhile { condition, body_stmts } => {
            condition_array_literal_scratch_count(condition).max(statements_array_literal_scratch_count(body_stmts))
        }
        DslStmt::For {
            init_stmts,
            condition,
            update_stmts,
            body_stmts,
        } => statements_array_literal_scratch_count(init_stmts)
            .max(
                condition
                    .as_ref()
                    .map(condition_array_literal_scratch_count)
                    .unwrap_or(0),
            )
            .max(statements_array_literal_scratch_count(update_stmts))
            .max(statements_array_literal_scratch_count(body_stmts)),
        DslStmt::Send { value, .. } => value_array_literal_scratch_count(value),
        DslStmt::DirectBufferFill {
            buffer,
            offset,
            length,
            value,
        } => value_array_literal_scratch_count(buffer)
            .max(value_array_literal_scratch_count(offset))
            .max(value_array_literal_scratch_count(length))
            .max(value_array_literal_scratch_count(value)),
        DslStmt::DirectBufferCopyFromByteArray {
            buffer,
            dst_offset,
            src,
            src_offset,
            length,
        } => value_array_literal_scratch_count(buffer)
            .max(value_array_literal_scratch_count(dst_offset))
            .max(value_array_literal_scratch_count(src))
            .max(value_array_literal_scratch_count(src_offset))
            .max(value_array_literal_scratch_count(length)),
        DslStmt::DirectBufferCopyToByteArray {
            buffer,
            src_offset,
            dst,
            dst_offset,
            length,
        } => value_array_literal_scratch_count(buffer)
            .max(value_array_literal_scratch_count(src_offset))
            .max(value_array_literal_scratch_count(dst))
            .max(value_array_literal_scratch_count(dst_offset))
            .max(value_array_literal_scratch_count(length)),
        DslStmt::Break | DslStmt::Continue | DslStmt::Count { .. } => 0,
        DslStmt::ReturnValue { value } => value.as_ref().map(value_array_literal_scratch_count).unwrap_or(0),
    }
}

fn field_stmt_array_literal_scratch_count(stmt: &DslFieldStmt) -> u16 {
    stmt.receiver
        .as_deref()
        .map(value_array_literal_scratch_count)
        .unwrap_or(0)
        .max(stmt.value.as_ref().map(value_array_literal_scratch_count).unwrap_or(0))
}

fn call_stmt_array_literal_scratch_count(stmt: &DslCallStmt) -> u16 {
    stmt.receiver
        .as_deref()
        .map(value_array_literal_scratch_count)
        .unwrap_or(0)
        .max(values_array_literal_scratch_count(&stmt.args))
}

fn orig_args_array_literal_scratch_count(args: &DslOrigArgs) -> u16 {
    match args {
        DslOrigArgs::Original => 0,
        DslOrigArgs::Values(values) => values_array_literal_scratch_count(values),
    }
}

fn values_array_literal_scratch_count(values: &[DslValue]) -> u16 {
    values.iter().map(value_array_literal_scratch_count).max().unwrap_or(0)
}

fn value_array_literal_scratch_count(value: &DslValue) -> u16 {
    match value {
        DslValue::ArrayLiteral { elements } => 1 + values_array_literal_scratch_count(elements),
        DslValue::UnaryOp { value, .. }
        | DslValue::Cast { value, .. }
        | DslValue::ArrayLength(value)
        | DslValue::DirectBufferCapacity { buffer: value } => value_array_literal_scratch_count(value),
        DslValue::DirectBufferGetU8 { buffer, offset } => {
            value_array_literal_scratch_count(buffer).max(value_array_literal_scratch_count(offset))
        }
        DslValue::IntBinOp { left, right, .. } => {
            value_array_literal_scratch_count(left).max(value_array_literal_scratch_count(right))
        }
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => condition_array_literal_scratch_count(condition)
            .max(value_array_literal_scratch_count(then_value))
            .max(value_array_literal_scratch_count(else_value)),
        DslValue::OrigCall(args) => orig_args_array_literal_scratch_count(args),
        DslValue::Call(stmt) => call_stmt_array_literal_scratch_count(stmt),
        DslValue::NewObject { args, .. } => values_array_literal_scratch_count(args),
        DslValue::NewArray { size, .. } => value_array_literal_scratch_count(size),
        DslValue::FieldGet { stmt, .. } => field_stmt_array_literal_scratch_count(stmt),
        DslValue::ArrayGet { array, index, .. } => {
            value_array_literal_scratch_count(array).max(value_array_literal_scratch_count(index))
        }
        DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Bool(_)
        | DslValue::Null
        | DslValue::DefaultValue { .. } => 0,
    }
}

fn condition_array_literal_scratch_count(condition: &DslCondition) -> u16 {
    match condition {
        DslCondition::Const(_) => 0,
        DslCondition::Null { value, .. } | DslCondition::Bool { value } | DslCondition::InstanceOf { value, .. } => {
            value_array_literal_scratch_count(value)
        }
        DslCondition::Cmp { left, right, .. } => {
            value_array_literal_scratch_count(left).max(value_array_literal_scratch_count(right))
        }
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            condition_array_literal_scratch_count(left).max(condition_array_literal_scratch_count(right))
        }
        DslCondition::Not(condition) => condition_array_literal_scratch_count(condition),
    }
}

fn statements_max_invoke_words(stmts: &[DslStmt], target_params: &[String], is_static: bool) -> Result<u16, String> {
    let mut max_words = 0u16;
    for stmt in stmts {
        let words = match stmt {
            DslStmt::Block(stmts) => statements_max_invoke_words(stmts, target_params, is_static)?,
            DslStmt::Let { value, .. } | DslStmt::Assign { value, .. } => value_max_invoke_words(value)?,
            DslStmt::LetOrig { args, .. } => orig_args_max_invoke_words(args, target_params, is_static)?,
            DslStmt::New { ctor_sig, args, .. } => {
                let mut words = constructor_max_direct_words(ctor_sig.as_deref(), args)?;
                for arg in args {
                    words = words.max(value_max_invoke_words(arg)?);
                }
                words
            }
            DslStmt::NewArray { size, .. } => value_max_invoke_words(size)?,
            DslStmt::Call(stmt) => {
                let mut words = call_stmt_max_direct_words(stmt)?;
                for arg in &stmt.args {
                    words = words.max(value_max_invoke_words(arg)?);
                }
                if let Some(receiver) = &stmt.receiver {
                    words = words.max(value_max_invoke_words(receiver)?);
                }
                words
            }
            DslStmt::IfNull {
                value,
                then_stmts,
                else_stmts,
                ..
            } => value_max_invoke_words(value)?
                .max(statements_max_invoke_words(then_stmts, target_params, is_static)?)
                .max(statements_max_invoke_words(else_stmts, target_params, is_static)?),
            DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            } => value_max_invoke_words(value)?
                .max(statements_max_invoke_words(then_stmts, target_params, is_static)?)
                .max(statements_max_invoke_words(else_stmts, target_params, is_static)?),
            DslStmt::IfCmp {
                left,
                right,
                then_stmts,
                else_stmts,
                ..
            } => value_max_invoke_words(left)?
                .max(value_max_invoke_words(right)?)
                .max(statements_max_invoke_words(then_stmts, target_params, is_static)?)
                .max(statements_max_invoke_words(else_stmts, target_params, is_static)?),
            DslStmt::IfInstanceOf {
                value,
                then_stmts,
                else_stmts,
                ..
            } => value_max_invoke_words(value)?
                .max(statements_max_invoke_words(then_stmts, target_params, is_static)?)
                .max(statements_max_invoke_words(else_stmts, target_params, is_static)?),
            DslStmt::Switch {
                value,
                cases,
                default_stmts,
            } => {
                let mut words = value_max_invoke_words(value)?;
                for (_, stmts) in cases {
                    words = words.max(statements_max_invoke_words(stmts, target_params, is_static)?);
                }
                if let Some(stmts) = default_stmts {
                    words = words.max(statements_max_invoke_words(stmts, target_params, is_static)?);
                }
                words
            }
            DslStmt::TryCatch { try_stmts, catches } => {
                let mut words = statements_max_invoke_words(try_stmts, target_params, is_static)?;
                for catch in catches {
                    words = words.max(statements_max_invoke_words(
                        &catch.catch_stmts,
                        target_params,
                        is_static,
                    )?);
                }
                words
            }
            DslStmt::While { condition, body_stmts } | DslStmt::DoWhile { condition, body_stmts } => {
                condition_max_invoke_words(condition)?.max(statements_max_invoke_words(
                    body_stmts,
                    target_params,
                    is_static,
                )?)
            }
            DslStmt::For {
                init_stmts,
                condition,
                update_stmts,
                body_stmts,
            } => statements_max_invoke_words(init_stmts, target_params, is_static)?
                .max(
                    condition
                        .as_ref()
                        .map(condition_max_invoke_words)
                        .transpose()?
                        .unwrap_or(0),
                )
                .max(statements_max_invoke_words(update_stmts, target_params, is_static)?)
                .max(statements_max_invoke_words(body_stmts, target_params, is_static)?),
            DslStmt::Cast { value, .. } => value_max_invoke_words(value)?,
            DslStmt::ArrayLength { array } => value_max_invoke_words(array)?,
            DslStmt::ArrayGet { array, index, .. } => {
                value_max_invoke_words(array)?.max(value_max_invoke_words(index)?)
            }
            DslStmt::ArrayPut {
                array, index, value, ..
            } => value_max_invoke_words(array)?
                .max(value_max_invoke_words(index)?)
                .max(value_max_invoke_words(value)?),
            DslStmt::ArrayUpdate {
                array, index, value, ..
            } => value_max_invoke_words(array)?
                .max(value_max_invoke_words(index)?)
                .max(value_max_invoke_words(value)?),
            DslStmt::FieldRead { stmt, .. } => stmt.target.as_ref().map(|_| 0).unwrap_or(0),
            DslStmt::FieldWrite { stmt, .. } => stmt
                .value
                .as_ref()
                .map(value_max_invoke_words)
                .transpose()?
                .unwrap_or(0),
            DslStmt::FieldUpdate { stmt, value, .. } => stmt
                .receiver
                .as_deref()
                .map(value_max_invoke_words)
                .transpose()?
                .unwrap_or(0)
                .max(value_max_invoke_words(value)?),
            DslStmt::Send { value, .. } => 2u16.max(value_max_invoke_words(value)?),
            DslStmt::DirectBufferFill {
                buffer,
                offset,
                length,
                value,
            } => 4u16
                .max(value_max_invoke_words(buffer)?)
                .max(value_max_invoke_words(offset)?)
                .max(value_max_invoke_words(length)?)
                .max(value_max_invoke_words(value)?),
            DslStmt::DirectBufferCopyFromByteArray {
                buffer,
                dst_offset,
                src,
                src_offset,
                length,
            } => 5u16
                .max(value_max_invoke_words(buffer)?)
                .max(value_max_invoke_words(dst_offset)?)
                .max(value_max_invoke_words(src)?)
                .max(value_max_invoke_words(src_offset)?)
                .max(value_max_invoke_words(length)?),
            DslStmt::DirectBufferCopyToByteArray {
                buffer,
                src_offset,
                dst,
                dst_offset,
                length,
            } => 5u16
                .max(value_max_invoke_words(buffer)?)
                .max(value_max_invoke_words(src_offset)?)
                .max(value_max_invoke_words(dst)?)
                .max(value_max_invoke_words(dst_offset)?)
                .max(value_max_invoke_words(length)?),
            DslStmt::Break | DslStmt::Continue | DslStmt::Count { .. } => 0,
            DslStmt::ReturnOrig { args } => orig_args_max_invoke_words(args, target_params, is_static)?,
            DslStmt::ReturnValue { value } => value.as_ref().map(value_max_invoke_words).transpose()?.unwrap_or(0),
            DslStmt::Throw { value } => value_max_invoke_words(value)?,
        };
        max_words = max_words.max(words);
    }
    Ok(max_words)
}

fn constructor_max_direct_words(ctor_sig: Option<&str>, args: &[DslValue]) -> Result<u16, String> {
    if let Some(sig) = ctor_sig {
        let (params, return_type) = parse_method_signature(sig)?;
        if return_type != "V" {
            return Err(format!("constructor signature must return void, got '{}'", return_type));
        }
        return invoke_arg_words(true, &params);
    }
    Ok(1u16.saturating_add((args.len() as u16).saturating_mul(2)))
}

fn value_max_invoke_words(value: &DslValue) -> Result<u16, String> {
    match value {
        DslValue::NewObject { ctor_sig, args, .. } => {
            let mut words = constructor_max_direct_words(ctor_sig.as_deref(), args)?;
            for arg in args {
                words = words.max(value_max_invoke_words(arg)?);
            }
            Ok(words)
        }
        DslValue::NewArray { size, .. } => value_max_invoke_words(size),
        DslValue::Call(stmt) => {
            let mut words = call_stmt_max_direct_words(stmt)?;
            for arg in &stmt.args {
                words = words.max(value_max_invoke_words(arg)?);
            }
            if let Some(receiver) = &stmt.receiver {
                words = words.max(value_max_invoke_words(receiver)?);
            }
            Ok(words)
        }
        DslValue::OrigCall(args) => orig_value_max_invoke_words(args),
        DslValue::ArrayLength(value) => value_max_invoke_words(value),
        DslValue::IntBinOp { op, left, right } => {
            let nested = value_max_invoke_words(left)?.max(value_max_invoke_words(right)?);
            if *op == DslIntBinOp::Add {
                Ok(nested.max(2))
            } else {
                Ok(nested)
            }
        }
        DslValue::UnaryOp { value, .. } => value_max_invoke_words(value),
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => Ok(condition_max_invoke_words(condition)?
            .max(value_max_invoke_words(then_value)?)
            .max(value_max_invoke_words(else_value)?)),
        DslValue::Cast { value, .. } => value_max_invoke_words(value),
        DslValue::DirectBufferCapacity { buffer } => Ok(1u16.max(value_max_invoke_words(buffer)?)),
        DslValue::DirectBufferGetU8 { buffer, offset } => Ok(2u16
            .max(value_max_invoke_words(buffer)?)
            .max(value_max_invoke_words(offset)?)),
        DslValue::ArrayGet { array, index, .. } => {
            Ok(value_max_invoke_words(array)?.max(value_max_invoke_words(index)?))
        }
        DslValue::ArrayLiteral { elements } => elements.iter().try_fold(0, |max_words, element| {
            value_max_invoke_words(element).map(|words| max_words.max(words))
        }),
        DslValue::FieldGet { .. }
        | DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Bool(_)
        | DslValue::Null
        | DslValue::DefaultValue { .. } => Ok(0),
    }
}

fn call_stmt_max_direct_words(stmt: &DslCallStmt) -> Result<u16, String> {
    let has_receiver = stmt.target.is_some() || stmt.receiver.is_some();
    if stmt.sig.is_empty() {
        let receiver_words = if has_receiver { 1 } else { 0 };
        let arg_words = stmt
            .args
            .len()
            .checked_mul(2)
            .ok_or_else(|| "too many direct-call arguments".to_string())?;
        return (receiver_words + arg_words)
            .try_into()
            .map_err(|_| "too many direct-call argument words".to_string());
    }
    let params = parse_call_params(&stmt.sig)?;
    invoke_arg_words(has_receiver, &params)
}

fn condition_max_invoke_words(condition: &DslCondition) -> Result<u16, String> {
    match condition {
        DslCondition::Const(_) => Ok(0),
        DslCondition::Null { value, .. } | DslCondition::Bool { value } | DslCondition::InstanceOf { value, .. } => {
            value_max_invoke_words(value)
        }
        DslCondition::Cmp { left, right, .. } => Ok(value_max_invoke_words(left)?.max(value_max_invoke_words(right)?)),
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            Ok(condition_max_invoke_words(left)?.max(condition_max_invoke_words(right)?))
        }
        DslCondition::Not(condition) => condition_max_invoke_words(condition),
    }
}

fn orig_args_max_invoke_words(args: &DslOrigArgs, target_params: &[String], is_static: bool) -> Result<u16, String> {
    let DslOrigArgs::Values(values) = args else {
        return Ok(0);
    };
    if values.len() != target_params.len() {
        return Err(format!(
            "orig(...) expects {} argument(s), got {}",
            target_params.len(),
            values.len()
        ));
    }
    let mut words = invoke_arg_words(!is_static, target_params)?;
    for value in values {
        words = words.max(value_max_invoke_words(value)?);
    }
    Ok(words)
}

fn orig_value_max_invoke_words(args: &DslOrigArgs) -> Result<u16, String> {
    let DslOrigArgs::Values(values) = args else {
        return Ok(0);
    };
    let word_count = values
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| "too many orig argument words".to_string())?;
    let mut words = u16::try_from(word_count).map_err(|_| "too many orig argument words".to_string())?;
    for value in values {
        words = words.max(value_max_invoke_words(value)?);
    }
    Ok(words)
}

pub(super) fn program_uses_orig(program: &DslProgram) -> bool {
    statements_use_orig(&program.stmts)
}

fn orig_args_are_original(args: &DslOrigArgs, param_count: usize) -> bool {
    match args {
        DslOrigArgs::Original => true,
        DslOrigArgs::Values(values) => values.len() == param_count
            && values.iter().enumerate().all(
                |(index, value)| matches!(value, DslValue::Target(DslTarget::Arg(arg_index)) if *arg_index == index),
            ),
    }
}

pub(super) fn program_fast_tail_orig(program: &DslProgram, param_count: usize) -> bool {
    let Some((last, prefix)) = program.stmts.split_last() else {
        return false;
    };
    let DslStmt::ReturnOrig { args } = last else {
        return false;
    };
    if !orig_args_are_original(args, param_count) {
        return false;
    }
    prefix.iter().all(|stmt| matches!(stmt, DslStmt::Count { .. }))
}

pub(super) fn program_orig_only_passthrough(program: &DslProgram, param_count: usize) -> bool {
    match program.stmts.as_slice() {
        [DslStmt::ReturnOrig { args }] => orig_args_are_original(args, param_count),
        _ => false,
    }
}

pub(super) fn program_fast_tail_orig_count_names(program: &DslProgram, param_count: usize) -> Option<Vec<String>> {
    if !program_fast_tail_orig(program, param_count) || program_orig_only_passthrough(program, param_count) {
        return None;
    }
    let mut names = Vec::new();
    for stmt in &program.stmts[..program.stmts.len().saturating_sub(1)] {
        let DslStmt::Count { name } = stmt else {
            return None;
        };
        names.push(name.clone());
    }
    (!names.is_empty()).then_some(names)
}

fn statements_use_orig(stmts: &[DslStmt]) -> bool {
    stmts.iter().any(stmt_uses_orig)
}

fn stmt_uses_orig(stmt: &DslStmt) -> bool {
    match stmt {
        DslStmt::Block(stmts) => statements_use_orig(stmts),
        DslStmt::ReturnOrig { .. } | DslStmt::LetOrig { .. } => true,
        DslStmt::Let { value, .. }
        | DslStmt::Assign { value, .. }
        | DslStmt::NewArray { size: value, .. }
        | DslStmt::Cast { value, .. }
        | DslStmt::ArrayLength { array: value }
        | DslStmt::Throw { value } => value_uses_orig(value),
        DslStmt::New { args, .. } => args.iter().any(value_uses_orig),
        DslStmt::Call(stmt) => call_stmt_uses_orig(stmt),
        DslStmt::ArrayGet { array, index, .. } => value_uses_orig(array) || value_uses_orig(index),
        DslStmt::ArrayPut {
            array, index, value, ..
        } => value_uses_orig(array) || value_uses_orig(index) || value_uses_orig(value),
        DslStmt::ArrayUpdate {
            array, index, value, ..
        } => value_uses_orig(array) || value_uses_orig(index) || value_uses_orig(value),
        DslStmt::FieldRead { stmt, .. } => field_stmt_uses_orig(stmt),
        DslStmt::FieldWrite { stmt, .. } => field_stmt_uses_orig(stmt),
        DslStmt::FieldUpdate { stmt, value, .. } => field_stmt_uses_orig(stmt) || value_uses_orig(value),
        DslStmt::IfNull {
            value,
            then_stmts,
            else_stmts,
            ..
        }
        | DslStmt::IfBool {
            value,
            then_stmts,
            else_stmts,
            ..
        }
        | DslStmt::IfInstanceOf {
            value,
            then_stmts,
            else_stmts,
            ..
        } => value_uses_orig(value) || statements_use_orig(then_stmts) || statements_use_orig(else_stmts),
        DslStmt::IfCmp {
            left,
            right,
            then_stmts,
            else_stmts,
            ..
        } => {
            value_uses_orig(left)
                || value_uses_orig(right)
                || statements_use_orig(then_stmts)
                || statements_use_orig(else_stmts)
        }
        DslStmt::Switch {
            value,
            cases,
            default_stmts,
        } => {
            value_uses_orig(value)
                || cases.iter().any(|(_, stmts)| statements_use_orig(stmts))
                || default_stmts
                    .as_ref()
                    .map(|stmts| statements_use_orig(stmts))
                    .unwrap_or(false)
        }
        DslStmt::TryCatch { try_stmts, catches } => {
            statements_use_orig(try_stmts) || catches.iter().any(|catch| statements_use_orig(&catch.catch_stmts))
        }
        DslStmt::While { condition, body_stmts } | DslStmt::DoWhile { condition, body_stmts } => {
            condition_uses_orig(condition) || statements_use_orig(body_stmts)
        }
        DslStmt::For {
            init_stmts,
            condition,
            update_stmts,
            body_stmts,
        } => {
            statements_use_orig(init_stmts)
                || condition.as_ref().map(condition_uses_orig).unwrap_or(false)
                || statements_use_orig(update_stmts)
                || statements_use_orig(body_stmts)
        }
        DslStmt::Send { value, .. } => value_uses_orig(value),
        DslStmt::DirectBufferFill {
            buffer,
            offset,
            length,
            value,
        } => value_uses_orig(buffer) || value_uses_orig(offset) || value_uses_orig(length) || value_uses_orig(value),
        DslStmt::DirectBufferCopyFromByteArray {
            buffer,
            dst_offset,
            src,
            src_offset,
            length,
        } => {
            value_uses_orig(buffer)
                || value_uses_orig(dst_offset)
                || value_uses_orig(src)
                || value_uses_orig(src_offset)
                || value_uses_orig(length)
        }
        DslStmt::DirectBufferCopyToByteArray {
            buffer,
            src_offset,
            dst,
            dst_offset,
            length,
        } => {
            value_uses_orig(buffer)
                || value_uses_orig(src_offset)
                || value_uses_orig(dst)
                || value_uses_orig(dst_offset)
                || value_uses_orig(length)
        }
        DslStmt::Break | DslStmt::Continue | DslStmt::Count { .. } => false,
        DslStmt::ReturnValue { value } => value.as_ref().map(value_uses_orig).unwrap_or(false),
    }
}

fn field_stmt_uses_orig(stmt: &DslFieldStmt) -> bool {
    stmt.receiver.as_deref().map(value_uses_orig).unwrap_or(false)
        || stmt.value.as_ref().map(value_uses_orig).unwrap_or(false)
}

fn call_stmt_uses_orig(stmt: &DslCallStmt) -> bool {
    stmt.receiver.as_deref().map(value_uses_orig).unwrap_or(false) || stmt.args.iter().any(value_uses_orig)
}

fn value_uses_orig(value: &DslValue) -> bool {
    match value {
        DslValue::OrigCall(_) => true,
        DslValue::UnaryOp { value, .. }
        | DslValue::Cast { value, .. }
        | DslValue::ArrayLength(value)
        | DslValue::DirectBufferCapacity { buffer: value } => value_uses_orig(value),
        DslValue::DirectBufferGetU8 { buffer, offset } => value_uses_orig(buffer) || value_uses_orig(offset),
        DslValue::IntBinOp { left, right, .. } => value_uses_orig(left) || value_uses_orig(right),
        DslValue::Ternary {
            condition,
            then_value,
            else_value,
        } => condition_uses_orig(condition) || value_uses_orig(then_value) || value_uses_orig(else_value),
        DslValue::Call(stmt) => call_stmt_uses_orig(stmt),
        DslValue::NewObject { args, .. } => args.iter().any(value_uses_orig),
        DslValue::NewArray { size, .. } => value_uses_orig(size),
        DslValue::FieldGet { stmt, .. } => field_stmt_uses_orig(stmt),
        DslValue::ArrayGet { array, index, .. } => value_uses_orig(array) || value_uses_orig(index),
        DslValue::ArrayLiteral { elements } => elements.iter().any(value_uses_orig),
        DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Bool(_)
        | DslValue::Null
        | DslValue::DefaultValue { .. } => false,
    }
}

fn condition_uses_orig(condition: &DslCondition) -> bool {
    match condition {
        DslCondition::Const(_) => false,
        DslCondition::Null { value, .. } | DslCondition::Bool { value } | DslCondition::InstanceOf { value, .. } => {
            value_uses_orig(value)
        }
        DslCondition::Cmp { left, right, .. } => value_uses_orig(left) || value_uses_orig(right),
        DslCondition::And(left, right) | DslCondition::Or(left, right) => {
            condition_uses_orig(left) || condition_uses_orig(right)
        }
        DslCondition::Not(condition) => condition_uses_orig(condition),
    }
}

pub(super) fn collect_local_slots(
    local_descriptors: &BTreeMap<String, String>,
    first_reg: u16,
) -> Result<(BTreeMap<String, LocalSlot>, u16), String> {
    let mut slots = BTreeMap::new();
    let mut next = first_reg;
    for (name, descriptor) in local_descriptors {
        let reg = checked_reg(next, "local register")?;
        next = next
            .checked_add(descriptor_word_count(descriptor))
            .ok_or_else(|| "too many dex registers".to_string())?;
        slots.insert(
            name.clone(),
            LocalSlot {
                reg,
                descriptor: descriptor.clone(),
            },
        );
    }
    Ok((slots, next - first_reg))
}

pub(super) struct EmitContext<'a> {
    pub(super) layout: &'a HelperParamLayout,
    pub(super) dsl_ctx: &'a mut DslBuildContext,
    pub(super) is_static: bool,
    pub(super) local_count: u16,
    pub(super) ins_size: u16,
    pub(super) target: &'a MethodRef,
    pub(super) orig_backup: &'a MethodRef,
    pub(super) target_is_interface: bool,
    pub(super) return_type: &'a str,
    pub(super) sink: &'a FieldRef,
    pub(super) loop_stack: Vec<LoopLabels>,
}

#[derive(Clone, Copy)]
pub(super) struct LoopLabels {
    break_label: DexLabel,
    continue_label: DexLabel,
}

fn emit_orig_invoke(ir: &mut DexIrBuilder, args: &DslOrigArgs, emit_ctx: &mut EmitContext<'_>) -> Result<(), String> {
    match args {
        DslOrigArgs::Original => {
            ir.invoke_static_range(
                emit_ctx.local_count,
                emit_ctx.ins_size as u8,
                emit_ctx.orig_backup.clone(),
            );
        }
        DslOrigArgs::Values(values) => {
            if values.len() != emit_ctx.layout.arg_descriptors.len() {
                return Err(format!(
                    "orig(...) expects {} argument(s), got {}",
                    emit_ctx.layout.arg_descriptors.len(),
                    values.len()
                ));
            }
            let (kind, receiver, params, call_args) = if emit_ctx.is_static {
                (
                    ManagedInvokeKind::Static,
                    None,
                    emit_ctx.layout.arg_descriptors.clone(),
                    values.as_slice(),
                )
            } else {
                let this_desc = emit_ctx
                    .layout
                    .this_descriptor
                    .as_deref()
                    .ok_or_else(|| "missing this descriptor for orig(...)".to_string())?;
                let this_reg = emit_ctx
                    .layout
                    .this_reg
                    .ok_or_else(|| "missing this register for orig(...)".to_string())?;
                (
                    ManagedInvokeKind::Static,
                    Some((this_reg, this_desc)),
                    emit_ctx.layout.arg_descriptors.clone(),
                    values.as_slice(),
                )
            };
            emit_invoke_with_values(
                ir,
                kind,
                emit_ctx.orig_backup.clone(),
                receiver,
                &params,
                call_args,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
        }
    }
    Ok(())
}

fn emit_orig_value(
    ir: &mut DexIrBuilder,
    args: &DslOrigArgs,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let Some(orig_ctx) = dsl_ctx.orig_emit.clone() else {
        return Err("orig() is not available in this helper".to_string());
    };
    if orig_ctx.return_type == "V" {
        return Err("void orig() cannot be used as a value".to_string());
    }
    if !value_descriptor_assignable_to(&orig_ctx.return_type, expected_type) {
        return Err(format!(
            "orig() return type {} cannot be passed as {}",
            orig_ctx.return_type, expected_type
        ));
    }
    match args {
        DslOrigArgs::Original => {
            ir.invoke_static_range(
                orig_ctx.local_count,
                orig_ctx.ins_size as u8,
                orig_ctx.orig_backup.clone(),
            );
        }
        DslOrigArgs::Values(values) => {
            if values.len() != layout.arg_descriptors.len() {
                return Err(format!(
                    "orig(...) expects {} argument(s), got {}",
                    layout.arg_descriptors.len(),
                    values.len()
                ));
            }
            let (receiver, params) = if orig_ctx.is_static {
                (None, layout.arg_descriptors.clone())
            } else {
                let this_desc = layout
                    .this_descriptor
                    .as_deref()
                    .ok_or_else(|| "missing this descriptor for orig(...)".to_string())?;
                let this_reg = layout
                    .this_reg
                    .ok_or_else(|| "missing this register for orig(...)".to_string())?;
                (Some((this_reg, this_desc)), layout.arg_descriptors.clone())
            };
            emit_invoke_with_values(
                ir,
                ManagedInvokeKind::Static,
                orig_ctx.orig_backup.clone(),
                receiver,
                &params,
                values,
                layout,
                dsl_ctx,
            )?;
        }
    }
    emit_move_result_value(ir, &orig_ctx.return_type, dst)
}

fn emit_return_orig(ir: &mut DexIrBuilder, args: &DslOrigArgs, emit_ctx: &mut EmitContext<'_>) -> Result<(), String> {
    emit_orig_invoke(ir, args, emit_ctx)?;
    match emit_ctx.return_type {
        "V" => {
            emit_managed_guard_leave(ir, emit_ctx.dsl_ctx);
            ir.return_void();
        }
        "J" | "D" => {
            ir.move_result_wide(REG_RESULT);
            emit_managed_guard_leave(ir, emit_ctx.dsl_ctx);
            ir.return_wide(REG_RESULT);
        }
        ret if return_is_object(ret) => {
            ir.move_result_object(REG_RESULT);
            emit_managed_guard_leave(ir, emit_ctx.dsl_ctx);
            ir.return_object(REG_RESULT);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.move_result(REG_RESULT);
            emit_managed_guard_leave(ir, emit_ctx.dsl_ctx);
            ir.return_value(REG_RESULT);
        }
        other => Err(format!("unsupported return type '{}'", other))?,
    }
    Ok(())
}

fn emit_return_value(
    ir: &mut DexIrBuilder,
    value: Option<&DslValue>,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<(), String> {
    match emit_ctx.return_type {
        "V" => {
            if value.is_some() {
                return Err("void method can only use return; or return orig(...);".to_string());
            }
            emit_managed_guard_leave(ir, emit_ctx.dsl_ctx);
            ir.return_void();
        }
        "J" | "D" => {
            let Some(value) = value else {
                return Err(format!(
                    "method returning {} requires return value",
                    emit_ctx.return_type
                ));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            emit_managed_guard_leave(ir, emit_ctx.dsl_ctx);
            ir.return_wide(reg);
        }
        ret if return_is_object(ret) => {
            let Some(value) = value else {
                return Err(format!(
                    "method returning {} requires return value",
                    emit_ctx.return_type
                ));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            emit_managed_guard_leave(ir, emit_ctx.dsl_ctx);
            ir.return_object(reg);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            let Some(value) = value else {
                return Err(format!(
                    "method returning {} requires return value",
                    emit_ctx.return_type
                ));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            emit_managed_guard_leave(ir, emit_ctx.dsl_ctx);
            ir.return_value(reg);
        }
        other => return Err(format!("unsupported direct return type '{}'", other)),
    }
    Ok(())
}

pub(super) fn emit_managed_guard_enter(ir: &mut DexIrBuilder, dsl_ctx: &DslBuildContext) {
    if !dsl_ctx.managed_guard_enabled {
        return;
    }
    ir.invoke_static(Vec::new(), dsl_ctx.guard_enter_method());
}

pub(super) fn emit_managed_guard_leave(ir: &mut DexIrBuilder, dsl_ctx: &DslBuildContext) {
    if !dsl_ctx.managed_guard_enabled {
        return;
    }
    ir.invoke_static(Vec::new(), dsl_ctx.guard_leave_method());
}

fn emit_throw(ir: &mut DexIrBuilder, value: &DslValue, emit_ctx: &mut EmitContext<'_>) -> Result<(), String> {
    let reg = emit_load_value(
        ir,
        value,
        "Ljava/lang/Object;",
        REG_TMP0,
        emit_ctx.layout,
        emit_ctx.dsl_ctx,
    )?;
    ir.check_cast(reg, "Ljava/lang/Throwable;");
    ir.throw_value(reg);
    Ok(())
}

fn emit_try_catch(
    ir: &mut DexIrBuilder,
    try_stmts: &[DslStmt],
    catches: &[DslCatch],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    if catches.is_empty() {
        return Err("try requires at least one catch block".to_string());
    }
    let try_start = ir.new_label();
    let try_end = ir.new_label();
    let catch_handlers = catches.iter().map(|_| ir.new_label()).collect::<Vec<_>>();
    let mut done = None;

    ir.bind(try_start)?;
    let try_returns = emit_statements(ir, try_stmts, emit_ctx)?;
    ir.bind(try_end)?;
    if !try_returns {
        let done_label = *done.get_or_insert_with(|| ir.new_label());
        ir.goto16(done_label);
    }

    let mut catch_returns = true;
    let mut handler_items = Vec::with_capacity(catches.len());
    for (catch, handler) in catches.iter().zip(catch_handlers.iter().copied()) {
        let catch_descriptor = java_class_to_descriptor(&catch.catch_type)?;
        let catch_slot = emit_ctx
            .layout
            .local_regs
            .get(&catch.catch_name)
            .ok_or_else(|| format!("catch local '{}' is not allocated", catch.catch_name))?;
        if catch_slot.descriptor != catch_descriptor {
            return Err(format!(
                "catch local '{}' type mismatch: declared {}, emitted {}",
                catch.catch_name, catch_slot.descriptor, catch_descriptor
            ));
        }
        handler_items.push(IrCatchHandler {
            handler_type: catch_descriptor,
            handler,
        });

        ir.bind(handler)?;
        ir.move_exception(catch_slot.reg);
        let branch_returns = emit_statements(ir, &catch.catch_stmts, emit_ctx)?;
        if !branch_returns {
            let done_label = *done.get_or_insert_with(|| ir.new_label());
            ir.goto16(done_label);
        }
        catch_returns = catch_returns && branch_returns;
    }
    if let Some(done) = done {
        ir.bind(done)?;
    }
    ir.add_try_handlers(try_start, try_end, handler_items, None);

    Ok(try_returns && catch_returns)
}

fn emit_count(ir: &mut DexIrBuilder, name: &str, dsl_ctx: &mut DslBuildContext) {
    let field = dsl_ctx.counter_field(name);
    ir.sget(REG_TMP0, field.clone(), ValueKind::Narrow);
    ir.int_binop_lit8(DexIntLit8Op::Add, REG_TMP0, REG_TMP0, 1);
    ir.sput(REG_TMP0, field, ValueKind::Narrow);
}

fn emit_send(
    ir: &mut DexIrBuilder,
    name: &str,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let code = dsl_ctx.message_channel_code(name);
    if i16::try_from(code).is_err() {
        return Err(format!("too many DSL message channels: {}", code));
    }
    let value_desc = infer_value_descriptor(value, layout, dsl_ctx)?;
    if value_desc.as_deref() == Some("Ljava/lang/String;") {
        let value_reg = emit_load_value(ir, value, "Ljava/lang/String;", REG_TMP1, layout, dsl_ctx)?;
        let mut value_reg = emit_copy_field_value_if_needed(ir, value_reg, REG_TMP1, ValueKind::Object);
        if value_reg == REG_TMP0 {
            ir.move_from16(REG_TMP1, REG_TMP0 as u16, ValueKind::Object);
            value_reg = REG_TMP1;
        }
        ir.const16(REG_TMP0, code as i16);
        ir.invoke_static(vec![REG_TMP0, value_reg], dsl_ctx.message_send_string_method());
    } else {
        let value_reg = emit_load_value(ir, value, "I", REG_TMP1, layout, dsl_ctx)?;
        let mut value_reg = emit_copy_field_value_if_needed(ir, value_reg, REG_TMP1, ValueKind::Narrow);
        if value_reg == REG_TMP0 {
            ir.move_from16(REG_TMP1, REG_TMP0 as u16, ValueKind::Narrow);
            value_reg = REG_TMP1;
        }
        ir.const16(REG_TMP0, code as i16);
        ir.invoke_static(vec![REG_TMP0, value_reg], dsl_ctx.message_send_method());
    }
    Ok(())
}

fn emit_direct_buffer_fill(
    ir: &mut DexIrBuilder,
    buffer: &DslValue,
    offset: &DslValue,
    length: &DslValue,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let method = dsl_ctx.direct_buffer_fill_method();
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Static,
        method,
        None,
        &[
            "Ljava/nio/ByteBuffer;".to_string(),
            "I".to_string(),
            "I".to_string(),
            "I".to_string(),
        ],
        &[buffer.clone(), offset.clone(), length.clone(), value.clone()],
        layout,
        dsl_ctx,
    )
}

fn emit_direct_buffer_copy_from_byte_array(
    ir: &mut DexIrBuilder,
    buffer: &DslValue,
    dst_offset: &DslValue,
    src: &DslValue,
    src_offset: &DslValue,
    length: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let method = dsl_ctx.direct_buffer_copy_from_byte_array_method();
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Static,
        method,
        None,
        &[
            "Ljava/nio/ByteBuffer;".to_string(),
            "I".to_string(),
            "[B".to_string(),
            "I".to_string(),
            "I".to_string(),
        ],
        &[
            buffer.clone(),
            dst_offset.clone(),
            src.clone(),
            src_offset.clone(),
            length.clone(),
        ],
        layout,
        dsl_ctx,
    )
}

fn emit_direct_buffer_copy_to_byte_array(
    ir: &mut DexIrBuilder,
    buffer: &DslValue,
    src_offset: &DslValue,
    dst: &DslValue,
    dst_offset: &DslValue,
    length: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let method = dsl_ctx.direct_buffer_copy_to_byte_array_method();
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Static,
        method,
        None,
        &[
            "Ljava/nio/ByteBuffer;".to_string(),
            "I".to_string(),
            "[B".to_string(),
            "I".to_string(),
            "I".to_string(),
        ],
        &[
            buffer.clone(),
            src_offset.clone(),
            dst.clone(),
            dst_offset.clone(),
            length.clone(),
        ],
        layout,
        dsl_ctx,
    )
}

fn emit_direct_buffer_capacity_value(
    ir: &mut DexIrBuilder,
    buffer: &DslValue,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let method = dsl_ctx.direct_buffer_capacity_method();
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Static,
        method,
        None,
        &["Ljava/nio/ByteBuffer;".to_string()],
        &[(*buffer).clone()],
        layout,
        dsl_ctx,
    )?;
    ir.move_result(dst);
    Ok(dst)
}

fn emit_direct_buffer_get_u8_value(
    ir: &mut DexIrBuilder,
    buffer: &DslValue,
    offset: &DslValue,
    dst: u8,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<u8, String> {
    let method = dsl_ctx.direct_buffer_get_u8_method();
    emit_invoke_with_values(
        ir,
        ManagedInvokeKind::Static,
        method,
        None,
        &["Ljava/nio/ByteBuffer;".to_string(), "I".to_string()],
        &[buffer.clone(), offset.clone()],
        layout,
        dsl_ctx,
    )?;
    ir.move_result(dst);
    Ok(dst)
}

fn emit_statement(ir: &mut DexIrBuilder, stmt: &DslStmt, emit_ctx: &mut EmitContext<'_>) -> Result<bool, String> {
    match stmt {
        DslStmt::Block(stmts) => emit_statements(ir, stmts, emit_ctx),
        DslStmt::Let { name, type_name, value } => {
            emit_let(ir, name, type_name.as_deref(), value, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::Assign { name, value } => {
            emit_assign(ir, name, value, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::LetOrig { name, type_name, args } => {
            emit_let_orig(ir, name, type_name.as_deref(), args, emit_ctx)?;
            Ok(false)
        }
        DslStmt::New {
            class_name,
            ctor_sig,
            args,
        } => {
            emit_new_object(
                ir,
                class_name,
                ctor_sig.as_deref(),
                args,
                emit_ctx.sink,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            emit_ctx
                .dsl_ctx
                .record_last_descriptor(java_class_to_descriptor(class_name)?);
            Ok(false)
        }
        DslStmt::NewArray { array_type_name, size } => {
            emit_new_array(
                ir,
                array_type_name,
                size,
                emit_ctx.sink,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::Call(stmt) => {
            let method = emit_call(ir, stmt, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            emit_ctx.dsl_ctx.record_value_descriptor(&method.proto.return_type);
            Ok(false)
        }
        DslStmt::Cast { value, class_name } => {
            emit_cast(ir, value, class_name, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::ArrayLength { array } => {
            emit_array_length_stmt(ir, array, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::ArrayGet {
            array,
            index,
            type_name,
        } => {
            emit_array_get_stmt(
                ir,
                array,
                index,
                type_name.as_deref(),
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::ArrayPut {
            array,
            index,
            type_name,
            value,
        } => {
            emit_array_put(
                ir,
                array,
                index,
                type_name.as_deref(),
                value,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::ArrayUpdate {
            array,
            index,
            type_name,
            op,
            value,
        } => {
            emit_array_update(
                ir,
                array,
                index,
                type_name.as_deref(),
                *op,
                value,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::FieldRead { stmt, is_static } => {
            emit_field_read(ir, stmt, emit_ctx.layout, *is_static, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::FieldWrite { stmt, is_static } => {
            emit_field_write(ir, stmt, emit_ctx.layout, *is_static, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::FieldUpdate {
            stmt,
            is_static,
            op,
            value,
        } => {
            emit_field_update(ir, stmt, *is_static, *op, value, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::IfNull {
            value,
            invert,
            then_stmts,
            else_stmts,
        } => emit_if_null(ir, value, *invert, then_stmts, else_stmts, emit_ctx),
        DslStmt::IfBool {
            value,
            then_stmts,
            else_stmts,
        } => emit_if_bool(ir, value, then_stmts, else_stmts, emit_ctx),
        DslStmt::IfCmp {
            op,
            left,
            right,
            then_stmts,
            else_stmts,
        } => emit_if_cmp(ir, *op, left, right, then_stmts, else_stmts, emit_ctx),
        DslStmt::IfInstanceOf {
            value,
            class_name,
            then_stmts,
            else_stmts,
        } => emit_if_instance_of(ir, value, class_name, then_stmts, else_stmts, emit_ctx),
        DslStmt::Switch {
            value,
            cases,
            default_stmts,
        } => emit_switch(ir, value, cases, default_stmts.as_deref(), emit_ctx),
        DslStmt::While { condition, body_stmts } => emit_while(ir, condition, body_stmts, emit_ctx),
        DslStmt::DoWhile { body_stmts, condition } => emit_do_while(ir, body_stmts, condition, emit_ctx),
        DslStmt::For {
            init_stmts,
            condition,
            update_stmts,
            body_stmts,
        } => emit_for(ir, init_stmts, condition.as_ref(), update_stmts, body_stmts, emit_ctx),
        DslStmt::TryCatch { try_stmts, catches } => emit_try_catch(ir, try_stmts, catches, emit_ctx),
        DslStmt::Break => {
            let labels = *emit_ctx
                .loop_stack
                .last()
                .ok_or_else(|| "break can only be used inside while".to_string())?;
            ir.goto16(labels.break_label);
            Ok(true)
        }
        DslStmt::Continue => {
            let labels = *emit_ctx
                .loop_stack
                .last()
                .ok_or_else(|| "continue can only be used inside while".to_string())?;
            ir.goto16(labels.continue_label);
            Ok(true)
        }
        DslStmt::Count { name } => {
            emit_count(ir, name, emit_ctx.dsl_ctx);
            Ok(false)
        }
        DslStmt::Send { name, value } => {
            emit_send(ir, name, value, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::DirectBufferFill {
            buffer,
            offset,
            length,
            value,
        } => {
            emit_direct_buffer_fill(ir, buffer, offset, length, value, emit_ctx.layout, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::DirectBufferCopyFromByteArray {
            buffer,
            dst_offset,
            src,
            src_offset,
            length,
        } => {
            emit_direct_buffer_copy_from_byte_array(
                ir,
                buffer,
                dst_offset,
                src,
                src_offset,
                length,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::DirectBufferCopyToByteArray {
            buffer,
            src_offset,
            dst,
            dst_offset,
            length,
        } => {
            emit_direct_buffer_copy_to_byte_array(
                ir,
                buffer,
                src_offset,
                dst,
                dst_offset,
                length,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::ReturnOrig { args } => {
            emit_return_orig(ir, args, emit_ctx)?;
            Ok(true)
        }
        DslStmt::ReturnValue { value } => {
            emit_return_value(ir, value.as_ref(), emit_ctx)?;
            Ok(true)
        }
        DslStmt::Throw { value } => {
            emit_throw(ir, value, emit_ctx)?;
            Ok(true)
        }
    }
}

pub(super) fn emit_statements(
    ir: &mut DexIrBuilder,
    stmts: &[DslStmt],
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    for stmt in stmts {
        if emit_statement(ir, stmt, emit_ctx)? {
            return Ok(true);
        }
    }
    Ok(false)
}
