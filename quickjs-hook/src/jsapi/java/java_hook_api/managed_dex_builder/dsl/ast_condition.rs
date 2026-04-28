use super::*;

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslCondition {
    Null {
        value: DslValue,
        invert: bool,
    },
    Cmp {
        op: IfCmpOp,
        left: DslValue,
        right: DslValue,
    },
    InstanceOf {
        value: DslValue,
        class_name: String,
    },
    Bool {
        value: DslValue,
    },
    Const(bool),
    And(Box<DslCondition>, Box<DslCondition>),
    Or(Box<DslCondition>, Box<DslCondition>),
    Not(Box<DslCondition>),
}

impl DslCondition {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn into_if_stmt(
        self,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    ) -> DslStmt {
        match self {
            DslCondition::Const(true) => DslStmt::Block(then_stmts),
            DslCondition::Const(false) => DslStmt::Block(else_stmts),
            DslCondition::Null { value, invert } => DslStmt::IfNull {
                value,
                invert,
                then_stmts,
                else_stmts,
            },
            DslCondition::Bool { value } => DslStmt::IfBool {
                value,
                then_stmts,
                else_stmts,
            },
            DslCondition::Cmp { op, left, right } => DslStmt::IfCmp {
                op,
                left,
                right,
                then_stmts,
                else_stmts,
            },
            DslCondition::InstanceOf { value, class_name } => DslStmt::IfInstanceOf {
                value,
                class_name,
                then_stmts,
                else_stmts,
            },
            DslCondition::And(left, right) => {
                let inner = right.into_if_stmt(then_stmts, else_stmts.clone());
                left.into_if_stmt(vec![inner], else_stmts)
            }
            DslCondition::Or(left, right) => {
                let inner = right.into_if_stmt(then_stmts.clone(), else_stmts);
                left.into_if_stmt(then_stmts, vec![inner])
            }
            DslCondition::Not(condition) => condition.into_if_stmt(else_stmts, then_stmts),
        }
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn condition_and(
    left: DslCondition,
    right: DslCondition,
) -> DslCondition {
    match (left, right) {
        (DslCondition::Const(false), _) | (_, DslCondition::Const(false)) => DslCondition::Const(false),
        (DslCondition::Const(true), right) => right,
        (left, DslCondition::Const(true)) => left,
        (left, right) => DslCondition::And(Box::new(left), Box::new(right)),
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn condition_or(
    left: DslCondition,
    right: DslCondition,
) -> DslCondition {
    match (left, right) {
        (DslCondition::Const(true), _) | (_, DslCondition::Const(true)) => DslCondition::Const(true),
        (DslCondition::Const(false), right) => right,
        (left, DslCondition::Const(false)) => left,
        (left, right) => DslCondition::Or(Box::new(left), Box::new(right)),
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn condition_not(
    condition: DslCondition,
) -> DslCondition {
    match condition {
        DslCondition::Const(value) => DslCondition::Const(!value),
        DslCondition::Not(inner) => *inner,
        other => DslCondition::Not(Box::new(other)),
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn fold_ternary(
    condition: DslCondition,
    then_value: DslValue,
    else_value: DslValue,
) -> DslValue {
    match condition {
        DslCondition::Const(true) => then_value,
        DslCondition::Const(false) => else_value,
        condition => DslValue::Ternary {
            condition: Box::new(condition),
            then_value: Box::new(then_value),
            else_value: Box::new(else_value),
        },
    }
}

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) fn fold_ternary_condition(
    condition: DslCondition,
    then_condition: DslCondition,
    else_condition: DslCondition,
) -> DslCondition {
    match condition {
        DslCondition::Const(true) => then_condition,
        DslCondition::Const(false) => else_condition,
        condition => condition_or(
            condition_and(condition.clone(), then_condition),
            condition_and(condition_not(condition), else_condition),
        ),
    }
}
