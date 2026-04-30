use super::*;

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslValue {
    Target(DslTarget),
    String(String),
    Int(i16),
    Bool(bool),
    Null,
    DefaultValue {
        type_name: String,
    },
    UnaryOp {
        op: DslUnaryOp,
        value: Box<DslValue>,
    },
    IntBinOp {
        op: DslIntBinOp,
        left: Box<DslValue>,
        right: Box<DslValue>,
    },
    Ternary {
        condition: Box<DslCondition>,
        then_value: Box<DslValue>,
        else_value: Box<DslValue>,
    },
    OrigCall(DslOrigArgs),
    DirectBufferCapacity {
        buffer: Box<DslValue>,
    },
    DirectBufferGetU8 {
        buffer: Box<DslValue>,
        offset: Box<DslValue>,
    },
    Call(DslCallStmt),
    NewObject {
        class_name: String,
        ctor_sig: Option<String>,
        args: Vec<DslValue>,
    },
    NewArray {
        array_type_name: String,
        size: Box<DslValue>,
    },
    FieldGet {
        stmt: Box<DslFieldStmt>,
        is_static: bool,
    },
    Cast {
        value: Box<DslValue>,
        class_name: String,
    },
    ArrayLength(Box<DslValue>),
    ArrayLiteral {
        elements: Vec<DslValue>,
    },
    ArrayGet {
        array: Box<DslValue>,
        index: Box<DslValue>,
        type_name: Option<String>,
    },
}

#[derive(Clone, Copy)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslUnaryOp {
    Neg,
    BitNot,
    BoolNot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslIntBinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslTarget {
    This,
    Arg(usize),
    Last,
    Result,
    Local(String),
}
