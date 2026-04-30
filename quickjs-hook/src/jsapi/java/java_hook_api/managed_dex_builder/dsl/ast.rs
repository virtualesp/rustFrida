use super::{DslCallStmt, DslCondition, DslFieldStmt, DslIntBinOp, DslValue, IfCmpOp};

pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) struct DslProgram {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) stmts: Vec<DslStmt>,
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslStmt {
    Block(Vec<DslStmt>),
    Let {
        name: String,
        type_name: Option<String>,
        value: DslValue,
    },
    Assign {
        name: String,
        value: DslValue,
    },
    LetOrig {
        name: String,
        type_name: Option<String>,
        args: DslOrigArgs,
    },
    New {
        class_name: String,
        ctor_sig: Option<String>,
        args: Vec<DslValue>,
    },
    NewArray {
        array_type_name: String,
        size: DslValue,
    },
    Call(DslCallStmt),
    Cast {
        value: DslValue,
        class_name: String,
    },
    ArrayLength {
        array: DslValue,
    },
    ArrayGet {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
    },
    ArrayPut {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
        value: DslValue,
    },
    ArrayUpdate {
        array: DslValue,
        index: DslValue,
        type_name: Option<String>,
        op: DslIntBinOp,
        value: DslValue,
    },
    FieldRead {
        stmt: DslFieldStmt,
        is_static: bool,
    },
    FieldWrite {
        stmt: DslFieldStmt,
        is_static: bool,
    },
    FieldUpdate {
        stmt: DslFieldStmt,
        is_static: bool,
        op: DslIntBinOp,
        value: DslValue,
    },
    IfNull {
        value: DslValue,
        invert: bool,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfBool {
        value: DslValue,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfCmp {
        op: IfCmpOp,
        left: DslValue,
        right: DslValue,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    IfInstanceOf {
        value: DslValue,
        class_name: String,
        then_stmts: Vec<DslStmt>,
        else_stmts: Vec<DslStmt>,
    },
    Switch {
        value: DslValue,
        cases: Vec<(i16, Vec<DslStmt>)>,
        default_stmts: Option<Vec<DslStmt>>,
    },
    TryCatch {
        try_stmts: Vec<DslStmt>,
        catches: Vec<DslCatch>,
    },
    While {
        condition: DslCondition,
        body_stmts: Vec<DslStmt>,
    },
    DoWhile {
        body_stmts: Vec<DslStmt>,
        condition: DslCondition,
    },
    For {
        init_stmts: Vec<DslStmt>,
        condition: Option<DslCondition>,
        update_stmts: Vec<DslStmt>,
        body_stmts: Vec<DslStmt>,
    },
    Break,
    Continue,
    Count {
        name: String,
    },
    Send {
        name: String,
        value: DslValue,
    },
    DirectBufferFill {
        buffer: DslValue,
        offset: DslValue,
        length: DslValue,
        value: DslValue,
    },
    DirectBufferCopyFromByteArray {
        buffer: DslValue,
        dst_offset: DslValue,
        src: DslValue,
        src_offset: DslValue,
        length: DslValue,
    },
    DirectBufferCopyToByteArray {
        buffer: DslValue,
        src_offset: DslValue,
        dst: DslValue,
        dst_offset: DslValue,
        length: DslValue,
    },
    Throw {
        value: DslValue,
    },
    ReturnOrig {
        args: DslOrigArgs,
    },
    ReturnValue {
        value: Option<DslValue>,
    },
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) struct DslCatch {
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) catch_type: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) catch_name: String,
    pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) catch_stmts: Vec<DslStmt>,
}

#[derive(Clone)]
pub(in crate::jsapi::java::java_hook_api::managed_dex_builder) enum DslOrigArgs {
    Original,
    Values(Vec<DslValue>),
}
