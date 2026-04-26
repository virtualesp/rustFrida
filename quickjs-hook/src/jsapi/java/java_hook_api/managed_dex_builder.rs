use std::collections::{BTreeMap, BTreeSet};

pub(super) const ACC_PUBLIC: u32 = 0x0001;
pub(super) const ACC_PRIVATE: u32 = 0x0002;
pub(super) const ACC_PROTECTED: u32 = 0x0004;
pub(super) const ACC_STATIC: u32 = 0x0008;
pub(super) const ACC_FINAL: u32 = 0x0010;
pub(super) const ACC_VOLATILE: u32 = 0x0040;
pub(super) const ACC_CONSTRUCTOR: u32 = 0x0001_0000;
pub(super) const ACC_DECLARED_SYNCHRONIZED: u32 = 0x0002_0000;

const TYPE_HEADER_ITEM: u16 = 0x0000;
const TYPE_STRING_ID_ITEM: u16 = 0x0001;
const TYPE_TYPE_ID_ITEM: u16 = 0x0002;
const TYPE_PROTO_ID_ITEM: u16 = 0x0003;
const TYPE_FIELD_ID_ITEM: u16 = 0x0004;
const TYPE_METHOD_ID_ITEM: u16 = 0x0005;
const TYPE_CLASS_DEF_ITEM: u16 = 0x0006;
const TYPE_MAP_LIST: u16 = 0x1000;
const TYPE_TYPE_LIST: u16 = 0x1001;
const TYPE_CLASS_DATA_ITEM: u16 = 0x2000;
const TYPE_CODE_ITEM: u16 = 0x2001;
const TYPE_STRING_DATA_ITEM: u16 = 0x2002;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ProtoSpec {
    pub return_type: String,
    pub params: Vec<String>,
}

impl ProtoSpec {
    pub(super) fn new(return_type: impl Into<String>, params: Vec<String>) -> Self {
        Self {
            return_type: return_type.into(),
            params,
        }
    }

    fn shorty(&self) -> String {
        let mut out = String::with_capacity(self.params.len() + 1);
        out.push(shorty_char(&self.return_type));
        for param in &self.params {
            out.push(shorty_char(param));
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FieldRef {
    pub class_type: String,
    pub type_name: String,
    pub name: String,
}

impl FieldRef {
    pub(super) fn new(
        class_type: impl Into<String>,
        type_name: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            class_type: class_type.into(),
            type_name: type_name.into(),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct MethodRef {
    pub class_type: String,
    pub proto: ProtoSpec,
    pub name: String,
}

impl MethodRef {
    pub(super) fn new(
        class_type: impl Into<String>,
        name: impl Into<String>,
        return_type: impl Into<String>,
        params: Vec<String>,
    ) -> Self {
        Self {
            class_type: class_type.into(),
            proto: ProtoSpec::new(return_type, params),
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct DexCode {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns: Vec<CodeWord>,
}

impl DexCode {
    pub(super) fn new(registers_size: u16, ins_size: u16, outs_size: u16) -> Self {
        Self {
            registers_size,
            ins_size,
            outs_size,
            insns: Vec::new(),
        }
    }

    pub(super) fn raw(&mut self, word: u16) {
        self.insns.push(CodeWord::Raw(word));
    }

    pub(super) fn type_idx(&mut self, ty: impl Into<String>) {
        self.insns.push(CodeWord::Type(ty.into()));
    }

    pub(super) fn string_idx(&mut self, value: impl Into<String>) {
        self.insns.push(CodeWord::String(value.into()));
    }

    pub(super) fn field_idx(&mut self, field: FieldRef) {
        self.insns.push(CodeWord::Field(field));
    }

    pub(super) fn method_idx(&mut self, method: MethodRef) {
        self.insns.push(CodeWord::Method(method));
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct DexLabel(usize);

pub(super) struct DexIrBuilder {
    registers_size: u16,
    ins_size: u16,
    outs_size: u16,
    instrs: Vec<IrInstr>,
    labels: Vec<Option<usize>>,
}

impl DexIrBuilder {
    pub(super) fn new(registers_size: u16, ins_size: u16, outs_size: u16) -> Self {
        Self {
            registers_size,
            ins_size,
            outs_size,
            instrs: Vec::new(),
            labels: Vec::new(),
        }
    }

    pub(super) fn new_label(&mut self) -> DexLabel {
        let id = self.labels.len();
        self.labels.push(None);
        DexLabel(id)
    }

    pub(super) fn bind(&mut self, label: DexLabel) -> Result<(), String> {
        let offset = self.current_offset();
        let slot = self
            .labels
            .get_mut(label.0)
            .ok_or_else(|| format!("invalid dex label {}", label.0))?;
        if slot.is_some() {
            return Err(format!("dex label {} bound twice", label.0));
        }
        *slot = Some(offset);
        Ok(())
    }

    pub(super) fn const4(&mut self, dst: u8, literal: i8) {
        self.instrs.push(IrInstr::Const4 { dst, literal });
    }

    pub(super) fn const16(&mut self, dst: u8, literal: i16) {
        self.instrs.push(IrInstr::Const16 { dst, literal });
    }

    pub(super) fn const_string(&mut self, dst: u8, value: impl Into<String>) {
        self.instrs.push(IrInstr::ConstString {
            dst,
            value: value.into(),
        });
    }

    pub(super) fn move_from16(&mut self, dst: u8, src: u16, kind: ValueKind) {
        self.instrs.push(IrInstr::MoveFrom16 { dst, src, kind });
    }

    pub(super) fn if_ge(&mut self, left: u8, right: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfGe { left, right, target });
    }

    pub(super) fn if_cmp(&mut self, op: IfCmpOp, left: u8, right: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfCmp {
            op,
            left,
            right,
            target,
        });
    }

    pub(super) fn if_eqz(&mut self, reg: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfEqz { reg, target });
    }

    pub(super) fn if_nez(&mut self, reg: u8, target: DexLabel) {
        self.instrs.push(IrInstr::IfNez { reg, target });
    }

    pub(super) fn goto16(&mut self, target: DexLabel) {
        self.instrs.push(IrInstr::Goto16 { target });
    }

    pub(super) fn new_instance(&mut self, dst: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::NewInstance { dst, ty: ty.into() });
    }

    pub(super) fn check_cast(&mut self, reg: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::CheckCast { reg, ty: ty.into() });
    }

    pub(super) fn instance_of(&mut self, dst: u8, obj: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::InstanceOf {
            dst,
            obj,
            ty: ty.into(),
        });
    }

    pub(super) fn array_length(&mut self, dst: u8, array: u8) {
        self.instrs.push(IrInstr::ArrayLength { dst, array });
    }

    pub(super) fn new_array(&mut self, dst: u8, size: u8, ty: impl Into<String>) {
        self.instrs.push(IrInstr::NewArray {
            dst,
            size,
            ty: ty.into(),
        });
    }

    pub(super) fn aget(&mut self, dst: u8, array: u8, index: u8, kind: ValueKind) {
        self.instrs.push(IrInstr::Aget {
            dst,
            array,
            index,
            kind,
        });
    }

    pub(super) fn aput(&mut self, src: u8, array: u8, index: u8, kind: ValueKind) {
        self.instrs.push(IrInstr::Aput {
            src,
            array,
            index,
            kind,
        });
    }

    pub(super) fn invoke_direct(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeDirect { args, method });
    }

    pub(super) fn invoke_virtual(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeVirtual { args, method });
    }

    pub(super) fn invoke_static(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeStatic { args, method });
    }

    pub(super) fn invoke_interface(&mut self, args: Vec<u8>, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeInterface { args, method });
    }

    pub(super) fn invoke_direct_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeDirectRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_static_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeStaticRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_virtual_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeVirtualRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn invoke_interface_range(&mut self, first_reg: u16, arg_words: u8, method: MethodRef) {
        self.instrs.push(IrInstr::InvokeInterfaceRange {
            first_reg,
            arg_words,
            method,
        });
    }

    pub(super) fn sput_object(&mut self, src: u8, field: FieldRef) {
        self.instrs.push(IrInstr::SputObject { src, field });
    }

    pub(super) fn iget(&mut self, dst: u8, obj: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Iget {
            dst,
            obj,
            field,
            kind,
        });
    }

    pub(super) fn iput(&mut self, src: u8, obj: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Iput {
            src,
            obj,
            field,
            kind,
        });
    }

    pub(super) fn sget(&mut self, dst: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Sget { dst, field, kind });
    }

    pub(super) fn sput(&mut self, src: u8, field: FieldRef, kind: ValueKind) {
        self.instrs.push(IrInstr::Sput { src, field, kind });
    }

    pub(super) fn add_int_lit8(&mut self, dst: u8, src: u8, literal: i8) {
        self.instrs.push(IrInstr::AddIntLit8 { dst, src, literal });
    }

    pub(super) fn move_result_object(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResultObject { dst });
    }

    pub(super) fn move_result(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResult { dst });
    }

    pub(super) fn move_result_wide(&mut self, dst: u8) {
        self.instrs.push(IrInstr::MoveResultWide { dst });
    }

    pub(super) fn return_object(&mut self, src: u8) {
        self.instrs.push(IrInstr::ReturnObject { src });
    }

    pub(super) fn return_value(&mut self, src: u8) {
        self.instrs.push(IrInstr::Return { src });
    }

    pub(super) fn return_wide(&mut self, src: u8) {
        self.instrs.push(IrInstr::ReturnWide { src });
    }

    pub(super) fn return_void(&mut self) {
        self.instrs.push(IrInstr::ReturnVoid);
    }

    pub(super) fn finish(self) -> Result<DexCode, String> {
        let mut offsets = Vec::with_capacity(self.instrs.len());
        let mut offset = 0usize;
        for instr in &self.instrs {
            offsets.push(offset);
            offset += instr.width();
        }

        for (idx, label) in self.labels.iter().enumerate() {
            if label.is_none() {
                return Err(format!("dex label {} was never bound", idx));
            }
        }

        let mut code = DexCode::new(self.registers_size, self.ins_size, self.outs_size);
        for (idx, instr) in self.instrs.into_iter().enumerate() {
            instr.emit(&mut code, offsets[idx], &self.labels)?;
        }
        Ok(code)
    }

    fn current_offset(&self) -> usize {
        self.instrs.iter().map(IrInstr::width).sum()
    }
}

enum IrInstr {
    Const4 { dst: u8, literal: i8 },
    Const16 { dst: u8, literal: i16 },
    ConstString { dst: u8, value: String },
    MoveFrom16 { dst: u8, src: u16, kind: ValueKind },
    IfGe { left: u8, right: u8, target: DexLabel },
    IfCmp {
        op: IfCmpOp,
        left: u8,
        right: u8,
        target: DexLabel,
    },
    IfEqz { reg: u8, target: DexLabel },
    IfNez { reg: u8, target: DexLabel },
    Goto16 { target: DexLabel },
    NewInstance { dst: u8, ty: String },
    CheckCast { reg: u8, ty: String },
    InstanceOf { dst: u8, obj: u8, ty: String },
    ArrayLength { dst: u8, array: u8 },
    NewArray { dst: u8, size: u8, ty: String },
    Aget { dst: u8, array: u8, index: u8, kind: ValueKind },
    Aput { src: u8, array: u8, index: u8, kind: ValueKind },
    InvokeDirect { args: Vec<u8>, method: MethodRef },
    InvokeVirtual { args: Vec<u8>, method: MethodRef },
    InvokeStatic { args: Vec<u8>, method: MethodRef },
    InvokeInterface { args: Vec<u8>, method: MethodRef },
    InvokeDirectRange { first_reg: u16, arg_words: u8, method: MethodRef },
    InvokeStaticRange { first_reg: u16, arg_words: u8, method: MethodRef },
    InvokeVirtualRange { first_reg: u16, arg_words: u8, method: MethodRef },
    InvokeInterfaceRange { first_reg: u16, arg_words: u8, method: MethodRef },
    SputObject { src: u8, field: FieldRef },
    Iget { dst: u8, obj: u8, field: FieldRef, kind: ValueKind },
    Iput { src: u8, obj: u8, field: FieldRef, kind: ValueKind },
    Sget { dst: u8, field: FieldRef, kind: ValueKind },
    Sput { src: u8, field: FieldRef, kind: ValueKind },
    AddIntLit8 { dst: u8, src: u8, literal: i8 },
    MoveResult { dst: u8 },
    MoveResultWide { dst: u8 },
    MoveResultObject { dst: u8 },
    Return { src: u8 },
    ReturnWide { src: u8 },
    ReturnObject { src: u8 },
    ReturnVoid,
}

#[derive(Clone, Copy)]
pub(super) enum IfCmpOp {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
}

impl IfCmpOp {
    fn opcode(self) -> u16 {
        match self {
            IfCmpOp::Eq => 0x0032,
            IfCmpOp::Ne => 0x0033,
            IfCmpOp::Lt => 0x0034,
            IfCmpOp::Ge => 0x0035,
            IfCmpOp::Gt => 0x0036,
            IfCmpOp::Le => 0x0037,
        }
    }

    fn name(self) -> &'static str {
        match self {
            IfCmpOp::Eq => "if-eq",
            IfCmpOp::Ne => "if-ne",
            IfCmpOp::Lt => "if-lt",
            IfCmpOp::Ge => "if-ge",
            IfCmpOp::Gt => "if-gt",
            IfCmpOp::Le => "if-le",
        }
    }

    fn invert(self) -> Self {
        match self {
            IfCmpOp::Eq => IfCmpOp::Ne,
            IfCmpOp::Ne => IfCmpOp::Eq,
            IfCmpOp::Lt => IfCmpOp::Ge,
            IfCmpOp::Ge => IfCmpOp::Lt,
            IfCmpOp::Gt => IfCmpOp::Le,
            IfCmpOp::Le => IfCmpOp::Gt,
        }
    }
}

impl IrInstr {
    fn width(&self) -> usize {
        match self {
            IrInstr::Const4 { .. } => 1,
            IrInstr::Const16 { .. } => 2,
            IrInstr::ConstString { .. } => 2,
            IrInstr::MoveFrom16 { .. } => 2,
            IrInstr::IfGe { .. } | IrInstr::IfCmp { .. } => 2,
            IrInstr::IfEqz { .. } | IrInstr::IfNez { .. } => 2,
            IrInstr::Goto16 { .. } => 2,
            IrInstr::NewInstance { .. } => 2,
            IrInstr::CheckCast { .. } => 2,
            IrInstr::InstanceOf { .. } => 2,
            IrInstr::ArrayLength { .. } => 1,
            IrInstr::NewArray { .. } => 2,
            IrInstr::Aget { .. } | IrInstr::Aput { .. } => 2,
            IrInstr::InvokeDirect { .. }
            | IrInstr::InvokeVirtual { .. }
            | IrInstr::InvokeStatic { .. }
            | IrInstr::InvokeInterface { .. } => 3,
            IrInstr::InvokeDirectRange { .. }
            | IrInstr::InvokeStaticRange { .. }
            | IrInstr::InvokeVirtualRange { .. }
            | IrInstr::InvokeInterfaceRange { .. } => 3,
            IrInstr::SputObject { .. } => 2,
            IrInstr::Iget { .. } | IrInstr::Iput { .. } | IrInstr::Sget { .. } | IrInstr::Sput { .. } => 2,
            IrInstr::AddIntLit8 { .. } => 2,
            IrInstr::MoveResult { .. } | IrInstr::MoveResultWide { .. } => 1,
            IrInstr::MoveResultObject { .. } => 1,
            IrInstr::Return { .. } | IrInstr::ReturnWide { .. } => 1,
            IrInstr::ReturnObject { .. } => 1,
            IrInstr::ReturnVoid => 1,
        }
    }

    fn emit(
        self,
        code: &mut DexCode,
        offset: usize,
        labels: &[Option<usize>],
    ) -> Result<(), String> {
        match self {
            IrInstr::Const4 { dst, literal } => {
                require_nibble(dst, "const/4 dst")?;
                if !(-8..=7).contains(&literal) {
                    return Err(format!("const/4 literal out of range: {}", literal));
                }
                code.raw(0x0012 | ((dst as u16) << 8) | (((literal as i16 as u16) & 0x0f) << 12));
            }
            IrInstr::Const16 { dst, literal } => {
                require_byte(dst, "const/16 dst")?;
                code.raw(0x0013 | ((dst as u16) << 8));
                code.raw(literal as u16);
            }
            IrInstr::ConstString { dst, value } => {
                require_byte(dst, "const-string dst")?;
                code.raw(0x001a | ((dst as u16) << 8));
                code.string_idx(value);
            }
            IrInstr::MoveFrom16 { dst, src, kind } => {
                require_byte(dst, "move/from16 dst")?;
                let opcode = match kind {
                    ValueKind::Wide => 0x0005,
                    ValueKind::Object => 0x0008,
                    ValueKind::Narrow | ValueKind::Boolean | ValueKind::Byte | ValueKind::Char | ValueKind::Short => 0x0002,
                };
                code.raw(opcode | ((dst as u16) << 8));
                code.raw(src);
            }
            IrInstr::IfGe { left, right, target } => {
                require_nibble(left, "if-ge left")?;
                require_nibble(right, "if-ge right")?;
                code.raw(0x0035 | ((left as u16) << 8) | ((right as u16) << 12));
                code.raw(branch_offset(offset, target, labels, "if-ge")? as u16);
            }
            IrInstr::IfCmp {
                op,
                left,
                right,
                target,
            } => {
                require_nibble(left, "if-cmp left")?;
                require_nibble(right, "if-cmp right")?;
                code.raw(op.opcode() | ((left as u16) << 8) | ((right as u16) << 12));
                code.raw(branch_offset(offset, target, labels, op.name())? as u16);
            }
            IrInstr::IfEqz { reg, target } => {
                require_byte(reg, "if-eqz reg")?;
                code.raw(0x0038 | ((reg as u16) << 8));
                code.raw(branch_offset(offset, target, labels, "if-eqz")? as u16);
            }
            IrInstr::IfNez { reg, target } => {
                require_byte(reg, "if-nez reg")?;
                code.raw(0x0039 | ((reg as u16) << 8));
                code.raw(branch_offset(offset, target, labels, "if-nez")? as u16);
            }
            IrInstr::Goto16 { target } => {
                code.raw(0x0029);
                code.raw(branch_offset(offset, target, labels, "goto/16")? as u16);
            }
            IrInstr::NewInstance { dst, ty } => {
                require_byte(dst, "new-instance dst")?;
                code.raw(0x0022 | ((dst as u16) << 8));
                code.type_idx(ty);
            }
            IrInstr::CheckCast { reg, ty } => {
                require_byte(reg, "check-cast reg")?;
                code.raw(0x001f | ((reg as u16) << 8));
                code.type_idx(ty);
            }
            IrInstr::InstanceOf { dst, obj, ty } => {
                require_nibble(dst, "instance-of dst")?;
                require_nibble(obj, "instance-of obj")?;
                code.raw(0x0020 | ((dst as u16) << 8) | ((obj as u16) << 12));
                code.type_idx(ty);
            }
            IrInstr::ArrayLength { dst, array } => {
                require_nibble(dst, "array-length dst")?;
                require_nibble(array, "array-length array")?;
                code.raw(0x0021 | ((dst as u16) << 8) | ((array as u16) << 12));
            }
            IrInstr::NewArray { dst, size, ty } => {
                require_nibble(dst, "new-array dst")?;
                require_nibble(size, "new-array size")?;
                code.raw(0x0023 | ((dst as u16) << 8) | ((size as u16) << 12));
                code.type_idx(ty);
            }
            IrInstr::Aget {
                dst,
                array,
                index,
                kind,
            } => {
                require_byte(dst, "aget dst")?;
                require_byte(array, "aget array")?;
                require_byte(index, "aget index")?;
                code.raw(array_opcode(false, kind) | ((dst as u16) << 8));
                code.raw((array as u16) | ((index as u16) << 8));
            }
            IrInstr::Aput {
                src,
                array,
                index,
                kind,
            } => {
                require_byte(src, "aput src")?;
                require_byte(array, "aput array")?;
                require_byte(index, "aput index")?;
                code.raw(array_opcode(true, kind) | ((src as u16) << 8));
                code.raw((array as u16) | ((index as u16) << 8));
            }
            IrInstr::InvokeDirect { args, method } => {
                emit_invoke35c(code, 0x70, &args, method)?;
            }
            IrInstr::InvokeVirtual { args, method } => {
                emit_invoke35c(code, 0x6e, &args, method)?;
            }
            IrInstr::InvokeStatic { args, method } => {
                emit_invoke35c(code, 0x71, &args, method)?;
            }
            IrInstr::InvokeInterface { args, method } => {
                emit_invoke35c(code, 0x72, &args, method)?;
            }
            IrInstr::InvokeDirectRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x76, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeStaticRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x77, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeVirtualRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x74, first_reg, arg_words, method)?;
            }
            IrInstr::InvokeInterfaceRange {
                first_reg,
                arg_words,
                method,
            } => {
                emit_invoke3rc(code, 0x78, first_reg, arg_words, method)?;
            }
            IrInstr::SputObject { src, field } => {
                require_byte(src, "sput-object src")?;
                code.raw(0x0069 | ((src as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::Iget { dst, obj, field, kind } => {
                require_nibble(dst, "iget dst")?;
                require_nibble(obj, "iget obj")?;
                code.raw(field_opcode(false, false, kind) | ((dst as u16) << 8) | ((obj as u16) << 12));
                code.field_idx(field);
            }
            IrInstr::Iput { src, obj, field, kind } => {
                require_nibble(src, "iput src")?;
                require_nibble(obj, "iput obj")?;
                code.raw(field_opcode(false, true, kind) | ((src as u16) << 8) | ((obj as u16) << 12));
                code.field_idx(field);
            }
            IrInstr::Sget { dst, field, kind } => {
                require_byte(dst, "sget dst")?;
                code.raw(field_opcode(true, false, kind) | ((dst as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::Sput { src, field, kind } => {
                require_byte(src, "sput src")?;
                code.raw(field_opcode(true, true, kind) | ((src as u16) << 8));
                code.field_idx(field);
            }
            IrInstr::AddIntLit8 { dst, src, literal } => {
                require_byte(dst, "add-int/lit8 dst")?;
                require_byte(src, "add-int/lit8 src")?;
                code.raw(0x00d8 | ((dst as u16) << 8));
                code.raw((src as u16) | (((literal as i16 as u16) & 0xff) << 8));
            }
            IrInstr::MoveResult { dst } => {
                require_byte(dst, "move-result dst")?;
                code.raw(0x000a | ((dst as u16) << 8));
            }
            IrInstr::MoveResultWide { dst } => {
                require_byte(dst, "move-result-wide dst")?;
                code.raw(0x000b | ((dst as u16) << 8));
            }
            IrInstr::MoveResultObject { dst } => {
                require_byte(dst, "move-result-object dst")?;
                code.raw(0x000c | ((dst as u16) << 8));
            }
            IrInstr::Return { src } => {
                require_byte(src, "return src")?;
                code.raw(0x000f | ((src as u16) << 8));
            }
            IrInstr::ReturnWide { src } => {
                require_byte(src, "return-wide src")?;
                code.raw(0x0010 | ((src as u16) << 8));
            }
            IrInstr::ReturnObject { src } => {
                require_byte(src, "return-object src")?;
                code.raw(0x0011 | ((src as u16) << 8));
            }
            IrInstr::ReturnVoid => {
                code.raw(0x000e);
            }
        }
        Ok(())
    }
}

fn emit_invoke35c(code: &mut DexCode, opcode: u16, args: &[u8], method: MethodRef) -> Result<(), String> {
    if args.len() > 5 {
        return Err(format!("invoke supports at most 5 args, got {}", args.len()));
    }
    for (idx, reg) in args.iter().enumerate() {
        require_nibble(*reg, &format!("invoke arg {}", idx))?;
    }
    let mut regs = [0u8; 5];
    for (idx, reg) in args.iter().enumerate() {
        regs[idx] = *reg;
    }
    let g = if args.len() == 5 { regs[4] } else { 0 };
    code.raw(opcode | ((g as u16) << 8) | ((args.len() as u16) << 12));
    code.method_idx(method);
    code.raw((regs[0] as u16) | ((regs[1] as u16) << 4) | ((regs[2] as u16) << 8) | ((regs[3] as u16) << 12));
    Ok(())
}

fn emit_invoke3rc(
    code: &mut DexCode,
    opcode: u16,
    first_reg: u16,
    arg_words: u8,
    method: MethodRef,
) -> Result<(), String> {
    code.raw(opcode | ((arg_words as u16) << 8));
    code.method_idx(method);
    code.raw(first_reg);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ValueKind {
    Narrow,
    Wide,
    Object,
    Boolean,
    Byte,
    Char,
    Short,
}

fn value_kind_from_descriptor(desc: &str) -> Result<ValueKind, String> {
    match desc {
        "Z" => Ok(ValueKind::Boolean),
        "B" => Ok(ValueKind::Byte),
        "C" => Ok(ValueKind::Char),
        "S" => Ok(ValueKind::Short),
        "I" | "F" => Ok(ValueKind::Narrow),
        "J" | "D" => Ok(ValueKind::Wide),
        value if return_is_object(value) => Ok(ValueKind::Object),
        other => Err(format!("unsupported value descriptor '{}'", other)),
    }
}

fn field_opcode(is_static: bool, is_put: bool, kind: ValueKind) -> u16 {
    match (is_static, is_put, kind) {
        (false, false, ValueKind::Narrow) => 0x52,
        (false, false, ValueKind::Wide) => 0x53,
        (false, false, ValueKind::Object) => 0x54,
        (false, false, ValueKind::Boolean) => 0x55,
        (false, false, ValueKind::Byte) => 0x56,
        (false, false, ValueKind::Char) => 0x57,
        (false, false, ValueKind::Short) => 0x58,
        (false, true, ValueKind::Narrow) => 0x59,
        (false, true, ValueKind::Wide) => 0x5a,
        (false, true, ValueKind::Object) => 0x5b,
        (false, true, ValueKind::Boolean) => 0x5c,
        (false, true, ValueKind::Byte) => 0x5d,
        (false, true, ValueKind::Char) => 0x5e,
        (false, true, ValueKind::Short) => 0x5f,
        (true, false, ValueKind::Narrow) => 0x60,
        (true, false, ValueKind::Wide) => 0x61,
        (true, false, ValueKind::Object) => 0x62,
        (true, false, ValueKind::Boolean) => 0x63,
        (true, false, ValueKind::Byte) => 0x64,
        (true, false, ValueKind::Char) => 0x65,
        (true, false, ValueKind::Short) => 0x66,
        (true, true, ValueKind::Narrow) => 0x67,
        (true, true, ValueKind::Wide) => 0x68,
        (true, true, ValueKind::Object) => 0x69,
        (true, true, ValueKind::Boolean) => 0x6a,
        (true, true, ValueKind::Byte) => 0x6b,
        (true, true, ValueKind::Char) => 0x6c,
        (true, true, ValueKind::Short) => 0x6d,
    }
}

fn array_opcode(is_put: bool, kind: ValueKind) -> u16 {
    match (is_put, kind) {
        (false, ValueKind::Narrow) => 0x44,
        (false, ValueKind::Wide) => 0x45,
        (false, ValueKind::Object) => 0x46,
        (false, ValueKind::Boolean) => 0x47,
        (false, ValueKind::Byte) => 0x48,
        (false, ValueKind::Char) => 0x49,
        (false, ValueKind::Short) => 0x4a,
        (true, ValueKind::Narrow) => 0x4b,
        (true, ValueKind::Wide) => 0x4c,
        (true, ValueKind::Object) => 0x4d,
        (true, ValueKind::Boolean) => 0x4e,
        (true, ValueKind::Byte) => 0x4f,
        (true, ValueKind::Char) => 0x50,
        (true, ValueKind::Short) => 0x51,
    }
}

fn branch_offset(
    source_offset: usize,
    target: DexLabel,
    labels: &[Option<usize>],
    opname: &str,
) -> Result<i16, String> {
    let target_offset = labels
        .get(target.0)
        .and_then(|v| *v)
        .ok_or_else(|| format!("{} target label {} is not bound", opname, target.0))?;
    let delta = target_offset as isize - source_offset as isize;
    if delta < i16::MIN as isize || delta > i16::MAX as isize {
        return Err(format!("{} branch offset out of range: {}", opname, delta));
    }
    Ok(delta as i16)
}

fn require_nibble(value: u8, what: &str) -> Result<(), String> {
    if value > 0x0f {
        return Err(format!("{} register out of range for nibble encoding: v{}", what, value));
    }
    Ok(())
}

fn require_byte(value: u8, what: &str) -> Result<(), String> {
    if value == u8::MAX {
        return Err(format!("{} invalid register v{}", what, value));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(super) enum CodeWord {
    Raw(u16),
    String(String),
    Type(String),
    Field(FieldRef),
    Method(MethodRef),
}

#[derive(Clone, Debug)]
pub(super) struct ClassField {
    pub field: FieldRef,
    pub access_flags: u32,
}

#[derive(Clone, Debug)]
pub(super) struct ClassMethod {
    pub method: MethodRef,
    pub access_flags: u32,
    pub code: Option<DexCode>,
}

#[derive(Clone, Debug)]
pub(super) struct DexClass {
    pub class_type: String,
    pub access_flags: u32,
    pub super_type: String,
    pub source_file: Option<String>,
    pub static_fields: Vec<ClassField>,
    pub instance_fields: Vec<ClassField>,
    pub direct_methods: Vec<ClassMethod>,
    pub virtual_methods: Vec<ClassMethod>,
}

impl DexClass {
    pub(super) fn new(class_type: impl Into<String>) -> Self {
        Self {
            class_type: class_type.into(),
            access_flags: ACC_PUBLIC | ACC_FINAL,
            super_type: "Ljava/lang/Object;".to_string(),
            source_file: None,
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        }
    }

    pub(super) fn source_file(mut self, source_file: impl Into<String>) -> Self {
        self.source_file = Some(source_file.into());
        self
    }

    pub(super) fn static_field(&mut self, name: &str, type_name: &str, access_flags: u32) -> FieldRef {
        let field = FieldRef::new(self.class_type.clone(), type_name.to_string(), name.to_string());
        self.static_fields.push(ClassField {
            field: field.clone(),
            access_flags,
        });
        field
    }

    pub(super) fn direct_method(
        &mut self,
        name: &str,
        return_type: &str,
        params: Vec<String>,
        access_flags: u32,
        code: DexCode,
    ) -> MethodRef {
        let method = MethodRef::new(self.class_type.clone(), name.to_string(), return_type.to_string(), params);
        self.direct_methods.push(ClassMethod {
            method: method.clone(),
            access_flags,
            code: Some(code),
        });
        method
    }
}

pub(super) struct DexBuilder {
    classes: Vec<DexClass>,
    field_refs: BTreeSet<FieldRef>,
    method_refs: BTreeSet<MethodRef>,
}

impl DexBuilder {
    pub(super) fn new() -> Self {
        Self {
            classes: Vec::new(),
            field_refs: BTreeSet::new(),
            method_refs: BTreeSet::new(),
        }
    }

    pub(super) fn add_class(&mut self, class: DexClass) {
        self.classes.push(class);
    }

    pub(super) fn add_field_ref(&mut self, field: FieldRef) -> FieldRef {
        self.field_refs.insert(field.clone());
        field
    }

    pub(super) fn add_method_ref(&mut self, method: MethodRef) -> MethodRef {
        self.method_refs.insert(method.clone());
        method
    }

    pub(super) fn build(mut self) -> Result<Vec<u8>, String> {
        if self.classes.is_empty() {
            return Err("dex builder requires at least one class".to_string());
        }

        for class in &self.classes {
            for field in class.static_fields.iter().chain(class.instance_fields.iter()) {
                self.field_refs.insert(field.field.clone());
            }
            for method in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                self.method_refs.insert(method.method.clone());
                if let Some(code) = &method.code {
                    for word in &code.insns {
                        match word {
                            CodeWord::Field(field) => {
                                self.field_refs.insert(field.clone());
                            }
                            CodeWord::Method(method) => {
                                self.method_refs.insert(method.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        let mut string_set = BTreeSet::<String>::new();
        let mut type_set = BTreeSet::<String>::new();
        let mut proto_set = BTreeSet::<ProtoSpec>::new();

        for class in &self.classes {
            type_set.insert(class.class_type.clone());
            type_set.insert(class.super_type.clone());
            if let Some(source_file) = &class.source_file {
                string_set.insert(source_file.clone());
            }
        }
        for field in &self.field_refs {
            type_set.insert(field.class_type.clone());
            type_set.insert(field.type_name.clone());
            string_set.insert(field.name.clone());
        }
        for method in &self.method_refs {
            type_set.insert(method.class_type.clone());
            type_set.insert(method.proto.return_type.clone());
            for param in &method.proto.params {
                type_set.insert(param.clone());
            }
            string_set.insert(method.name.clone());
            string_set.insert(method.proto.shorty());
            proto_set.insert(method.proto.clone());
        }
        for class in &self.classes {
            for method in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                if let Some(code) = &method.code {
                    for word in &code.insns {
                        match word {
                            CodeWord::String(value) => {
                                string_set.insert(value.clone());
                            }
                            CodeWord::Type(ty) => {
                                type_set.insert(ty.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        for ty in &type_set {
            string_set.insert(ty.clone());
        }

        let strings: Vec<String> = string_set.into_iter().collect();
        let string_idx: BTreeMap<String, u32> = strings
            .iter()
            .enumerate()
            .map(|(i, s)| (s.clone(), i as u32))
            .collect();

        let mut types: Vec<String> = type_set.into_iter().collect();
        types.sort_by_key(|ty| string_idx[ty]);
        let type_idx: BTreeMap<String, u32> = types
            .iter()
            .enumerate()
            .map(|(i, s)| (s.clone(), i as u32))
            .collect();

        let mut protos: Vec<ProtoSpec> = proto_set.into_iter().collect();
        protos.sort_by_key(|p| {
            (
                type_idx[&p.return_type],
                p.params.iter().map(|ty| type_idx[ty]).collect::<Vec<_>>(),
                string_idx[&p.shorty()],
            )
        });
        let proto_idx: BTreeMap<ProtoSpec, u32> = protos
            .iter()
            .enumerate()
            .map(|(i, p)| (p.clone(), i as u32))
            .collect();

        let mut fields: Vec<FieldRef> = self.field_refs.into_iter().collect();
        fields.sort_by_key(|f| {
            (
                type_idx[&f.class_type],
                string_idx[&f.name],
                type_idx[&f.type_name],
            )
        });
        let field_idx: BTreeMap<FieldRef, u32> = fields
            .iter()
            .enumerate()
            .map(|(i, f)| (f.clone(), i as u32))
            .collect();

        let mut methods: Vec<MethodRef> = self.method_refs.into_iter().collect();
        methods.sort_by_key(|m| {
            (
                type_idx[&m.class_type],
                string_idx[&m.name],
                proto_idx[&m.proto],
            )
        });
        let method_idx: BTreeMap<MethodRef, u32> = methods
            .iter()
            .enumerate()
            .map(|(i, m)| (m.clone(), i as u32))
            .collect();

        let mut type_lists = BTreeSet::<Vec<u32>>::new();
        for proto in &protos {
            if !proto.params.is_empty() {
                type_lists.insert(proto.params.iter().map(|p| type_idx[p]).collect());
            }
        }

        let header_size = 0x70usize;
        let string_ids_off = header_size;
        let type_ids_off = align4(string_ids_off + strings.len() * 4);
        let proto_ids_off = align4(type_ids_off + types.len() * 4);
        let field_ids_off = align4(proto_ids_off + protos.len() * 12);
        let method_ids_off = align4(field_ids_off + fields.len() * 8);
        let class_defs_off = align4(method_ids_off + methods.len() * 8);
        let data_off = align4(class_defs_off + self.classes.len() * 32);

        let mut data = Vec::new();
        let mut type_list_offsets = BTreeMap::<Vec<u32>, u32>::new();
        let first_type_list_off = if type_lists.is_empty() {
            0
        } else {
            data_off as u32
        };
        for key in &type_lists {
            align_vec4(&mut data);
            let off = (data_off + data.len()) as u32;
            write_u32(&mut data, key.len() as u32);
            for idx in key {
                write_u16(&mut data, *idx as u16);
            }
            if key.len() % 2 != 0 {
                write_u16(&mut data, 0);
            }
            type_list_offsets.insert(key.clone(), off);
        }

        let first_string_data_off = (data_off + data.len()) as u32;
        let mut string_data_offsets = Vec::with_capacity(strings.len());
        for s in &strings {
            string_data_offsets.push((data_off + data.len()) as u32);
            write_uleb128(&mut data, s.chars().count() as u32);
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }

        let mut class_data_offsets = Vec::<u32>::with_capacity(self.classes.len());
        let mut code_patch_offsets = Vec::<(usize, DexCode)>::new();
        for class in &self.classes {
            align_vec4(&mut data);
            let class_data_off = (data_off + data.len()) as u32;
            class_data_offsets.push(class_data_off);
            write_class_data_item(
                &mut data,
                class,
                &field_idx,
                &method_idx,
                &mut code_patch_offsets,
            )?;
        }

        let mut code_offsets = Vec::<u32>::new();
        for (patch_pos, code) in code_patch_offsets {
            align_vec4(&mut data);
            let code_off = (data_off + data.len()) as u32;
            data[patch_pos..patch_pos + 5].copy_from_slice(&uleb128_padded5(code_off));
            code_offsets.push(code_off);
            write_code_item(&mut data, &code, &string_idx, &type_idx, &field_idx, &method_idx)?;
        }

        align_vec4(&mut data);
        let map_off = (data_off + data.len()) as u32;
        write_map_list(
            &mut data,
            &[
                (TYPE_HEADER_ITEM, 1, 0),
                (TYPE_STRING_ID_ITEM, strings.len() as u32, string_ids_off as u32),
                (TYPE_TYPE_ID_ITEM, types.len() as u32, type_ids_off as u32),
                (TYPE_PROTO_ID_ITEM, protos.len() as u32, proto_ids_off as u32),
                (TYPE_FIELD_ID_ITEM, fields.len() as u32, field_ids_off as u32),
                (TYPE_METHOD_ID_ITEM, methods.len() as u32, method_ids_off as u32),
                (TYPE_CLASS_DEF_ITEM, self.classes.len() as u32, class_defs_off as u32),
                (TYPE_MAP_LIST, 1, map_off),
                (TYPE_TYPE_LIST, type_lists.len() as u32, first_type_list_off),
                (TYPE_CLASS_DATA_ITEM, self.classes.len() as u32, class_data_offsets[0]),
                (TYPE_CODE_ITEM, code_offsets.len() as u32, code_offsets.first().copied().unwrap_or(0)),
                (TYPE_STRING_DATA_ITEM, strings.len() as u32, first_string_data_off),
            ],
        );

        let file_size = data_off + data.len();
        let mut out = vec![0u8; data_off];
        out.extend_from_slice(&data);

        out[0..8].copy_from_slice(b"dex\n035\0");
        write_u32_at(&mut out, 32, file_size as u32);
        write_u32_at(&mut out, 36, header_size as u32);
        write_u32_at(&mut out, 40, 0x1234_5678);
        write_u32_at(&mut out, 52, map_off);
        write_u32_at(&mut out, 56, strings.len() as u32);
        write_u32_at(&mut out, 60, string_ids_off as u32);
        write_u32_at(&mut out, 64, types.len() as u32);
        write_u32_at(&mut out, 68, type_ids_off as u32);
        write_u32_at(&mut out, 72, protos.len() as u32);
        write_u32_at(&mut out, 76, proto_ids_off as u32);
        write_u32_at(&mut out, 80, fields.len() as u32);
        write_u32_at(&mut out, 84, field_ids_off as u32);
        write_u32_at(&mut out, 88, methods.len() as u32);
        write_u32_at(&mut out, 92, method_ids_off as u32);
        write_u32_at(&mut out, 96, self.classes.len() as u32);
        write_u32_at(&mut out, 100, class_defs_off as u32);
        write_u32_at(&mut out, 104, (file_size - data_off) as u32);
        write_u32_at(&mut out, 108, data_off as u32);

        for (i, off) in string_data_offsets.iter().enumerate() {
            write_u32_at(&mut out, string_ids_off + i * 4, *off);
        }
        for (i, ty) in types.iter().enumerate() {
            write_u32_at(&mut out, type_ids_off + i * 4, string_idx[ty]);
        }
        for (i, proto) in protos.iter().enumerate() {
            let params: Vec<u32> = proto.params.iter().map(|p| type_idx[p]).collect();
            let params_off = if params.is_empty() {
                0
            } else {
                type_list_offsets[&params]
            };
            let off = proto_ids_off + i * 12;
            write_u32_at(&mut out, off, string_idx[&proto.shorty()]);
            write_u32_at(&mut out, off + 4, type_idx[&proto.return_type]);
            write_u32_at(&mut out, off + 8, params_off);
        }
        for (i, field) in fields.iter().enumerate() {
            let off = field_ids_off + i * 8;
            write_u16_at(&mut out, off, type_idx[&field.class_type] as u16);
            write_u16_at(&mut out, off + 2, type_idx[&field.type_name] as u16);
            write_u32_at(&mut out, off + 4, string_idx[&field.name]);
        }
        for (i, method) in methods.iter().enumerate() {
            let off = method_ids_off + i * 8;
            write_u16_at(&mut out, off, type_idx[&method.class_type] as u16);
            write_u16_at(&mut out, off + 2, proto_idx[&method.proto] as u16);
            write_u32_at(&mut out, off + 4, string_idx[&method.name]);
        }

        for (i, class) in self.classes.iter().enumerate() {
            let off = class_defs_off + i * 32;
            write_u32_at(&mut out, off, type_idx[&class.class_type]);
            write_u32_at(&mut out, off + 4, class.access_flags);
            write_u32_at(&mut out, off + 8, type_idx[&class.super_type]);
            write_u32_at(&mut out, off + 12, 0);
            let source_idx = class
                .source_file
                .as_ref()
                .map(|s| string_idx[s])
                .unwrap_or(0xffff_ffff);
            write_u32_at(&mut out, off + 16, source_idx);
            write_u32_at(&mut out, off + 20, 0);
            write_u32_at(&mut out, off + 24, class_data_offsets[i]);
            write_u32_at(&mut out, off + 28, 0);
        }

        let signature = sha1_digest(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum = adler32(&out[12..]);
        write_u32_at(&mut out, 8, checksum);

        Ok(out)
    }
}

pub(super) struct GeneratedManagedDex {
    pub dex: Vec<u8>,
    pub class_name: String,
    pub method_name: String,
    pub method_sig: String,
    pub string_literals: Vec<GeneratedStringLiteral>,
}

#[derive(Clone, Debug)]
pub(super) struct GeneratedStringLiteral {
    pub field_name: String,
    pub value: String,
}

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

fn descriptor_word_count(desc: &str) -> u16 {
    if desc == "J" || desc == "D" {
        2
    } else {
        1
    }
}

fn descriptor_list_word_count(descs: &[String]) -> Result<u16, String> {
    let mut total = 0u16;
    for desc in descs {
        total = total
            .checked_add(descriptor_word_count(desc))
            .ok_or_else(|| "too many dex registers".to_string())?;
    }
    Ok(total)
}

fn build_method_sig(params: &[String], return_type: &str) -> String {
    let mut sig = String::from("(");
    for param in params {
        sig.push_str(param);
    }
    sig.push(')');
    sig.push_str(return_type);
    sig
}

fn return_is_object(return_type: &str) -> bool {
    return_type.starts_with('L') || return_type.starts_with('[')
}

fn emit_return_from_orig(ir: &mut DexIrBuilder, return_type: &str) -> Result<(), String> {
    match return_type {
        "V" => ir.return_void(),
        "J" | "D" => {
            ir.move_result_wide(0);
            ir.return_wide(0);
        }
        ret if return_is_object(ret) => {
            ir.move_result_object(0);
            ir.return_object(0);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            ir.move_result(0);
            ir.return_value(0);
        }
        other => return Err(format!("unsupported return type '{}'", other)),
    }
    Ok(())
}

const BASE_LOCAL_REG_COUNT: u16 = 5;
const REG_RESULT: u8 = 0;
const REG_LAST_OBJECT: u8 = 1;
const REG_LOOP_LIMIT: u8 = 2;
const REG_TMP0: u8 = 3;
const REG_TMP1: u8 = 4;

struct HelperParamLayout {
    this_reg: Option<u8>,
    arg_regs: Vec<u8>,
    local_regs: BTreeMap<String, LocalSlot>,
}

#[derive(Clone)]
struct LocalSlot {
    reg: u8,
    descriptor: String,
}

struct DslBuildContext {
    generated_type: String,
    string_literals: Vec<GeneratedStringLiteral>,
    range_scratch_base: u16,
}

impl DslBuildContext {
    fn new(generated_type: String, range_scratch_base: u16) -> Self {
        Self {
            generated_type,
            string_literals: Vec::new(),
            range_scratch_base,
        }
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
        FieldRef::new(self.generated_type.clone(), "Ljava/lang/String;".to_string(), field_name)
    }
}

fn helper_param_layout(
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
    let mut arg_regs = Vec::with_capacity(target_params.len());
    for param in target_params {
        let reg = checked_reg(next, "argument register")?;
        next += descriptor_word_count(param);
        arg_regs.push(reg);
    }
    Ok(HelperParamLayout {
        this_reg,
        arg_regs,
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
    let (params, return_type) = if let Some(sig) = ctor_sig {
        parse_method_signature(sig)?
    } else {
        (Vec::new(), "V".to_string())
    };
    if return_type != "V" {
        return Err(format!("constructor signature must return void, got '{}'", return_type));
    }
    if params.len() != args.len() {
        return Err(format!(
            "{}.<init>{} expects {} explicit args, got {}",
            class_name,
            ctor_sig.unwrap_or("()V"),
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

fn emit_new_loop(
    ir: &mut DexIrBuilder,
    class_name: &str,
    iterations: u16,
    sink: &FieldRef,
) -> Result<MethodRef, String> {
    let new_type = java_class_to_descriptor(class_name)?;
    let ctor = MethodRef::new(new_type.clone(), "<init>", "V", Vec::new());
    let loop_label = ir.new_label();
    let done_label = ir.new_label();
    ir.const4(REG_RESULT, 0);
    ir.const16(REG_LOOP_LIMIT, iterations as i16);
    ir.bind(loop_label)?;
    ir.if_ge(REG_RESULT, REG_LOOP_LIMIT, done_label);
    ir.new_instance(REG_LAST_OBJECT, new_type);
    ir.invoke_direct(vec![REG_LAST_OBJECT], ctor.clone());
    ir.sput_object(REG_LAST_OBJECT, sink.clone());
    ir.add_int_lit8(REG_RESULT, REG_RESULT, 1);
    ir.goto16(loop_label);
    ir.bind(done_label)?;
    Ok(ctor)
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
    let class_type = java_class_to_descriptor(&stmt.class_name)?;
    let (params, return_type) = parse_method_signature(&stmt.sig)?;
    if return_type == "V" {
        return Err(format!("{}.{}{} returns void and cannot be used as a value", stmt.class_name, stmt.method_name, stmt.sig));
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
            stmt.class_name,
            stmt.method_name,
            stmt.sig,
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
    let invoke_kind = match stmt.kind {
        DslCallKind::Virtual => ManagedInvokeKind::Virtual,
        DslCallKind::Interface => ManagedInvokeKind::Interface,
        DslCallKind::Static => ManagedInvokeKind::Static,
    };
    emit_invoke_with_values(
        ir,
        invoke_kind,
        method,
        receiver,
        &params,
        &stmt.args,
        layout,
        dsl_ctx,
    )?;
    emit_move_result_value(ir, &return_type, dst)
}

fn emit_field_get_value(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    is_static: bool,
    expected_type: &str,
    dst: u8,
    layout: &HelperParamLayout,
) -> Result<u8, String> {
    let class_type = java_class_to_descriptor(&stmt.class_name)?;
    let field_type = java_class_to_descriptor_or_primitive(&stmt.type_name)?;
    if !value_descriptor_assignable_to(&field_type, expected_type) {
        return Err(format!(
            "field expression type {} cannot be passed as {}",
            field_type, expected_type
        ));
    }
    let field = FieldRef::new(class_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    if is_static {
        ir.sget(dst, field, kind);
    } else {
        let Some(target) = &stmt.target else {
            return Err("instance field access requires a target".to_string());
        };
        let obj = emit_copy_object_if_needed(ir, resolve_target_reg(target, layout)?, REG_TMP1);
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
        DslValue::Null => {
            if !return_is_object(expected_type) {
                return Err(format!("null cannot be passed as {}", expected_type));
            }
            ir.const4(temp_reg, 0);
            Ok(temp_reg)
        }
        DslValue::AddLit(value, literal) => {
            if expected_type != "I" {
                return Err(format!("int expression cannot be passed as {}", expected_type));
            }
            let src = emit_load_value(ir, value, expected_type, temp_reg, layout, dsl_ctx)?;
            let src = emit_copy_field_value_if_needed(ir, src, temp_reg, ValueKind::Narrow);
            ir.add_int_lit8(temp_reg, src, *literal);
            Ok(temp_reg)
        }
        DslValue::SubLit(value, literal) => {
            if expected_type != "I" {
                return Err(format!("int expression cannot be passed as {}", expected_type));
            }
            let src = emit_load_value(ir, value, expected_type, temp_reg, layout, dsl_ctx)?;
            let src = emit_copy_field_value_if_needed(ir, src, temp_reg, ValueKind::Narrow);
            let Some(negated) = literal.checked_neg() else {
                return Err("sub literal -128 cannot be encoded as add-int/lit8".to_string());
            };
            ir.add_int_lit8(temp_reg, src, negated);
            Ok(temp_reg)
        }
        DslValue::Call(stmt) => emit_call_value(ir, stmt, expected_type, temp_reg, layout, dsl_ctx),
        DslValue::FieldGet { stmt, is_static } => {
            emit_field_get_value(ir, stmt, *is_static, expected_type, temp_reg, layout)
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
            let component_type = java_class_to_descriptor_or_primitive(type_name)?;
            if !value_descriptor_assignable_to(&component_type, expected_type) {
                return Err(format!(
                    "aget expression type {} cannot be passed as {}",
                    component_type, expected_type
                ));
            }
            emit_array_get_value(ir, array, index, &component_type, temp_reg, layout, dsl_ctx)
        }
    }
}

fn value_descriptor_assignable_to(src: &str, dst: &str) -> bool {
    src == dst || (return_is_object(src) && return_is_object(dst))
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

fn emit_field_read(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    layout: &HelperParamLayout,
    is_static: bool,
) -> Result<(), String> {
    let class_type = java_class_to_descriptor(&stmt.class_name)?;
    let field_type = java_class_to_descriptor_or_primitive(&stmt.type_name)?;
    let field = FieldRef::new(class_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    let dst = if matches!(kind, ValueKind::Object) {
        REG_LAST_OBJECT
    } else {
        REG_RESULT
    };
    if is_static {
        ir.sget(dst, field, kind);
    } else {
        let Some(target) = &stmt.target else {
            return Err("instance field access requires a target".to_string());
        };
        let obj = emit_copy_object_if_needed(ir, resolve_target_reg(target, layout)?, REG_TMP1);
        ir.iget(dst, obj, field, kind);
    }
    Ok(())
}

fn emit_field_write(
    ir: &mut DexIrBuilder,
    stmt: &DslFieldStmt,
    layout: &HelperParamLayout,
    is_static: bool,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let class_type = java_class_to_descriptor(&stmt.class_name)?;
    let field_type = java_class_to_descriptor_or_primitive(&stmt.type_name)?;
    let field = FieldRef::new(class_type, field_type.clone(), stmt.field_name.clone());
    let kind = value_kind_from_descriptor(&field_type)?;
    let Some(value) = &stmt.value else {
        return Err("field write requires a value".to_string());
    };
    let raw_src = emit_load_value(ir, value, &field_type, REG_TMP0, layout, dsl_ctx)?;
    let src = emit_copy_field_value_if_needed(ir, raw_src, REG_TMP0, kind);
    if is_static {
        ir.sput(src, field, kind);
    } else {
        let Some(target) = &stmt.target else {
            return Err("instance field write requires a target".to_string());
        };
        let obj = emit_copy_object_if_needed(ir, resolve_target_reg(target, layout)?, REG_TMP1);
        ir.iput(src, obj, field, kind);
    }
    Ok(())
}

fn emit_let(
    ir: &mut DexIrBuilder,
    name: &str,
    type_name: &str,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
    let Some(slot) = layout.local_regs.get(name) else {
        return Err(format!("local '{}' is not allocated", name));
    };
    if slot.descriptor != descriptor {
        return Err(format!(
            "local '{}' type mismatch: declared {}, emitted {}",
            name, slot.descriptor, descriptor
        ));
    }
    let src = emit_load_value(ir, value, &descriptor, REG_TMP0, layout, dsl_ctx)?;
    emit_copy_value(ir, slot.reg, src, &descriptor)?;
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

fn infer_cmp_descriptor(value: &DslValue, layout: &HelperParamLayout) -> Option<&'static str> {
    match value {
        DslValue::Int(_) | DslValue::AddLit(_, _) | DslValue::SubLit(_, _) => Some("I"),
        DslValue::Target(DslTarget::Result) => Some("I"),
        DslValue::Target(DslTarget::Local(name)) => layout
            .local_regs
            .get(name)
            .and_then(|slot| if slot.descriptor == "I" { Some("I") } else { None }),
        DslValue::Call(stmt) => parse_method_signature(&stmt.sig)
            .ok()
            .and_then(|(_, ret)| if ret == "I" { Some("I") } else { None }),
        DslValue::FieldGet { stmt, .. } => java_class_to_descriptor_or_primitive(&stmt.type_name)
            .ok()
            .and_then(|desc| if desc == "I" { Some("I") } else { None }),
        DslValue::ArrayLength(_) => Some("I"),
        DslValue::ArrayGet { type_name, .. } => java_class_to_descriptor_or_primitive(type_name)
            .ok()
            .and_then(|desc| if desc == "I" { Some("I") } else { None }),
        _ => None,
    }
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
    let expected_type = if infer_cmp_descriptor(left, emit_ctx.layout) == Some("I")
        || infer_cmp_descriptor(right, emit_ctx.layout) == Some("I")
    {
        "I"
    } else {
        "Ljava/lang/Object;"
    };
    let left_reg = emit_load_cmp_value(
        ir,
        left,
        expected_type,
        REG_TMP0,
        emit_ctx.layout,
        emit_ctx.dsl_ctx,
    )?;
    let right_reg = emit_load_cmp_value(
        ir,
        right,
        expected_type,
        REG_TMP1,
        emit_ctx.layout,
        emit_ctx.dsl_ctx,
    )?;
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
    Ok(())
}

fn emit_array_length_stmt(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let _ = emit_array_length_value(ir, array, REG_RESULT, layout, dsl_ctx)?;
    Ok(())
}

fn emit_array_get_stmt(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    type_name: &str,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let component_type = java_class_to_descriptor_or_primitive(type_name)?;
    let kind = value_kind_from_descriptor(&component_type)?;
    let dst = if matches!(kind, ValueKind::Object) {
        REG_LAST_OBJECT
    } else {
        REG_RESULT
    };
    let _ = emit_array_get_value(ir, array, index, &component_type, dst, layout, dsl_ctx)?;
    Ok(())
}

fn emit_array_put(
    ir: &mut DexIrBuilder,
    array: &DslValue,
    index: &DslValue,
    type_name: &str,
    value: &DslValue,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<(), String> {
    let component_type = java_class_to_descriptor_or_primitive(type_name)?;
    let kind = value_kind_from_descriptor(&component_type)?;
    let array_reg = emit_load_value(ir, array, "Ljava/lang/Object;", REG_TMP1, layout, dsl_ctx)?;
    let array_reg = emit_copy_object_if_needed(ir, array_reg, REG_TMP1);
    let index_reg = emit_load_value(ir, index, "I", REG_TMP0, layout, dsl_ctx)?;
    let index_reg = emit_copy_field_value_if_needed(ir, index_reg, REG_TMP0, ValueKind::Narrow);
    let value_temp = if matches!(kind, ValueKind::Object) {
        REG_LAST_OBJECT
    } else {
        REG_LOOP_LIMIT
    };
    let value_reg = emit_load_value(ir, value, &component_type, value_temp, layout, dsl_ctx)?;
    let value_reg = emit_copy_field_value_if_needed(ir, value_reg, value_temp, kind);
    ir.aput(value_reg, array_reg, index_reg, kind);
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
    ir.instance_of(REG_TMP0, obj, ty);

    let else_label = ir.new_label();
    let done_label = ir.new_label();
    ir.if_eqz(REG_TMP0, else_label);

    let then_returns = emit_statements(ir, then_stmts, emit_ctx)?;
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

fn value_contains_invoke(value: &DslValue) -> bool {
    match value {
        DslValue::Call(_) => true,
        DslValue::AddLit(value, _) | DslValue::SubLit(value, _) | DslValue::ArrayLength(value) => {
            value_contains_invoke(value)
        }
        DslValue::Cast { value, .. } => value_contains_invoke(value),
        DslValue::ArrayGet { array, index, .. } => {
            value_contains_invoke(array) || value_contains_invoke(index)
        }
        DslValue::FieldGet { .. }
        | DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Null => false,
    }
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
    let has_wide = params.iter().any(|param| matches!(param.as_str(), "J" | "D"));
    if args.iter().any(value_contains_invoke) {
        return Err("call expressions cannot be nested inside invoke arguments; assign the value with let(...) first".to_string());
    }
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

    let mut next = dsl_ctx.range_scratch_base;
    if let Some((receiver_reg, receiver_desc)) = receiver {
        let dst = checked_reg(next, "range receiver register")?;
        emit_copy_value(ir, dst, receiver_reg, receiver_desc)?;
        next += 1;
    }
    for (idx, arg) in args.iter().enumerate() {
        let dst = checked_reg(next, "range argument register")?;
        let src = emit_load_value(ir, arg, &params[idx], dst, layout, dsl_ctx)?;
        emit_copy_value(ir, dst, src, &params[idx])?;
        next = next
            .checked_add(descriptor_word_count(&params[idx]))
            .ok_or_else(|| "too many dex registers".to_string())?;
    }
    let arg_words = next
        .checked_sub(dsl_ctx.range_scratch_base)
        .ok_or_else(|| "invalid range invoke register layout".to_string())?;
    if arg_words > u8::MAX as u16 {
        return Err(format!("too many invoke argument words: {}", arg_words));
    }
    match kind {
        ManagedInvokeKind::Direct => ir.invoke_direct_range(dsl_ctx.range_scratch_base, arg_words as u8, method),
        ManagedInvokeKind::Virtual => ir.invoke_virtual_range(dsl_ctx.range_scratch_base, arg_words as u8, method),
        ManagedInvokeKind::Interface => ir.invoke_interface_range(dsl_ctx.range_scratch_base, arg_words as u8, method),
        ManagedInvokeKind::Static => ir.invoke_static_range(dsl_ctx.range_scratch_base, arg_words as u8, method),
    }
    Ok(())
}

fn emit_call(
    ir: &mut DexIrBuilder,
    stmt: &DslCallStmt,
    layout: &HelperParamLayout,
    dsl_ctx: &mut DslBuildContext,
) -> Result<MethodRef, String> {
    let class_type = java_class_to_descriptor(&stmt.class_name)?;
    let (params, return_type) = parse_method_signature(&stmt.sig)?;
    if params.len() != stmt.args.len() {
        return Err(format!(
            "{}.{}{} expects {} explicit args, got {}",
            stmt.class_name,
            stmt.method_name,
            stmt.sig,
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
    let invoke_kind = match stmt.kind {
        DslCallKind::Virtual => ManagedInvokeKind::Virtual,
        DslCallKind::Interface => ManagedInvokeKind::Interface,
        DslCallKind::Static => ManagedInvokeKind::Static,
    };
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
    Ok(method)
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

fn invoke_arg_words(has_receiver: bool, params: &[String]) -> Result<u16, String> {
    let mut words = if has_receiver { 1u16 } else { 0u16 };
    words = words
        .checked_add(descriptor_list_word_count(params)?)
        .ok_or_else(|| "too many dex registers".to_string())?;
    Ok(words)
}

fn program_max_invoke_words(program: &DslProgram) -> Result<u16, String> {
    statements_max_invoke_words(&program.stmts)
}

fn statements_max_invoke_words(stmts: &[DslStmt]) -> Result<u16, String> {
    let mut max_words = 0u16;
    for stmt in stmts {
        let words = match stmt {
            DslStmt::Let { value, .. } => value_max_invoke_words(value)?,
            DslStmt::New { ctor_sig, args, .. } => {
                let params = if let Some(sig) = ctor_sig {
                    let (params, return_type) = parse_method_signature(sig)?;
                    if return_type != "V" {
                        return Err(format!("constructor signature must return void, got '{}'", return_type));
                    }
                    params
                } else {
                    Vec::new()
                };
                let mut words = invoke_arg_words(true, &params)?;
                for arg in args {
                    words = words.max(value_max_invoke_words(arg)?);
                }
                words
            }
            DslStmt::NewArray { size, .. } => value_max_invoke_words(size)?,
            DslStmt::Call(stmt) => {
                let (params, _) = parse_method_signature(&stmt.sig)?;
                let mut words = invoke_arg_words(stmt.target.is_some(), &params)?;
                for arg in &stmt.args {
                    words = words.max(value_max_invoke_words(arg)?);
                }
                words
            }
            DslStmt::IfNull {
                value,
                then_stmts,
                else_stmts,
                ..
            } => value_max_invoke_words(value)?
                .max(statements_max_invoke_words(then_stmts)?)
                .max(statements_max_invoke_words(else_stmts)?),
            DslStmt::IfCmp {
                left,
                right,
                then_stmts,
                else_stmts,
                ..
            } => value_max_invoke_words(left)?
                .max(value_max_invoke_words(right)?)
                .max(statements_max_invoke_words(then_stmts)?)
                .max(statements_max_invoke_words(else_stmts)?),
            DslStmt::IfInstanceOf {
                value,
                then_stmts,
                else_stmts,
                ..
            } => value_max_invoke_words(value)?
                .max(statements_max_invoke_words(then_stmts)?)
                .max(statements_max_invoke_words(else_stmts)?),
            DslStmt::Cast { value, .. } => value_max_invoke_words(value)?,
            DslStmt::ArrayLength { array } => value_max_invoke_words(array)?,
            DslStmt::ArrayGet { array, index, .. } => {
                value_max_invoke_words(array)?.max(value_max_invoke_words(index)?)
            }
            DslStmt::ArrayPut {
                array,
                index,
                value,
                ..
            } => value_max_invoke_words(array)?
                .max(value_max_invoke_words(index)?)
                .max(value_max_invoke_words(value)?),
            DslStmt::FieldRead { stmt, .. } => stmt
                .target
                .as_ref()
                .map(|_| 0)
                .unwrap_or(0),
            DslStmt::FieldWrite { stmt, .. } => {
                stmt.value.as_ref().map(value_max_invoke_words).transpose()?.unwrap_or(0)
            }
            DslStmt::NewLoop { .. }
            | DslStmt::ReturnOrig => 0,
            DslStmt::ReturnValue { value } => value.as_ref().map(value_max_invoke_words).transpose()?.unwrap_or(0),
        };
        max_words = max_words.max(words);
    }
    Ok(max_words)
}

fn value_max_invoke_words(value: &DslValue) -> Result<u16, String> {
    match value {
        DslValue::Call(stmt) => {
            let (params, _) = parse_method_signature(&stmt.sig)?;
            let mut words = invoke_arg_words(stmt.target.is_some(), &params)?;
            for arg in &stmt.args {
                words = words.max(value_max_invoke_words(arg)?);
            }
            Ok(words)
        }
        DslValue::AddLit(value, _) | DslValue::SubLit(value, _) | DslValue::ArrayLength(value) => {
            value_max_invoke_words(value)
        }
        DslValue::Cast { value, .. } => value_max_invoke_words(value),
        DslValue::ArrayGet { array, index, .. } => {
            Ok(value_max_invoke_words(array)?.max(value_max_invoke_words(index)?))
        }
        DslValue::FieldGet { .. }
        | DslValue::Target(_)
        | DslValue::String(_)
        | DslValue::Int(_)
        | DslValue::Null => Ok(0),
    }
}

fn collect_local_slots(program: &DslProgram, first_reg: u16) -> Result<(BTreeMap<String, LocalSlot>, u16), String> {
    let mut slots = BTreeMap::new();
    let mut next = first_reg;
    collect_local_slots_from_stmts(&program.stmts, &mut slots, &mut next)?;
    Ok((slots, next - first_reg))
}

fn collect_local_slots_from_stmts(
    stmts: &[DslStmt],
    slots: &mut BTreeMap<String, LocalSlot>,
    next: &mut u16,
) -> Result<(), String> {
    for stmt in stmts {
        match stmt {
            DslStmt::Let {
                name,
                type_name,
                ..
            } => {
                if slots.contains_key(name) {
                    continue;
                }
                let descriptor = java_class_to_descriptor_or_primitive(type_name)?;
                let reg = checked_reg(*next, "local register")?;
                *next = (*next)
                    .checked_add(descriptor_word_count(&descriptor))
                    .ok_or_else(|| "too many dex registers".to_string())?;
                slots.insert(
                    name.clone(),
                    LocalSlot {
                        reg,
                        descriptor,
                    },
                );
            }
            DslStmt::IfNull {
                then_stmts,
                else_stmts,
                ..
            } => {
                collect_local_slots_from_stmts(then_stmts, slots, next)?;
                collect_local_slots_from_stmts(else_stmts, slots, next)?;
            }
            DslStmt::IfCmp {
                then_stmts,
                else_stmts,
                ..
            } => {
                collect_local_slots_from_stmts(then_stmts, slots, next)?;
                collect_local_slots_from_stmts(else_stmts, slots, next)?;
            }
            DslStmt::IfInstanceOf {
                then_stmts,
                else_stmts,
                ..
            } => {
                collect_local_slots_from_stmts(then_stmts, slots, next)?;
                collect_local_slots_from_stmts(else_stmts, slots, next)?;
            }
            _ => {}
        }
    }
    Ok(())
}

struct EmitContext<'a> {
    layout: &'a HelperParamLayout,
    dsl_ctx: &'a mut DslBuildContext,
    is_static: bool,
    local_count: u16,
    ins_size: u16,
    target: &'a MethodRef,
    return_type: &'a str,
    sink: &'a FieldRef,
}

fn emit_return_orig(ir: &mut DexIrBuilder, emit_ctx: &EmitContext<'_>) -> Result<(), String> {
    if emit_ctx.is_static {
        ir.invoke_static_range(emit_ctx.local_count, emit_ctx.ins_size as u8, emit_ctx.target.clone());
    } else {
        ir.invoke_virtual_range(emit_ctx.local_count, emit_ctx.ins_size as u8, emit_ctx.target.clone());
    }
    emit_return_from_orig(ir, emit_ctx.return_type)
}

fn emit_return_value(
    ir: &mut DexIrBuilder,
    value: Option<&DslValue>,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<(), String> {
    match emit_ctx.return_type {
        "V" => {
            if value.is_some() {
                return Err("void method can only use return; or return orig();".to_string());
            }
            ir.return_void();
        }
        "J" | "D" => {
            let Some(value) = value else {
                return Err(format!("method returning {} requires return value", emit_ctx.return_type));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            ir.return_wide(reg);
        }
        ret if return_is_object(ret) => {
            let Some(value) = value else {
                return Err(format!("method returning {} requires return value", emit_ctx.return_type));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            ir.return_object(reg);
        }
        "Z" | "B" | "C" | "S" | "I" | "F" => {
            let Some(value) = value else {
                return Err(format!("method returning {} requires return value", emit_ctx.return_type));
            };
            let reg = emit_load_value(
                ir,
                value,
                emit_ctx.return_type,
                REG_TMP0,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            ir.return_value(reg);
        }
        other => return Err(format!("unsupported direct return type '{}'", other)),
    }
    Ok(())
}

fn emit_statement(
    ir: &mut DexIrBuilder,
    stmt: &DslStmt,
    emit_ctx: &mut EmitContext<'_>,
) -> Result<bool, String> {
    match stmt {
        DslStmt::Let {
            name,
            type_name,
            value,
        } => {
            emit_let(ir, name, type_name, value, emit_ctx.layout, emit_ctx.dsl_ctx)?;
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
            Ok(false)
        }
        DslStmt::NewArray {
            array_type_name,
            size,
        } => {
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
        DslStmt::NewLoop {
            class_name,
            iterations,
        } => {
            emit_new_loop(ir, class_name, *iterations, emit_ctx.sink)?;
            Ok(false)
        }
        DslStmt::Call(stmt) => {
            emit_call(ir, stmt, emit_ctx.layout, emit_ctx.dsl_ctx)?;
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
            emit_array_get_stmt(ir, array, index, type_name, emit_ctx.layout, emit_ctx.dsl_ctx)?;
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
                type_name,
                value,
                emit_ctx.layout,
                emit_ctx.dsl_ctx,
            )?;
            Ok(false)
        }
        DslStmt::FieldRead { stmt, is_static } => {
            emit_field_read(ir, stmt, emit_ctx.layout, *is_static)?;
            Ok(false)
        }
        DslStmt::FieldWrite { stmt, is_static } => {
            emit_field_write(ir, stmt, emit_ctx.layout, *is_static, emit_ctx.dsl_ctx)?;
            Ok(false)
        }
        DslStmt::IfNull {
            value,
            invert,
            then_stmts,
            else_stmts,
        } => emit_if_null(ir, value, *invert, then_stmts, else_stmts, emit_ctx),
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
        DslStmt::ReturnOrig => {
            emit_return_orig(ir, emit_ctx)?;
            Ok(true)
        }
        DslStmt::ReturnValue { value } => {
            emit_return_value(ir, value.as_ref(), emit_ctx)?;
            Ok(true)
        }
    }
}

fn emit_statements(
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

pub(super) fn build_managed_dsl_dex(
    class_id: u64,
    target_class_name: &str,
    target_method_name: &str,
    target_sig: &str,
    is_static: bool,
    dsl: &str,
) -> Result<GeneratedManagedDex, String> {
    let program = parse_managed_dsl(dsl)?;
    let target_type = java_class_to_descriptor(target_class_name)?;
    let object_type = "Ljava/lang/Object;".to_string();
    let (target_params, return_type) = parse_method_signature(target_sig)?;
    let mut helper_params = Vec::new();
    if !is_static {
        helper_params.push(target_type.clone());
    }
    helper_params.extend(target_params.clone());

    let ins_size = descriptor_list_word_count(&helper_params)?;
    if ins_size > u8::MAX as u16 {
        return Err(format!("too many invoke argument words: {}", ins_size));
    }
    let max_invoke_words = program_max_invoke_words(&program)?;
    if max_invoke_words > u8::MAX as u16 {
        return Err(format!("too many DSL invoke argument words: {}", max_invoke_words));
    }
    let locals_start = BASE_LOCAL_REG_COUNT
        .checked_add(max_invoke_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let (local_slots, local_words) = collect_local_slots(&program, locals_start)?;
    let local_count = locals_start
        .checked_add(local_words)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let registers_size = local_count
        .checked_add(ins_size)
        .ok_or_else(|| "too many dex registers".to_string())?;
    let outs_size = std::cmp::max(1u16, std::cmp::max(ins_size, max_invoke_words));
    if registers_size > u8::MAX as u16 {
        return Err(format!("too many dex registers for generated helper: {}", registers_size));
    }

    let generated_type = format!("Lrustfrida/DynManagedHook{};", class_id);
    let generated_class_name = format!("rustfrida.DynManagedHook{}", class_id);
    let sink = FieldRef::new(generated_type.clone(), object_type.clone(), "sink");
    let mut dsl_ctx = DslBuildContext::new(generated_type.clone(), BASE_LOCAL_REG_COUNT);
    let target = MethodRef::new(
        target_type.clone(),
        target_method_name.to_string(),
        return_type.clone(),
        target_params.clone(),
    );

    let mut ir = DexIrBuilder::new(registers_size, ins_size, outs_size);
    let layout = helper_param_layout(is_static, &target_type, &target_params, local_count, local_slots)?;
    let mut emit_ctx = EmitContext {
        layout: &layout,
        dsl_ctx: &mut dsl_ctx,
        is_static,
        local_count,
        ins_size,
        target: &target,
        return_type: &return_type,
        sink: &sink,
    };
    let saw_return = emit_statements(&mut ir, &program.stmts, &mut emit_ctx)?;
    if !saw_return {
        return Err("managed DSL must end with return statement".to_string());
    }
    let code = ir.finish()?;

    let mut class = DexClass::new(generated_type.clone()).source_file("RustFridaDynamicManagedHook.java");
    class.static_field("sink", &object_type, ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
    for lit in &dsl_ctx.string_literals {
        class.static_field(&lit.field_name, "Ljava/lang/String;", ACC_PUBLIC | ACC_STATIC | ACC_VOLATILE);
    }
    class.direct_method(
        "hook",
        &return_type,
        helper_params.clone(),
        ACC_PUBLIC | ACC_STATIC,
        code,
    );

    let mut builder = DexBuilder::new();
    builder.add_class(class);
    builder.add_method_ref(target);
    let dex = builder.build()?;

    Ok(GeneratedManagedDex {
        dex,
        class_name: generated_class_name,
        method_name: "hook".to_string(),
        method_sig: build_method_sig(&helper_params, &return_type),
        string_literals: dsl_ctx.string_literals,
    })
}

struct DslProgram {
    stmts: Vec<DslStmt>,
}

enum DslStmt {
    Let {
        name: String,
        type_name: String,
        value: DslValue,
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
    NewLoop { class_name: String, iterations: u16 },
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
        type_name: String,
    },
    ArrayPut {
        array: DslValue,
        index: DslValue,
        type_name: String,
        value: DslValue,
    },
    FieldRead { stmt: DslFieldStmt, is_static: bool },
    FieldWrite { stmt: DslFieldStmt, is_static: bool },
    IfNull {
        value: DslValue,
        invert: bool,
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
    ReturnOrig,
    ReturnValue {
        value: Option<DslValue>,
    },
}

struct DslCallStmt {
    kind: DslCallKind,
    target: Option<DslTarget>,
    class_name: String,
    method_name: String,
    sig: String,
    args: Vec<DslValue>,
}

#[derive(Clone, Copy)]
enum DslCallKind {
    Virtual,
    Interface,
    Static,
}

struct DslFieldStmt {
    target: Option<DslTarget>,
    class_name: String,
    field_name: String,
    type_name: String,
    value: Option<DslValue>,
}

enum DslValue {
    Target(DslTarget),
    String(String),
    Int(i16),
    Null,
    AddLit(Box<DslValue>, i8),
    SubLit(Box<DslValue>, i8),
    Call(DslCallStmt),
    FieldGet { stmt: Box<DslFieldStmt>, is_static: bool },
    Cast {
        value: Box<DslValue>,
        class_name: String,
    },
    ArrayLength(Box<DslValue>),
    ArrayGet {
        array: Box<DslValue>,
        index: Box<DslValue>,
        type_name: String,
    },
}

enum DslTarget {
    This,
    Arg(usize),
    Last,
    Result,
    Local(String),
}

fn parse_managed_dsl(dsl: &str) -> Result<DslProgram, String> {
    let mut parser = DslParser::new(dsl);
    let stmts = parser.parse_statements(false)?;
    parser.skip_ws();
    parser.expect_eof()?;
    Ok(DslProgram { stmts })
}

impl<'a> DslParser<'a> {
    fn parse_statements(&mut self, stop_on_brace: bool) -> Result<Vec<DslStmt>, String> {
        let mut stmts = Vec::new();
        loop {
            self.skip_ws();
            if self.is_eof() {
                if stop_on_brace {
                    return Err(self.err("expected '}'"));
                }
                break;
            }
            if stop_on_brace && self.peek() == Some('}') {
                self.expect_char('}')?;
                break;
            }
            let stmt = self.parse_statement()?;
            stmts.push(stmt);
        }
        Ok(stmts)
    }

    fn parse_block(&mut self) -> Result<Vec<DslStmt>, String> {
        self.skip_ws();
        self.expect_char('{')?;
        self.parse_statements(true)
    }

    fn parse_statement(&mut self) -> Result<DslStmt, String> {
        self.skip_ws();
        if self.peek_ident("return") {
            self.expect_ident("return")?;
            self.skip_ws();
            if self.peek_ident("orig") {
                self.expect_ident("orig")?;
                self.skip_ws();
                self.expect_char('(')?;
                self.skip_ws();
                self.expect_char(')')?;
                self.skip_ws();
                self.expect_char(';')?;
                return Ok(DslStmt::ReturnOrig);
            }
            let value = if self.peek() == Some(';') {
                None
            } else {
                Some(self.parse_value_arg()?)
            };
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::ReturnValue { value });
        }

        let name = self.parse_ident()?;
        self.skip_ws();
        self.expect_char('(')?;
        let stmt = match name.as_str() {
            "let" => {
                let local_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let value = self.parse_value_arg()?;
                self.expect_char(')')?;
                DslStmt::Let {
                    name: local_name,
                    type_name,
                    value,
                }
            }
            "ifNull" | "ifNotNull" => {
                let value = self.parse_value_arg()?;
                self.expect_char(')')?;
                let then_stmts = self.parse_block()?;
                self.skip_ws();
                let else_stmts = if self.peek_ident("else") {
                    self.expect_ident("else")?;
                    self.parse_block()?
                } else {
                    Vec::new()
                };
                return Ok(DslStmt::IfNull {
                    value,
                    invert: name == "ifNotNull",
                    then_stmts,
                    else_stmts,
                });
            }
            "ifEq" | "ifNe" | "ifLt" | "ifGe" | "ifGt" | "ifLe" => {
                let left = self.parse_value_arg()?;
                self.expect_char(',')?;
                let right = self.parse_value_arg()?;
                self.expect_char(')')?;
                let then_stmts = self.parse_block()?;
                self.skip_ws();
                let else_stmts = if self.peek_ident("else") {
                    self.expect_ident("else")?;
                    self.parse_block()?
                } else {
                    Vec::new()
                };
                let op = match name.as_str() {
                    "ifEq" => IfCmpOp::Eq,
                    "ifNe" => IfCmpOp::Ne,
                    "ifLt" => IfCmpOp::Lt,
                    "ifGe" => IfCmpOp::Ge,
                    "ifGt" => IfCmpOp::Gt,
                    "ifLe" => IfCmpOp::Le,
                    _ => unreachable!(),
                };
                return Ok(DslStmt::IfCmp {
                    op,
                    left,
                    right,
                    then_stmts,
                    else_stmts,
                });
            }
            "ifInstanceOf" => {
                let value = self.parse_value_arg()?;
                self.expect_char(',')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                let then_stmts = self.parse_block()?;
                self.skip_ws();
                let else_stmts = if self.peek_ident("else") {
                    self.expect_ident("else")?;
                    self.parse_block()?
                } else {
                    Vec::new()
                };
                return Ok(DslStmt::IfInstanceOf {
                    value,
                    class_name,
                    then_stmts,
                    else_stmts,
                });
            }
            "$new" | "new" => {
                self.skip_ws();
                let class_name = self.parse_string()?;
                self.skip_ws();
                let (ctor_sig, args) = if self.peek() == Some(',') {
                    self.expect_char(',')?;
                    let sig = self.parse_string_arg()?;
                    let args = self.parse_optional_value_args()?;
                    (Some(sig), args)
                } else {
                    (None, Vec::new())
                };
                self.expect_char(')')?;
                DslStmt::New {
                    class_name,
                    ctor_sig,
                    args,
                }
            }
            "newArray" => {
                let array_type_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let size = self.parse_value_arg()?;
                self.expect_char(')')?;
                DslStmt::NewArray {
                    array_type_name,
                    size,
                }
            }
            "newLoop" => {
                self.skip_ws();
                let class_name = self.parse_string()?;
                self.skip_ws();
                self.expect_char(',')?;
                self.skip_ws();
                let iterations = self.parse_u16()?;
                self.skip_ws();
                self.expect_char(')')?;
                DslStmt::NewLoop {
                    class_name,
                    iterations,
                }
            }
            "call" | "callVirtual" | "callInterface" => {
                let kind = if name == "callInterface" {
                    DslCallKind::Interface
                } else {
                    DslCallKind::Virtual
                };
                let target = self.parse_target_arg()?;
                self.skip_ws();
                self.expect_char(',')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let method_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let sig = self.parse_string_arg()?;
                let args = self.parse_optional_value_args()?;
                self.expect_char(')')?;
                DslStmt::Call(DslCallStmt {
                    kind,
                    target: Some(target),
                    class_name,
                    method_name,
                    sig,
                    args,
                })
            }
            "callStatic" => {
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let method_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let sig = self.parse_string_arg()?;
                let args = self.parse_optional_value_args()?;
                self.expect_char(')')?;
                DslStmt::Call(DslCallStmt {
                    kind: DslCallKind::Static,
                    target: None,
                    class_name,
                    method_name,
                    sig,
                    args,
                })
            }
            "cast" => {
                let value = self.parse_value_arg()?;
                self.expect_char(',')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                DslStmt::Cast { value, class_name }
            }
            "arrayLength" => {
                let array = self.parse_value_arg()?;
                self.expect_char(')')?;
                DslStmt::ArrayLength { array }
            }
            "aget" => {
                let array = self.parse_value_arg()?;
                self.expect_char(',')?;
                let index = self.parse_value_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                DslStmt::ArrayGet {
                    array,
                    index,
                    type_name,
                }
            }
            "aput" => {
                let array = self.parse_value_arg()?;
                self.expect_char(',')?;
                let index = self.parse_value_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let value = self.parse_value_arg()?;
                self.expect_char(')')?;
                DslStmt::ArrayPut {
                    array,
                    index,
                    type_name,
                    value,
                }
            }
            "get" => {
                let target = self.parse_target_arg()?;
                self.skip_ws();
                self.expect_char(',')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let field_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                DslStmt::FieldRead {
                    stmt: DslFieldStmt {
                        target: Some(target),
                        class_name,
                        field_name,
                        type_name,
                        value: None,
                    },
                    is_static: false,
                }
            }
            "set" => {
                let target = self.parse_target_arg()?;
                self.skip_ws();
                self.expect_char(',')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let field_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let value = self.parse_value_arg()?;
                self.expect_char(')')?;
                DslStmt::FieldWrite {
                    stmt: DslFieldStmt {
                        target: Some(target),
                        class_name,
                        field_name,
                        type_name,
                        value: Some(value),
                    },
                    is_static: false,
                }
            }
            "getStatic" => {
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let field_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                DslStmt::FieldRead {
                    stmt: DslFieldStmt {
                        target: None,
                        class_name,
                        field_name,
                        type_name,
                        value: None,
                    },
                    is_static: true,
                }
            }
            "setStatic" => {
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let field_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let value = self.parse_value_arg()?;
                self.expect_char(')')?;
                DslStmt::FieldWrite {
                    stmt: DslFieldStmt {
                        target: None,
                        class_name,
                        field_name,
                        type_name,
                        value: Some(value),
                    },
                    is_static: true,
                }
            }
            other => return Err(self.err(&format!("unknown managed DSL statement '{}'", other))),
        };
        self.skip_ws();
        self.expect_char(';')?;
        Ok(stmt)
    }
}

struct DslParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> DslParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn skip_ws(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_whitespace() {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
    }

    fn expect_ident(&mut self, expected: &str) -> Result<(), String> {
        if !self.input[self.pos..].starts_with(expected) {
            return Err(self.err(&format!("expected identifier {}", expected)));
        }
        let end = self.pos + expected.len();
        if self
            .input
            .get(end..)
            .and_then(|s| s.chars().next())
            .map(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            .unwrap_or(false)
        {
            return Err(self.err(&format!("expected identifier {}", expected)));
        }
        self.pos = end;
        Ok(())
    }

    fn peek_ident(&self, expected: &str) -> bool {
        if !self.input[self.pos..].starts_with(expected) {
            return false;
        }
        let end = self.pos + expected.len();
        !self
            .input
            .get(end..)
            .and_then(|s| s.chars().next())
            .map(is_ident_continue)
            .unwrap_or(false)
    }

    fn parse_ident(&mut self) -> Result<String, String> {
        let start = self.pos;
        let Some(first) = self.peek() else {
            return Err(self.err("expected identifier"));
        };
        if !is_ident_start(first) {
            return Err(self.err("expected identifier"));
        }
        self.pos += first.len_utf8();
        while let Some(ch) = self.peek() {
            if is_ident_continue(ch) {
                self.pos += ch.len_utf8();
            } else {
                break;
            }
        }
        Ok(self.input[start..self.pos].to_string())
    }

    fn expect_char(&mut self, expected: char) -> Result<(), String> {
        match self.peek() {
            Some(ch) if ch == expected => {
                self.pos += ch.len_utf8();
                Ok(())
            }
            _ => Err(self.err(&format!("expected '{}'", expected))),
        }
    }

    fn parse_string_arg(&mut self) -> Result<String, String> {
        self.skip_ws();
        let value = self.parse_string()?;
        self.skip_ws();
        Ok(value)
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_char('"')?;
        let mut out = String::new();
        loop {
            let Some(ch) = self.peek() else {
                return Err(self.err("unterminated string"));
            };
            self.pos += ch.len_utf8();
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err(self.err("unterminated string escape"));
                    };
                    self.pos += escaped.len_utf8();
                    match escaped {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        other => return Err(self.err(&format!("unsupported string escape \\{}", other))),
                    }
                }
                other => out.push(other),
            }
        }
    }

    fn parse_u16(&mut self) -> Result<u16, String> {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(self.err("expected integer"));
        }
        let value: u32 = self.input[start..self.pos]
            .parse()
            .map_err(|_| self.err("invalid integer"))?;
        if value == 0 || value > i16::MAX as u32 {
            return Err(self.err("integer must be 1..32767"));
        }
        Ok(value as u16)
    }

    fn parse_i16(&mut self) -> Result<i16, String> {
        self.skip_ws();
        let negative = if self.peek() == Some('-') {
            self.pos += 1;
            true
        } else {
            false
        };
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if self.pos == start {
            return Err(self.err("expected integer"));
        }
        let value: i32 = self.input[start..self.pos]
            .parse()
            .map_err(|_| self.err("invalid integer"))?;
        let signed = if negative { -value } else { value };
        if signed < i16::MIN as i32 || signed > i16::MAX as i32 {
            return Err(self.err("integer must fit int16"));
        }
        self.skip_ws();
        Ok(signed as i16)
    }

    fn parse_i8(&mut self) -> Result<i8, String> {
        let value = self.parse_i16()?;
        if value < i8::MIN as i16 || value > i8::MAX as i16 {
            return Err(self.err("integer must fit int8"));
        }
        Ok(value as i8)
    }

    fn parse_target_arg(&mut self) -> Result<DslTarget, String> {
        self.skip_ws();
        let name = if self.peek() == Some('"') {
            self.parse_string()?
        } else {
            self.parse_ident()?
        };
        self.skip_ws();
        parse_target_name(&name).ok_or_else(|| self.err(&format!("unknown target '{}'", name)))
    }

    fn parse_value_arg(&mut self) -> Result<DslValue, String> {
        self.skip_ws();
        let value = if self.peek() == Some('"') {
            DslValue::String(self.parse_string()?)
        } else if self.peek() == Some('-') || self.peek().map(|ch| ch.is_ascii_digit()).unwrap_or(false) {
            DslValue::Int(self.parse_i16()?)
        } else {
            let ident = self.parse_ident()?;
            if ident == "null" {
                DslValue::Null
            } else if ident == "add" || ident == "sub" {
                self.skip_ws();
                self.expect_char('(')?;
                let base = self.parse_value_arg()?;
                self.expect_char(',')?;
                let literal = self.parse_i8()?;
                self.expect_char(')')?;
                if ident == "add" {
                    DslValue::AddLit(Box::new(base), literal)
                } else {
                    DslValue::SubLit(Box::new(base), literal)
                }
            } else if ident == "call" || ident == "callVirtual" || ident == "callInterface" {
                self.skip_ws();
                self.expect_char('(')?;
                let kind = if ident == "callInterface" {
                    DslCallKind::Interface
                } else {
                    DslCallKind::Virtual
                };
                let target = self.parse_target_arg()?;
                self.skip_ws();
                self.expect_char(',')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let method_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let sig = self.parse_string_arg()?;
                let args = self.parse_optional_value_args()?;
                self.expect_char(')')?;
                DslValue::Call(DslCallStmt {
                    kind,
                    target: Some(target),
                    class_name,
                    method_name,
                    sig,
                    args,
                })
            } else if ident == "callStatic" {
                self.skip_ws();
                self.expect_char('(')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let method_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let sig = self.parse_string_arg()?;
                let args = self.parse_optional_value_args()?;
                self.expect_char(')')?;
                DslValue::Call(DslCallStmt {
                    kind: DslCallKind::Static,
                    target: None,
                    class_name,
                    method_name,
                    sig,
                    args,
                })
            } else if ident == "get" {
                self.skip_ws();
                self.expect_char('(')?;
                let target = self.parse_target_arg()?;
                self.expect_char(',')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let field_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: Some(target),
                        class_name,
                        field_name,
                        type_name,
                        value: None,
                    }),
                    is_static: false,
                }
            } else if ident == "getStatic" {
                self.skip_ws();
                self.expect_char('(')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let field_name = self.parse_string_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                DslValue::FieldGet {
                    stmt: Box::new(DslFieldStmt {
                        target: None,
                        class_name,
                        field_name,
                        type_name,
                        value: None,
                    }),
                    is_static: true,
                }
            } else if ident == "cast" {
                self.skip_ws();
                self.expect_char('(')?;
                let value = self.parse_value_arg()?;
                self.expect_char(',')?;
                let class_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                DslValue::Cast {
                    value: Box::new(value),
                    class_name,
                }
            } else if ident == "arrayLength" {
                self.skip_ws();
                self.expect_char('(')?;
                let array = self.parse_value_arg()?;
                self.expect_char(')')?;
                DslValue::ArrayLength(Box::new(array))
            } else if ident == "aget" {
                self.skip_ws();
                self.expect_char('(')?;
                let array = self.parse_value_arg()?;
                self.expect_char(',')?;
                let index = self.parse_value_arg()?;
                self.expect_char(',')?;
                let type_name = self.parse_string_arg()?;
                self.expect_char(')')?;
                DslValue::ArrayGet {
                    array: Box::new(array),
                    index: Box::new(index),
                    type_name,
                }
            } else {
                let target = parse_target_name(&ident);
                let target = target.unwrap_or_else(|| DslTarget::Local(ident));
                DslValue::Target(target)
            }
        };
        self.skip_ws();
        Ok(value)
    }

    fn parse_optional_value_args(&mut self) -> Result<Vec<DslValue>, String> {
        let mut args = Vec::new();
        loop {
            self.skip_ws();
            if self.peek() != Some(',') {
                break;
            }
            self.expect_char(',')?;
            args.push(self.parse_value_arg()?);
        }
        Ok(args)
    }

    fn expect_eof(&self) -> Result<(), String> {
        if self.pos == self.input.len() {
            Ok(())
        } else {
            Err(self.err("unexpected trailing input"))
        }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn is_eof(&self) -> bool {
        self.pos == self.input.len()
    }

    fn err(&self, msg: &str) -> String {
        format!("managed dex DSL parse error at byte {}: {}", self.pos, msg)
    }
}

fn is_ident_start(ch: char) -> bool {
    ch == '$' || ch == '_' || ch.is_ascii_alphabetic()
}

fn is_ident_continue(ch: char) -> bool {
    ch == '$' || ch == '_' || ch.is_ascii_alphanumeric()
}

fn parse_target_name(name: &str) -> Option<DslTarget> {
    match name {
        "this" | "$this" => Some(DslTarget::This),
        "last" | "$last" => Some(DslTarget::Last),
        "result" | "$result" => Some(DslTarget::Result),
        value if value.starts_with("arg") => value[3..].parse::<usize>().ok().map(DslTarget::Arg),
        value if value.starts_with('$') => value[1..].parse::<usize>().ok().map(DslTarget::Arg),
        value if value.starts_with('p') => value[1..].parse::<usize>().ok().map(DslTarget::Arg),
        value if is_local_ident(value) => Some(DslTarget::Local(value.to_string())),
        _ => None,
    }
}

fn is_local_ident(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first == '$' {
        return false;
    }
    first == '_' || first.is_ascii_alphabetic()
}

fn write_class_data_item(
    out: &mut Vec<u8>,
    class: &DexClass,
    field_idx: &BTreeMap<FieldRef, u32>,
    method_idx: &BTreeMap<MethodRef, u32>,
    code_patch_offsets: &mut Vec<(usize, DexCode)>,
) -> Result<(), String> {
    write_uleb128(out, class.static_fields.len() as u32);
    write_uleb128(out, class.instance_fields.len() as u32);
    write_uleb128(out, class.direct_methods.len() as u32);
    write_uleb128(out, class.virtual_methods.len() as u32);

    write_encoded_fields(out, &class.static_fields, field_idx)?;
    write_encoded_fields(out, &class.instance_fields, field_idx)?;
    write_encoded_methods(out, &class.direct_methods, method_idx, code_patch_offsets)?;
    write_encoded_methods(out, &class.virtual_methods, method_idx, code_patch_offsets)?;
    Ok(())
}

fn write_encoded_fields(
    out: &mut Vec<u8>,
    fields: &[ClassField],
    field_idx: &BTreeMap<FieldRef, u32>,
) -> Result<(), String> {
    let mut entries = fields
        .iter()
        .map(|f| {
            let idx = *field_idx
                .get(&f.field)
                .ok_or_else(|| format!("missing field index for {}", f.field.name))?;
            Ok((idx, f.access_flags))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(idx, _)| *idx);

    let mut prev = 0u32;
    for (idx, access) in entries {
        write_uleb128(out, idx - prev);
        write_uleb128(out, access);
        prev = idx;
    }
    Ok(())
}

fn write_encoded_methods(
    out: &mut Vec<u8>,
    methods: &[ClassMethod],
    method_idx: &BTreeMap<MethodRef, u32>,
    code_patch_offsets: &mut Vec<(usize, DexCode)>,
) -> Result<(), String> {
    let mut entries = methods
        .iter()
        .map(|m| {
            let idx = *method_idx
                .get(&m.method)
                .ok_or_else(|| format!("missing method index for {}", m.method.name))?;
            Ok((idx, m.access_flags, m.code.clone()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_by_key(|(idx, _, _)| *idx);

    let mut prev = 0u32;
    for (idx, access, code) in entries {
        write_uleb128(out, idx - prev);
        write_uleb128(out, access);
        if let Some(code) = code {
            let patch_pos = out.len();
            out.extend_from_slice(&[0, 0, 0, 0, 0]);
            code_patch_offsets.push((patch_pos, code));
        } else {
            write_uleb128(out, 0);
        }
        prev = idx;
    }
    Ok(())
}

fn write_code_item(
    out: &mut Vec<u8>,
    code: &DexCode,
    string_idx: &BTreeMap<String, u32>,
    type_idx: &BTreeMap<String, u32>,
    field_idx: &BTreeMap<FieldRef, u32>,
    method_idx: &BTreeMap<MethodRef, u32>,
) -> Result<(), String> {
    write_u16(out, code.registers_size);
    write_u16(out, code.ins_size);
    write_u16(out, code.outs_size);
    write_u16(out, 0);
    write_u32(out, 0);
    write_u32(out, code.insns.len() as u32);
    for word in &code.insns {
        match word {
            CodeWord::Raw(value) => write_u16(out, *value),
            CodeWord::String(value) => write_u16(out, lookup_u16(string_idx, value, "string")?),
            CodeWord::Type(ty) => write_u16(out, lookup_u16(type_idx, ty, "type")?),
            CodeWord::Field(field) => write_u16(out, lookup_u16(field_idx, field, "field")?),
            CodeWord::Method(method) => write_u16(out, lookup_u16(method_idx, method, "method")?),
        }
    }
    Ok(())
}

fn lookup_u16<K: Ord + std::fmt::Debug>(
    map: &BTreeMap<K, u32>,
    key: &K,
    kind: &str,
) -> Result<u16, String> {
    let value = *map
        .get(key)
        .ok_or_else(|| format!("missing {} index for {:?}", kind, key))?;
    if value > u16::MAX as u32 {
        return Err(format!("{} index too large: {}", kind, value));
    }
    Ok(value as u16)
}

fn shorty_char(descriptor: &str) -> char {
    match descriptor.as_bytes().first().copied() {
        Some(b'V') => 'V',
        Some(b'Z') => 'Z',
        Some(b'B') => 'B',
        Some(b'S') => 'S',
        Some(b'C') => 'C',
        Some(b'I') => 'I',
        Some(b'J') => 'J',
        Some(b'F') => 'F',
        Some(b'D') => 'D',
        _ => 'L',
    }
}

fn write_map_list(out: &mut Vec<u8>, entries: &[(u16, u32, u32)]) {
    let mut filtered: Vec<(u16, u32, u32)> = entries
        .iter()
        .copied()
        .filter(|(_, size, off)| *size != 0 || *off == 0)
        .collect();
    filtered.sort_by_key(|(_, _, off)| *off);
    write_u32(out, filtered.len() as u32);
    for (ty, size, off) in filtered {
        write_u16(out, ty);
        write_u16(out, 0);
        write_u32(out, size);
        write_u32(out, off);
    }
}

fn uleb128_padded5(mut value: u32) -> [u8; 5] {
    let mut out = [0u8; 5];
    let mut i = 0;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out[i] = byte;
        i += 1;
        if value == 0 {
            break;
        }
    }
    out
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn align_vec4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u16_at(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for byte in bytes {
        a = (a + *byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

fn sha1_digest(bytes: &[u8]) -> [u8; 20] {
    let mut h0 = 0x6745_2301u32;
    let mut h1 = 0xefcd_ab89u32;
    let mut h2 = 0x98ba_dcfeu32;
    let mut h3 = 0x1032_5476u32;
    let mut h4 = 0xc3d2_e1f0u32;

    let bit_len = (bytes.len() as u64) * 8;
    let mut msg = bytes.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            let off = i * 4;
            w[i] = u32::from_be_bytes([
                chunk[off],
                chunk[off + 1],
                chunk[off + 2],
                chunk[off + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}
