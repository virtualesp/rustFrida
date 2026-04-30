use super::*;
use std::collections::BTreeMap;
use token_stream::DslTokenStream;

const V2_INT_BINARY_TOKEN_OPS: &[(&str, DslIntBinOp, u8)] = &[
    (">>>", DslIntBinOp::Ushr, 5),
    ("<<", DslIntBinOp::Shl, 5),
    (">>", DslIntBinOp::Shr, 5),
];

const V2_INT_BINARY_CHAR_OPS: &[(char, DslIntBinOp, u8)] = &[
    ('|', DslIntBinOp::Or, 1),
    ('^', DslIntBinOp::Xor, 2),
    ('&', DslIntBinOp::And, 3),
    ('+', DslIntBinOp::Add, 6),
    ('-', DslIntBinOp::Sub, 6),
    ('*', DslIntBinOp::Mul, 7),
    ('/', DslIntBinOp::Div, 7),
    ('%', DslIntBinOp::Rem, 7),
];

impl<'a> DslParser<'a> {
    pub(super) fn parse_expr_v2(&mut self) -> Result<DslValue, String> {
        let start = self.pos;
        let mut stream = DslTokenStream::new(self.input, &self.tokens, self.pos);
        if !can_start_v2_expr(&stream) {
            return Err(stream.err("expected expression"));
        }
        let value = match parse_v2_value_expr(&mut stream, &self.local_scopes) {
            Ok(value) => value,
            Err(err) => {
                self.pos = start;
                return Err(err);
            }
        };
        if has_v2_unsupported_trailing_token(&stream) {
            self.pos = start;
            return Err(stream.err("unsupported expression tail"));
        }
        self.pos = stream.pos();
        Ok(value)
    }

    pub(super) fn parse_condition_v2(&mut self) -> Result<DslCondition, String> {
        let start = self.pos;
        let mut stream = DslTokenStream::new(self.input, &self.tokens, self.pos);
        let condition = match parse_v2_condition_expr(&mut stream, &self.local_scopes) {
            Ok(condition) => condition,
            Err(err) => {
                self.pos = start;
                return Err(err);
            }
        };
        self.pos = stream.pos();
        Ok(condition)
    }
}

fn parse_v2_value_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    let mark = stream.mark();
    if let Ok(condition) = parse_v2_or_condition(stream, local_scopes) {
        if stream.consume_char('?') {
            let then_value = parse_v2_value_expr(stream, local_scopes)?;
            if !stream.consume_char(':') {
                return Err(stream.err("expected ':'"));
            }
            let else_value = parse_v2_value_expr(stream, local_scopes)?;
            return Ok(fold_ternary(condition, then_value, else_value));
        }
    }
    stream.restore(mark);
    parse_v2_int_binary_expr(stream, local_scopes, 0)
}

fn parse_v2_condition_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslCondition, String> {
    let condition = parse_v2_or_condition(stream, local_scopes)?;
    if stream.consume_char('?') {
        let then_condition = parse_v2_condition_expr(stream, local_scopes)?;
        if !stream.consume_char(':') {
            return Err(stream.err("expected ':'"));
        }
        let else_condition = parse_v2_condition_expr(stream, local_scopes)?;
        return Ok(fold_ternary_condition(condition, then_condition, else_condition));
    }
    Ok(condition)
}

fn parse_v2_or_condition(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslCondition, String> {
    let mut condition = parse_v2_and_condition(stream, local_scopes)?;
    while stream.consume_op("||") {
        let right = parse_v2_and_condition(stream, local_scopes)?;
        condition = condition_or(condition, right);
    }
    Ok(condition)
}

fn parse_v2_and_condition(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslCondition, String> {
    let mut condition = parse_v2_unary_condition(stream, local_scopes)?;
    while stream.consume_op("&&") {
        let right = parse_v2_unary_condition(stream, local_scopes)?;
        condition = condition_and(condition, right);
    }
    Ok(condition)
}

fn parse_v2_unary_condition(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslCondition, String> {
    if stream.consume_char('!') {
        return Ok(condition_not(parse_v2_unary_condition(stream, local_scopes)?));
    }

    if stream.peek_char('(') {
        let mark = stream.mark();
        stream.consume_char('(');
        if let Ok(condition) = parse_v2_condition_expr(stream, local_scopes) {
            if stream.consume_char(')') && !peek_v2_cmp_op(stream) {
                return Ok(condition);
            }
        }
        stream.restore(mark);
    }

    parse_v2_condition_leaf(stream, local_scopes)
}

fn parse_v2_condition_leaf(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslCondition, String> {
    let left = parse_v2_int_binary_expr(stream, local_scopes, 0)?;
    if stream.consume_ident("instanceof") {
        let class_name = parse_type_name_v2(stream)?;
        return Ok(DslCondition::InstanceOf {
            value: left,
            class_name,
        });
    }
    if !peek_v2_cmp_op(stream) {
        if let DslValue::Bool(value) = left {
            return Ok(DslCondition::Const(value));
        }
        return Ok(DslCondition::Bool { value: left });
    }
    let op = parse_v2_cmp_op(stream)?;
    let right = parse_v2_int_binary_expr(stream, local_scopes, 0)?;
    let left_is_null = matches!(left, DslValue::Null);
    let right_is_null = matches!(right, DslValue::Null);
    if right_is_null {
        return match op {
            IfCmpOp::Eq => Ok(DslCondition::Null {
                value: left,
                invert: false,
            }),
            IfCmpOp::Ne => Ok(DslCondition::Null {
                value: left,
                invert: true,
            }),
            _ => Err(stream.err("null condition only supports == and !=")),
        };
    }
    if left_is_null {
        return match op {
            IfCmpOp::Eq => Ok(DslCondition::Null {
                value: right,
                invert: false,
            }),
            IfCmpOp::Ne => Ok(DslCondition::Null {
                value: right,
                invert: true,
            }),
            _ => Err(stream.err("null condition only supports == and !=")),
        };
    }
    Ok(DslCondition::Cmp { op, left, right })
}

fn parse_v2_int_binary_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
    min_prec: u8,
) -> Result<DslValue, String> {
    let mut left = parse_v2_unary_expr(stream, local_scopes)?;
    loop {
        let Some((op, prec)) = peek_v2_int_binary_op(stream) else {
            break;
        };
        if prec < min_prec {
            break;
        }
        consume_v2_int_binary_op(stream, op)?;
        let right = parse_v2_int_binary_expr(stream, local_scopes, prec + 1)?;
        left = fold_int_binop(op, left, right);
    }
    Ok(left)
}

fn parse_v2_unary_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    if stream.consume_char('-') {
        if matches!(stream.current_kind(), Some(DslTokenKind::Number(_))) {
            return Ok(DslValue::Int(stream.parse_i16_after_sign(true)?));
        }
        let value = parse_v2_unary_expr(stream, local_scopes)?;
        return Ok(fold_unary_op(DslUnaryOp::Neg, value));
    }
    if stream.consume_char('~') {
        let value = parse_v2_unary_expr(stream, local_scopes)?;
        return Ok(fold_unary_op(DslUnaryOp::BitNot, value));
    }
    if stream.consume_char('!') {
        let value = parse_v2_unary_expr(stream, local_scopes)?;
        return Ok(fold_unary_op(DslUnaryOp::BoolNot, value));
    }
    parse_v2_postfix_expr(stream, local_scopes)
}

fn parse_v2_postfix_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    let mut value = parse_v2_primary_expr(stream, local_scopes)?;
    loop {
        if stream.consume_ident("as") {
            let class_name = parse_type_name_v2(stream)?;
            value = DslValue::Cast {
                value: Box::new(value),
                class_name,
            };
        } else if stream.consume_char('[') {
            let index = parse_v2_value_expr(stream, local_scopes)?;
            let type_name = if stream.consume_char(':') {
                Some(parse_type_name_v2(stream)?)
            } else {
                None
            };
            if !stream.consume_char(']') {
                return Err(stream.err("expected ']'"));
            }
            value = DslValue::ArrayGet {
                array: Box::new(value),
                index: Box::new(index),
                type_name,
            };
        } else if stream.peek_op("?.") || stream.peek_char('.') {
            value = parse_v2_member_postfix(stream, local_scopes, value)?;
        } else {
            return Ok(value);
        }
    }
}

fn parse_v2_primary_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    match stream.current_kind() {
        Some(DslTokenKind::Number(_)) => Ok(DslValue::Int(stream.parse_i16_after_sign(false)?)),
        Some(DslTokenKind::Ident(value)) if value == "true" => {
            stream.advance();
            Ok(DslValue::Bool(true))
        }
        Some(DslTokenKind::Ident(value)) if value == "false" => {
            stream.advance();
            Ok(DslValue::Bool(false))
        }
        Some(DslTokenKind::Ident(value)) if value == "null" => {
            stream.advance();
            Ok(DslValue::Null)
        }
        Some(DslTokenKind::Ident(value)) if value == "new" => parse_v2_new_expr(stream, local_scopes),
        Some(DslTokenKind::Ident(value)) if value == "orig" => {
            stream.advance();
            if stream.peek_char('(') {
                Ok(DslValue::OrigCall(parse_orig_args_v2(stream, local_scopes)?))
            } else {
                Ok(DslValue::Target(DslTarget::Local("orig".to_string())))
            }
        }
        Some(DslTokenKind::Ident(value)) if value == "dbbCapacity" => {
            stream.advance();
            if !stream.consume_char('(') {
                return Err(stream.err("expected '(' after dbbCapacity"));
            }
            let buffer = parse_v2_value_expr(stream, local_scopes)?;
            if !stream.consume_char(')') {
                return Err(stream.err("expected ')'"));
            }
            Ok(DslValue::DirectBufferCapacity {
                buffer: Box::new(buffer),
            })
        }
        Some(DslTokenKind::Ident(value)) if value == "dbbGetU8" => {
            stream.advance();
            if !stream.consume_char('(') {
                return Err(stream.err("expected '(' after dbbGetU8"));
            }
            let buffer = parse_v2_value_expr(stream, local_scopes)?;
            if !stream.consume_char(',') {
                return Err(stream.err("expected ','"));
            }
            let offset = parse_v2_value_expr(stream, local_scopes)?;
            if !stream.consume_char(')') {
                return Err(stream.err("expected ')'"));
            }
            Ok(DslValue::DirectBufferGetU8 {
                buffer: Box::new(buffer),
                offset: Box::new(offset),
            })
        }
        Some(DslTokenKind::Ident(_)) => {
            if let Some(value) = try_parse_v2_static_member_primary(stream, local_scopes)? {
                return Ok(value);
            }
            let value = stream.parse_ident()?;
            Ok(DslValue::Target(
                scoped_target_name_v2(local_scopes, &value).unwrap_or(DslTarget::Local(value)),
            ))
        }
        Some(DslTokenKind::String(value)) => {
            let value = value.clone();
            stream.advance();
            Ok(DslValue::String(value))
        }
        Some(DslTokenKind::Symbol('(')) => {
            stream.advance();
            let value = parse_v2_value_expr(stream, local_scopes)?;
            if !stream.consume_char(')') {
                return Err(stream.err("expected ')'"));
            }
            Ok(value)
        }
        Some(DslTokenKind::Symbol('[')) => parse_v2_array_literal(stream, local_scopes),
        _ => Err(stream.err("expected expression")),
    }
}

fn parse_v2_new_expr(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    if !stream.consume_ident("new") {
        return Err(stream.err("expected new expression"));
    }
    let class_name = parse_new_type_name_v2(stream)?;
    if stream.consume_char('[') {
        if stream.consume_char(']') {
            return Err(stream.err("new array requires size in the first dimension"));
        }
        let size = parse_v2_value_expr(stream, local_scopes)?;
        if !stream.consume_char(']') {
            return Err(stream.err("expected ']'"));
        }
        let mut array_type_name = format!("{class_name}[]");
        while stream.consume_char('[') {
            if !stream.consume_char(']') {
                return Err(stream.err("only the first new array dimension can specify size"));
            }
            array_type_name.push_str("[]");
        }
        return Ok(DslValue::NewArray {
            array_type_name,
            size: Box::new(size),
        });
    }
    if !stream.consume_char('(') {
        return Err(stream.err("expected '('"));
    }
    if class_name.ends_with("[]") {
        let size = parse_v2_value_expr(stream, local_scopes)?;
        if !stream.consume_char(')') {
            return Err(stream.err("expected ')'"));
        }
        return Ok(DslValue::NewArray {
            array_type_name: class_name,
            size: Box::new(size),
        });
    }
    let (ctor_sig, args) = parse_v2_new_constructor_args(stream, local_scopes)?;
    if !stream.consume_char(')') {
        return Err(stream.err("expected ')'"));
    }
    Ok(DslValue::NewObject {
        class_name,
        ctor_sig,
        args,
    })
}

fn parse_new_type_name_v2(stream: &mut DslTokenStream<'_>) -> Result<String, String> {
    if matches!(stream.current_kind(), Some(DslTokenKind::String(_))) {
        return stream.parse_string();
    }
    let mut name = stream.parse_ident()?;
    while stream.consume_char('.') {
        let part = stream.parse_ident()?;
        name.push('.');
        name.push_str(&part);
    }
    Ok(name)
}

fn try_parse_v2_static_member_primary(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<Option<DslValue>, String> {
    let mark = stream.mark();
    let mut parts = vec![stream.parse_ident()?];
    if !stream.consume_char('.') {
        stream.restore(mark);
        return Ok(None);
    }
    loop {
        parts.push(stream.parse_ident()?);
        if !stream.consume_char('.') {
            break;
        }
    }
    if parts.len() < 2
        || !parts[..parts.len() - 1]
            .iter()
            .any(|part| looks_like_static_class_name(part))
    {
        stream.restore(mark);
        return Ok(None);
    }
    if parts.last().map(|part| part.as_str()) == Some("$new") {
        let class_parts = &parts[..parts.len() - 1];
        if !class_parts.iter().any(|part| looks_like_static_class_name(part)) {
            stream.restore(mark);
            return Ok(None);
        }
        if !stream.consume_char('(') {
            return Err(stream.err("expected '('"));
        }
        let (ctor_sig, args) = parse_v2_new_constructor_args(stream, local_scopes)?;
        if !stream.consume_char(')') {
            return Err(stream.err("expected ')'"));
        }
        return Ok(Some(DslValue::NewObject {
            class_name: class_parts.join("."),
            ctor_sig,
            args,
        }));
    }
    if parts.last().map(|part| part.as_str()) == Some("overload") && parts.len() >= 3 {
        let method_name = parts[parts.len() - 2].clone();
        let class_parts = &parts[..parts.len() - 2];
        if !class_parts.iter().any(|part| looks_like_static_class_name(part)) {
            stream.restore(mark);
            return Ok(None);
        }
        let overload_args = parse_v2_overload_selector_args(stream)?;
        let args = parse_v2_overload_call_args(stream, local_scopes)?;
        let sig = resolve_v2_static_overload_sig(stream, &overload_args)?;
        return Ok(Some(DslValue::Call(DslCallStmt {
            kind: DslCallKind::Static,
            target: None,
            receiver: None,
            null_safe: false,
            class_name: Some(class_parts.join(".")),
            method_name,
            sig,
            args,
        })));
    }
    let member_name = parts.pop().unwrap();
    let class_name = parts.join(".");
    if stream.consume_char(':') {
        let type_name = parse_type_name_v2(stream)?;
        return Ok(Some(DslValue::FieldGet {
            stmt: Box::new(DslFieldStmt {
                target: None,
                receiver: None,
                class_name: Some(class_name),
                field_name: member_name,
                type_name,
                value: None,
            }),
            is_static: true,
        }));
    }
    if stream.consume_char('(') {
        let parsed_args = parse_v2_member_call_args(stream, local_scopes, false)?;
        return Ok(Some(build_v2_static_member_value(class_name, member_name, parsed_args)));
    }
    Ok(Some(DslValue::FieldGet {
        stmt: Box::new(DslFieldStmt {
            target: None,
            receiver: None,
            class_name: Some(class_name),
            field_name: member_name,
            type_name: String::new(),
            value: None,
        }),
        is_static: true,
    }))
}

fn parse_orig_args_v2(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslOrigArgs, String> {
    if !stream.consume_char('(') {
        return Err(stream.err("expected '('"));
    }
    if stream.consume_char(')') {
        return Ok(DslOrigArgs::Original);
    }
    let args = parse_v2_value_arg_list_until_close(stream, local_scopes)?;
    if !stream.consume_char(')') {
        return Err(stream.err("expected ')'"));
    }
    Ok(DslOrigArgs::Values(args))
}

fn parse_v2_new_constructor_args(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<(Option<String>, Vec<DslValue>), String> {
    enum NewArgToken {
        String(String),
        Value(DslValue),
    }

    fn token_to_value(token: NewArgToken) -> DslValue {
        match token {
            NewArgToken::String(value) => DslValue::String(value),
            NewArgToken::Value(value) => value,
        }
    }

    if stream.peek_char(')') {
        return Ok((None, Vec::new()));
    }

    let mut tokens = Vec::new();
    loop {
        let token = if matches!(stream.current_kind(), Some(DslTokenKind::String(_))) {
            NewArgToken::String(stream.parse_string()?)
        } else {
            NewArgToken::Value(parse_v2_value_expr(stream, local_scopes)?)
        };
        tokens.push(token);
        if !stream.consume_char(',') {
            break;
        }
    }

    if let Some(NewArgToken::String(first)) = tokens.first() {
        if first.starts_with('(') {
            let sig = first.clone();
            let args = tokens.into_iter().skip(1).map(token_to_value).collect::<Vec<_>>();
            return Ok((Some(sig), args));
        }
    }

    Ok((None, tokens.into_iter().map(token_to_value).collect()))
}

fn parse_v2_array_literal(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<DslValue, String> {
    if !stream.consume_char('[') {
        return Err(stream.err("expected '['"));
    }
    let mut elements = Vec::new();
    loop {
        if stream.consume_char(']') {
            return Ok(DslValue::ArrayLiteral { elements });
        }
        elements.push(parse_v2_value_expr(stream, local_scopes)?);
        if stream.consume_char(',') {
            if stream.consume_char(']') {
                return Ok(DslValue::ArrayLiteral { elements });
            }
            continue;
        }
        if stream.consume_char(']') {
            return Ok(DslValue::ArrayLiteral { elements });
        }
        return Err(stream.err("array literal expects ',' or ']'"));
    }
}

fn parse_v2_value_arg_list_until_close(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<Vec<DslValue>, String> {
    let mut args = Vec::new();
    loop {
        if stream.peek_char(')') {
            return Ok(args);
        }
        args.push(parse_v2_value_expr(stream, local_scopes)?);
        if !stream.consume_char(',') {
            return Ok(args);
        }
    }
}

fn parse_v2_member_postfix(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
    receiver: DslValue,
) -> Result<DslValue, String> {
    let null_safe = if stream.consume_op("?.") {
        true
    } else if stream.consume_char('.') {
        false
    } else {
        return Err(stream.err("expected member access"));
    };
    let member_name = stream.parse_ident()?;
    if member_name == "length" && !stream.peek_char('(') && !stream.peek_char('.') {
        return Ok(DslValue::ArrayLength(Box::new(receiver)));
    }
    if member_name == "$new" {
        return Err(stream.err("$new is only supported on class names"));
    }

    let mut call_kind = DslCallKind::Virtual;
    let mut wants_overload = false;
    let selector_mark = stream.mark();
    if stream.consume_char('.') {
        if stream.consume_ident("interface") {
            call_kind = DslCallKind::Interface;
            if stream.consume_char('.') {
                if !stream.consume_ident("overload") {
                    return Err(stream.err("expected overload after interface member access"));
                }
                wants_overload = true;
            }
        } else if stream.consume_ident("overload") {
            wants_overload = true;
        } else {
            stream.restore(selector_mark);
        }
    }
    if wants_overload {
        let overload_args = parse_v2_overload_selector_args(stream)?;
        let args = parse_v2_overload_call_args(stream, local_scopes)?;
        return build_v2_receiver_overload_call(
            stream,
            receiver,
            null_safe,
            member_name,
            call_kind,
            overload_args,
            args,
        );
    }
    if stream.consume_char(':') {
        let type_name = parse_type_name_v2(stream)?;
        return build_v2_receiver_field(stream, receiver, member_name, call_kind, type_name);
    }
    if !stream.peek_char('(') {
        return build_v2_receiver_field(stream, receiver, member_name, call_kind, String::new());
    }
    stream.consume_char('(');
    let allow_explicit_class = matches!(receiver, DslValue::Target(DslTarget::Last | DslTarget::Result));
    let parsed_args = parse_v2_member_call_args(stream, local_scopes, allow_explicit_class)?;
    build_v2_receiver_call(stream, receiver, null_safe, member_name, call_kind, parsed_args)
}

fn parse_v2_member_call_args(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
    allow_explicit_class: bool,
) -> Result<ParsedCallArgs, String> {
    if stream.consume_char(')') {
        return Ok(ParsedCallArgs::Direct(Vec::new()));
    }

    if matches!(stream.current_kind(), Some(DslTokenKind::String(_))) {
        let first = stream.parse_string()?;
        if first.starts_with('(') {
            let args = parse_v2_optional_value_args(stream, local_scopes)?;
            if !stream.consume_char(')') {
                return Err(stream.err("expected ')'"));
            }
            return Ok(ParsedCallArgs::ExplicitSignatureCall {
                class_name: None,
                sig: first,
                args,
            });
        }
        if allow_explicit_class && stream.peek_char(',') && looks_like_type_name(&first) {
            let checkpoint = stream.mark();
            stream.consume_char(',');
            if matches!(stream.current_kind(), Some(DslTokenKind::String(_))) {
                let second = stream.parse_string()?;
                if second.starts_with('(') {
                    let args = parse_v2_optional_value_args(stream, local_scopes)?;
                    if !stream.consume_char(')') {
                        return Err(stream.err("expected ')'"));
                    }
                    return Ok(ParsedCallArgs::ExplicitSignatureCall {
                        class_name: Some(first),
                        sig: second,
                        args,
                    });
                }
            }
            stream.restore(checkpoint);
        }
        let mut args = vec![DslValue::String(first)];
        while stream.consume_char(',') {
            args.push(parse_v2_value_expr(stream, local_scopes)?);
        }
        if !stream.consume_char(')') {
            return Err(stream.err("expected ')'"));
        }
        return Ok(ParsedCallArgs::Direct(args));
    }

    let mut args = Vec::new();
    loop {
        if stream.peek_char(')') {
            stream.consume_char(')');
            return Ok(ParsedCallArgs::Direct(args));
        }
        args.push(parse_v2_value_expr(stream, local_scopes)?);
        if !stream.consume_char(',') {
            if !stream.consume_char(')') {
                return Err(stream.err("expected ')'"));
            }
            return Ok(ParsedCallArgs::Direct(args));
        }
    }
}

fn parse_v2_optional_value_args(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<Vec<DslValue>, String> {
    let mut args = Vec::new();
    while stream.consume_char(',') {
        args.push(parse_v2_value_expr(stream, local_scopes)?);
    }
    Ok(args)
}

fn parse_v2_overload_selector_args(stream: &mut DslTokenStream<'_>) -> Result<Vec<String>, String> {
    if !stream.consume_char('(') {
        return Err(stream.err("expected '('"));
    }
    let mut overload_args = Vec::new();
    if !stream.peek_char(')') {
        loop {
            overload_args.push(stream.parse_string()?);
            if !stream.consume_char(',') {
                break;
            }
        }
    }
    if !stream.consume_char(')') {
        return Err(stream.err("expected ')'"));
    }
    Ok(overload_args)
}

fn parse_v2_overload_call_args(
    stream: &mut DslTokenStream<'_>,
    local_scopes: &[BTreeMap<String, String>],
) -> Result<Vec<DslValue>, String> {
    if !stream.consume_char('(') {
        return Err(stream.err("expected '('"));
    }
    let args = parse_v2_value_arg_list_until_close(stream, local_scopes)?;
    if !stream.consume_char(')') {
        return Err(stream.err("expected ')'"));
    }
    Ok(args)
}

fn build_v2_receiver_overload_call(
    stream: &DslTokenStream<'_>,
    receiver: DslValue,
    null_safe: bool,
    method_name: String,
    kind: DslCallKind,
    overload_args: Vec<String>,
    args: Vec<DslValue>,
) -> Result<DslValue, String> {
    let (target, receiver) = split_simple_target_receiver(receiver);
    let (class_name, sig) = if let Some(target) = target.as_ref() {
        resolve_v2_target_overload_sig(stream, target, kind, &overload_args)?
    } else {
        resolve_v2_postfix_overload_sig(stream, kind, &overload_args)?
    };
    Ok(DslValue::Call(DslCallStmt {
        kind,
        target,
        receiver: receiver.map(Box::new),
        null_safe,
        class_name,
        method_name,
        sig,
        args,
    }))
}

fn build_v2_receiver_call(
    _stream: &DslTokenStream<'_>,
    receiver: DslValue,
    null_safe: bool,
    method_name: String,
    kind: DslCallKind,
    parsed_args: ParsedCallArgs,
) -> Result<DslValue, String> {
    match parsed_args {
        ParsedCallArgs::Direct(args) => {
            let (target, receiver) = split_simple_target_receiver(receiver);
            Ok(DslValue::Call(DslCallStmt {
                kind,
                target,
                receiver: receiver.map(Box::new),
                null_safe,
                class_name: None,
                method_name,
                sig: String::new(),
                args,
            }))
        }
        ParsedCallArgs::ExplicitSignatureCall { class_name, sig, args } => {
            let (target, receiver) = split_simple_target_receiver(receiver);
            Ok(DslValue::Call(DslCallStmt {
                kind,
                target,
                receiver: receiver.map(Box::new),
                null_safe,
                class_name,
                method_name,
                sig,
                args,
            }))
        }
    }
}

fn build_v2_receiver_field(
    stream: &DslTokenStream<'_>,
    receiver: DslValue,
    field_name: String,
    kind: DslCallKind,
    type_name: String,
) -> Result<DslValue, String> {
    if kind == DslCallKind::Interface {
        return Err(stream.err("interface field access is not supported"));
    }
    let (target, receiver) = split_simple_target_receiver(receiver);
    Ok(DslValue::FieldGet {
        stmt: Box::new(DslFieldStmt {
            target,
            receiver: receiver.map(Box::new),
            class_name: None,
            field_name,
            type_name,
            value: None,
        }),
        is_static: false,
    })
}

fn split_simple_target_receiver(value: DslValue) -> (Option<DslTarget>, Option<DslValue>) {
    match value {
        DslValue::Target(target) => (Some(target), None),
        value => (None, Some(value)),
    }
}

fn build_v2_static_member_value(class_name: String, member_name: String, parsed_args: ParsedCallArgs) -> DslValue {
    match parsed_args {
        ParsedCallArgs::Direct(args) => DslValue::Call(DslCallStmt {
            kind: DslCallKind::Static,
            target: None,
            receiver: None,
            null_safe: false,
            class_name: Some(class_name),
            method_name: member_name,
            sig: String::new(),
            args,
        }),
        ParsedCallArgs::ExplicitSignatureCall { sig, args, .. } => DslValue::Call(DslCallStmt {
            kind: DslCallKind::Static,
            target: None,
            receiver: None,
            null_safe: false,
            class_name: Some(class_name),
            method_name: member_name,
            sig,
            args,
        }),
    }
}

fn resolve_v2_postfix_overload_sig(
    stream: &DslTokenStream<'_>,
    call_kind: DslCallKind,
    overload_args: &[String],
) -> Result<(Option<String>, String), String> {
    if call_kind == DslCallKind::Interface {
        return resolve_v2_interface_overload_sig(stream, overload_args);
    }
    if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
        if overload_args.len() != 1 {
            return Err(stream.err("full-signature overload expects overload(\"sig\")"));
        }
        return Ok((None, overload_args[0].clone()));
    }
    if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
        return Ok((Some(overload_args[0].clone()), overload_args[1].clone()));
    }
    Ok((None, overload_params_sig_v2(overload_args)?))
}

fn resolve_v2_target_overload_sig(
    stream: &DslTokenStream<'_>,
    target: &DslTarget,
    call_kind: DslCallKind,
    overload_args: &[String],
) -> Result<(Option<String>, String), String> {
    if call_kind == DslCallKind::Interface {
        return resolve_v2_interface_overload_sig(stream, overload_args);
    }
    if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
        return Ok((None, overload_args[0].clone()));
    }
    if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
        return Ok((Some(overload_args[0].clone()), overload_args[1].clone()));
    }
    let first_is_explicit_class = matches!(target, DslTarget::Last | DslTarget::Result)
        && overload_args.len() >= 2
        && overload_args[0].contains('.');
    if first_is_explicit_class {
        return Ok((
            Some(overload_args[0].clone()),
            overload_params_sig_v2(&overload_args[1..])?,
        ));
    }
    Ok((None, overload_params_sig_v2(overload_args)?))
}

fn resolve_v2_static_overload_sig(stream: &DslTokenStream<'_>, overload_args: &[String]) -> Result<String, String> {
    if overload_args.first().map(|arg| arg.starts_with('(')).unwrap_or(false) {
        if overload_args.len() != 1 {
            return Err(stream.err("static full-signature overload expects overload(\"sig\")"));
        }
        return Ok(overload_args[0].clone());
    }
    overload_params_sig_v2(overload_args)
}

fn resolve_v2_interface_overload_sig(
    stream: &DslTokenStream<'_>,
    overload_args: &[String],
) -> Result<(Option<String>, String), String> {
    let Some(class_name) = overload_args.first() else {
        return Err(stream.err("interface overload expects overload(\"InterfaceClass\", ...)"));
    };
    if class_name.starts_with('(') {
        return Err(stream.err("interface overload expects overload(\"InterfaceClass\", ...)"));
    }
    let params = if overload_args.len() >= 2 && overload_args[1].starts_with('(') {
        overload_args[1].clone()
    } else {
        overload_params_sig_v2(&overload_args[1..])?
    };
    Ok((Some(class_name.clone()), params))
}

fn overload_params_sig_v2(overload_args: &[String]) -> Result<String, String> {
    let param_types = overload_args
        .iter()
        .map(|arg| java_class_to_descriptor_or_primitive(arg))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(build_params_sig(&param_types))
}

fn peek_v2_int_binary_op(stream: &DslTokenStream<'_>) -> Option<(DslIntBinOp, u8)> {
    for (token, op, prec) in V2_INT_BINARY_TOKEN_OPS {
        if stream.peek_op(token) {
            return Some((*op, *prec));
        }
    }
    V2_INT_BINARY_CHAR_OPS
        .iter()
        .find_map(|(ch, op, prec)| stream.peek_char(*ch).then_some((*op, *prec)))
}

fn consume_v2_int_binary_op(stream: &mut DslTokenStream<'_>, op: DslIntBinOp) -> Result<(), String> {
    if let Some((token, _, _)) = V2_INT_BINARY_TOKEN_OPS
        .iter()
        .find(|(_, candidate, _)| *candidate == op)
    {
        if stream.consume_op(token) {
            return Ok(());
        }
    }
    if let Some((ch, _, _)) = V2_INT_BINARY_CHAR_OPS.iter().find(|(_, candidate, _)| *candidate == op) {
        if stream.consume_char(*ch) {
            return Ok(());
        }
    }
    Err(stream.err("unsupported integer binary operator"))
}

fn parse_v2_cmp_op(stream: &mut DslTokenStream<'_>) -> Result<IfCmpOp, String> {
    if stream.consume_op("==") {
        Ok(IfCmpOp::Eq)
    } else if stream.consume_op("!=") {
        Ok(IfCmpOp::Ne)
    } else if stream.consume_op("<=") {
        Ok(IfCmpOp::Le)
    } else if stream.consume_op(">=") {
        Ok(IfCmpOp::Ge)
    } else if stream.consume_char('<') {
        Ok(IfCmpOp::Lt)
    } else if stream.consume_char('>') {
        Ok(IfCmpOp::Gt)
    } else {
        Err(stream.err("expected comparison operator"))
    }
}

fn peek_v2_cmp_op(stream: &DslTokenStream<'_>) -> bool {
    stream.peek_op("==")
        || stream.peek_op("!=")
        || stream.peek_op("<=")
        || stream.peek_op(">=")
        || stream.peek_char('<')
        || stream.peek_char('>')
}

fn scoped_target_name_v2(local_scopes: &[BTreeMap<String, String>], name: &str) -> Option<DslTarget> {
    match parse_target_name(name) {
        Some(DslTarget::Local(local)) => Some(DslTarget::Local(
            resolve_local_v2(local_scopes, &local).unwrap_or(local),
        )),
        other => other,
    }
}

fn resolve_local_v2(local_scopes: &[BTreeMap<String, String>], source_name: &str) -> Option<String> {
    local_scopes
        .iter()
        .rev()
        .find_map(|scope| scope.get(source_name).cloned())
}

fn parse_type_name_v2(stream: &mut DslTokenStream<'_>) -> Result<String, String> {
    if matches!(stream.current_kind(), Some(DslTokenKind::String(_))) {
        return stream.parse_string();
    }
    let mut name = stream.parse_ident()?;
    loop {
        if stream.consume_char('.') {
            let part = stream.parse_ident()?;
            name.push('.');
            name.push_str(&part);
        } else if stream.consume_char('[') {
            if !stream.consume_char(']') {
                return Err(stream.err("expected ']'"));
            }
            name.push_str("[]");
        } else {
            return Ok(name);
        }
    }
}

fn has_v2_unsupported_trailing_token(stream: &DslTokenStream<'_>) -> bool {
    stream.peek_char('.') || stream.peek_char('(') || stream.peek_op("?.")
}

fn can_start_v2_expr(stream: &DslTokenStream<'_>) -> bool {
    matches!(
        stream.current_kind(),
        Some(DslTokenKind::Number(_) | DslTokenKind::Ident(_) | DslTokenKind::String(_))
            | Some(DslTokenKind::Symbol('(' | '[' | '-' | '~' | '!'))
    )
}
