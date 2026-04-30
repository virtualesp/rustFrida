use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_prefix_increment_statement(&mut self) -> Result<DslStmt, String> {
        let delta = if self.peek_op("++") {
            self.expect_op("++")?;
            1
        } else {
            self.expect_op("--")?;
            -1
        };
        let name = self.parse_ident()?;
        let name = self.resolve_local_name_or_source(name);
        self.skip_ws();
        self.expect_char(';')?;
        Ok(self.local_increment_stmt(name, delta))
    }

    pub(super) fn parse_named_statement_tail(&mut self, name: String, name_mark: DslMark) -> Result<DslStmt, String> {
        if (name == "let" || name == "var") && self.peek() != Some('(') {
            return self.parse_let_statement();
        }
        if name == "count" && self.peek() == Some('(') {
            return self.parse_count_statement();
        }
        if name == "send" && self.peek() == Some('(') {
            return self.parse_send_statement();
        }
        if name == "dbbFill" && self.peek() == Some('(') {
            return self.parse_direct_buffer_fill_statement();
        }
        if name == "dbbCopyFromByteArray" && self.peek() == Some('(') {
            return self.parse_direct_buffer_copy_from_byte_array_statement();
        }
        if name == "dbbCopyToByteArray" && self.peek() == Some('(') {
            return self.parse_direct_buffer_copy_to_byte_array_statement();
        }
        if self.peek() == Some('=') {
            self.expect_char('=')?;
            let value = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            let name = self.resolve_local_name_or_source(name);
            return Ok(DslStmt::Assign { name, value });
        }
        if let Some(op) = self.peek_compound_assign_op() {
            self.consume_compound_assign_op(op)?;
            let rhs = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            let name = self.resolve_local_name_or_source(name);
            return Ok(self.local_compound_assign_stmt(name, op, rhs));
        }
        if self.peek_op("++") || self.peek_op("--") {
            let delta = if self.peek_op("++") {
                self.expect_op("++")?;
                1
            } else {
                self.expect_op("--")?;
                -1
            };
            self.skip_ws();
            self.expect_char(';')?;
            let name = self.resolve_local_name_or_source(name);
            return Ok(self.local_increment_stmt(name, delta));
        }
        if name == "new" || self.peek() == Some('.') || self.peek() == Some('[') || self.peek_ident("as") {
            self.restore(name_mark);
            let value = self.parse_expr_v2()?;
            return self.parse_value_statement_tail(
                value,
                "only method calls and field reads can be used as expression statements",
            );
        }
        Err(self.err(&format!("unknown managed DSL statement '{}'", name)))
    }

    fn parse_count_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_char('(')?;
        self.skip_ws();
        let counter_name = self.parse_string_arg()?;
        self.skip_ws();
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char(';')?;
        Ok(DslStmt::Count { name: counter_name })
    }

    fn parse_send_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_char('(')?;
        self.skip_ws();
        let channel_name = self.parse_string_arg()?;
        self.skip_ws();
        let value = if self.peek() == Some(',') {
            self.expect_char(',')?;
            self.parse_value_arg()?
        } else {
            DslValue::Int(0)
        };
        self.skip_ws();
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char(';')?;
        Ok(DslStmt::Send {
            name: channel_name,
            value,
        })
    }

    fn parse_direct_buffer_fill_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_char('(')?;
        let buffer = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let offset = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let length = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let value = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char(';')?;
        Ok(DslStmt::DirectBufferFill {
            buffer,
            offset,
            length,
            value,
        })
    }

    fn parse_direct_buffer_copy_from_byte_array_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_char('(')?;
        let buffer = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let dst_offset = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let src = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let src_offset = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let length = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char(';')?;
        Ok(DslStmt::DirectBufferCopyFromByteArray {
            buffer,
            dst_offset,
            src,
            src_offset,
            length,
        })
    }

    fn parse_direct_buffer_copy_to_byte_array_statement(&mut self) -> Result<DslStmt, String> {
        self.expect_char('(')?;
        let buffer = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let src_offset = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let dst = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let dst_offset = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(',')?;
        let length = self.parse_value_arg()?;
        self.skip_ws();
        self.expect_char(')')?;
        self.skip_ws();
        self.expect_char(';')?;
        Ok(DslStmt::DirectBufferCopyToByteArray {
            buffer,
            src_offset,
            dst,
            dst_offset,
            length,
        })
    }

    pub(super) fn parse_value_statement_tail(
        &mut self,
        value: DslValue,
        expression_error: &str,
    ) -> Result<DslStmt, String> {
        self.skip_ws();
        if self.peek() == Some('=') {
            self.expect_char('=')?;
            let rhs = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            return match value {
                DslValue::FieldGet { stmt, is_static } => {
                    let mut stmt = *stmt;
                    stmt.value = Some(rhs);
                    Ok(DslStmt::FieldWrite { stmt, is_static })
                }
                DslValue::ArrayGet {
                    array,
                    index,
                    type_name,
                } => Ok(DslStmt::ArrayPut {
                    array: *array,
                    index: *index,
                    type_name,
                    value: rhs,
                }),
                _ => Err(self.err("only fields and array elements can be assigned")),
            };
        }
        if let Some(op) = self.peek_compound_assign_op() {
            self.consume_compound_assign_op(op)?;
            let rhs = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            return self.compound_assign_value_stmt(value, op, rhs);
        }
        if self.peek_op("++") || self.peek_op("--") {
            let delta = if self.peek_op("++") {
                self.expect_op("++")?;
                1
            } else {
                self.expect_op("--")?;
                -1
            };
            self.skip_ws();
            self.expect_char(';')?;
            return self.increment_value_stmt(value, delta);
        }
        self.expect_char(';')?;
        value.into_statement().ok_or_else(|| self.err(expression_error))
    }
}
