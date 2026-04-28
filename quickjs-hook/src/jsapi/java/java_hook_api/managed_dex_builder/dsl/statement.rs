use super::*;

impl<'a> DslParser<'a> {
    pub(super) fn parse_statements(&mut self, stop_on_brace: bool) -> Result<Vec<DslStmt>, String> {
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

    pub(super) fn parse_block(&mut self) -> Result<Vec<DslStmt>, String> {
        self.skip_ws();
        self.expect_char('{')?;
        self.with_local_scope(|parser| parser.parse_statements(true))
    }

    pub(super) fn parse_statement_body(&mut self) -> Result<Vec<DslStmt>, String> {
        self.skip_ws();
        if self.peek() == Some('{') {
            self.parse_block()
        } else {
            self.with_local_scope(|parser| Ok(vec![parser.parse_statement()?]))
        }
    }

    fn parse_statement(&mut self) -> Result<DslStmt, String> {
        self.skip_ws();
        if self.peek_ident("return") {
            self.expect_ident("return")?;
            self.skip_ws();
            if self.peek_ident("orig") {
                self.expect_ident("orig")?;
                let args = self.parse_orig_args()?;
                self.skip_ws();
                self.expect_char(';')?;
                return Ok(DslStmt::ReturnOrig { args });
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
        if self.peek_ident("throw") {
            self.expect_ident("throw")?;
            let value = self.parse_value_arg()?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Throw { value });
        }
        if self.peek_ident("if") {
            return self.parse_js_if_statement();
        }
        if self.peek_ident("while") {
            return self.parse_js_while_statement();
        }
        if self.peek_ident("do") {
            return self.parse_js_do_while_statement();
        }
        if self.peek_ident("for") {
            return self.parse_js_for_statement();
        }
        if self.peek_ident("switch") {
            return self.parse_js_switch_statement();
        }
        if self.peek_ident("try") {
            return self.parse_js_try_catch_statement();
        }
        if self.peek_ident("break") {
            self.expect_ident("break")?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Break);
        }
        if self.peek_ident("continue") {
            self.expect_ident("continue")?;
            self.skip_ws();
            self.expect_char(';')?;
            return Ok(DslStmt::Continue);
        }
        if self.peek_op("++") || self.peek_op("--") {
            return self.parse_prefix_increment_statement();
        }

        let name = self.parse_ident()?;
        self.skip_ws();
        self.parse_named_statement_tail(name)
    }
}
