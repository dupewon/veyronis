use crate::ast::*;
use crate::lexer::{Lexer, Token};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("lexer error: {0}")]
    Lexer(#[from] crate::lexer::LexerError),

    #[error("unexpected token: expected {expected}, found {found:?}")]
    UnexpectedToken {
        expected: &'static str,
        found: Token,
    },

    #[error("unexpected end of query string")]
    UnexpectedEof,
}

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn parse_str(query_str: &str) -> Result<Query, ParserError> {
        let mut lexer = Lexer::new(query_str);
        let tokens = lexer.tokenize()?;
        let mut parser = Parser::new(tokens);
        parser.parse()
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> Token {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            tok
        } else {
            Token::Eof
        }
    }

    fn expect(&mut self, expected: Token, name: &'static str) -> Result<(), ParserError> {
        let tok = self.advance();
        if tok == expected {
            Ok(())
        } else {
            Err(ParserError::UnexpectedToken {
                expected: name,
                found: tok,
            })
        }
    }

    pub fn parse(&mut self) -> Result<Query, ParserError> {
        match self.peek() {
            Token::Find => {
                self.advance();
                let target = match self.advance() {
                    Token::Event => TargetEntity::Event,
                    Token::Process => TargetEntity::Process,
                    tok => {
                        return Err(ParserError::UnexpectedToken {
                            expected: "event or process",
                            found: tok,
                        })
                    }
                };

                let mut filter = None;
                if *self.peek() == Token::Where {
                    self.advance();
                    filter = Some(self.parse_expr()?);
                }

                let mut limit = None;
                if *self.peek() == Token::Limit {
                    self.advance();
                    if let Token::NumberLit(n) = self.advance() {
                        limit = Some(n as usize);
                    } else {
                        return Err(ParserError::UnexpectedToken {
                            expected: "number after LIMIT",
                            found: self.peek().clone(),
                        });
                    }
                }

                Ok(Query::Find(FindQuery {
                    target,
                    filter,
                    limit,
                }))
            }
            Token::Match => {
                self.advance();
                let mut sequence = Vec::new();

                loop {
                    let ident = match self.advance() {
                        Token::Identifier(s) => s,
                        Token::Event => "Event".into(),
                        Token::Process => "Process".into(),
                        tok => {
                            return Err(ParserError::UnexpectedToken {
                                expected: "event name in MATCH sequence",
                                found: tok,
                            })
                        }
                    };
                    sequence.push(ident);

                    if *self.peek() == Token::Arrow {
                        self.advance();
                    } else {
                        break;
                    }
                }

                Ok(Query::Match(MatchQuery { sequence }))
            }
            tok => Err(ParserError::UnexpectedToken {
                expected: "FIND or MATCH",
                found: tok.clone(),
            }),
        }
    }

    fn parse_expr(&mut self) -> Result<Expr, ParserError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<Expr, ParserError> {
        let mut left = self.parse_and()?;

        while *self.peek() == Token::Or {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParserError> {
        let mut left = self.parse_unary()?;

        while *self.peek() == Token::And {
            self.advance();
            let right = self.parse_unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParserError> {
        if *self.peek() == Token::Not {
            self.advance();
            let expr = self.parse_unary()?;
            Ok(Expr::Not(Box::new(expr)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, ParserError> {
        if *self.peek() == Token::LParen {
            self.advance();
            let expr = self.parse_expr()?;
            self.expect(Token::RParen, ")")?;
            return Ok(expr);
        }

        let field = match self.advance() {
            Token::Identifier(s) => s,
            Token::Event => "event".into(),
            Token::Process => "process".into(),
            tok => {
                return Err(ParserError::UnexpectedToken {
                    expected: "field name",
                    found: tok,
                })
            }
        };

        let op = match self.advance() {
            Token::Eq => CmpOp::Eq,
            Token::Ne => CmpOp::Ne,
            Token::Lt => CmpOp::Lt,
            Token::Lte => CmpOp::Lte,
            Token::Gt => CmpOp::Gt,
            Token::Gte => CmpOp::Gte,
            Token::Contains => CmpOp::Contains,
            Token::StartsWith => CmpOp::StartsWith,
            tok => {
                return Err(ParserError::UnexpectedToken {
                    expected: "comparison operator (=, !=, <, >, CONTAINS, STARTS_WITH)",
                    found: tok,
                })
            }
        };

        let value = match self.advance() {
            Token::StringLit(s) => Value::String(s),
            Token::Identifier(s) => Value::String(s),
            Token::NumberLit(n) => Value::Number(n),
            Token::BoolLit(b) => Value::Bool(b),
            tok => {
                return Err(ParserError::UnexpectedToken {
                    expected: "value literal (string, number, boolean, identifier)",
                    found: tok,
                })
            }
        };

        Ok(Expr::Comparison { field, op, value })
    }
}
