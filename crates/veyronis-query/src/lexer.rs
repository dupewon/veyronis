use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Find,
    Match,
    Where,
    Limit,
    And,
    Or,
    Not,
    Contains,
    StartsWith,
    Event,
    Process,
    Arrow, // ->
    Eq,    // =
    Ne,    // !=
    Lt,    // <
    Lte,   // <=
    Gt,    // >
    Gte,   // >=
    LParen,
    RParen,
    Identifier(String),
    StringLit(String),
    NumberLit(f64),
    BoolLit(bool),
    Eof,
}

#[derive(Error, Debug)]
pub enum LexerError {
    #[error("unexpected character: '{0}' at position {1}")]
    UnexpectedChar(char, usize),

    #[error("unterminated string literal starting at position {0}")]
    UnterminatedString(usize),
}

pub struct Lexer<'a> {
    _input: &'a str,
    chars: Vec<(usize, char)>,
    pos: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        let chars = input.char_indices().collect();
        Self {
            _input: input,
            chars,
            pos: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).map(|&(_, c)| c)
    }

    fn advance(&mut self) -> Option<char> {
        if self.pos < self.chars.len() {
            let c = self.chars[self.pos].1;
            self.pos += 1;
            Some(c)
        } else {
            None
        }
    }

    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexerError> {
        let mut tokens = Vec::new();

        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
                continue;
            }

            match c {
                '(' => {
                    self.advance();
                    tokens.push(Token::LParen);
                }
                ')' => {
                    self.advance();
                    tokens.push(Token::RParen);
                }
                '=' => {
                    self.advance();
                    tokens.push(Token::Eq);
                }
                '!' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        tokens.push(Token::Ne);
                    } else {
                        return Err(LexerError::UnexpectedChar('!', self.pos));
                    }
                }
                '<' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        tokens.push(Token::Lte);
                    } else {
                        tokens.push(Token::Lt);
                    }
                }
                '>' => {
                    self.advance();
                    if self.peek() == Some('=') {
                        self.advance();
                        tokens.push(Token::Gte);
                    } else {
                        tokens.push(Token::Gt);
                    }
                }
                '-' => {
                    self.advance();
                    if self.peek() == Some('>') {
                        self.advance();
                        tokens.push(Token::Arrow);
                    } else {
                        return Err(LexerError::UnexpectedChar('-', self.pos));
                    }
                }
                '"' | '\'' => {
                    let quote = c;
                    let start = self.pos;
                    self.advance();
                    let mut s = String::new();
                    let mut closed = false;
                    while let Some(ch) = self.advance() {
                        if ch == quote {
                            closed = true;
                            break;
                        } else if ch == '\\' {
                            if let Some(escaped) = self.advance() {
                                s.push(escaped);
                            }
                        } else {
                            s.push(ch);
                        }
                    }
                    if !closed {
                        return Err(LexerError::UnterminatedString(start));
                    }
                    tokens.push(Token::StringLit(s));
                }
                _ if c.is_ascii_digit() => {
                    let mut num_str = String::new();
                    while let Some(ch) = self.peek() {
                        if ch.is_ascii_digit() || ch == '.' {
                            num_str.push(ch);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let num = num_str.parse::<f64>().unwrap_or(0.0);
                    tokens.push(Token::NumberLit(num));
                }
                _ if c.is_alphabetic() || c == '_' => {
                    let mut ident = String::new();
                    while let Some(ch) = self.peek() {
                        if ch.is_alphanumeric() || ch == '_' || ch == '.' {
                            ident.push(ch);
                            self.advance();
                        } else {
                            break;
                        }
                    }

                    match ident.to_uppercase().as_str() {
                        "FIND" => tokens.push(Token::Find),
                        "MATCH" => tokens.push(Token::Match),
                        "WHERE" => tokens.push(Token::Where),
                        "LIMIT" => tokens.push(Token::Limit),
                        "AND" => tokens.push(Token::And),
                        "OR" => tokens.push(Token::Or),
                        "NOT" => tokens.push(Token::Not),
                        "CONTAINS" => tokens.push(Token::Contains),
                        "STARTS_WITH" => tokens.push(Token::StartsWith),
                        "EVENT" | "EVENTS" => tokens.push(Token::Event),
                        "PROCESS" | "PROCESSES" => tokens.push(Token::Process),
                        "TRUE" => tokens.push(Token::BoolLit(true)),
                        "FALSE" => tokens.push(Token::BoolLit(false)),
                        _ => tokens.push(Token::Identifier(ident)),
                    }
                }
                _ => {
                    return Err(LexerError::UnexpectedChar(c, self.pos));
                }
            }
        }

        tokens.push(Token::Eof);
        Ok(tokens)
    }
}
