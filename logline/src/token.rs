//! Token types for LogLine lexical analysis

use crate::position::Span;
use std::fmt;

/// A token with its type and source location
#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    pub fn new(kind: TokenKind, span: Span) -> Self {
        Self { kind, span }
    }
}

/// The type of a token
#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // Literals
    Identifier(String),  // JOB, GOAL, etc.
    String(String),      // Quoted or unquoted string values
    Number(f64),         // 123, 3.14, -5
    Boolean(bool),       // true, false
    
    // Delimiters
    Colon,               // :
    Comma,               // ,
    LeftBrace,           // {
    RightBrace,          // }
    LeftBracket,         // [
    RightBracket,        // ]
    
    // Special
    Newline,
    End,                 // END keyword
    Indent(usize),       // Indentation level
    Eof,
}

impl TokenKind {
    /// Check if this token can start a value
    pub fn is_value_start(&self) -> bool {
        matches!(
            self,
            TokenKind::String(_)
                | TokenKind::Number(_)
                | TokenKind::Boolean(_)
                | TokenKind::LeftBrace
                | TokenKind::LeftBracket
                | TokenKind::Identifier(_)
        )
    }
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TokenKind::Identifier(s) => write!(f, "identifier '{}'", s),
            TokenKind::String(s) => write!(f, "string \"{}\"", s),
            TokenKind::Number(n) => write!(f, "number {}", n),
            TokenKind::Boolean(b) => write!(f, "boolean {}", b),
            TokenKind::Colon => write!(f, "':'"),
            TokenKind::Comma => write!(f, "','"),
            TokenKind::LeftBrace => write!(f, "'{{'"),
            TokenKind::RightBrace => write!(f, "'}}'"),
            TokenKind::LeftBracket => write!(f, "'['"),
            TokenKind::RightBracket => write!(f, "']'"),
            TokenKind::Newline => write!(f, "newline"),
            TokenKind::End => write!(f, "END"),
            TokenKind::Indent(n) => write!(f, "indent({})", n),
            TokenKind::Eof => write!(f, "end of file"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::position::{Position, Span};

    #[test]
    fn test_token_creation() {
        let span = Span::single(Position::start());
        let token = Token::new(TokenKind::Colon, span);
        assert_eq!(token.kind, TokenKind::Colon);
    }

    #[test]
    fn test_token_display() {
        assert_eq!(
            format!("{}", TokenKind::Identifier("test".to_string())),
            "identifier 'test'"
        );
        assert_eq!(
            format!("{}", TokenKind::String("hello".to_string())),
            "string \"hello\""
        );
        assert_eq!(format!("{}", TokenKind::Colon), "':'");
    }

    #[test]
    fn test_is_value_start() {
        assert!(TokenKind::String("test".to_string()).is_value_start());
        assert!(TokenKind::Number(42.0).is_value_start());
        assert!(TokenKind::LeftBrace.is_value_start());
        assert!(!TokenKind::Colon.is_value_start());
        assert!(!TokenKind::Newline.is_value_start());
    }
}

