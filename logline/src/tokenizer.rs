//! Lexical analysis for LogLine
//!
//! Converts source text into a stream of tokens with position information.

use crate::error::ParseError;
use crate::position::{Position, Span};
use crate::token::{Token, TokenKind};

/// Tokenizer for LogLine source text
pub struct Tokenizer {
    input: Vec<char>,
    position: usize,
    line: usize,
    column: usize,
    /// Track if we're at the start of a line (for indent detection)
    at_line_start: bool,
}

impl Tokenizer {
    /// Create a new tokenizer for the given input
    pub fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            position: 0,
            line: 1,
            column: 1,
            at_line_start: true,
        }
    }
    
    fn current_position(&self) -> Position {
        Position::new(self.line, self.column, self.position)
    }
    
    fn current_char(&self) -> Option<char> {
        self.input.get(self.position).copied()
    }
    
    fn peek_char(&self, offset: usize) -> Option<char> {
        self.input.get(self.position + offset).copied()
    }
    
    fn advance(&mut self) -> Option<char> {
        let ch = self.current_char()?;
        self.position += 1;
        
        if ch == '\n' {
            self.line += 1;
            self.column = 1;
            self.at_line_start = true;
        } else {
            self.column += 1;
            if !ch.is_whitespace() {
                self.at_line_start = false;
            }
        }
        
        Some(ch)
    }
    
    fn skip_whitespace_except_newline(&mut self) -> usize {
        let mut count = 0;
        while let Some(ch) = self.current_char() {
            if ch == ' ' || ch == '\t' || ch == '\r' {
                count += 1;
                self.advance();
            } else {
                break;
            }
        }
        count
    }
    
    /// Count leading whitespace for indentation
    fn count_indent(&mut self) -> usize {
        let mut indent = 0;
        while let Some(ch) = self.current_char() {
            match ch {
                ' ' => indent += 1,
                '\t' => indent += 4, // Tab = 4 spaces
                _ => break,
            }
            self.advance();
        }
        indent
    }
    
    fn read_identifier(&mut self) -> String {
        let mut result = String::new();
        while let Some(ch) = self.current_char() {
            if ch.is_alphanumeric() || ch == '_' || ch == '-' {
                result.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        result
    }
    
    fn read_number(&mut self, start: Position) -> Result<f64, ParseError> {
        let mut result = String::new();
        let mut has_dot = false;
        
        // Handle negative sign
        if self.current_char() == Some('-') {
            result.push('-');
            self.advance();
        }
        
        while let Some(ch) = self.current_char() {
            if ch.is_numeric() {
                result.push(ch);
                self.advance();
            } else if ch == '.' && !has_dot && self.peek_char(1).map(|c| c.is_numeric()).unwrap_or(false) {
                has_dot = true;
                result.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        
        result.parse().map_err(|_| ParseError::InvalidNumber {
            span: Span::new(start, self.current_position()),
        })
    }
    
    fn read_string(&mut self, start: Position) -> Result<String, ParseError> {
        let mut result = String::new();
        self.advance(); // Skip opening quote
        
        while let Some(ch) = self.current_char() {
            if ch == '"' {
                self.advance();
                return Ok(result);
            } else if ch == '\\' {
                self.advance();
                match self.current_char() {
                    Some('n') => {
                        result.push('\n');
                        self.advance();
                    }
                    Some('t') => {
                        result.push('\t');
                        self.advance();
                    }
                    Some('r') => {
                        result.push('\r');
                        self.advance();
                    }
                    Some('"') => {
                        result.push('"');
                        self.advance();
                    }
                    Some('\\') => {
                        result.push('\\');
                        self.advance();
                    }
                    Some(_) => {
                        return Err(ParseError::InvalidEscape {
                            pos: self.current_position(),
                        });
                    }
                    None => {
                        return Err(ParseError::UnterminatedString {
                            span: Span::new(start, self.current_position()),
                        });
                    }
                }
            } else if ch == '\n' {
                return Err(ParseError::UnterminatedString {
                    span: Span::new(start, self.current_position()),
                });
            } else {
                result.push(ch);
                self.advance();
            }
        }
        
        Err(ParseError::UnterminatedString {
            span: Span::new(start, self.current_position()),
        })
    }
    
    /// Read unquoted string value (until delimiter)
    fn read_unquoted_value(&mut self) -> String {
        let mut result = String::new();
        while let Some(ch) = self.current_char() {
            // Stop at delimiters
            if ch == '\n' || ch == '{' || ch == '}' || ch == '[' || ch == ']' || ch == ',' {
                break;
            }
            result.push(ch);
            self.advance();
        }
        result.trim().to_string()
    }
    
    /// Get the next token
    pub fn next_token(&mut self) -> Result<Token, ParseError> {
        // Handle indentation at line start
        if self.at_line_start {
            let indent = self.count_indent();
            // Check if there's content after indent
            if let Some(ch) = self.current_char() {
                if ch != '\n' {
                    self.at_line_start = false;
                    if indent > 0 {
                        let start = Position::new(self.line, 1, self.position - indent);
                        return Ok(Token::new(
                            TokenKind::Indent(indent),
                            Span::new(start, self.current_position())
                        ));
                    }
                }
            }
        }
        
        self.skip_whitespace_except_newline();
        
        let start = self.current_position();
        
        match self.current_char() {
            None => Ok(Token::new(TokenKind::Eof, Span::single(start))),
            
            Some('\n') => {
                self.advance();
                Ok(Token::new(TokenKind::Newline, Span::new(start, self.current_position())))
            }
            
            Some(':') => {
                self.advance();
                Ok(Token::new(TokenKind::Colon, Span::new(start, self.current_position())))
            }
            
            Some('{') => {
                self.advance();
                Ok(Token::new(TokenKind::LeftBrace, Span::new(start, self.current_position())))
            }
            
            Some('}') => {
                self.advance();
                Ok(Token::new(TokenKind::RightBrace, Span::new(start, self.current_position())))
            }
            
            Some('[') => {
                self.advance();
                Ok(Token::new(TokenKind::LeftBracket, Span::new(start, self.current_position())))
            }
            
            Some(']') => {
                self.advance();
                Ok(Token::new(TokenKind::RightBracket, Span::new(start, self.current_position())))
            }
            
            Some(',') => {
                self.advance();
                Ok(Token::new(TokenKind::Comma, Span::new(start, self.current_position())))
            }
            
            Some('"') => {
                let value = self.read_string(start)?;
                Ok(Token::new(
                    TokenKind::String(value),
                    Span::new(start, self.current_position())
                ))
            }
            
            Some(ch) if ch.is_numeric() || (ch == '-' && self.peek_char(1).map(|c| c.is_numeric()).unwrap_or(false)) => {
                let value = self.read_number(start)?;
                Ok(Token::new(
                    TokenKind::Number(value),
                    Span::new(start, self.current_position())
                ))
            }
            
            Some(ch) if ch.is_alphabetic() || ch == '_' => {
                let ident = self.read_identifier();
                let kind = match ident.to_uppercase().as_str() {
                    "END" => TokenKind::End,
                    "TRUE" => TokenKind::Boolean(true),
                    "FALSE" => TokenKind::Boolean(false),
                    _ => TokenKind::Identifier(ident),
                };
                Ok(Token::new(kind, Span::new(start, self.current_position())))
            }
            
            Some(_) => {
                // Try to read as unquoted string value
                let value = self.read_unquoted_value();
                if value.is_empty() {
                    Err(ParseError::InvalidCharacter { 
                        ch: self.current_char().unwrap_or('\0'),
                        pos: start,
                    })
                } else {
                    Ok(Token::new(
                        TokenKind::String(value),
                        Span::new(start, self.current_position())
                    ))
                }
            }
        }
    }
    
    /// Tokenize the entire input into a vector of tokens
    pub fn tokenize(&mut self) -> Result<Vec<Token>, ParseError> {
        let mut tokens = Vec::new();
        loop {
            let token = self.next_token()?;
            let is_eof = matches!(token.kind, TokenKind::Eof);
            tokens.push(token);
            if is_eof {
                break;
            }
        }
        Ok(tokens)
    }
    
    /// Peek at the next token without consuming it
    pub fn peek(&mut self) -> Result<Token, ParseError> {
        let saved_position = self.position;
        let saved_line = self.line;
        let saved_column = self.column;
        let saved_at_line_start = self.at_line_start;
        
        let token = self.next_token()?;
        
        self.position = saved_position;
        self.line = saved_line;
        self.column = saved_column;
        self.at_line_start = saved_at_line_start;
        
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_tokens() {
        let mut tokenizer = Tokenizer::new("JOB: test");
        let tokens = tokenizer.tokenize().unwrap();
        
        assert!(matches!(&tokens[0].kind, TokenKind::Identifier(s) if s == "JOB"));
        assert!(matches!(tokens[1].kind, TokenKind::Colon));
        assert!(matches!(&tokens[2].kind, TokenKind::Identifier(s) if s == "test"));
    }

    #[test]
    fn test_numbers() {
        let mut tokenizer = Tokenizer::new("42 3.14 -5");
        
        let t1 = tokenizer.next_token().unwrap();
        assert_eq!(t1.kind, TokenKind::Number(42.0));
        
        let t2 = tokenizer.next_token().unwrap();
        assert_eq!(t2.kind, TokenKind::Number(3.14));
        
        let t3 = tokenizer.next_token().unwrap();
        assert_eq!(t3.kind, TokenKind::Number(-5.0));
    }

    #[test]
    fn test_strings() {
        let mut tokenizer = Tokenizer::new(r#""hello world" "escaped \"quote\"""#);
        
        let t1 = tokenizer.next_token().unwrap();
        if let TokenKind::String(s) = &t1.kind {
            assert_eq!(s, "hello world");
        } else {
            panic!("Expected string token");
        }
        
        let t2 = tokenizer.next_token().unwrap();
        if let TokenKind::String(s) = &t2.kind {
            assert_eq!(s, "escaped \"quote\"");
        } else {
            panic!("Expected string token");
        }
    }

    #[test]
    fn test_unterminated_string() {
        let mut tokenizer = Tokenizer::new(r#""hello"#);
        let result = tokenizer.next_token();
        assert!(matches!(result, Err(ParseError::UnterminatedString { .. })));
    }

    #[test]
    fn test_position_tracking() {
        let mut tokenizer = Tokenizer::new("JOB:\n  test");
        
        let t1 = tokenizer.next_token().unwrap();
        assert_eq!(t1.span.start.line, 1);
        assert_eq!(t1.span.start.column, 1);
        
        tokenizer.next_token().unwrap(); // :
        tokenizer.next_token().unwrap(); // newline
        tokenizer.next_token().unwrap(); // indent
        
        let t2 = tokenizer.next_token().unwrap();
        assert_eq!(t2.span.start.line, 2);
    }

    #[test]
    fn test_end_keyword() {
        let mut tokenizer = Tokenizer::new("END");
        let token = tokenizer.next_token().unwrap();
        assert_eq!(token.kind, TokenKind::End);
    }

    #[test]
    fn test_boolean() {
        let mut tokenizer = Tokenizer::new("true false TRUE FALSE");
        
        let t1 = tokenizer.next_token().unwrap();
        assert_eq!(t1.kind, TokenKind::Boolean(true));
        
        let t2 = tokenizer.next_token().unwrap();
        assert_eq!(t2.kind, TokenKind::Boolean(false));
        
        let t3 = tokenizer.next_token().unwrap();
        assert_eq!(t3.kind, TokenKind::Boolean(true));
        
        let t4 = tokenizer.next_token().unwrap();
        assert_eq!(t4.kind, TokenKind::Boolean(false));
    }

    #[test]
    fn test_delimiters() {
        let mut tokenizer = Tokenizer::new("{}[],:");
        
        assert_eq!(tokenizer.next_token().unwrap().kind, TokenKind::LeftBrace);
        assert_eq!(tokenizer.next_token().unwrap().kind, TokenKind::RightBrace);
        assert_eq!(tokenizer.next_token().unwrap().kind, TokenKind::LeftBracket);
        assert_eq!(tokenizer.next_token().unwrap().kind, TokenKind::RightBracket);
        assert_eq!(tokenizer.next_token().unwrap().kind, TokenKind::Comma);
        assert_eq!(tokenizer.next_token().unwrap().kind, TokenKind::Colon);
    }

    #[test]
    fn test_full_logline() {
        let input = r#"JOB: fix-bug-123
  GOAL: Fix the login error
  BUDGET: {
    TOKENS: 50000
    STEPS: 20
  }
END"#;
        
        let mut tokenizer = Tokenizer::new(input);
        let tokens = tokenizer.tokenize().unwrap();
        
        // Should have tokens for the full structure
        assert!(tokens.iter().any(|t| matches!(&t.kind, TokenKind::Identifier(s) if s == "JOB")));
        assert!(tokens.iter().any(|t| matches!(t.kind, TokenKind::LeftBrace)));
        assert!(tokens.iter().any(|t| matches!(t.kind, TokenKind::End)));
    }
}

