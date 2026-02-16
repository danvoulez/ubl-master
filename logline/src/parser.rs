//! Recursive descent parser for LogLine
//!
//! Parses tokenized input into an AST.

use crate::ast::{LogLineSpan, LogLineValue};
use crate::error::ParseError;
use crate::position::Span;
use crate::token::{Token, TokenKind};
use crate::tokenizer::Tokenizer;

/// Maximum nesting depth for objects/arrays
const MAX_NESTING_DEPTH: usize = 32;

/// Parser for LogLine documents
pub struct Parser {
    tokens: Vec<Token>,
    position: usize,
    depth: usize,
}

impl Parser {
    /// Create a parser from a token stream
    pub fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            position: 0,
            depth: 0,
        }
    }
    
    /// Create a parser from source text
    pub fn from_source(input: &str) -> Result<Self, ParseError> {
        let mut tokenizer = Tokenizer::new(input);
        let tokens = tokenizer.tokenize()?;
        Ok(Self::new(tokens))
    }
    
    /// Get the current token
    fn current(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }
    
    /// Get the current token kind
    fn current_kind(&self) -> Option<&TokenKind> {
        self.current().map(|t| &t.kind)
    }
    
    /// Advance to the next token
    fn advance(&mut self) -> Option<&Token> {
        if self.position < self.tokens.len() {
            self.position += 1;
        }
        self.tokens.get(self.position - 1)
    }
    
    /// Check if we're at EOF
    fn is_eof(&self) -> bool {
        matches!(self.current_kind(), Some(TokenKind::Eof) | None)
    }
    
    /// Skip newlines and indents
    fn skip_whitespace(&mut self) {
        while matches!(
            self.current_kind(),
            Some(TokenKind::Newline) | Some(TokenKind::Indent(_))
        ) {
            self.advance();
        }
    }
    
    /// Skip newlines only (preserve indents)
    fn skip_newlines(&mut self) {
        while matches!(self.current_kind(), Some(TokenKind::Newline)) {
            self.advance();
        }
    }
    
    /// Expect a specific token kind
    fn expect(&mut self, _expected: &str) -> Result<Token, ParseError> {
        let token = self.current().cloned().ok_or_else(|| ParseError::UnexpectedEof {
            pos: self.tokens.last()
                .map(|t| t.span.end)
                .unwrap_or_default(),
        })?;
        
        self.advance();
        Ok(token)
    }
    
    /// Parse a complete LogLine document
    pub fn parse(&mut self) -> Result<LogLineSpan, ParseError> {
        self.skip_whitespace();
        
        // Parse header: TYPE: name
        let (span_type, name, start_span) = self.parse_header()?;
        
        // Parse parameters
        let params = self.parse_params()?;
        
        // Expect END
        self.skip_whitespace();
        if !matches!(self.current_kind(), Some(TokenKind::End)) {
            return Err(ParseError::MissingEnd);
        }
        self.advance();
        
        let end_span = self.current()
            .map(|t| t.span)
            .unwrap_or(start_span);
        
        Ok(LogLineSpan {
            r#type: span_type,
            name,
            params,
            span: Some(Span::new(start_span.start, end_span.end)),
        })
    }
    
    /// Parse the header line (TYPE: name)
    fn parse_header(&mut self) -> Result<(String, Option<String>, Span), ParseError> {
        // Expect identifier (TYPE)
        let type_token = match self.current_kind() {
            Some(TokenKind::Identifier(s)) => {
                let s = s.clone();
                let span = self.current().unwrap().span;
                self.advance();
                (s, span)
            }
            _ => return Err(ParseError::InvalidHeader),
        };
        
        // Expect colon
        if !matches!(self.current_kind(), Some(TokenKind::Colon)) {
            return Err(ParseError::InvalidHeader);
        }
        self.advance();
        
        // Optional name (rest of line until newline)
        let name = self.parse_optional_name()?;
        
        Ok((type_token.0.to_lowercase(), name, type_token.1))
    }
    
    /// Parse optional name after colon
    fn parse_optional_name(&mut self) -> Result<Option<String>, ParseError> {
        match self.current_kind() {
            Some(TokenKind::Newline) | Some(TokenKind::Eof) | None => Ok(None),
            Some(TokenKind::Identifier(s)) => {
                let name = s.clone();
                self.advance();
                Ok(Some(name))
            }
            Some(TokenKind::String(s)) => {
                let name = s.clone();
                self.advance();
                Ok(Some(name))
            }
            Some(TokenKind::Number(n)) => {
                let name = n.to_string();
                self.advance();
                Ok(Some(name))
            }
            _ => Ok(None),
        }
    }
    
    /// Parse parameters until END
    fn parse_params(&mut self) -> Result<Vec<(String, LogLineValue)>, ParseError> {
        let mut params = Vec::new();
        
        loop {
            self.skip_whitespace();
            
            match self.current_kind() {
                Some(TokenKind::End) | Some(TokenKind::Eof) | None => break,
                Some(TokenKind::RightBrace) => break, // For nested objects
                Some(TokenKind::Identifier(_)) => {
                    let (key, value) = self.parse_param()?;
                    params.push((key, value));
                }
                _ => {
                    // Skip unexpected tokens
                    self.advance();
                }
            }
        }
        
        Ok(params)
    }
    
    /// Parse a single parameter (KEY: value)
    fn parse_param(&mut self) -> Result<(String, LogLineValue), ParseError> {
        // Get key
        let key = match self.current_kind() {
            Some(TokenKind::Identifier(s)) => {
                let k = s.clone().to_lowercase();
                self.advance();
                k
            }
            _ => return Err(ParseError::InvalidHeader),
        };
        
        // Expect colon
        if !matches!(self.current_kind(), Some(TokenKind::Colon)) {
            // Might be a bare identifier (treated as boolean true)
            return Ok((key, LogLineValue::Bool(true)));
        }
        self.advance();
        
        // Parse value
        let value = self.parse_value()?;
        
        Ok((key, value))
    }
    
    /// Parse a value (string, number, bool, object, array)
    fn parse_value(&mut self) -> Result<LogLineValue, ParseError> {
        // Check nesting depth
        if self.depth > MAX_NESTING_DEPTH {
            return Err(ParseError::NestingTooDeep {
                max: MAX_NESTING_DEPTH,
                span: self.current().map(|t| t.span).unwrap_or_default(),
            });
        }
        
        match self.current_kind() {
            Some(TokenKind::String(s)) => {
                let v = s.clone();
                self.advance();
                Ok(LogLineValue::Str(v))
            }
            Some(TokenKind::Number(n)) => {
                let v = *n;
                self.advance();
                Ok(LogLineValue::Num(v))
            }
            Some(TokenKind::Boolean(b)) => {
                let v = *b;
                self.advance();
                Ok(LogLineValue::Bool(v))
            }
            Some(TokenKind::Identifier(_)) => {
                // Collect all tokens until newline as a string
                let mut parts = Vec::new();
                while let Some(kind) = self.current_kind() {
                    match kind {
                        TokenKind::Newline | TokenKind::End | TokenKind::Eof => break,
                        TokenKind::LeftBrace | TokenKind::LeftBracket => break,
                        TokenKind::RightBrace | TokenKind::RightBracket | TokenKind::Comma => break,
                        TokenKind::Identifier(s) => {
                            parts.push(s.clone());
                            self.advance();
                        }
                        TokenKind::String(s) => {
                            parts.push(s.clone());
                            self.advance();
                        }
                        TokenKind::Number(n) => {
                            parts.push(n.to_string());
                            self.advance();
                        }
                        TokenKind::Boolean(b) => {
                            parts.push(b.to_string());
                            self.advance();
                        }
                        TokenKind::Colon => {
                            parts.push(":".to_string());
                            self.advance();
                        }
                        _ => {
                            self.advance();
                        }
                    }
                }
                Ok(LogLineValue::Str(parts.join(" ")))
            }
            Some(TokenKind::LeftBrace) => {
                self.depth += 1;
                let result = self.parse_object();
                self.depth -= 1;
                result
            }
            Some(TokenKind::LeftBracket) => {
                self.depth += 1;
                let result = self.parse_array();
                self.depth -= 1;
                result
            }
            Some(TokenKind::Newline) => {
                // Empty value = empty string
                Ok(LogLineValue::Str(String::new()))
            }
            _ => {
                // Default to empty string for missing values
                Ok(LogLineValue::Str(String::new()))
            }
        }
    }
    
    /// Parse an object { KEY: value, ... }
    fn parse_object(&mut self) -> Result<LogLineValue, ParseError> {
        // Expect {
        if !matches!(self.current_kind(), Some(TokenKind::LeftBrace)) {
            return Err(ParseError::UnexpectedToken {
                expected: "'{'".to_string(),
                found: self.current_kind().map(|k| k.to_string()).unwrap_or_default(),
                span: self.current().map(|t| t.span).unwrap_or_default(),
            });
        }
        self.advance();
        
        let mut fields = Vec::new();
        
        loop {
            self.skip_whitespace();
            
            match self.current_kind() {
                Some(TokenKind::RightBrace) => {
                    self.advance();
                    break;
                }
                Some(TokenKind::Eof) | None => {
                    return Err(ParseError::UnexpectedEof {
                        pos: self.tokens.last().map(|t| t.span.end).unwrap_or_default(),
                    });
                }
                Some(TokenKind::Identifier(_)) => {
                    let (key, value) = self.parse_param()?;
                    fields.push((key, value));
                    
                    // Optional comma
                    self.skip_whitespace();
                    if matches!(self.current_kind(), Some(TokenKind::Comma)) {
                        self.advance();
                    }
                }
                _ => {
                    self.advance(); // Skip unexpected
                }
            }
        }
        
        Ok(LogLineValue::Object(fields))
    }
    
    /// Parse an array [ value, value, ... ]
    fn parse_array(&mut self) -> Result<LogLineValue, ParseError> {
        // Expect [
        if !matches!(self.current_kind(), Some(TokenKind::LeftBracket)) {
            return Err(ParseError::UnexpectedToken {
                expected: "'['".to_string(),
                found: self.current_kind().map(|k| k.to_string()).unwrap_or_default(),
                span: self.current().map(|t| t.span).unwrap_or_default(),
            });
        }
        self.advance();
        
        let mut items = Vec::new();
        
        loop {
            self.skip_whitespace();
            
            match self.current_kind() {
                Some(TokenKind::RightBracket) => {
                    self.advance();
                    break;
                }
                Some(TokenKind::Eof) | None => {
                    return Err(ParseError::UnexpectedEof {
                        pos: self.tokens.last().map(|t| t.span.end).unwrap_or_default(),
                    });
                }
                _ => {
                    let value = self.parse_value()?;
                    items.push(value);
                    
                    // Optional comma
                    self.skip_whitespace();
                    if matches!(self.current_kind(), Some(TokenKind::Comma)) {
                        self.advance();
                    }
                }
            }
        }
        
        Ok(LogLineValue::List(items))
    }
}

/// Parse a LogLine document from source text
pub fn parse_logline(input: &str) -> Result<LogLineSpan, ParseError> {
    if input.trim().is_empty() {
        return Err(ParseError::EmptyInput);
    }
    
    let mut parser = Parser::from_source(input)?;
    parser.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_parse() {
        let input = "JOB: test\nEND";
        let result = parse_logline(input).unwrap();
        assert_eq!(result.r#type, "job");
        assert_eq!(result.name, Some("test".to_string()));
    }

    #[test]
    fn test_parse_with_params() {
        let input = r#"JOB: fix-bug
  GOAL: Fix the login error
  PRIORITY: high
END"#;
        let result = parse_logline(input).unwrap();
        assert_eq!(result.r#type, "job");
        assert_eq!(result.name, Some("fix-bug".to_string()));
        assert_eq!(result.get_str("goal"), Some("Fix the login error"));
        assert_eq!(result.get_str("priority"), Some("high"));
    }

    #[test]
    fn test_parse_with_numbers() {
        let input = r#"JOB: test
  TOKENS: 50000
  STEPS: 20
END"#;
        let result = parse_logline(input).unwrap();
        assert_eq!(result.get_num("tokens"), Some(50000.0));
        assert_eq!(result.get_num("steps"), Some(20.0));
    }

    #[test]
    fn test_parse_with_object() {
        let input = r#"JOB: test
  BUDGET: {
    TOKENS: 50000
    STEPS: 20
  }
END"#;
        let result = parse_logline(input).unwrap();
        let budget = result.get("budget").unwrap();
        assert!(budget.is_object());
        assert_eq!(budget.get("tokens").unwrap().as_num(), Some(50000.0));
        assert_eq!(budget.get("steps").unwrap().as_num(), Some(20.0));
    }

    #[test]
    fn test_parse_with_array() {
        let input = r#"JOB: test
  TAGS: [urgent, security, backend]
END"#;
        let result = parse_logline(input).unwrap();
        let tags = result.get("tags").unwrap();
        assert!(tags.is_list());
        let list = tags.as_list().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].as_str(), Some("urgent"));
    }

    #[test]
    fn test_parse_nested_object() {
        let input = r#"JOB: test
  CONFIG: {
    LIMITS: {
      MAX_FILES: 5
      MAX_LINES: 200
    }
  }
END"#;
        let result = parse_logline(input).unwrap();
        let config = result.get("config").unwrap();
        let limits = config.get("limits").unwrap();
        assert_eq!(limits.get("max_files").unwrap().as_num(), Some(5.0));
    }

    #[test]
    fn test_parse_empty_fails() {
        let result = parse_logline("");
        assert!(matches!(result, Err(ParseError::EmptyInput)));
    }

    #[test]
    fn test_parse_missing_end() {
        let input = "JOB: test\n  GOAL: something";
        let result = parse_logline(input);
        assert!(matches!(result, Err(ParseError::MissingEnd)));
    }

    #[test]
    fn test_roundtrip() {
        let input = r#"JOB: test
  GOAL: Fix the bug
  TOKENS: 50000
END"#;
        let parsed = parse_logline(input).unwrap();
        assert_eq!(parsed.name, Some("test".to_string()));
        assert_eq!(parsed.get_str("goal"), Some("Fix the bug"));
        assert_eq!(parsed.get_num("tokens"), Some(50000.0));
    }
}
