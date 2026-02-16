//! Error types for LogLine parsing

use crate::position::{Position, Span};
use thiserror::Error;

/// Errors that can occur during parsing
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unexpected token: expected {expected}, found {found} at {span}")]
    UnexpectedToken {
        expected: String,
        found: String,
        span: Span,
    },
    
    #[error("unexpected end of file at {pos}")]
    UnexpectedEof {
        pos: Position,
    },
    
    #[error("invalid number literal at {span}")]
    InvalidNumber {
        span: Span,
    },
    
    #[error("unterminated string at {span}")]
    UnterminatedString {
        span: Span,
    },
    
    #[error("invalid escape sequence at {pos}")]
    InvalidEscape {
        pos: Position,
    },
    
    #[error("invalid character '{ch}' at {pos}")]
    InvalidCharacter {
        ch: char,
        pos: Position,
    },
    
    #[error("missing END marker")]
    MissingEnd,
    
    #[error("empty input")]
    EmptyInput,
    
    #[error("invalid header: expected TYPE: NAME")]
    InvalidHeader,
    
    #[error("duplicate key '{key}' at {span}")]
    DuplicateKey {
        key: String,
        span: Span,
    },
    
    #[error("nesting too deep (max {max}) at {span}")]
    NestingTooDeep {
        max: usize,
        span: Span,
    },
}

impl ParseError {
    /// Create a formatted error message with source context
    pub fn format_with_source(&self, source: &str) -> String {
        let (span, message) = match self {
            ParseError::UnexpectedToken { span, expected, found } => {
                (*span, format!("Expected {}, found {}", expected, found))
            }
            ParseError::UnexpectedEof { pos } => {
                (Span::single(*pos), "Unexpected end of file".to_string())
            }
            ParseError::InvalidNumber { span } => {
                (*span, "Invalid number literal".to_string())
            }
            ParseError::UnterminatedString { span } => {
                (*span, "Unterminated string".to_string())
            }
            ParseError::InvalidEscape { pos } => {
                (Span::single(*pos), "Invalid escape sequence".to_string())
            }
            ParseError::InvalidCharacter { ch, pos } => {
                (Span::single(*pos), format!("Invalid character '{}'", ch))
            }
            ParseError::MissingEnd => {
                return "Error: missing END marker".to_string();
            }
            ParseError::EmptyInput => {
                return "Error: empty input".to_string();
            }
            ParseError::InvalidHeader => {
                return "Error: invalid header, expected TYPE: NAME".to_string();
            }
            ParseError::DuplicateKey { key, span } => {
                (*span, format!("Duplicate key '{}'", key))
            }
            ParseError::NestingTooDeep { max, span } => {
                (*span, format!("Nesting too deep (max {})", max))
            }
        };

        format!(
            "Error at {}: {}\n{}",
            span,
            message,
            format_source_context(source, span)
        )
    }
    
    /// Get the span where this error occurred
    pub fn span(&self) -> Option<Span> {
        match self {
            ParseError::UnexpectedToken { span, .. } => Some(*span),
            ParseError::UnexpectedEof { pos } => Some(Span::single(*pos)),
            ParseError::InvalidNumber { span } => Some(*span),
            ParseError::UnterminatedString { span } => Some(*span),
            ParseError::InvalidEscape { pos } => Some(Span::single(*pos)),
            ParseError::InvalidCharacter { pos, .. } => Some(Span::single(*pos)),
            ParseError::DuplicateKey { span, .. } => Some(*span),
            ParseError::NestingTooDeep { span, .. } => Some(*span),
            _ => None,
        }
    }
}

/// Format source context for error messages
fn format_source_context(source: &str, span: Span) -> String {
    let lines: Vec<&str> = source.lines().collect();
    
    if span.start.line == 0 || span.start.line > lines.len() {
        return String::new();
    }
    
    let line_idx = span.start.line - 1;
    let line = lines[line_idx];
    let line_num_width = span.start.line.to_string().len().max(3);
    
    let mut result = String::new();
    
    // Show line before for context if available
    if line_idx > 0 {
        result.push_str(&format!(
            "{:>width$} │ {}\n",
            span.start.line - 1,
            lines[line_idx - 1],
            width = line_num_width
        ));
    }
    
    // Show error line
    result.push_str(&format!(
        "{:>width$} │ {}\n",
        span.start.line,
        line,
        width = line_num_width
    ));
    
    // Show error pointer
    result.push_str(&" ".repeat(line_num_width));
    result.push_str(" │ ");
    result.push_str(&" ".repeat(span.start.column.saturating_sub(1)));
    
    let error_len = if span.start.line == span.end.line {
        (span.end.column - span.start.column).max(1)
    } else {
        1
    };
    
    result.push_str(&"^".repeat(error_len));
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = ParseError::EmptyInput;
        assert_eq!(format!("{}", error), "empty input");
    }

    #[test]
    fn test_error_with_context() {
        let source = "JOB: test\n  GOAL: build";
        let span = Span::new(
            Position::new(1, 1, 0),
            Position::new(1, 4, 3)
        );
        let error = ParseError::UnexpectedToken {
            expected: "colon".to_string(),
            found: "identifier".to_string(),
            span,
        };
        
        let formatted = error.format_with_source(source);
        assert!(formatted.contains("JOB: test"));
        assert!(formatted.contains("^^^"));
    }

    #[test]
    fn test_error_span() {
        let span = Span::single(Position::start());
        let error = ParseError::InvalidNumber { span };
        assert_eq!(error.span(), Some(span));
        
        let error = ParseError::EmptyInput;
        assert_eq!(error.span(), None);
    }
}

