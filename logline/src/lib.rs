//! LogLine Parser and Serializer
//!
//! A complete implementation for parsing and serializing LogLine documents,
//! the structured text format used throughout the TDLN system.
//!
//! # LogLine Format
//!
//! ```text
//! TYPE: name
//!   KEY: value
//!   NESTED: {
//!     INNER: value
//!   }
//!   LIST: [item1, item2, item3]
//! END
//! ```
//!
//! # Example
//!
//! ```
//! use logline::{parse_logline, serialize_logline, LogLineSpan, LogLineValue};
//!
//! // Parse a LogLine document
//! let input = r#"JOB: fix-bug-123
//!   GOAL: Fix the login error
//!   BUDGET: {
//!     TOKENS: 50000
//!     STEPS: 20
//!   }
//!   TAGS: [urgent, security]
//! END"#;
//!
//! let span = parse_logline(input).unwrap();
//! assert_eq!(span.name, Some("fix-bug-123".to_string()));
//! assert_eq!(span.get_str("goal"), Some("Fix the login error"));
//!
//! // Access nested values
//! let budget = span.get("budget").unwrap();
//! assert_eq!(budget.get("tokens").unwrap().as_num(), Some(50000.0));
//!
//! // Serialize back to text
//! let output = serialize_logline(&span);
//! assert!(output.contains("JOB: fix-bug-123"));
//! ```
//!
//! # Building LogLine Documents
//!
//! ```
//! use logline::{LogLineSpan, LogLineValue, LogLineBuilder};
//!
//! // Using the builder pattern
//! let output = LogLineBuilder::new("job")
//!     .name("my-job")
//!     .str("goal", "Do something")
//!     .num("tokens", 10000.0)
//!     .to_string();
//!
//! // Or using the span directly
//! let span = LogLineSpan::new("result")
//!     .with_name("success")
//!     .with_str("message", "Task completed")
//!     .with_bool("success", true);
//! ```

pub mod ast;
pub mod error;
pub mod parser;
pub mod position;
pub mod serializer;
pub mod token;
pub mod tokenizer;

// Re-exports
pub use ast::{LogLineSpan, LogLineValue};
pub use error::ParseError;
pub use parser::parse_logline;
pub use position::{Position, Span};
pub use serializer::{serialize_logline, serialize_with_options, SerializeOptions, LogLineBuilder};
pub use token::{Token, TokenKind};
pub use tokenizer::Tokenizer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_roundtrip() {
        let input = r#"JOB: fix-bug-123
  GOAL: Fix the login error in auth module
  BUDGET: {
    TOKENS: 50000
    STEPS: 20
    TIMEOUT_MS: 60000
  }
  TAGS: [urgent, security, backend]
  PRIORITY: high
  URGENT: true
END"#;

        // Parse
        let span = parse_logline(input).unwrap();
        assert_eq!(span.r#type, "job");
        assert_eq!(span.name, Some("fix-bug-123".to_string()));
        assert_eq!(span.get_str("goal"), Some("Fix the login error in auth module"));
        assert_eq!(span.get_str("priority"), Some("high"));
        assert_eq!(span.get_bool("urgent"), Some(true));

        // Check nested object
        let budget = span.get("budget").unwrap();
        assert_eq!(budget.get("tokens").unwrap().as_num(), Some(50000.0));
        assert_eq!(budget.get("steps").unwrap().as_num(), Some(20.0));

        // Check array
        let tags = span.get("tags").unwrap().as_list().unwrap();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].as_str(), Some("urgent"));

        // Serialize and re-parse
        let serialized = serialize_logline(&span);
        let reparsed = parse_logline(&serialized).unwrap();
        
        assert_eq!(reparsed.r#type, span.r#type);
        assert_eq!(reparsed.name, span.name);
        assert_eq!(reparsed.get_str("goal"), span.get_str("goal"));
    }

    #[test]
    fn test_builder_with_complex_values() {
        let span = LogLineBuilder::new("result")
            .name("task-complete")
            .str("status", "success")
            .num("duration_ms", 1234.0)
            .bool("cached", false)
            .list("files", vec![
                LogLineValue::Str("src/main.rs".to_string()),
                LogLineValue::Str("src/lib.rs".to_string()),
            ])
            .object("stats", vec![
                ("lines_added".to_string(), LogLineValue::Num(42.0)),
                ("lines_removed".to_string(), LogLineValue::Num(10.0)),
            ])
            .build();

        assert_eq!(span.r#type, "result");
        assert_eq!(span.name, Some("task-complete".to_string()));
        assert_eq!(span.get_str("status"), Some("success"));
        
        let files = span.get("files").unwrap().as_list().unwrap();
        assert_eq!(files.len(), 2);
        
        let stats = span.get("stats").unwrap();
        assert_eq!(stats.get("lines_added").unwrap().as_num(), Some(42.0));
    }

    #[test]
    fn test_error_messages() {
        let input = "JOB: test\n  GOAL: something";
        let result = parse_logline(input);
        
        match result {
            Err(ParseError::MissingEnd) => {
                // Expected
            }
            other => panic!("Expected MissingEnd, got {:?}", other),
        }
    }

    #[test]
    fn test_deeply_nested() {
        let input = r#"JOB: test
  CONFIG: {
    LEVEL1: {
      LEVEL2: {
        LEVEL3: {
          VALUE: deep
        }
      }
    }
  }
END"#;

        let span = parse_logline(input).unwrap();
        let config = span.get("config").unwrap();
        let l1 = config.get("level1").unwrap();
        let l2 = l1.get("level2").unwrap();
        let l3 = l2.get("level3").unwrap();
        assert_eq!(l3.get("value").unwrap().as_str(), Some("deep"));
    }
}
