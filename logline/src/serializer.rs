//! Serializer for LogLine documents
//!
//! Converts AST back to LogLine text format.

use crate::ast::{LogLineSpan, LogLineValue};

/// Options for serialization
#[derive(Debug, Clone)]
pub struct SerializeOptions {
    /// Base indentation string (default: 2 spaces)
    pub indent: String,
    /// Whether to uppercase keywords (default: true)
    pub uppercase_keywords: bool,
    /// Whether to quote string values (default: false, only when needed)
    pub quote_strings: bool,
}

impl Default for SerializeOptions {
    fn default() -> Self {
        Self {
            indent: "  ".to_string(),
            uppercase_keywords: true,
            quote_strings: false,
        }
    }
}

/// Serialize a LogLine span to text with default options
pub fn serialize_logline(span: &LogLineSpan) -> String {
    serialize_with_options(span, &SerializeOptions::default())
}

/// Serialize a LogLine span to text with custom options
pub fn serialize_with_options(span: &LogLineSpan, options: &SerializeOptions) -> String {
    let mut output = String::new();
    
    // Header
    let span_type = if options.uppercase_keywords {
        span.r#type.to_uppercase()
    } else {
        span.r#type.clone()
    };
    
    output.push_str(&span_type);
    output.push(':');
    
    if let Some(name) = &span.name {
        output.push(' ');
        if needs_quoting(name) {
            output.push('"');
            output.push_str(&escape_string(name));
            output.push('"');
        } else {
            output.push_str(name);
        }
    }
    output.push('\n');
    
    // Parameters
    for (key, value) in &span.params {
        output.push_str(&options.indent);
        if options.uppercase_keywords {
            output.push_str(&key.to_uppercase());
        } else {
            output.push_str(key);
        }
        output.push_str(": ");
        serialize_value(&mut output, value, &options.indent, 1, options);
        output.push('\n');
    }
    
    // END marker
    output.push_str("END");
    output
}

/// Serialize a value
fn serialize_value(
    output: &mut String,
    value: &LogLineValue,
    base_indent: &str,
    depth: usize,
    options: &SerializeOptions,
) {
    match value {
        LogLineValue::Str(s) => {
            if options.quote_strings || needs_quoting(s) {
                output.push('"');
                output.push_str(&escape_string(s));
                output.push('"');
            } else {
                output.push_str(s);
            }
        }
        LogLineValue::Num(n) => {
            if n.fract() == 0.0 && *n >= i64::MIN as f64 && *n <= i64::MAX as f64 {
                output.push_str(&(*n as i64).to_string());
            } else {
                output.push_str(&n.to_string());
            }
        }
        LogLineValue::Bool(b) => {
            output.push_str(if *b { "true" } else { "false" });
        }
        LogLineValue::List(items) => {
            output.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    output.push_str(", ");
                }
                serialize_value(output, item, base_indent, depth + 1, options);
            }
            output.push(']');
        }
        LogLineValue::Object(fields) => {
            output.push_str("{\n");
            
            let field_indent = base_indent.repeat(depth + 1);
            for (key, val) in fields {
                output.push_str(&field_indent);
                if options.uppercase_keywords {
                    output.push_str(&key.to_uppercase());
                } else {
                    output.push_str(key);
                }
                output.push_str(": ");
                serialize_value(output, val, base_indent, depth + 1, options);
                output.push('\n');
            }
            
            output.push_str(&base_indent.repeat(depth));
            output.push('}');
        }
    }
}

/// Check if a string needs quoting
fn needs_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    
    // Check for special characters
    s.chars().any(|c| {
        c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t'
            || c == '{' || c == '}' || c == '[' || c == ']' || c == ','
    })
}

/// Escape special characters in a string
fn escape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            _ => result.push(c),
        }
    }
    result
}

/// Builder pattern for creating LogLine documents
pub struct LogLineBuilder {
    span: LogLineSpan,
    options: SerializeOptions,
}

impl LogLineBuilder {
    /// Create a new builder with the given type
    pub fn new(r#type: impl Into<String>) -> Self {
        Self {
            span: LogLineSpan::new(r#type),
            options: SerializeOptions::default(),
        }
    }
    
    /// Set the name
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.span.name = Some(name.into());
        self
    }
    
    /// Add a string parameter
    pub fn str(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.span.params.push((key.into(), LogLineValue::Str(value.into())));
        self
    }
    
    /// Add a number parameter
    pub fn num(mut self, key: impl Into<String>, value: f64) -> Self {
        self.span.params.push((key.into(), LogLineValue::Num(value)));
        self
    }
    
    /// Add a boolean parameter
    pub fn bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.span.params.push((key.into(), LogLineValue::Bool(value)));
        self
    }
    
    /// Add a list parameter
    pub fn list(mut self, key: impl Into<String>, values: Vec<LogLineValue>) -> Self {
        self.span.params.push((key.into(), LogLineValue::List(values)));
        self
    }
    
    /// Add an object parameter
    pub fn object(mut self, key: impl Into<String>, fields: Vec<(String, LogLineValue)>) -> Self {
        self.span.params.push((key.into(), LogLineValue::Object(fields)));
        self
    }
    
    /// Build the span
    pub fn build(self) -> LogLineSpan {
        self.span
    }
    
    /// Build and serialize to string
    pub fn to_string(self) -> String {
        serialize_with_options(&self.span, &self.options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_logline;

    #[test]
    fn test_serialize_simple() {
        let span = LogLineSpan::new("job")
            .with_name("test");
        
        let output = serialize_logline(&span);
        assert!(output.contains("JOB: test"));
        assert!(output.contains("END"));
    }

    #[test]
    fn test_serialize_with_params() {
        let span = LogLineSpan::new("job")
            .with_name("test")
            .with_str("goal", "Fix the bug")
            .with_num("tokens", 50000.0);
        
        let output = serialize_logline(&span);
        assert!(output.contains("GOAL: Fix the bug"));
        assert!(output.contains("TOKENS: 50000"));
    }

    #[test]
    fn test_serialize_object() {
        let span = LogLineSpan::new("job")
            .with_param("budget", LogLineValue::Object(vec![
                ("tokens".to_string(), LogLineValue::Num(50000.0)),
                ("steps".to_string(), LogLineValue::Num(20.0)),
            ]));
        
        let output = serialize_logline(&span);
        assert!(output.contains("BUDGET: {"));
        assert!(output.contains("TOKENS: 50000"));
        assert!(output.contains("}"));
    }

    #[test]
    fn test_serialize_array() {
        let span = LogLineSpan::new("job")
            .with_param("tags", LogLineValue::List(vec![
                LogLineValue::Str("urgent".to_string()),
                LogLineValue::Str("security".to_string()),
            ]));
        
        let output = serialize_logline(&span);
        assert!(output.contains("TAGS: [urgent, security]"));
    }

    #[test]
    fn test_roundtrip() {
        let original = LogLineSpan::new("job")
            .with_name("test-job")
            .with_str("goal", "Fix the bug")
            .with_num("tokens", 50000.0)
            .with_bool("urgent", true);
        
        let serialized = serialize_logline(&original);
        let parsed = parse_logline(&serialized).unwrap();
        
        assert_eq!(parsed.r#type, original.r#type);
        assert_eq!(parsed.name, original.name);
        assert_eq!(parsed.get_str("goal"), original.get_str("goal"));
        assert_eq!(parsed.get_num("tokens"), original.get_num("tokens"));
    }

    #[test]
    fn test_builder() {
        let output = LogLineBuilder::new("job")
            .name("test")
            .str("goal", "Fix it")
            .num("tokens", 1000.0)
            .to_string();
        
        assert!(output.contains("JOB: test"));
        assert!(output.contains("GOAL: Fix it"));
        assert!(output.contains("TOKENS: 1000"));
    }

    #[test]
    fn test_escape_string() {
        assert_eq!(escape_string("hello"), "hello");
        assert_eq!(escape_string("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_string("say \"hi\""), "say \\\"hi\\\"");
    }
}
