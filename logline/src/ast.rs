//! Abstract Syntax Tree for LogLine
//!
//! Defines the data structures that represent parsed LogLine documents.

use serde::{Deserialize, Serialize};
use crate::position::Span;

/// A value in a LogLine document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum LogLineValue {
    /// String value
    Str(String),
    /// Numeric value
    Num(f64),
    /// Boolean value
    Bool(bool),
    /// List/array of values
    List(Vec<LogLineValue>),
    /// Nested object (key-value pairs)
    Object(Vec<(String, LogLineValue)>),
}

impl LogLineValue {
    /// Check if this value is a string
    pub fn is_string(&self) -> bool {
        matches!(self, LogLineValue::Str(_))
    }
    
    /// Check if this value is a number
    pub fn is_number(&self) -> bool {
        matches!(self, LogLineValue::Num(_))
    }
    
    /// Check if this value is a boolean
    pub fn is_bool(&self) -> bool {
        matches!(self, LogLineValue::Bool(_))
    }
    
    /// Check if this value is a list
    pub fn is_list(&self) -> bool {
        matches!(self, LogLineValue::List(_))
    }
    
    /// Check if this value is an object
    pub fn is_object(&self) -> bool {
        matches!(self, LogLineValue::Object(_))
    }
    
    /// Try to get as string
    pub fn as_str(&self) -> Option<&str> {
        match self {
            LogLineValue::Str(s) => Some(s),
            _ => None,
        }
    }
    
    /// Try to get as number
    pub fn as_num(&self) -> Option<f64> {
        match self {
            LogLineValue::Num(n) => Some(*n),
            _ => None,
        }
    }
    
    /// Try to get as boolean
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            LogLineValue::Bool(b) => Some(*b),
            _ => None,
        }
    }
    
    /// Try to get as list
    pub fn as_list(&self) -> Option<&[LogLineValue]> {
        match self {
            LogLineValue::List(l) => Some(l),
            _ => None,
        }
    }
    
    /// Try to get as object
    pub fn as_object(&self) -> Option<&[(String, LogLineValue)]> {
        match self {
            LogLineValue::Object(o) => Some(o),
            _ => None,
        }
    }
    
    /// Get a field from an object by key
    pub fn get(&self, key: &str) -> Option<&LogLineValue> {
        match self {
            LogLineValue::Object(fields) => {
                fields.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(key))
                    .map(|(_, v)| v)
            }
            _ => None,
        }
    }
}

/// A LogLine span (the main document structure)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogLineSpan {
    /// The type of span (JOB, TOOL, RESULT, etc.)
    pub r#type: String,
    /// Optional name/identifier
    pub name: Option<String>,
    /// Key-value parameters
    pub params: Vec<(String, LogLineValue)>,
    /// Source span (not serialized)
    #[serde(skip)]
    pub span: Option<Span>,
}

impl LogLineSpan {
    /// Create a new LogLine span
    pub fn new(r#type: impl Into<String>) -> Self {
        Self {
            r#type: r#type.into(),
            name: None,
            params: Vec::new(),
            span: None,
        }
    }
    
    /// Set the name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
    
    /// Add a parameter
    pub fn with_param(mut self, key: impl Into<String>, value: LogLineValue) -> Self {
        self.params.push((key.into(), value));
        self
    }
    
    /// Add a string parameter
    pub fn with_str(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((key.into(), LogLineValue::Str(value.into())));
        self
    }
    
    /// Add a number parameter
    pub fn with_num(mut self, key: impl Into<String>, value: f64) -> Self {
        self.params.push((key.into(), LogLineValue::Num(value)));
        self
    }
    
    /// Add a boolean parameter
    pub fn with_bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.params.push((key.into(), LogLineValue::Bool(value)));
        self
    }
    
    /// Get a parameter by key (case-insensitive)
    pub fn get(&self, key: &str) -> Option<&LogLineValue> {
        self.params.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v)
    }
    
    /// Get a string parameter
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }
    
    /// Get a number parameter
    pub fn get_num(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| v.as_num())
    }
    
    /// Get a boolean parameter
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }
    
    /// Check if a parameter exists
    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
    
    /// Get all parameter keys
    pub fn keys(&self) -> Vec<&str> {
        self.params.iter().map(|(k, _)| k.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_types() {
        let str_val = LogLineValue::Str("hello".to_string());
        assert!(str_val.is_string());
        assert_eq!(str_val.as_str(), Some("hello"));
        
        let num_val = LogLineValue::Num(42.0);
        assert!(num_val.is_number());
        assert_eq!(num_val.as_num(), Some(42.0));
        
        let bool_val = LogLineValue::Bool(true);
        assert!(bool_val.is_bool());
        assert_eq!(bool_val.as_bool(), Some(true));
        
        let list_val = LogLineValue::List(vec![LogLineValue::Num(1.0), LogLineValue::Num(2.0)]);
        assert!(list_val.is_list());
        assert_eq!(list_val.as_list().unwrap().len(), 2);
        
        let obj_val = LogLineValue::Object(vec![
            ("key".to_string(), LogLineValue::Str("value".to_string()))
        ]);
        assert!(obj_val.is_object());
        assert_eq!(obj_val.get("key").unwrap().as_str(), Some("value"));
    }

    #[test]
    fn test_span_builder() {
        let span = LogLineSpan::new("JOB")
            .with_name("test-job")
            .with_str("goal", "Fix the bug")
            .with_num("tokens", 50000.0)
            .with_bool("urgent", true);
        
        assert_eq!(span.r#type, "JOB");
        assert_eq!(span.name, Some("test-job".to_string()));
        assert_eq!(span.get_str("goal"), Some("Fix the bug"));
        assert_eq!(span.get_num("tokens"), Some(50000.0));
        assert_eq!(span.get_bool("urgent"), Some(true));
    }

    #[test]
    fn test_case_insensitive_get() {
        let span = LogLineSpan::new("JOB")
            .with_str("GOAL", "test");
        
        assert_eq!(span.get_str("goal"), Some("test"));
        assert_eq!(span.get_str("GOAL"), Some("test"));
        assert_eq!(span.get_str("Goal"), Some("test"));
    }
}
