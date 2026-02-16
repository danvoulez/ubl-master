use logline::{parse_logline, serialize_logline, LogLineValue};

#[test]
fn round_trip_basic() {
    let text = "OPERATION: demo\n  GOAL: build\nEND";
    let span = parse_logline(text).expect("parse");
    assert_eq!(span.r#type, "operation");
    assert_eq!(span.name.as_deref(), Some("demo"));
    assert_eq!(span.params.len(), 1);
    assert_eq!(span.params[0].1, LogLineValue::Str("build".into()));

    let serialized = serialize_logline(&span);
    assert!(serialized.contains("OPERATION"));
}
