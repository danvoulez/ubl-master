use crate::capability;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ubl_chipstore::{ChipStore, ChipStoreError, StoredChip};

pub const TYPE_AUDIT_REPORT_REQUEST_V1: &str = "audit/report.request.v1";
pub const TYPE_AUDIT_LEDGER_SNAPSHOT_REQUEST_V1: &str = "audit/ledger.snapshot.request.v1";
pub const TYPE_LEDGER_SEGMENT_COMPACT_V1: &str = "ledger/segment.compact.v1";
pub const TYPE_AUDIT_ADVISORY_REQUEST_V1: &str = "audit/advisory.request.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRequest {
    pub window: Option<String>,
    pub range: Option<TimeRange>,
    pub format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRequest {
    pub range: TimeRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentSource {
    pub path: String,
    pub sha256: String,
    pub lines: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactRequest {
    pub range: TimeRange,
    pub snapshot_ref: String,
    pub source_segments: Vec<SegmentSource>,
    pub mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryRequest {
    pub subject_kind: String,
    pub subject_receipt_cid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditRequest {
    Report(ReportRequest),
    Snapshot(SnapshotRequest),
    Compact(CompactRequest),
    Advisory(AdvisoryRequest),
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("invalid chip body: {0}")]
    InvalidBody(String),
    #[error("invalid field: {0}")]
    InvalidField(String),
    #[error("capability check failed: {0}")]
    Capability(String),
    #[error("chipstore query failed: {0}")]
    ChipStore(String),
    #[error("chipstore required for audit validation")]
    ChipStoreRequired,
    #[error("snapshot overlap detected for range {0}..{1}")]
    SnapshotOverlap(String, String),
    #[error("snapshot reference not found: {0}")]
    SnapshotRefNotFound(String),
    #[error("snapshot reference type mismatch: expected {expected}, got {got}")]
    SnapshotRefTypeMismatch { expected: String, got: String },
    #[error("snapshot range does not cover compact range")]
    SnapshotDoesNotCoverRange,
    #[error("subject receipt not found: {0}")]
    SubjectReceiptNotFound(String),
}

fn chipstore_err(err: ChipStoreError) -> AuditError {
    AuditError::ChipStore(err.to_string())
}

pub fn is_audit_request_type(chip_type: &str) -> bool {
    matches!(
        chip_type,
        TYPE_AUDIT_REPORT_REQUEST_V1
            | TYPE_AUDIT_LEDGER_SNAPSHOT_REQUEST_V1
            | TYPE_LEDGER_SEGMENT_COMPACT_V1
            | TYPE_AUDIT_ADVISORY_REQUEST_V1
    )
}

pub fn parse_request(chip_type: &str, body: &Value) -> Result<AuditRequest, AuditError> {
    match chip_type {
        TYPE_AUDIT_REPORT_REQUEST_V1 => Ok(AuditRequest::Report(parse_report_request(body)?)),
        TYPE_AUDIT_LEDGER_SNAPSHOT_REQUEST_V1 => {
            Ok(AuditRequest::Snapshot(parse_snapshot_request(body)?))
        }
        TYPE_LEDGER_SEGMENT_COMPACT_V1 => Ok(AuditRequest::Compact(parse_compact_request(body)?)),
        TYPE_AUDIT_ADVISORY_REQUEST_V1 => Ok(AuditRequest::Advisory(parse_advisory_request(body)?)),
        _ => Err(AuditError::InvalidField(format!(
            "unsupported audit chip type '{}'",
            chip_type
        ))),
    }
}

pub async fn validate_request_for_check(
    chip_type: &str,
    body: &Value,
    world: &str,
    chip_store: Option<&ChipStore>,
) -> Result<AuditRequest, AuditError> {
    let parsed = parse_request(chip_type, body)?;
    match &parsed {
        AuditRequest::Report(req) => {
            capability::require_cap(body, "audit:report", world)
                .map_err(|e| AuditError::Capability(e.to_string()))?;
            if let Some(format) = &req.format {
                if !matches!(format.as_str(), "ndjson" | "csv" | "pdf") {
                    return Err(AuditError::InvalidField(format!(
                        "format must be one of ndjson|csv|pdf, got '{}'",
                        format
                    )));
                }
            }
        }
        AuditRequest::Snapshot(req) => {
            capability::require_cap(body, "audit:snapshot", world)
                .map_err(|e| AuditError::Capability(e.to_string()))?;
            let store = chip_store.ok_or(AuditError::ChipStoreRequired)?;
            ensure_no_snapshot_overlap(store, world, &req.range, body).await?;
        }
        AuditRequest::Compact(req) => {
            capability::require_cap(body, "ledger:compact", world)
                .map_err(|e| AuditError::Capability(e.to_string()))?;
            let store = chip_store.ok_or(AuditError::ChipStoreRequired)?;
            ensure_snapshot_reference_covers_range(store, &req.snapshot_ref, &req.range).await?;
            validate_source_segments(&req.source_segments)?;
        }
        AuditRequest::Advisory(req) => {
            capability::require_cap(body, "audit:advisory", world)
                .map_err(|e| AuditError::Capability(e.to_string()))?;
            validate_advisory_inputs(body)?;
            let store = chip_store.ok_or(AuditError::ChipStoreRequired)?;
            let subject = store
                .get_chip_by_receipt_cid(&req.subject_receipt_cid)
                .await
                .map_err(chipstore_err)?;
            if subject.is_none() {
                return Err(AuditError::SubjectReceiptNotFound(
                    req.subject_receipt_cid.clone(),
                ));
            }
        }
    }
    Ok(parsed)
}

fn parse_report_request(body: &Value) -> Result<ReportRequest, AuditError> {
    let window = body
        .get("window")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    if let Some(w) = &window {
        parse_window(w)?;
    }

    let range = match body.get("range") {
        Some(range_val) => Some(parse_range(range_val)?),
        None => match (body.get("start"), body.get("end")) {
            (Some(start), Some(end)) => {
                let range = serde_json::json!({ "start": start, "end": end });
                Some(parse_range(&range)?)
            }
            _ => None,
        },
    };
    if window.is_none() && range.is_none() {
        return Err(AuditError::InvalidField(
            "report request requires either window or range".to_string(),
        ));
    }

    let format = body
        .get("format")
        .and_then(Value::as_str)
        .map(|s| s.to_string());
    Ok(ReportRequest {
        window,
        range,
        format,
    })
}

fn parse_snapshot_request(body: &Value) -> Result<SnapshotRequest, AuditError> {
    let range_val = body
        .get("range")
        .ok_or_else(|| AuditError::InvalidField("missing range".to_string()))?;
    let range = parse_range(range_val)?;
    Ok(SnapshotRequest { range })
}

fn parse_compact_request(body: &Value) -> Result<CompactRequest, AuditError> {
    let range_val = body
        .get("range")
        .ok_or_else(|| AuditError::InvalidField("missing range".to_string()))?;
    let range = parse_range(range_val)?;
    let snapshot_ref = body
        .get("snapshot_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidField("missing snapshot_ref".to_string()))?
        .to_string();
    if !snapshot_ref.starts_with("b3:") {
        return Err(AuditError::InvalidField(
            "snapshot_ref must be CID-like (b3:...)".to_string(),
        ));
    }

    let mode = body
        .get("mode")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidField("missing mode".to_string()))?
        .to_string();
    if !matches!(mode.as_str(), "archive_then_delete" | "delete_with_rollup") {
        return Err(AuditError::InvalidField(
            "mode must be archive_then_delete|delete_with_rollup".to_string(),
        ));
    }

    let mut source_segments = Vec::new();
    let segments = body
        .get("source_segments")
        .and_then(Value::as_array)
        .ok_or_else(|| AuditError::InvalidField("missing source_segments".to_string()))?;
    if segments.is_empty() {
        return Err(AuditError::InvalidField(
            "source_segments cannot be empty".to_string(),
        ));
    }
    for (idx, segment) in segments.iter().enumerate() {
        let path = segment
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| AuditError::InvalidField(format!("source_segments[{}].path", idx)))?
            .to_string();
        let sha256 = segment
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| AuditError::InvalidField(format!("source_segments[{}].sha256", idx)))?
            .to_string();
        let lines = segment
            .get("lines")
            .and_then(Value::as_u64)
            .ok_or_else(|| AuditError::InvalidField(format!("source_segments[{}].lines", idx)))?;
        source_segments.push(SegmentSource {
            path,
            sha256,
            lines,
        });
    }
    validate_source_segments(&source_segments)?;

    Ok(CompactRequest {
        range,
        snapshot_ref,
        source_segments,
        mode,
    })
}

fn parse_advisory_request(body: &Value) -> Result<AdvisoryRequest, AuditError> {
    let subject = body
        .get("subject")
        .ok_or_else(|| AuditError::InvalidField("missing subject".to_string()))?;
    let subject_kind = subject
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidField("subject.kind".to_string()))?
        .to_string();
    if !matches!(subject_kind.as_str(), "report" | "snapshot") {
        return Err(AuditError::InvalidField(
            "subject.kind must be report|snapshot".to_string(),
        ));
    }
    let subject_receipt_cid = subject
        .get("receipt_cid")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidField("subject.receipt_cid".to_string()))?
        .to_string();
    if !subject_receipt_cid.starts_with("b3:") {
        return Err(AuditError::InvalidField(
            "subject.receipt_cid must be CID-like (b3:...)".to_string(),
        ));
    }

    Ok(AdvisoryRequest {
        subject_kind,
        subject_receipt_cid,
    })
}

fn parse_range(value: &Value) -> Result<TimeRange, AuditError> {
    let start = value
        .get("start")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidField("range.start missing".to_string()))?;
    let end = value
        .get("end")
        .and_then(Value::as_str)
        .ok_or_else(|| AuditError::InvalidField("range.end missing".to_string()))?;
    let start = DateTime::parse_from_rfc3339(start)
        .map_err(|e| AuditError::InvalidField(format!("range.start invalid RFC-3339: {}", e)))?
        .with_timezone(&Utc);
    let end = DateTime::parse_from_rfc3339(end)
        .map_err(|e| AuditError::InvalidField(format!("range.end invalid RFC-3339: {}", e)))?
        .with_timezone(&Utc);
    if end <= start {
        return Err(AuditError::InvalidField(
            "range.end must be greater than range.start".to_string(),
        ));
    }
    Ok(TimeRange { start, end })
}

fn parse_window(window: &str) -> Result<(), AuditError> {
    if window.is_empty() {
        return Err(AuditError::InvalidField(
            "window cannot be empty".to_string(),
        ));
    }
    let (num, unit) = window.split_at(window.len().saturating_sub(1));
    let value = num
        .parse::<u64>()
        .map_err(|_| AuditError::InvalidField("window must be like 30s|5m|1h".to_string()))?;
    if value == 0 {
        return Err(AuditError::InvalidField(
            "window must be greater than zero".to_string(),
        ));
    }
    if !matches!(unit, "s" | "S" | "m" | "M" | "h" | "H") {
        return Err(AuditError::InvalidField(
            "window unit must be s|m|h".to_string(),
        ));
    }
    Ok(())
}

fn ranges_overlap(a: &TimeRange, b: &TimeRange) -> bool {
    a.start <= b.end && b.start <= a.end
}

fn range_covers(outer: &TimeRange, inner: &TimeRange) -> bool {
    outer.start <= inner.start && outer.end >= inner.end
}

fn validate_source_segments(source_segments: &[SegmentSource]) -> Result<(), AuditError> {
    for (idx, segment) in source_segments.iter().enumerate() {
        if segment.path.trim().is_empty() {
            return Err(AuditError::InvalidField(format!(
                "source_segments[{}].path cannot be empty",
                idx
            )));
        }
        if segment.lines == 0 {
            return Err(AuditError::InvalidField(format!(
                "source_segments[{}].lines must be > 0",
                idx
            )));
        }
        let is_hex =
            segment.sha256.len() == 64 && segment.sha256.chars().all(|c| c.is_ascii_hexdigit());
        if !is_hex {
            return Err(AuditError::InvalidField(format!(
                "source_segments[{}].sha256 must be 64 hex chars",
                idx
            )));
        }
    }
    Ok(())
}

fn validate_advisory_inputs(body: &Value) -> Result<(), AuditError> {
    let Some(inputs) = body.get("inputs") else {
        return Ok(());
    };
    let inputs = inputs
        .as_object()
        .ok_or_else(|| AuditError::InvalidField("inputs must be object".to_string()))?;
    for key in inputs.keys() {
        if !matches!(key.as_str(), "dataset_cid" | "histograms_cid" | "hll_cid") {
            return Err(AuditError::InvalidField(format!(
                "inputs.{} not allowed; only aggregate CIDs are accepted",
                key
            )));
        }
    }
    Ok(())
}

async fn ensure_no_snapshot_overlap(
    store: &ChipStore,
    world: &str,
    requested_range: &TimeRange,
    body: &Value,
) -> Result<(), AuditError> {
    let existing = store
        .get_chips_by_type(TYPE_AUDIT_LEDGER_SNAPSHOT_REQUEST_V1)
        .await
        .map_err(chipstore_err)?;
    let requested_id = body.get("@id").and_then(Value::as_str);

    for chip in existing {
        if chip
            .chip_data
            .get("@world")
            .and_then(Value::as_str)
            .map(|w| w != world)
            .unwrap_or(false)
        {
            continue;
        }
        if requested_id.is_some()
            && chip
                .chip_data
                .get("@id")
                .and_then(Value::as_str)
                .and_then(|id| requested_id.map(|rid| rid == id))
                .unwrap_or(false)
        {
            continue;
        }
        let Ok(existing_req) = parse_snapshot_request(&chip.chip_data) else {
            continue;
        };
        if ranges_overlap(requested_range, &existing_req.range) {
            return Err(AuditError::SnapshotOverlap(
                requested_range.start.to_rfc3339(),
                requested_range.end.to_rfc3339(),
            ));
        }
    }

    Ok(())
}

async fn ensure_snapshot_reference_covers_range(
    store: &ChipStore,
    snapshot_ref: &str,
    compact_range: &TimeRange,
) -> Result<(), AuditError> {
    let snapshot_chip = find_snapshot_chip_by_ref(store, snapshot_ref)
        .await?
        .ok_or_else(|| AuditError::SnapshotRefNotFound(snapshot_ref.to_string()))?;
    if snapshot_chip.chip_type != TYPE_AUDIT_LEDGER_SNAPSHOT_REQUEST_V1 {
        return Err(AuditError::SnapshotRefTypeMismatch {
            expected: TYPE_AUDIT_LEDGER_SNAPSHOT_REQUEST_V1.to_string(),
            got: snapshot_chip.chip_type,
        });
    }
    let snapshot_req = parse_snapshot_request(&snapshot_chip.chip_data)?;
    if !range_covers(&snapshot_req.range, compact_range) {
        return Err(AuditError::SnapshotDoesNotCoverRange);
    }
    Ok(())
}

async fn find_snapshot_chip_by_ref(
    store: &ChipStore,
    snapshot_ref: &str,
) -> Result<Option<StoredChip>, AuditError> {
    if let Some(chip) = store.get_chip(snapshot_ref).await.map_err(chipstore_err)? {
        return Ok(Some(chip));
    }
    if let Some(chip) = store
        .get_chip_by_receipt_cid(snapshot_ref)
        .await
        .map_err(chipstore_err)?
    {
        return Ok(Some(chip));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_report_window_or_range() {
        let report = parse_report_request(&json!({
            "window":"5m",
            "format":"ndjson"
        }))
        .unwrap();
        assert_eq!(report.window.as_deref(), Some("5m"));
        assert!(report.range.is_none());

        let report = parse_report_request(&json!({
            "range":{"start":"2026-02-18T00:00:00Z","end":"2026-02-18T01:00:00Z"}
        }))
        .unwrap();
        assert!(report.window.is_none());
        assert!(report.range.is_some());
    }

    #[test]
    fn parse_snapshot_requires_closed_range() {
        let err = parse_snapshot_request(&json!({
            "range":{"start":"2026-02-18T01:00:00Z","end":"2026-02-18T00:00:00Z"}
        }))
        .unwrap_err();
        assert!(err.to_string().contains("range.end must be greater"));
    }

    #[test]
    fn parse_compact_validates_mode_and_segments() {
        let err = parse_compact_request(&json!({
            "range":{"start":"2026-02-18T00:00:00Z","end":"2026-02-18T01:00:00Z"},
            "snapshot_ref":"b3:test",
            "mode":"invalid",
            "source_segments":[{"path":"seg","sha256":"00","lines":1}]
        }))
        .unwrap_err();
        assert!(err.to_string().contains("mode must be"));

        let err = parse_compact_request(&json!({
            "range":{"start":"2026-02-18T00:00:00Z","end":"2026-02-18T01:00:00Z"},
            "snapshot_ref":"b3:test",
            "mode":"archive_then_delete",
            "source_segments":[{"path":"seg","sha256":"00","lines":1}]
        }))
        .unwrap_err();
        assert!(err.to_string().contains("sha256"));
    }

    #[test]
    fn parse_advisory_subject_validates_kind() {
        let err = parse_advisory_request(&json!({
            "subject":{"kind":"raw","receipt_cid":"b3:abc"}
        }))
        .unwrap_err();
        assert!(err.to_string().contains("subject.kind"));
    }
}
