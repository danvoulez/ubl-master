//! Advanced query capabilities for the ChipStore

use crate::StoredChip;
use serde::{Deserialize, Serialize};

/// Advanced query builder for complex chip lookups
pub struct ChipQueryBuilder {
    chip_type: Option<String>,
    tags: Vec<String>,
    created_after: Option<String>,
    created_before: Option<String>,
    executor_did: Option<String>,
    has_tags: Vec<String>,
    excludes_tags: Vec<String>,
    related_to: Option<String>,
    fuel_consumed_min: Option<u64>,
    fuel_consumed_max: Option<u64>,
    execution_time_min: Option<i64>,
    execution_time_max: Option<i64>,
    limit: Option<usize>,
    offset: Option<usize>,
    sort_by: Option<SortField>,
    sort_order: SortOrder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortField {
    CreatedAt,
    ExecutionTime,
    FuelConsumed,
    ChipType,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum SortOrder {
    Ascending,
    #[default]
    Descending,
}

impl ChipQueryBuilder {
    pub fn new() -> Self {
        Self {
            chip_type: None,
            tags: Vec::new(),
            created_after: None,
            created_before: None,
            executor_did: None,
            has_tags: Vec::new(),
            excludes_tags: Vec::new(),
            related_to: None,
            fuel_consumed_min: None,
            fuel_consumed_max: None,
            execution_time_min: None,
            execution_time_max: None,
            limit: None,
            offset: None,
            sort_by: None,
            sort_order: SortOrder::Descending,
        }
    }

    pub fn chip_type<S: Into<String>>(mut self, chip_type: S) -> Self {
        self.chip_type = Some(chip_type.into());
        self
    }

    pub fn with_tag<S: Into<String>>(mut self, tag: S) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags.extend(tags.into_iter().map(|s| s.into()));
        self
    }

    pub fn created_after<S: Into<String>>(mut self, timestamp: S) -> Self {
        self.created_after = Some(timestamp.into());
        self
    }

    pub fn created_before<S: Into<String>>(mut self, timestamp: S) -> Self {
        self.created_before = Some(timestamp.into());
        self
    }

    pub fn executor<S: Into<String>>(mut self, executor_did: S) -> Self {
        self.executor_did = Some(executor_did.into());
        self
    }

    pub fn has_tag<S: Into<String>>(mut self, tag: S) -> Self {
        self.has_tags.push(tag.into());
        self
    }

    pub fn excludes_tag<S: Into<String>>(mut self, tag: S) -> Self {
        self.excludes_tags.push(tag.into());
        self
    }

    pub fn related_to<S: Into<String>>(mut self, cid: S) -> Self {
        self.related_to = Some(cid.into());
        self
    }

    pub fn fuel_consumed_between(mut self, min: u64, max: u64) -> Self {
        self.fuel_consumed_min = Some(min);
        self.fuel_consumed_max = Some(max);
        self
    }

    pub fn execution_time_between(mut self, min_ms: i64, max_ms: i64) -> Self {
        self.execution_time_min = Some(min_ms);
        self.execution_time_max = Some(max_ms);
        self
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    pub fn sort_by(mut self, field: SortField, order: SortOrder) -> Self {
        self.sort_by = Some(field);
        self.sort_order = order;
        self
    }

    pub fn matches(&self, chip: &StoredChip) -> bool {
        // Check chip type
        if let Some(ref chip_type) = self.chip_type {
            if chip.chip_type != *chip_type {
                return false;
            }
        }

        // Check required tags
        if !self.tags.is_empty() {
            let has_all_tags = self.tags.iter().all(|tag| chip.tags.contains(tag));
            if !has_all_tags {
                return false;
            }
        }

        // Check has_tags (alternative to tags for more specific matching)
        if !self.has_tags.is_empty() {
            let has_required_tags = self.has_tags.iter().all(|tag| chip.tags.contains(tag));
            if !has_required_tags {
                return false;
            }
        }

        // Check excluded tags
        if !self.excludes_tags.is_empty() {
            let has_excluded_tags = self.excludes_tags.iter().any(|tag| chip.tags.contains(tag));
            if has_excluded_tags {
                return false;
            }
        }

        // Check date range
        if let Some(ref after) = self.created_after {
            if chip.created_at <= *after {
                return false;
            }
        }

        if let Some(ref before) = self.created_before {
            if chip.created_at >= *before {
                return false;
            }
        }

        // Check executor
        if let Some(ref executor_did) = self.executor_did {
            if chip.execution_metadata.executor_did.as_str() != executor_did.as_str() {
                return false;
            }
        }

        // Check fuel consumption range
        if let Some(min_fuel) = self.fuel_consumed_min {
            if chip.execution_metadata.fuel_consumed < min_fuel {
                return false;
            }
        }

        if let Some(max_fuel) = self.fuel_consumed_max {
            if chip.execution_metadata.fuel_consumed > max_fuel {
                return false;
            }
        }

        // Check execution time range
        if let Some(min_time) = self.execution_time_min {
            if chip.execution_metadata.execution_time_ms < min_time {
                return false;
            }
        }

        if let Some(max_time) = self.execution_time_max {
            if chip.execution_metadata.execution_time_ms > max_time {
                return false;
            }
        }

        // Check related chips
        if let Some(ref related_cid) = self.related_to {
            if !chip.related_chips.contains(related_cid) {
                return false;
            }
        }

        true
    }

    pub fn sort_chips(&self, chips: &mut [StoredChip]) {
        if let Some(ref sort_field) = self.sort_by {
            match sort_field {
                SortField::CreatedAt => {
                    chips.sort_by(|a, b| match self.sort_order {
                        SortOrder::Ascending => a.created_at.cmp(&b.created_at),
                        SortOrder::Descending => b.created_at.cmp(&a.created_at),
                    });
                }
                SortField::ExecutionTime => {
                    chips.sort_by(|a, b| match self.sort_order {
                        SortOrder::Ascending => a
                            .execution_metadata
                            .execution_time_ms
                            .cmp(&b.execution_metadata.execution_time_ms),
                        SortOrder::Descending => b
                            .execution_metadata
                            .execution_time_ms
                            .cmp(&a.execution_metadata.execution_time_ms),
                    });
                }
                SortField::FuelConsumed => {
                    chips.sort_by(|a, b| match self.sort_order {
                        SortOrder::Ascending => a
                            .execution_metadata
                            .fuel_consumed
                            .cmp(&b.execution_metadata.fuel_consumed),
                        SortOrder::Descending => b
                            .execution_metadata
                            .fuel_consumed
                            .cmp(&a.execution_metadata.fuel_consumed),
                    });
                }
                SortField::ChipType => {
                    chips.sort_by(|a, b| match self.sort_order {
                        SortOrder::Ascending => a.chip_type.cmp(&b.chip_type),
                        SortOrder::Descending => b.chip_type.cmp(&a.chip_type),
                    });
                }
            }
        } else {
            // Default sort by creation time, newest first
            chips.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        }
    }
}

impl Default for ChipQueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Predefined common queries
pub struct CommonQueries;

impl CommonQueries {
    /// Get all customer registrations
    pub fn customers() -> ChipQueryBuilder {
        ChipQueryBuilder::new().chip_type("ubl/customer.register")
    }

    /// Get all email sends in the last 24 hours
    pub fn recent_emails() -> ChipQueryBuilder {
        let yesterday = chrono::Utc::now() - chrono::Duration::hours(24);
        ChipQueryBuilder::new()
            .chip_type("ubl/email.send")
            .created_after(yesterday.to_rfc3339())
    }

    /// Get all failed operations
    pub fn failed_operations() -> ChipQueryBuilder {
        ChipQueryBuilder::new().with_tag("status:failed")
    }

    /// Get high fuel consumption operations
    pub fn expensive_operations(min_fuel: u64) -> ChipQueryBuilder {
        ChipQueryBuilder::new()
            .fuel_consumed_between(min_fuel, u64::MAX)
            .sort_by(SortField::FuelConsumed, SortOrder::Descending)
    }

    /// Get operations by a specific user
    pub fn user_operations(user_id: &str) -> ChipQueryBuilder {
        ChipQueryBuilder::new().with_tag(format!("user:{}", user_id))
    }

    /// Get all payments
    pub fn payments() -> ChipQueryBuilder {
        ChipQueryBuilder::new()
            .chip_type("ubl/payment.charge")
            .sort_by(SortField::CreatedAt, SortOrder::Descending)
    }

    /// Get audit trail for compliance
    pub fn audit_trail(start_date: &str, end_date: &str) -> ChipQueryBuilder {
        ChipQueryBuilder::new()
            .created_after(start_date.to_string())
            .created_before(end_date.to_string())
            .sort_by(SortField::CreatedAt, SortOrder::Ascending)
    }
}
