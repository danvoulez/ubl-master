//! Policy Loader - loads policies from chip ancestry
//!
//! Implements the hierarchical policy loading:
//! chip → tenant → app → genesis

use crate::genesis::{create_genesis_policy, is_genesis_chip};
use crate::policy_bit::PolicyBit;
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy not found: {0}")]
    NotFound(String),
    #[error("Invalid policy format: {0}")]
    InvalidFormat(String),
    #[error("Circular dependency detected: {0}")]
    CircularDependency(String),
    #[error("Storage error: {0}")]
    Storage(String),
}

/// Trait for policy storage backends
#[async_trait::async_trait]
pub trait PolicyStorage: Send + Sync {
    /// Get a chip by its CID
    async fn get_chip(&self, cid: &str) -> Result<Option<ChipData>, PolicyError>;

    /// Query chips by type
    async fn query_by_type(&self, chip_type: &str) -> Result<Vec<ChipData>, PolicyError>;

    /// Find chips that have the given CID as parent
    async fn find_children(&self, parent_cid: &str) -> Result<Vec<ChipData>, PolicyError>;
}

/// Chip data from storage
#[derive(Debug, Clone)]
pub struct ChipData {
    pub cid: String,
    pub chip_type: String,
    pub body: Value,
    pub parents: Vec<String>,
}

/// Policy loader with ancestry resolution
pub struct PolicyLoader {
    storage: Box<dyn PolicyStorage>,
}

impl PolicyLoader {
    pub fn new(storage: Box<dyn PolicyStorage>) -> Self {
        Self { storage }
    }

    /// Load complete policy chain for a chip request
    pub async fn load_policy_chain(
        &self,
        chip_request: &ChipRequest,
    ) -> Result<Vec<PolicyBit>, PolicyError> {
        let mut policies = Vec::new();

        // 1. Always start with genesis policy
        policies.push(create_genesis_policy());

        // 2. Walk ancestry chain and collect policies
        let ancestry = self.resolve_ancestry(chip_request).await?;

        for ancestor_cid in ancestry {
            let attached_policies = self.find_attached_policies(&ancestor_cid).await?;
            policies.extend(attached_policies);
        }

        Ok(policies)
    }

    /// Resolve ancestry chain: chip → tenant → app → genesis
    async fn resolve_ancestry(
        &self,
        chip_request: &ChipRequest,
    ) -> Result<Vec<String>, PolicyError> {
        let mut ancestry = Vec::new();
        let mut visited = std::collections::HashSet::new();

        // Start with explicit parents from the chip request
        let mut current_parents = chip_request.parents.clone();

        while !current_parents.is_empty() {
            let mut next_parents = Vec::new();

            for parent_cid in current_parents {
                // Avoid circular dependencies
                if visited.contains(&parent_cid) {
                    return Err(PolicyError::CircularDependency(parent_cid));
                }
                visited.insert(parent_cid.clone());

                // Skip if this is genesis (we already added it)
                if is_genesis_chip(&parent_cid) {
                    continue;
                }

                // Add to ancestry
                ancestry.push(parent_cid.clone());

                // Get the parent chip to find its parents
                if let Some(parent_chip) = self.storage.get_chip(&parent_cid).await? {
                    next_parents.extend(parent_chip.parents);
                }
            }

            current_parents = next_parents;
        }

        // Reverse so we get: genesis → app → tenant → chip (most general to most specific)
        ancestry.reverse();
        Ok(ancestry)
    }

    /// Find all policy chips attached to a given chip
    async fn find_attached_policies(&self, chip_cid: &str) -> Result<Vec<PolicyBit>, PolicyError> {
        let policy_chips = self.storage.find_children(chip_cid).await?;

        let mut policies = Vec::new();
        for chip in policy_chips {
            // Only process policy chips
            if chip.chip_type.starts_with("ubl/policy") {
                let policy_bit = self.parse_policy_chip(&chip)?;
                policies.push(policy_bit);
            }
        }

        Ok(policies)
    }

    /// Parse a policy chip into a PolicyBit
    fn parse_policy_chip(&self, chip: &ChipData) -> Result<PolicyBit, PolicyError> {
        // Extract PolicyBit from chip body
        let circuits = chip
            .body
            .get("circuits")
            .ok_or_else(|| PolicyError::InvalidFormat("Missing circuits field".to_string()))?;

        let scope = chip
            .body
            .get("scope")
            .ok_or_else(|| PolicyError::InvalidFormat("Missing scope field".to_string()))?;

        let circuits: Vec<crate::circuit::Circuit> = serde_json::from_value(circuits.clone())
            .map_err(|e| PolicyError::InvalidFormat(format!("Invalid circuits: {}", e)))?;

        let scope: crate::policy_bit::PolicyScope = serde_json::from_value(scope.clone())
            .map_err(|e| PolicyError::InvalidFormat(format!("Invalid scope: {}", e)))?;

        let id = chip
            .body
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&chip.cid)
            .to_string();

        let name = chip
            .body
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();

        Ok(PolicyBit {
            id,
            name,
            circuits,
            scope,
        })
    }
}

/// Request to create/update a chip
#[derive(Debug, Clone)]
pub struct ChipRequest {
    pub chip_type: String,
    pub body: Value,
    pub parents: Vec<String>,
    pub operation: String, // "create", "update", "delete"
}

/// In-memory policy storage for testing/development
pub struct InMemoryPolicyStorage {
    chips: HashMap<String, ChipData>,
    by_type: HashMap<String, Vec<String>>, // type -> list of CIDs
    by_parent: HashMap<String, Vec<String>>, // parent_cid -> list of child CIDs
}

impl InMemoryPolicyStorage {
    pub fn new() -> Self {
        Self {
            chips: HashMap::new(),
            by_type: HashMap::new(),
            by_parent: HashMap::new(),
        }
    }

    pub fn add_chip(&mut self, chip: ChipData) {
        let cid = chip.cid.clone();

        // Index by type
        self.by_type
            .entry(chip.chip_type.clone())
            .or_default()
            .push(cid.clone());

        // Index by parents
        for parent in &chip.parents {
            self.by_parent
                .entry(parent.clone())
                .or_default()
                .push(cid.clone());
        }

        // Store the chip
        self.chips.insert(cid, chip);
    }
}

#[async_trait::async_trait]
impl PolicyStorage for InMemoryPolicyStorage {
    async fn get_chip(&self, cid: &str) -> Result<Option<ChipData>, PolicyError> {
        Ok(self.chips.get(cid).cloned())
    }

    async fn query_by_type(&self, chip_type: &str) -> Result<Vec<ChipData>, PolicyError> {
        let cids = self.by_type.get(chip_type).cloned().unwrap_or_default();

        let chips = cids
            .into_iter()
            .filter_map(|cid| self.chips.get(&cid).cloned())
            .collect();

        Ok(chips)
    }

    async fn find_children(&self, parent_cid: &str) -> Result<Vec<ChipData>, PolicyError> {
        let child_cids = self.by_parent.get(parent_cid).cloned().unwrap_or_default();

        let children = child_cids
            .into_iter()
            .filter_map(|cid| self.chips.get(&cid).cloned())
            .collect();

        Ok(children)
    }
}

impl Default for InMemoryPolicyStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_test_app_chip() -> ChipData {
        ChipData {
            cid: "b3:app123".to_string(),
            chip_type: "ubl/app".to_string(),
            body: json!({
                "@type": "ubl/app",
                "id": "acme",
                "name": "ACME Corp"
            }),
            parents: vec![],
        }
    }

    fn create_test_tenant_chip() -> ChipData {
        ChipData {
            cid: "b3:tenant456".to_string(),
            chip_type: "ubl/tenant".to_string(),
            body: json!({
                "@type": "ubl/tenant",
                "id": "acme-prod",
                "app": "acme"
            }),
            parents: vec!["b3:app123".to_string()],
        }
    }

    fn create_test_policy_chip() -> ChipData {
        ChipData {
            cid: "b3:policy789".to_string(),
            chip_type: "ubl/policy.app".to_string(),
            body: json!({
                "@type": "ubl/policy.app",
                "id": "acme.auth.v1",
                "circuits": [],
                "scope": {
                    "chip_types": ["ubl/user"],
                    "operations": ["create"],
                    "level": "app"
                }
            }),
            parents: vec!["b3:app123".to_string()],
        }
    }

    #[tokio::test]
    async fn test_policy_loader_genesis_only() {
        let storage = InMemoryPolicyStorage::new();
        let loader = PolicyLoader::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/user".to_string(),
            body: json!({"@type": "ubl/user", "id": "alice"}),
            parents: vec![],
            operation: "create".to_string(),
        };

        let policies = loader.load_policy_chain(&request).await.unwrap();

        // Should have genesis policy
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id, "ubl.genesis.v1");
    }

    #[tokio::test]
    async fn test_policy_loader_with_ancestry() {
        let mut storage = InMemoryPolicyStorage::new();

        // Add chips
        storage.add_chip(create_test_app_chip());
        storage.add_chip(create_test_tenant_chip());
        storage.add_chip(create_test_policy_chip());

        let loader = PolicyLoader::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/user".to_string(),
            body: json!({"@type": "ubl/user", "id": "alice"}),
            parents: vec!["b3:tenant456".to_string()], // Points to tenant
            operation: "create".to_string(),
        };

        let policies = loader.load_policy_chain(&request).await.unwrap();

        // Should have genesis + app policy
        assert!(policies.len() >= 2);
        assert_eq!(policies[0].id, "ubl.genesis.v1");

        // Should contain the app policy
        let has_app_policy = policies.iter().any(|p| p.id == "acme.auth.v1");
        assert!(has_app_policy, "Should load app policy from ancestry");
    }

    #[tokio::test]
    async fn test_circular_dependency_detection() {
        let mut storage = InMemoryPolicyStorage::new();

        // Create circular reference: A → B → A
        storage.add_chip(ChipData {
            cid: "b3:a".to_string(),
            chip_type: "ubl/app".to_string(),
            body: json!({"@type": "ubl/app", "id": "a"}),
            parents: vec!["b3:b".to_string()],
        });

        storage.add_chip(ChipData {
            cid: "b3:b".to_string(),
            chip_type: "ubl/tenant".to_string(),
            body: json!({"@type": "ubl/tenant", "id": "b"}),
            parents: vec!["b3:a".to_string()],
        });

        let loader = PolicyLoader::new(Box::new(storage));

        let request = ChipRequest {
            chip_type: "ubl/user".to_string(),
            body: json!({"@type": "ubl/user", "id": "test"}),
            parents: vec!["b3:a".to_string()],
            operation: "create".to_string(),
        };

        let result = loader.load_policy_chain(&request).await;
        assert!(result.is_err());

        if let Err(PolicyError::CircularDependency(_)) = result {
            // Expected
        } else {
            panic!("Expected CircularDependency error");
        }
    }
}
