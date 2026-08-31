use netcatty_ssh::{
    NormalizedPortForwardRule, PortForwardKind, PortForwardRule, ResolvedPortForwardRuntime,
};
use netcatty_vault::{
    SavedPortForwardKind, SavedPortForwardRule, SavedVaultGraph, SavedVaultInventoryRevision,
};
use serde::{Deserialize, Serialize};

pub(crate) const PORT_FORWARD_INVALID: &str = "PORT_FORWARD_INVALID";
pub(crate) const PORT_FORWARD_NOT_FOUND: &str = "PORT_FORWARD_NOT_FOUND";
pub(crate) const PORT_FORWARD_INVENTORY_CHANGED: &str = "PORT_FORWARD_INVENTORY_CHANGED";
pub(crate) const PORT_FORWARD_PUBLICATION_FAILED: &str = "PORT_FORWARD_PUBLICATION_FAILED";
pub(crate) const PORT_FORWARD_ALREADY_RUNNING: &str = "PORT_FORWARD_ALREADY_RUNNING";
pub(crate) const PORT_FORWARD_NOT_RUNNING: &str = "PORT_FORWARD_NOT_RUNNING";
pub(crate) const PORT_FORWARD_CONNECTION_FAILED: &str = "PORT_FORWARD_CONNECTION_FAILED";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PortForwardMetadataRequest {
    pub(crate) label: String,
    #[serde(rename = "type")]
    pub(crate) kind: SavedPortForwardKind,
    pub(crate) local_port: u32,
    pub(crate) bind_address: String,
    #[serde(default)]
    pub(crate) remote_host: Option<String>,
    #[serde(default)]
    pub(crate) remote_port: Option<u32>,
    pub(crate) host_id: String,
    #[serde(default)]
    pub(crate) auto_start: bool,
    #[serde(default)]
    pub(crate) order: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreatePortForwardRuleRequest {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: PortForwardMetadataRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdatePortForwardRuleRequest {
    pub(crate) id: String,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) metadata: PortForwardMetadataRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DeletePortForwardRuleRequest {
    pub(crate) id: String,
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PortForwardCatalog {
    pub(crate) inventory_revision: SavedVaultInventoryRevision,
    pub(crate) rules: Vec<SavedPortForwardRule>,
    pub(crate) runtime: Vec<ResolvedPortForwardRuntime>,
}

pub(crate) struct PreparedPortForwardMutation {
    pub(crate) expected_inventory_revision: SavedVaultInventoryRevision,
    pub(crate) target_graph: SavedVaultGraph,
    pub(crate) rule: Option<SavedPortForwardRule>,
}

pub(crate) fn prepare_creation(
    graph: SavedVaultGraph,
    request: CreatePortForwardRuleRequest,
    id: String,
    now: u64,
) -> Result<PreparedPortForwardMutation, String> {
    if graph.port_forward_rules().iter().any(|rule| rule.id == id) {
        return Err(port_forward_invalid());
    }
    ensure_host(&graph, &request.metadata.host_id)?;
    let order = request.metadata.order.or_else(|| next_order(&graph));
    let rule = build_rule(id, request.metadata, now, None, order)?;
    let mut rules = graph.port_forward_rules().to_vec();
    rules.push(rule.clone());
    Ok(PreparedPortForwardMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph.with_port_forward_rules(rules),
        rule: Some(rule),
    })
}

pub(crate) fn prepare_update(
    graph: SavedVaultGraph,
    request: UpdatePortForwardRuleRequest,
) -> Result<PreparedPortForwardMutation, String> {
    let current = graph
        .port_forward_rules()
        .iter()
        .find(|rule| rule.id == request.id)
        .cloned()
        .ok_or_else(port_forward_not_found)?;
    ensure_host(&graph, &request.metadata.host_id)?;
    let rule = build_rule(
        current.id.clone(),
        request.metadata,
        current.created_at,
        current.last_used_at,
        current.order,
    )?;
    let mut rules = graph.port_forward_rules().to_vec();
    let index = rules
        .iter()
        .position(|candidate| candidate.id == current.id)
        .ok_or_else(port_forward_not_found)?;
    rules[index] = rule.clone();
    Ok(PreparedPortForwardMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph.with_port_forward_rules(rules),
        rule: Some(rule),
    })
}

pub(crate) fn prepare_deletion(
    graph: SavedVaultGraph,
    request: DeletePortForwardRuleRequest,
) -> Result<PreparedPortForwardMutation, String> {
    if !graph
        .port_forward_rules()
        .iter()
        .any(|rule| rule.id == request.id)
    {
        return Err(port_forward_not_found());
    }
    let mut rules = graph.port_forward_rules().to_vec();
    rules.retain(|rule| rule.id != request.id);
    Ok(PreparedPortForwardMutation {
        expected_inventory_revision: request.expected_inventory_revision,
        target_graph: graph.with_port_forward_rules(rules),
        rule: None,
    })
}

pub(crate) fn normalized_transport_rule(
    rule: &SavedPortForwardRule,
) -> Result<NormalizedPortForwardRule, String> {
    PortForwardRule {
        id: rule.id.clone(),
        label: rule.label.clone(),
        kind: match rule.kind {
            SavedPortForwardKind::Local => PortForwardKind::Local,
            SavedPortForwardKind::Remote => PortForwardKind::Remote,
            SavedPortForwardKind::Dynamic => PortForwardKind::Dynamic,
        },
        local_port: rule.local_port,
        bind_address: rule.bind_address.clone(),
        remote_host: rule.remote_host.clone(),
        remote_port: rule.remote_port,
        host_id: rule.host_id.as_str().to_owned(),
        auto_start: rule.auto_start,
        created_at: rule.created_at,
        last_used_at: rule.last_used_at,
        order: rule.order,
    }
    .normalize()
    .map_err(|_| port_forward_invalid())
}

fn build_rule(
    id: String,
    metadata: PortForwardMetadataRequest,
    created_at: u64,
    last_used_at: Option<u64>,
    preserved_order: Option<i64>,
) -> Result<SavedPortForwardRule, String> {
    let local_port = u16::try_from(metadata.local_port).map_err(|_| port_forward_invalid())?;
    let remote_port = metadata
        .remote_port
        .map(u16::try_from)
        .transpose()
        .map_err(|_| port_forward_invalid())?;
    SavedPortForwardRule::new(
        id,
        metadata.label,
        metadata.kind,
        local_port,
        metadata.bind_address,
        metadata.remote_host,
        remote_port,
        metadata.host_id,
        metadata.auto_start,
        created_at,
        last_used_at,
        metadata.order.or(preserved_order),
    )
    .map_err(|_| port_forward_invalid())
}

fn ensure_host(graph: &SavedVaultGraph, id: &str) -> Result<(), String> {
    let host = graph
        .hosts()
        .iter()
        .find(|host| host.id.as_str() == id)
        .ok_or_else(port_forward_invalid)?;
    if !host.protocol.is_ssh() {
        return Err(port_forward_invalid());
    }
    Ok(())
}

fn next_order(graph: &SavedVaultGraph) -> Option<i64> {
    Some(
        graph
            .port_forward_rules()
            .iter()
            .filter_map(|rule| rule.order)
            .max()
            .and_then(|order| order.checked_add(1))
            .unwrap_or(0),
    )
}

pub(crate) fn port_forward_invalid() -> String {
    format!("{PORT_FORWARD_INVALID}: Port-forward rule metadata is invalid")
}

pub(crate) fn port_forward_not_found() -> String {
    format!("{PORT_FORWARD_NOT_FOUND}: Port-forward rule was not found")
}

pub(crate) fn port_forward_error(code: &str, message: &str) -> String {
    format!("{code}: {message}")
}
