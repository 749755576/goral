//! Docker inventory over a remote session.
//!
//! Docker's `--format '{{json .}}'` emits one JSON object per line rather than
//! a JSON array, so the parsers here are line-oriented. A single malformed
//! line is skipped rather than failing the whole listing: a daemon that emits
//! one odd record should not blank the user's container list.

use serde::{Deserialize, Serialize};

/// How far to escalate when the daemon socket refuses us.
///
/// The rungs are deliberately ordered least-privilege first, and the ladder
/// stops as soon as one rung works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escalation {
    /// `docker …` as the logged-in user.
    None,
    /// `sudo -n docker …`, which only succeeds where sudo is configured
    /// NOPASSWD and can never wait for a password on the PTY-free channel.
    PasswordlessSudo,
}

impl Escalation {
    /// The next rung to try, or `None` when the ladder is exhausted.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::None => Some(Self::PasswordlessSudo),
            Self::PasswordlessSudo => None,
        }
    }
}

/// Builds the shell command for one Docker invocation at a given rung.
#[must_use]
pub fn build_command(args: &str, escalation: Escalation) -> String {
    let base = format!("docker {}", args.trim());
    let base = base.trim_end().to_owned();
    match escalation {
        Escalation::None => base,
        Escalation::PasswordlessSudo => format!("sudo -n {base}"),
    }
}

/// Fixed read-only daemon probe used to choose one execution route before an
/// operation. Route selection never depends on localized stderr and a failed
/// mutation is never replayed with different privileges.
pub const ACCESS_PROBE_ARGS: &str = "version --format '{{.Server.Version}}'";
pub const LIST_CONTAINERS_ARGS: &str = "ps -a --format '{{json .}}'";
pub const LIST_IMAGES_ARGS: &str = "images --format '{{json .}}'";

/// Builds the `docker stats` arguments for an optional id subset.
///
/// Ids are filtered to the safe alphabet Docker actually uses before they
/// reach a shell command line; anything else is dropped rather than quoted,
/// because a container id is never legitimately exotic and a caller passing
/// one is either confused or hostile.
#[must_use]
pub fn stats_args(ids: &[String]) -> String {
    let safe: Vec<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| is_safe_container_id(id))
        .collect();
    if safe.is_empty() {
        "stats --no-stream --format '{{json .}}'".to_owned()
    } else {
        format!(
            "stats --no-stream --format '{{{{json .}}}}' {}",
            safe.join(" ")
        )
    }
}

/// Builds `docker inspect` for one container.
#[must_use]
pub fn inspect_args(container_id: &str) -> Option<String> {
    is_safe_container_id(container_id).then(|| format!("inspect {container_id}"))
}

/// A lifecycle action that can be taken on one container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContainerAction {
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
    Remove,
}

impl ContainerAction {
    #[must_use]
    pub const fn verb(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Pause => "pause",
            Self::Unpause => "unpause",
            Self::Remove => "rm",
        }
    }

    /// Whether this action destroys state the user cannot get back.
    ///
    /// The UI is expected to confirm these separately; it is recorded here so
    /// the policy lives with the action rather than in a screen.
    #[must_use]
    pub const fn is_destructive(self) -> bool {
        matches!(self, Self::Remove)
    }
}

/// Builds a container action command, or `None` for an unusable id.
#[must_use]
pub fn action_args(action: ContainerAction, container_id: &str) -> Option<String> {
    is_safe_container_id(container_id).then(|| format!("{} {container_id}", action.verb()))
}

/// Docker ids are hex, and names are a restricted alphabet. Nothing that
/// reaches a shell command line here needs anything else.
#[must_use]
pub fn is_safe_container_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerContainer {
    pub id: String,
    pub names: String,
    pub image: String,
    pub command: String,
    pub created_at: String,
    pub status: String,
    pub state: String,
    pub ports: String,
    pub networks: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub created_since: String,
    pub size: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerStat {
    pub id: String,
    pub name: String,
    pub cpu_percent: String,
    pub memory_usage: String,
    pub memory_percent: String,
    pub net_io: String,
    pub block_io: String,
    pub pids: String,
}

/// Renderer-safe, read-only subset of `docker inspect`.
///
/// Docker's raw document contains `Config.Env`, command arguments, labels,
/// registry material and extension-defined fields. Those fields are never
/// represented by this allowlisted DTO, so adding a new daemon field cannot
/// silently make it cross the native/renderer boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerContainerInspect {
    pub id: String,
    pub name: String,
    pub image: String,
    pub created: String,
    pub state: DockerInspectState,
    pub restart: DockerInspectRestart,
    pub network: DockerInspectNetwork,
    pub mounts: Vec<DockerInspectMount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerInspectState {
    pub status: String,
    pub running: bool,
    pub paused: bool,
    pub restarting: bool,
    pub oom_killed: bool,
    pub dead: bool,
    pub exit_code: Option<i32>,
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerInspectRestart {
    pub policy: String,
    pub maximum_retry_count: Option<u32>,
    pub current_restart_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerInspectNetwork {
    pub mode: String,
    pub ip_address: String,
    pub gateway: String,
    pub mac_address: String,
    pub published_ports: Vec<DockerInspectPortBinding>,
    pub attachments: Vec<DockerInspectNetworkAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerInspectPortBinding {
    pub container_port: String,
    pub host_ip: String,
    pub host_port: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerInspectNetworkAttachment {
    pub name: String,
    pub network_id: String,
    pub endpoint_id: String,
    pub gateway: String,
    pub ip_address: String,
    pub ip_prefix_len: Option<u32>,
    pub global_ipv6_address: String,
    pub global_ipv6_prefix_len: Option<u32>,
    pub mac_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerInspectMount {
    #[serde(rename = "type")]
    pub mount_type: String,
    pub name: String,
    pub destination: String,
    pub mode: String,
    pub read_only: bool,
    pub propagation: String,
}

/// Safe parser failures deliberately carry no source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerInspectParseError {
    InvalidJson,
    InvalidShape,
    LimitExceeded,
}

const MAX_INSPECT_TEXT_BYTES: usize = 4 * 1024;
const MAX_INSPECT_COLLECTION_ITEMS: usize = 256;

fn inspect_object(
    value: Option<&serde_json::Value>,
) -> Result<Option<&serde_json::Map<String, serde_json::Value>>, DockerInspectParseError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Object(object)) => Ok(Some(object)),
        Some(_) => Err(DockerInspectParseError::InvalidShape),
    }
}

fn inspect_text(value: Option<&serde_json::Value>) -> Result<String, DockerInspectParseError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(String::new()),
        Some(serde_json::Value::String(text)) if text.len() <= MAX_INSPECT_TEXT_BYTES => {
            Ok(text.clone())
        }
        Some(serde_json::Value::String(_)) => Err(DockerInspectParseError::LimitExceeded),
        Some(_) => Err(DockerInspectParseError::InvalidShape),
    }
}

fn inspect_bool(value: Option<&serde_json::Value>) -> Result<bool, DockerInspectParseError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(value)) => Ok(*value),
        Some(_) => Err(DockerInspectParseError::InvalidShape),
    }
}

fn inspect_i32(value: Option<&serde_json::Value>) -> Result<Option<i32>, DockerInspectParseError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .map(Some)
            .ok_or(DockerInspectParseError::InvalidShape),
        Some(_) => Err(DockerInspectParseError::InvalidShape),
    }
}

fn inspect_u32(value: Option<&serde_json::Value>) -> Result<Option<u32>, DockerInspectParseError> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .map(Some)
            .ok_or(DockerInspectParseError::InvalidShape),
        Some(_) => Err(DockerInspectParseError::InvalidShape),
    }
}

fn parse_inspect_ports(
    value: Option<&serde_json::Value>,
) -> Result<Vec<DockerInspectPortBinding>, DockerInspectParseError> {
    let Some(ports) = inspect_object(value)? else {
        return Ok(Vec::new());
    };
    if ports.len() > MAX_INSPECT_COLLECTION_ITEMS {
        return Err(DockerInspectParseError::LimitExceeded);
    }

    let mut parsed = Vec::new();
    for (container_port, bindings) in ports {
        let container_port =
            inspect_text(Some(&serde_json::Value::String(container_port.clone())))?;
        match bindings {
            serde_json::Value::Null => {
                if parsed.len() >= MAX_INSPECT_COLLECTION_ITEMS {
                    return Err(DockerInspectParseError::LimitExceeded);
                }
                parsed.push(DockerInspectPortBinding {
                    container_port,
                    host_ip: String::new(),
                    host_port: String::new(),
                });
            }
            serde_json::Value::Array(bindings) => {
                if parsed.len().saturating_add(bindings.len()) > MAX_INSPECT_COLLECTION_ITEMS {
                    return Err(DockerInspectParseError::LimitExceeded);
                }
                for binding in bindings {
                    let binding = binding
                        .as_object()
                        .ok_or(DockerInspectParseError::InvalidShape)?;
                    parsed.push(DockerInspectPortBinding {
                        container_port: container_port.clone(),
                        host_ip: inspect_text(binding.get("HostIp"))?,
                        host_port: inspect_text(binding.get("HostPort"))?,
                    });
                }
            }
            _ => return Err(DockerInspectParseError::InvalidShape),
        }
    }
    parsed.sort_by(|left, right| {
        (&left.container_port, &left.host_ip, &left.host_port).cmp(&(
            &right.container_port,
            &right.host_ip,
            &right.host_port,
        ))
    });
    Ok(parsed)
}

fn parse_inspect_networks(
    value: Option<&serde_json::Value>,
) -> Result<Vec<DockerInspectNetworkAttachment>, DockerInspectParseError> {
    let Some(networks) = inspect_object(value)? else {
        return Ok(Vec::new());
    };
    if networks.len() > MAX_INSPECT_COLLECTION_ITEMS {
        return Err(DockerInspectParseError::LimitExceeded);
    }

    let mut parsed = Vec::with_capacity(networks.len());
    for (name, value) in networks {
        let network = value
            .as_object()
            .ok_or(DockerInspectParseError::InvalidShape)?;
        parsed.push(DockerInspectNetworkAttachment {
            name: inspect_text(Some(&serde_json::Value::String(name.clone())))?,
            network_id: inspect_text(network.get("NetworkID"))?,
            endpoint_id: inspect_text(network.get("EndpointID"))?,
            gateway: inspect_text(network.get("Gateway"))?,
            ip_address: inspect_text(network.get("IPAddress"))?,
            ip_prefix_len: inspect_u32(network.get("IPPrefixLen"))?,
            global_ipv6_address: inspect_text(network.get("GlobalIPv6Address"))?,
            global_ipv6_prefix_len: inspect_u32(network.get("GlobalIPv6PrefixLen"))?,
            mac_address: inspect_text(network.get("MacAddress"))?,
        });
    }
    parsed.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(parsed)
}

fn parse_inspect_mounts(
    value: Option<&serde_json::Value>,
) -> Result<Vec<DockerInspectMount>, DockerInspectParseError> {
    let mounts = match value {
        None | Some(serde_json::Value::Null) => return Ok(Vec::new()),
        Some(serde_json::Value::Array(mounts)) => mounts,
        Some(_) => return Err(DockerInspectParseError::InvalidShape),
    };
    if mounts.len() > MAX_INSPECT_COLLECTION_ITEMS {
        return Err(DockerInspectParseError::LimitExceeded);
    }

    mounts
        .iter()
        .map(|value| {
            let mount = value
                .as_object()
                .ok_or(DockerInspectParseError::InvalidShape)?;
            Ok(DockerInspectMount {
                mount_type: inspect_text(mount.get("Type"))?,
                name: inspect_text(mount.get("Name"))?,
                destination: inspect_text(mount.get("Destination"))?,
                mode: inspect_text(mount.get("Mode"))?,
                read_only: !inspect_bool(mount.get("RW"))?,
                propagation: inspect_text(mount.get("Propagation"))?,
            })
        })
        .collect()
}

/// Parses exactly one raw `docker inspect` record into the strict allowlist
/// above. Unknown keys are ignored by construction and cannot appear when the
/// result is serialized for the renderer.
pub fn parse_container_inspect(
    stdout: &str,
) -> Result<DockerContainerInspect, DockerInspectParseError> {
    let root = serde_json::from_str::<serde_json::Value>(stdout)
        .map_err(|_| DockerInspectParseError::InvalidJson)?;
    let records = root
        .as_array()
        .ok_or(DockerInspectParseError::InvalidShape)?;
    if records.len() != 1 {
        return Err(DockerInspectParseError::InvalidShape);
    }
    let container = records[0]
        .as_object()
        .ok_or(DockerInspectParseError::InvalidShape)?;
    let config = inspect_object(container.get("Config"))?;
    let state = inspect_object(container.get("State"))?;
    let host_config = inspect_object(container.get("HostConfig"))?;
    let restart_policy = inspect_object(host_config.and_then(|value| value.get("RestartPolicy")))?;
    let network_settings = inspect_object(container.get("NetworkSettings"))?;

    let image = match config {
        Some(config) => inspect_text(config.get("Image"))?,
        None => String::new(),
    };
    let image = if image.is_empty() {
        inspect_text(container.get("Image"))?
    } else {
        image
    };
    let name = inspect_text(container.get("Name"))?;
    let name = name.strip_prefix('/').unwrap_or(&name).to_owned();

    Ok(DockerContainerInspect {
        id: inspect_text(container.get("Id"))?,
        name,
        image,
        created: inspect_text(container.get("Created"))?,
        state: DockerInspectState {
            status: inspect_text(state.and_then(|value| value.get("Status")))?,
            running: inspect_bool(state.and_then(|value| value.get("Running")))?,
            paused: inspect_bool(state.and_then(|value| value.get("Paused")))?,
            restarting: inspect_bool(state.and_then(|value| value.get("Restarting")))?,
            oom_killed: inspect_bool(state.and_then(|value| value.get("OOMKilled")))?,
            dead: inspect_bool(state.and_then(|value| value.get("Dead")))?,
            exit_code: inspect_i32(state.and_then(|value| value.get("ExitCode")))?,
            started_at: inspect_text(state.and_then(|value| value.get("StartedAt")))?,
            finished_at: inspect_text(state.and_then(|value| value.get("FinishedAt")))?,
        },
        restart: DockerInspectRestart {
            policy: inspect_text(restart_policy.and_then(|value| value.get("Name")))?,
            maximum_retry_count: inspect_u32(
                restart_policy.and_then(|value| value.get("MaximumRetryCount")),
            )?,
            current_restart_count: inspect_u32(container.get("RestartCount"))?,
        },
        network: DockerInspectNetwork {
            mode: inspect_text(host_config.and_then(|value| value.get("NetworkMode")))?,
            ip_address: inspect_text(network_settings.and_then(|value| value.get("IPAddress")))?,
            gateway: inspect_text(network_settings.and_then(|value| value.get("Gateway")))?,
            mac_address: inspect_text(network_settings.and_then(|value| value.get("MacAddress")))?,
            published_ports: parse_inspect_ports(
                network_settings.and_then(|value| value.get("Ports")),
            )?,
            attachments: parse_inspect_networks(
                network_settings.and_then(|value| value.get("Networks")),
            )?,
        },
        mounts: parse_inspect_mounts(container.get("Mounts"))?,
    })
}

/// Reads a string field, tolerating Docker's inconsistent key casing.
fn field(value: &serde_json::Value, keys: &[&str]) -> String {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(serde_json::Value::as_str) {
            return text.to_owned();
        }
    }
    String::new()
}

/// Parses one JSON object per line, skipping lines that are not objects.
fn parse_lines<T>(stdout: &str, build: impl Fn(&serde_json::Value) -> Option<T>) -> Vec<T> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|value| build(&value))
        .collect()
}

#[must_use]
pub fn parse_containers(stdout: &str) -> Vec<DockerContainer> {
    parse_lines(stdout, |value| {
        let id = field(value, &["ID", "Id"]);
        // A record with no id cannot be acted on, so it is not worth showing.
        if id.is_empty() {
            return None;
        }
        Some(DockerContainer {
            id,
            names: field(value, &["Names", "Name"]),
            image: field(value, &["Image"]),
            command: field(value, &["Command"]),
            created_at: field(value, &["CreatedAt"]),
            status: field(value, &["Status"]),
            state: field(value, &["State"]),
            ports: field(value, &["Ports"]),
            networks: field(value, &["Networks"]),
        })
    })
}

#[must_use]
pub fn parse_images(stdout: &str) -> Vec<DockerImage> {
    parse_lines(stdout, |value| {
        let id = field(value, &["ID", "Id"]);
        if id.is_empty() {
            return None;
        }
        Some(DockerImage {
            id,
            repository: field(value, &["Repository"]),
            tag: field(value, &["Tag"]),
            created_since: field(value, &["CreatedSince", "CreatedAt"]),
            size: field(value, &["Size"]),
        })
    })
}

#[must_use]
pub fn parse_stats(stdout: &str) -> Vec<DockerStat> {
    parse_lines(stdout, |value| {
        let id = field(value, &["ID", "Container"]);
        if id.is_empty() {
            return None;
        }
        Some(DockerStat {
            id,
            name: field(value, &["Name"]),
            cpu_percent: field(value, &["CPUPerc"]),
            memory_usage: field(value, &["MemUsage"]),
            memory_percent: field(value, &["MemPerc"]),
            net_io: field(value, &["NetIO"]),
            block_io: field(value, &["BlockIO"]),
            pids: field(value, &["PIDs"]),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_plain_and_sudo_commands() {
        assert_eq!(
            build_command(ACCESS_PROBE_ARGS, Escalation::None),
            "docker version --format '{{.Server.Version}}'"
        );
        assert_eq!(
            build_command(LIST_CONTAINERS_ARGS, Escalation::None),
            "docker ps -a --format '{{json .}}'"
        );
        assert_eq!(
            build_command(LIST_CONTAINERS_ARGS, Escalation::PasswordlessSudo),
            "sudo -n docker ps -a --format '{{json .}}'"
        );
    }

    #[test]
    fn parses_one_container_per_line() {
        let stdout = concat!(
            r#"{"ID":"abc123","Names":"web","Image":"nginx:latest","Command":"nginx","CreatedAt":"2026-01-01","Status":"Up 2 hours","State":"running","Ports":"80/tcp","Networks":"bridge"}"#,
            "\n",
            r#"{"ID":"def456","Names":"db","Image":"postgres:16","Command":"postgres","CreatedAt":"2026-01-02","Status":"Exited (0)","State":"exited","Ports":"","Networks":"bridge"}"#,
        );
        let containers = parse_containers(stdout);
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].names, "web");
        assert_eq!(containers[1].state, "exited");
    }

    #[test]
    fn a_malformed_line_does_not_blank_the_listing() {
        let stdout = concat!(
            r#"{"ID":"abc123","Names":"web"}"#,
            "\n",
            "this is not json\n",
            r#"{"ID":"def456","Names":"db"}"#,
        );
        let containers = parse_containers(stdout);
        assert_eq!(containers.len(), 2, "one bad record must not hide the rest");
    }

    #[test]
    fn a_record_without_an_id_is_dropped() {
        // Nothing in the UI can act on it, so showing it would only mislead.
        let containers = parse_containers(r#"{"Names":"orphan"}"#);
        assert!(containers.is_empty());
    }

    #[test]
    fn parses_images_and_stats() {
        let images = parse_images(
            r#"{"ID":"sha256:aaa","Repository":"nginx","Tag":"latest","CreatedSince":"2 days ago","Size":"142MB"}"#,
        );
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].repository, "nginx");

        let stats = parse_stats(
            r#"{"ID":"abc123","Name":"web","CPUPerc":"0.15%","MemUsage":"12MiB / 2GiB","MemPerc":"0.60%","NetIO":"1kB / 2kB","BlockIO":"0B / 0B","PIDs":"5"}"#,
        );
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].cpu_percent, "0.15%");
    }

    #[test]
    fn inspect_is_an_explicit_allowlist_and_drops_secret_bearing_fields() {
        let raw = r#"[{
          "Id":"container-123",
          "Name":"/web",
          "Image":"sha256:image-id",
          "Created":"2026-08-31T10:00:00Z",
          "Path":"/bin/sh",
          "Args":["--token","ARGS_TOKEN_SECRET"],
          "Config":{
            "Image":"registry.example/app:latest",
            "Env":["PASSWORD=env-password-secret","API_KEY=env-api-key-secret","TOKEN=env-token-secret"],
            "Cmd":["run","--password=cmd-secret"],
            "Labels":{"com.example.secret":"label-secret"},
            "RegistryAuth":"registry-auth-secret"
          },
          "State":{
            "Status":"running","Running":true,"Paused":false,"Restarting":false,
            "OOMKilled":false,"Dead":false,"ExitCode":0,
            "StartedAt":"2026-08-31T10:00:01Z","FinishedAt":"",
            "Error":"state-token-secret"
          },
          "RestartCount":2,
          "HostConfig":{
            "RestartPolicy":{"Name":"unless-stopped","MaximumRetryCount":3},
            "NetworkMode":"bridge",
            "Binds":["/host/private:/container/private"],
            "RegistryAuth":"host-registry-secret"
          },
          "NetworkSettings":{
            "IPAddress":"172.17.0.2","Gateway":"172.17.0.1","MacAddress":"02:42:ac:11:00:02",
            "Ports":{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080","Secret":"port-secret"}]},
            "Networks":{"bridge":{
              "NetworkID":"network-id","EndpointID":"endpoint-id","Gateway":"172.17.0.1",
              "IPAddress":"172.17.0.2","IPPrefixLen":16,"GlobalIPv6Address":"",
              "GlobalIPv6PrefixLen":0,"MacAddress":"02:42:ac:11:00:02",
              "IPAMConfig":{"Token":"network-token-secret"}
            }}
          },
          "Mounts":[{
            "Type":"bind","Name":"data","Source":"/host/private/secret",
            "Destination":"/data","Mode":"ro","RW":false,"Propagation":"rprivate",
            "SecretBody":"mount-secret"
          }],
          "UnknownFutureField":{"API_KEY":"unknown-field-secret"}
        }]"#;

        let inspect = parse_container_inspect(raw).expect("safe inspect");
        assert_eq!(inspect.id, "container-123");
        assert_eq!(inspect.name, "web");
        assert_eq!(inspect.image, "registry.example/app:latest");
        assert_eq!(inspect.state.status, "running");
        assert_eq!(inspect.restart.policy, "unless-stopped");
        assert_eq!(inspect.network.published_ports.len(), 1);
        assert_eq!(inspect.network.attachments.len(), 1);
        assert_eq!(inspect.mounts.len(), 1);
        assert!(inspect.mounts[0].read_only);

        let renderer_json = serde_json::to_string(&inspect).expect("renderer DTO JSON");
        for forbidden in [
            "PASSWORD",
            "API_KEY",
            "TOKEN",
            "env-password-secret",
            "env-api-key-secret",
            "env-token-secret",
            "ARGS_TOKEN_SECRET",
            "cmd-secret",
            "label-secret",
            "registry-auth-secret",
            "host-registry-secret",
            "state-token-secret",
            "/host/private",
            "port-secret",
            "network-token-secret",
            "mount-secret",
            "unknown-field-secret",
            "UnknownFutureField",
            "RegistryAuth",
            "Labels",
            "Env",
            "Args",
            "Source",
        ] {
            assert!(
                !renderer_json.contains(forbidden),
                "raw inspect field crossed the allowlist: {forbidden}"
            );
        }
        assert!(renderer_json.contains("publishedPorts"));
        assert!(renderer_json.contains("currentRestartCount"));
    }

    #[test]
    fn inspect_rejects_noncanonical_or_unbounded_documents_without_echoing_them() {
        assert_eq!(
            parse_container_inspect(r#"{"Id":"one"}"#),
            Err(DockerInspectParseError::InvalidShape)
        );
        assert_eq!(
            parse_container_inspect(r#"[{"Id":"one"},{"Id":"two"}]"#),
            Err(DockerInspectParseError::InvalidShape)
        );
        let oversized = "x".repeat(MAX_INSPECT_TEXT_BYTES + 1);
        let raw = format!(r#"[{{"Id":"{oversized}"}}]"#);
        assert_eq!(
            parse_container_inspect(&raw),
            Err(DockerInspectParseError::LimitExceeded)
        );
    }

    #[test]
    fn rejects_container_ids_that_could_reach_the_shell() {
        assert!(is_safe_container_id("abc123"));
        assert!(is_safe_container_id("my-container_1.2"));
        assert!(!is_safe_container_id(""));
        assert!(!is_safe_container_id("abc; rm -rf /"));
        assert!(!is_safe_container_id("$(whoami)"));
        assert!(!is_safe_container_id("a`id`"));
        assert!(!is_safe_container_id("a b"));
    }

    #[test]
    fn unsafe_ids_produce_no_command_at_all() {
        // Refusing to build the string is stronger than quoting it: there is
        // no path where a crafted id reaches a remote shell.
        assert!(action_args(ContainerAction::Remove, "abc; reboot").is_none());
        assert!(inspect_args("$(id)").is_none());
        assert_eq!(
            stats_args(&["ok1".to_owned(), "bad;id".to_owned()]),
            "stats --no-stream --format '{{json .}}' ok1"
        );
    }

    #[test]
    fn stats_without_ids_covers_every_container() {
        assert_eq!(stats_args(&[]), "stats --no-stream --format '{{json .}}'");
    }

    #[test]
    fn action_verbs_match_the_docker_cli() {
        assert_eq!(
            action_args(ContainerAction::Stop, "abc").as_deref(),
            Some("stop abc")
        );
        assert_eq!(
            action_args(ContainerAction::Remove, "abc").as_deref(),
            Some("rm abc")
        );
        assert!(ContainerAction::Remove.is_destructive());
        assert!(!ContainerAction::Restart.is_destructive());
    }
}
