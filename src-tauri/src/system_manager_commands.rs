//! Remote system management commands.
//!
//! These are thin adapters in the usual style: resolve the session, run a
//! command through `netcatty-sysmanager`'s policy, parse, return. The command
//! strings, the escalation policy and the parsers all live in the crate so
//! they stay unit-testable without a network.
//!
//! Every command here runs on a *second* channel of the user's existing SSH
//! connection rather than typing into their shell. The interactive session
//! keeps its scrollback and shell state, and parsed output can never be
//! polluted by whatever the user is running.

use netcatty_ssh::{CommandOutput, ExecLimits, SessionExecError};
use netcatty_sysmanager::ExecResult;
use netcatty_sysmanager::docker::{
    self, ContainerAction, DockerContainer, DockerContainerInspect, DockerImage, DockerStat,
    Escalation,
};
use netcatty_sysmanager::gpu::{self, NvidiaGpu};
use netcatty_sysmanager::inventory::{
    self, InventoryActionKind, InventoryActionPlan, InventoryActionRoute, ListeningPort,
    PROCESS_IDENTITY_MISMATCH_EXIT_STATUS, ProcessSignal, RemoteProcess, ServiceAction,
    SystemService,
};
use netcatty_sysmanager::overview::{self, SystemOverview};
use netcatty_sysmanager::tmux::{
    self, TmuxExecKind, TmuxExecPlan, TmuxOperation, TmuxOperationPlan, TmuxSession,
};
use tauri::State;

use super::DesktopState;

/// Docker listings are interactive: a user is waiting on them, so they get a
/// tighter deadline than the transport default.
const DOCKER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
const GPU_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
const OVERVIEW_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
const TMUX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);

pub(super) const SYSTEM_MANAGER_SESSION_UNAVAILABLE: &str = "SYSTEM_MANAGER_SESSION_UNAVAILABLE";
pub(super) const SYSTEM_MANAGER_COMMAND_FAILED: &str = "SYSTEM_MANAGER_COMMAND_FAILED";
pub(super) const SYSTEM_MANAGER_COMMAND_TIMEOUT: &str = "SYSTEM_MANAGER_COMMAND_TIMEOUT";
pub(super) const SYSTEM_MANAGER_RESPONSE_TOO_LARGE: &str = "SYSTEM_MANAGER_RESPONSE_TOO_LARGE";
pub(super) const SYSTEM_MANAGER_INVALID_TARGET: &str = "SYSTEM_MANAGER_INVALID_TARGET";
pub(super) const SYSTEM_MANAGER_RESPONSE_INVALID: &str = "SYSTEM_MANAGER_RESPONSE_INVALID";
pub(super) const SYSTEM_MANAGER_TMUX_ATTACH_UNAVAILABLE: &str =
    "SYSTEM_MANAGER_TMUX_ATTACH_UNAVAILABLE";

fn session_error(error: SessionExecError) -> String {
    match error {
        SessionExecError::Session(_) | SessionExecError::TransportUnavailable => {
            SYSTEM_MANAGER_SESSION_UNAVAILABLE.to_owned()
        }
        SessionExecError::Transport(_) => SYSTEM_MANAGER_COMMAND_FAILED.to_owned(),
    }
}

async fn run_docker_attempt(
    state: &DesktopState,
    session_id: &str,
    args: &str,
    escalation: Escalation,
) -> Result<CommandOutput, String> {
    let limits = ExecLimits {
        timeout: DOCKER_TIMEOUT,
        ..ExecLimits::default()
    };
    let command = docker::build_command(args, escalation);
    let output = state
        .sessions
        .exec_capture(session_id, &command, limits)
        .await
        .map_err(session_error)?;
    if output.timed_out {
        return Err(SYSTEM_MANAGER_COMMAND_TIMEOUT.to_owned());
    }
    if output.truncated {
        return Err(SYSTEM_MANAGER_RESPONSE_TOO_LARGE.to_owned());
    }
    Ok(output)
}

/// Selects one Docker route with a read-only daemon probe. Probe failures are
/// safe to retry because no remote state can change. The actual operation is
/// then executed exactly once and is never replayed after an ambiguous error.
async fn run_docker(state: &DesktopState, session_id: &str, args: &str) -> Result<String, String> {
    let mut route = Escalation::None;
    let selected = loop {
        let probe = run_docker_attempt(state, session_id, docker::ACCESS_PROBE_ARGS, route).await?;
        if probe.succeeded() {
            break route;
        }
        route = route
            .next()
            .ok_or_else(|| SYSTEM_MANAGER_COMMAND_FAILED.to_owned())?;
    };

    let output = run_docker_attempt(state, session_id, args, selected).await?;
    if output.succeeded() {
        Ok(output.stdout_lossy().into_owned())
    } else {
        Err(SYSTEM_MANAGER_COMMAND_FAILED.to_owned())
    }
}

#[tauri::command]
pub(super) async fn list_docker_containers(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<Vec<DockerContainer>, String> {
    let stdout = run_docker(state.inner(), &session_id, docker::LIST_CONTAINERS_ARGS).await?;
    Ok(docker::parse_containers(&stdout))
}

#[tauri::command]
pub(super) async fn list_docker_images(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<Vec<DockerImage>, String> {
    let stdout = run_docker(state.inner(), &session_id, docker::LIST_IMAGES_ARGS).await?;
    Ok(docker::parse_images(&stdout))
}

#[tauri::command]
pub(super) async fn get_docker_stats(
    state: State<'_, DesktopState>,
    session_id: String,
    ids: Vec<String>,
) -> Result<Vec<DockerStat>, String> {
    let stdout = run_docker(state.inner(), &session_id, &docker::stats_args(&ids)).await?;
    Ok(docker::parse_stats(&stdout))
}

#[tauri::command]
pub(super) async fn inspect_docker_container(
    state: State<'_, DesktopState>,
    session_id: String,
    container_id: String,
) -> Result<DockerContainerInspect, String> {
    // An id that cannot be made safe produces no command at all, so a crafted
    // value has no path to a remote shell.
    let args = docker::inspect_args(&container_id)
        .ok_or_else(|| SYSTEM_MANAGER_INVALID_TARGET.to_owned())?;
    let stdout = run_docker(state.inner(), &session_id, &args).await?;
    // Raw inspect output may contain environment variables, labels, command
    // arguments and registry material. Only the crate's strict allowlisted
    // DTO is permitted across the renderer boundary.
    docker::parse_container_inspect(&stdout).map_err(|_| SYSTEM_MANAGER_RESPONSE_INVALID.to_owned())
}

#[tauri::command]
pub(super) async fn run_docker_container_action(
    state: State<'_, DesktopState>,
    session_id: String,
    container_id: String,
    action: ContainerAction,
) -> Result<(), String> {
    let args = docker::action_args(action, &container_id)
        .ok_or_else(|| SYSTEM_MANAGER_INVALID_TARGET.to_owned())?;
    run_docker(state.inner(), &session_id, &args)
        .await
        .map(|_| ())
}

/// Runs the crate-owned, read-only NVIDIA inventory query with a deliberately
/// small output ceiling. A truncated snapshot is rejected rather than parsed
/// as a complete inventory.
async fn run_nvidia_query(state: &DesktopState, session_id: &str) -> Result<String, String> {
    let output = state
        .sessions
        .exec_capture(
            session_id,
            gpu::LIST_NVIDIA_GPUS,
            ExecLimits {
                max_output_bytes: gpu::MAX_NVIDIA_OUTPUT_BYTES,
                timeout: GPU_TIMEOUT,
            },
        )
        .await
        .map_err(session_error)?;

    if output.timed_out {
        return Err(SYSTEM_MANAGER_COMMAND_TIMEOUT.to_owned());
    }
    if output.truncated {
        return Err(SYSTEM_MANAGER_RESPONSE_TOO_LARGE.to_owned());
    }

    let result = ExecResult {
        stdout: output.stdout_lossy().into_owned(),
        stderr: output.stderr_lossy().into_owned(),
        exit_status: output.exit_status.map(|code| code as i32),
        timed_out: false,
    };
    if result.succeeded() {
        Ok(result.stdout)
    } else {
        Err(SYSTEM_MANAGER_COMMAND_FAILED.to_owned())
    }
}

#[tauri::command]
pub(super) async fn list_nvidia_gpus(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<Vec<NvidiaGpu>, String> {
    let stdout = run_nvidia_query(state.inner(), &session_id).await?;
    gpu::parse_nvidia_gpus(&stdout).map_err(|_| SYSTEM_MANAGER_RESPONSE_INVALID.to_owned())
}

/// Executes the crate-owned overview probe with the same strict transport
/// limits enforced again by its parser.
#[tauri::command]
pub(super) async fn get_system_overview(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<SystemOverview, String> {
    let output = state
        .sessions
        .exec_capture(
            &session_id,
            overview::GET_SYSTEM_OVERVIEW,
            ExecLimits {
                max_output_bytes: overview::MAX_OVERVIEW_OUTPUT_BYTES,
                timeout: OVERVIEW_TIMEOUT,
            },
        )
        .await
        .map_err(session_error)?;

    if output.timed_out {
        return Err(SYSTEM_MANAGER_COMMAND_TIMEOUT.to_owned());
    }
    if output.truncated {
        return Err(SYSTEM_MANAGER_RESPONSE_TOO_LARGE.to_owned());
    }
    if output.exit_status != Some(0) {
        return Err(SYSTEM_MANAGER_COMMAND_FAILED.to_owned());
    }

    overview::parse_system_overview(&output.stdout_lossy())
        .map_err(|_| SYSTEM_MANAGER_RESPONSE_INVALID.to_owned())
}

/* ---------------------------------------------------------------------
 * tmux session catalog
 *
 * The crate owns validation, exact targeting, quoting, output limits and
 * parsing. This adapter executes only its fixed non-interactive plans.
 * Attaching needs a new PTY-backed terminal runtime; `exec_capture` has no
 * PTY and therefore rejects that plan instead of pretending to attach.
 * ------------------------------------------------------------------- */

fn tmux_exec_plan(operation: &TmuxOperation) -> Result<TmuxExecPlan, String> {
    match tmux::plan_operation(operation).map_err(|_| SYSTEM_MANAGER_INVALID_TARGET.to_owned())? {
        TmuxOperationPlan::Exec(plan) => Ok(plan),
        TmuxOperationPlan::TerminalAttach(_) => {
            Err(SYSTEM_MANAGER_TMUX_ATTACH_UNAVAILABLE.to_owned())
        }
    }
}

async fn run_tmux_operation(
    state: &DesktopState,
    session_id: &str,
    operation: TmuxOperation,
) -> Result<String, String> {
    let plan = tmux_exec_plan(&operation)?;
    let kind = plan.kind();
    let output = state
        .sessions
        .exec_capture(
            session_id,
            plan.shell_command(),
            ExecLimits {
                max_output_bytes: plan.max_output_bytes(),
                timeout: TMUX_TIMEOUT,
            },
        )
        .await
        .map_err(session_error)?;

    if output.timed_out {
        return Err(SYSTEM_MANAGER_COMMAND_TIMEOUT.to_owned());
    }
    if output.truncated {
        return Err(SYSTEM_MANAGER_RESPONSE_TOO_LARGE.to_owned());
    }

    let exit_status = output.exit_status.map(|code| code as i32);
    if exit_status == Some(0) {
        return Ok(output.stdout_lossy().into_owned());
    }
    if kind == TmuxExecKind::ListSessions
        && tmux::is_no_server_message(&output.stderr_lossy(), exit_status)
    {
        return Ok(String::new());
    }
    Err(SYSTEM_MANAGER_COMMAND_FAILED.to_owned())
}

#[tauri::command]
pub(super) async fn list_tmux_sessions(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<Vec<TmuxSession>, String> {
    let stdout =
        run_tmux_operation(state.inner(), &session_id, TmuxOperation::ListSessions).await?;
    tmux::parse_sessions(&stdout).map_err(|_| SYSTEM_MANAGER_RESPONSE_INVALID.to_owned())
}

#[tauri::command]
pub(super) async fn create_tmux_session(
    state: State<'_, DesktopState>,
    session_id: String,
    name: String,
) -> Result<(), String> {
    run_tmux_operation(
        state.inner(),
        &session_id,
        TmuxOperation::CreateSession { name },
    )
    .await
    .map(|_| ())
}

#[tauri::command]
pub(super) async fn rename_tmux_session(
    state: State<'_, DesktopState>,
    session_id: String,
    name: String,
    new_name: String,
) -> Result<(), String> {
    run_tmux_operation(
        state.inner(),
        &session_id,
        TmuxOperation::RenameSession { name, new_name },
    )
    .await
    .map(|_| ())
}

#[tauri::command]
pub(super) async fn kill_tmux_session(
    state: State<'_, DesktopState>,
    session_id: String,
    name: String,
) -> Result<(), String> {
    run_tmux_operation(
        state.inner(),
        &session_id,
        TmuxOperation::KillSession { name },
    )
    .await
    .map(|_| ())
}

/* ---------------------------------------------------------------------
 * Process, port and service inventory
 *
 * These listings use tool-fallback chains that end in `|| true`, so a host
 * without `ss` or without systemd returns an empty list rather than an
 * error the user cannot act on. That means a zero exit status here means
 * "the chain ran", not "the tool existed" — an empty listing is a valid,
 * expected result.
 * ------------------------------------------------------------------- */

/// Inventory listings can be large on a busy host and are not as latency
/// sensitive as a container list, so they get a slightly longer deadline.
const INVENTORY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const INVENTORY_ACTION_OUTPUT_BYTES: usize = 8 * 1024;

async fn run_plain(
    state: &DesktopState,
    session_id: &str,
    command: &str,
) -> Result<String, String> {
    let limits = ExecLimits {
        timeout: INVENTORY_TIMEOUT,
        ..ExecLimits::default()
    };
    let output = state
        .sessions
        .exec_capture(session_id, command, limits)
        .await
        .map_err(session_error)?;

    if output.timed_out {
        return Err(SYSTEM_MANAGER_COMMAND_TIMEOUT.to_owned());
    }
    if output.truncated {
        return Err(SYSTEM_MANAGER_RESPONSE_TOO_LARGE.to_owned());
    }

    let result = ExecResult {
        stdout: output.stdout_lossy().into_owned(),
        stderr: output.stderr_lossy().into_owned(),
        exit_status: output.exit_status.map(|code| code as i32),
        timed_out: false,
    };
    if result.succeeded() {
        Ok(result.stdout)
    } else {
        Err(SYSTEM_MANAGER_COMMAND_FAILED.to_owned())
    }
}

#[tauri::command]
pub(super) async fn list_remote_processes(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<Vec<RemoteProcess>, String> {
    let stdout = run_plain(state.inner(), &session_id, inventory::LIST_PROCESSES).await?;
    Ok(inventory::parse_processes(&stdout))
}

#[tauri::command]
pub(super) async fn list_listening_ports(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<Vec<ListeningPort>, String> {
    let stdout = run_plain(state.inner(), &session_id, inventory::LIST_PORTS).await?;
    Ok(inventory::parse_ports(&stdout))
}

#[tauri::command]
pub(super) async fn list_system_services(
    state: State<'_, DesktopState>,
    session_id: String,
) -> Result<Vec<SystemService>, String> {
    let stdout = run_plain(state.inner(), &session_id, inventory::LIST_SERVICES).await?;
    Ok(inventory::parse_services(&stdout))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InventoryProbeResult {
    Available,
    Rejected,
    IdentityMismatch,
}

/// Runs one non-mutating route probe. Diagnostics are deliberately ignored:
/// route selection depends only on an explicit zero status, never localized
/// or ambiguous stderr text.
async fn run_inventory_probe(
    state: &DesktopState,
    session_id: &str,
    plan: &InventoryActionPlan,
    route: InventoryActionRoute,
) -> Result<InventoryProbeResult, String> {
    let output = state
        .sessions
        .exec_capture(
            session_id,
            plan.probe_command(route),
            ExecLimits {
                max_output_bytes: INVENTORY_ACTION_OUTPUT_BYTES,
                timeout: INVENTORY_TIMEOUT,
            },
        )
        .await
        .map_err(session_error)?;

    if output.timed_out {
        return Err(SYSTEM_MANAGER_COMMAND_TIMEOUT.to_owned());
    }
    if output.truncated {
        return Err(SYSTEM_MANAGER_RESPONSE_TOO_LARGE.to_owned());
    }

    Ok(match output.exit_status {
        Some(0) => InventoryProbeResult::Available,
        Some(PROCESS_IDENTITY_MISMATCH_EXIT_STATUS)
            if plan.kind() == InventoryActionKind::ProcessSignal =>
        {
            InventoryProbeResult::IdentityMismatch
        }
        _ => InventoryProbeResult::Rejected,
    })
}

/// Selects a route through non-mutating probes, then executes the mutation
/// exactly once. Failure, timeout, truncation, missing status and transport
/// loss after that point are final and can never trigger a replay.
async fn run_inventory_action(
    state: &DesktopState,
    session_id: &str,
    plan: InventoryActionPlan,
) -> Result<(), String> {
    let mut selected_route = None;
    for route in plan.probe_order() {
        match run_inventory_probe(state, session_id, &plan, route).await? {
            InventoryProbeResult::Available => {
                selected_route = Some(route);
                break;
            }
            InventoryProbeResult::IdentityMismatch => {
                return Err(SYSTEM_MANAGER_INVALID_TARGET.to_owned());
            }
            InventoryProbeResult::Rejected => {}
        }
    }
    let route = selected_route.ok_or_else(|| SYSTEM_MANAGER_COMMAND_FAILED.to_owned())?;
    let output = state
        .sessions
        .exec_capture(
            session_id,
            plan.command(route),
            ExecLimits {
                max_output_bytes: INVENTORY_ACTION_OUTPUT_BYTES,
                timeout: INVENTORY_TIMEOUT,
            },
        )
        .await
        .map_err(session_error)?;

    if output.timed_out {
        return Err(SYSTEM_MANAGER_COMMAND_TIMEOUT.to_owned());
    }
    if output.truncated {
        return Err(SYSTEM_MANAGER_RESPONSE_TOO_LARGE.to_owned());
    }
    match output.exit_status {
        Some(0) => Ok(()),
        Some(PROCESS_IDENTITY_MISMATCH_EXIT_STATUS)
            if plan.kind() == InventoryActionKind::ProcessSignal =>
        {
            Err(SYSTEM_MANAGER_INVALID_TARGET.to_owned())
        }
        _ => Err(SYSTEM_MANAGER_COMMAND_FAILED.to_owned()),
    }
}

#[tauri::command]
pub(super) async fn signal_remote_process(
    state: State<'_, DesktopState>,
    session_id: String,
    pid: u32,
    start_time_token: String,
    signal: ProcessSignal,
) -> Result<(), String> {
    // Invalid PIDs (including dangerous process-group target 0 and values
    // above the signed pid_t boundary) produce no command and no sudo rung.
    let plan = inventory::signal_action_plan(signal, pid, &start_time_token)
        .ok_or_else(|| SYSTEM_MANAGER_INVALID_TARGET.to_owned())?;
    run_inventory_action(state.inner(), &session_id, plan).await
}

#[tauri::command]
pub(super) async fn run_system_service_action(
    state: State<'_, DesktopState>,
    session_id: String,
    unit: String,
    action: ServiceAction,
) -> Result<(), String> {
    // An unusable unit name produces no command at all.
    let plan = inventory::service_action_plan(action, &unit)
        .ok_or_else(|| SYSTEM_MANAGER_INVALID_TARGET.to_owned())?;
    run_inventory_action(state.inner(), &session_id, plan).await
}

#[cfg(test)]
mod tmux_adapter_tests {
    use super::*;

    #[test]
    fn adapter_accepts_only_non_interactive_tmux_plans() {
        let list = tmux_exec_plan(&TmuxOperation::ListSessions).expect("list plan");
        assert_eq!(list.kind(), TmuxExecKind::ListSessions);
        assert!(!list.mutates());
        assert!(!list.retry_on_empty_output());

        assert_eq!(
            tmux_exec_plan(&TmuxOperation::AttachSession {
                name: "ops".to_owned(),
            })
            .expect_err("attach needs a PTY"),
            SYSTEM_MANAGER_TMUX_ATTACH_UNAVAILABLE,
        );
    }

    #[test]
    fn adapter_maps_invalid_targets_without_exposing_the_name() {
        assert_eq!(
            tmux_exec_plan(&TmuxOperation::RenameSession {
                name: "bad:name".to_owned(),
                new_name: "still-bad".to_owned(),
            })
            .expect_err("invalid target"),
            SYSTEM_MANAGER_INVALID_TARGET,
        );
    }
}
