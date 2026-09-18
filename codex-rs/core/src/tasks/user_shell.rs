use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use codex_async_utils::CancelErr;
use codex_async_utils::OrCancelExt;
use codex_network_proxy::PROXY_ACTIVE_ENV_KEY;
use codex_utils_absolute_path::AbsolutePathBuf;
use tokio_util::sync::CancellationToken;
use tracing::error;
use uuid::Uuid;

use crate::exec::ExecCapturePolicy;
use crate::exec::StdoutStream;
use crate::exec::build_exec_request;
use crate::exec::execute_exec_request;
use crate::exec_env::create_env;
use crate::exec_env::inject_apply_patch_env;
use crate::exec_env::inject_session_env;
use crate::session::TurnInput;
use crate::session::turn_context::TurnContext;
use crate::shell::Shell;
use crate::state::TaskKind;
use crate::tools::format_exec_output_str;
use crate::tools::runtimes::RuntimePathPrepends;
#[cfg(unix)]
use crate::tools::runtimes::apply_package_path_prepend;
use crate::tools::runtimes::maybe_wrap_shell_lc_with_snapshot;
use crate::tools::runtimes::strip_managed_proxy_env;
use crate::user_shell_command::user_shell_command_record_item;
use codex_protocol::exec_output::ExecToolCallOutput;
use codex_protocol::exec_output::StreamOutput;
use codex_protocol::items::CommandExecutionItem;
use codex_protocol::items::CommandExecutionStatus;
use codex_protocol::items::TurnItem;
use codex_protocol::protocol::ErrorEvent;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::ExecCommandSource;
use codex_sandboxing::SandboxType;
use codex_shell_command::parse_command::parse_command;
use codex_thread_store::PersistContext;

use super::SessionTask;
use super::SessionTaskResult;
use crate::session::session::Session;
use codex_protocol::models::PermissionProfile;

const USER_SHELL_TIMEOUT_MS: u64 = 60 * 60 * 1000; // 1 hour

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserShellCommandMode {
    /// Executes as an independent turn lifecycle (emits TurnStarted/TurnComplete
    /// via task lifecycle plumbing).
    StandaloneTurn,
    /// Executes while another turn is already active. This mode must not emit a
    /// second TurnStarted/TurnComplete pair for the same active turn.
    ActiveTurnAuxiliary,
}

#[derive(Clone)]
pub(crate) struct UserShellCommandTask {
    command: String,
    timeout_ms: Option<u64>,
}

impl UserShellCommandTask {
    pub(crate) fn new(command: String, timeout_ms: Option<u64>) -> Self {
        Self {
            command,
            timeout_ms,
        }
    }
}

impl SessionTask for UserShellCommandTask {
    fn kind(&self) -> TaskKind {
        TaskKind::Regular
    }

    fn span_name(&self) -> &'static str {
        "session_task.user_shell"
    }

    async fn run(
        self: Arc<Self>,
        session: Arc<Session>,
        turn_context: Arc<TurnContext>,
        _input: Vec<TurnInput>,
        cancellation_token: CancellationToken,
    ) -> SessionTaskResult {
        execute_user_shell_command(
            session,
            turn_context,
            self.command.clone(),
            self.timeout_ms,
            cancellation_token,
            UserShellCommandMode::StandaloneTurn,
        )
        .await;
        Ok(None)
    }
}

pub(crate) async fn execute_user_shell_command(
    session: Arc<Session>,
    turn_context: Arc<TurnContext>,
    command: String,
    timeout_ms: Option<u64>,
    cancellation_token: CancellationToken,
    mode: UserShellCommandMode,
) {
    session
        .services
        .session_telemetry
        .counter("codex.task.user_shell", /*inc*/ 1, &[]);

    if mode == UserShellCommandMode::StandaloneTurn {
        // Auxiliary mode runs within an existing active turn. That turn already
        // emitted TurnStarted, so emitting another TurnStarted here would create
        // duplicate turn lifecycle events and confuse clients.
        // TODO(ccunningham): After TurnStarted, emit model-visible turn context diffs for
        // standalone lifecycle tasks (for example /shell, and review once it emits TurnStarted).
        // `/compact` is an intentional exception because compaction requests should not include
        // freshly reinjected context before the summary/replacement history is applied.
        session.emit_turn_started(&turn_context).await;
    }

    let Some((turn_environment, environment_shell)) = turn_context
        .environments
        .local()
        .and_then(|environment| environment.shell.as_ref().map(|shell| (environment, shell)))
    else {
        send_user_shell_error(
            &session,
            turn_context.as_ref(),
            "shell is unavailable in this session",
        )
        .await;
        return;
    };

    // Execute the user's script under the environment's shell; this
    // allows commands that use shell features (pipes, &&, redirects, etc.).
    // We do not source rc files or otherwise reformat the script.
    let use_login_shell = true;
    let display_command = environment_shell.derive_exec_args(&command, use_login_shell);
    // TODO(anp): Migrate user-shell events and execution plumbing to PathUri so this local-only
    // feature does not need to project the selected environment cwd onto the Codex host.
    let Ok(cwd) = turn_environment.cwd().to_abs_path() else {
        send_user_shell_error(
            &session,
            turn_context.as_ref(),
            "shell working directory is not native to the Codex host",
        )
        .await;
        return;
    };
    if turn_environment.workspace_roots().is_empty() {
        send_user_shell_error(
            &session,
            turn_context.as_ref(),
            "shell requires an explicit workspace root",
        )
        .await;
        return;
    }

    let environment_permission_profile =
        turn_environment.permission_profile_with_workspace_roots();
    let permission_profile = match &environment_permission_profile {
        PermissionProfile::External { .. } => {
            send_user_shell_error(
                &session,
                turn_context.as_ref(),
                "shell is unavailable with an external filesystem authority",
            )
            .await;
            return;
        }
        PermissionProfile::Disabled => PermissionProfile::workspace_write_with_path_uris(
            turn_environment.workspace_roots(),
            NetworkSandboxPolicy::Restricted,
            /*exclude_tmpdir_env_var*/ false,
            /*exclude_slash_tmp*/ false,
        ),
        PermissionProfile::Managed { .. }
            if environment_permission_profile
                .file_system_sandbox_policy()
                .has_full_disk_write_access_for_convention(
                    turn_environment.cwd().infer_path_convention(),
                ) =>
        {
            PermissionProfile::workspace_write_with_path_uris(
                turn_environment.workspace_roots(),
                NetworkSandboxPolicy::Restricted,
                /*exclude_tmpdir_env_var*/ false,
                /*exclude_slash_tmp*/ false,
            )
        }
        _ => environment_permission_profile,
    };

    let shell_environment_policy = turn_environment.shell_environment_policy();
    let mut exec_env_map = create_env(shell_environment_policy, Some(session.thread_id));
    inject_session_env(&mut exec_env_map, session.session_id());
    inject_apply_patch_env(&mut exec_env_map, &turn_context.config.features);
    if exec_env_map.contains_key(PROXY_ACTIVE_ENV_KEY) {
        strip_managed_proxy_env(&mut exec_env_map);
    }

    // Do not prewarm an unsandboxed shell snapshot on this path.
    let exec_command = prepare_user_shell_exec_command(
        &display_command,
        environment_shell,
        /*shell_snapshot*/ None,
        &shell_environment_policy.r#set,
        &mut exec_env_map,
    );

    let call_id = Uuid::new_v4().to_string();
    let raw_command = command;

    let parsed_cmd = parse_command(&display_command);
    session
        .emit_turn_item_started(
            turn_context.as_ref(),
            &TurnItem::CommandExecution(CommandExecutionItem {
                model_context: None,
                id: call_id.clone(),
                plugin_id: None,
                script_path: None,
                process_id: None,
                command: display_command.clone(),
                cwd: cwd.clone().into(),
                parsed_cmd: parsed_cmd.clone(),
                source: ExecCommandSource::UserShell,
                interaction_input: None,
                status: CommandExecutionStatus::InProgress,
                stdout: None,
                stderr: None,
                aggregated_output: None,
                exit_code: None,
                duration: None,
                formatted_output: None,
            }),
        )
        .await;

    let windows_sandbox_type = codex_protocol::sandbox::effective_windows_sandbox_type(
        turn_context.config.windows_sandbox_type,
        turn_context.config.windows_sandbox_level,
    );
    let exec_env = match build_exec_request(
        crate::exec::ExecParams {
            command: exec_command.clone(),
            cwd: cwd.clone(),
            env: exec_env_map,
            expiration: timeout_ms.unwrap_or(USER_SHELL_TIMEOUT_MS).into(),
            capture_policy: ExecCapturePolicy::ShellTool,
            network: None,
            network_environment_id: None,
            sandbox_permissions: crate::sandboxing::SandboxPermissions::UseDefault,
            windows_sandbox_level: turn_context.windows_sandbox_level,
            windows_sandbox_private_desktop: turn_context.config.permissions.windows_sandbox_private_desktop,
            justification: None,
            arg0: None,
        },
        &permission_profile,
        &cwd,
        turn_environment.workspace_roots(),
        &turn_context.config.codex_linux_sandbox_exe,
        &turn_context.config.codex_self_exe,
        windows_sandbox_type,
        turn_context.config.use_legacy_landlock,
    ) {
        Ok(exec_env) => exec_env,
        Err(err) => {
            send_user_shell_error(
                &session,
                turn_context.as_ref(),
                &format!("shell execution could not be sandboxed: {err}"),
            )
            .await;
            return;
        }
    };

    if exec_env.sandbox == SandboxType::None {
        send_user_shell_error(
            &session,
            turn_context.as_ref(),
            "shell execution was rejected because no enforceable sandbox is available",
        )
        .await;
        return;
    }
    let stdout_stream = Some(StdoutStream {
        sub_id: turn_context.sub_id.clone(),
        call_id: call_id.clone(),
        tx_event: session.get_tx_event(),
    });

    let exec_result = execute_exec_request(exec_env, stdout_stream, /*after_spawn*/ None)
        .or_cancel(&cancellation_token)
        .await;

    match exec_result {
        Err(CancelErr::Cancelled) => {
            let aborted_message = "command aborted by user".to_string();
            let exec_output = ExecToolCallOutput {
                exit_code: -1,
                stdout: StreamOutput::new(String::new()),
                stderr: StreamOutput::new(aborted_message.clone()),
                aggregated_output: StreamOutput::new(aborted_message.clone()),
                duration: Duration::ZERO,
                timed_out: false,
            };
            persist_user_shell_output(
                &session,
                turn_context.as_ref(),
                &raw_command,
                &exec_output,
                mode,
            )
            .await;
            session
                .emit_turn_item_completed(
                    turn_context.as_ref(),
                    TurnItem::CommandExecution(CommandExecutionItem {
                        model_context: None,
                        id: call_id,
                        plugin_id: None,
                        script_path: None,
                        process_id: None,
                        command: display_command.clone(),
                        cwd: cwd.clone().into(),
                        parsed_cmd: parsed_cmd.clone(),
                        source: ExecCommandSource::UserShell,
                        interaction_input: None,
                        status: CommandExecutionStatus::Failed,
                        stdout: Some(String::new()),
                        stderr: Some(aborted_message.clone()),
                        aggregated_output: Some(aborted_message.clone()),
                        exit_code: Some(-1),
                        duration: Some(Duration::ZERO),
                        formatted_output: Some(aborted_message),
                    }),
                )
                .await;
        }
        Ok(Ok(output)) => {
            session
                .emit_turn_item_completed(
                    turn_context.as_ref(),
                    TurnItem::CommandExecution(CommandExecutionItem {
                        model_context: None,
                        id: call_id.clone(),
                        plugin_id: None,
                        script_path: None,
                        process_id: None,
                        command: display_command.clone(),
                        cwd: cwd.clone().into(),
                        parsed_cmd: parsed_cmd.clone(),
                        source: ExecCommandSource::UserShell,
                        interaction_input: None,
                        status: if output.exit_code == 0 {
                            CommandExecutionStatus::Completed
                        } else {
                            CommandExecutionStatus::Failed
                        },
                        stdout: Some(output.stdout.text.clone()),
                        stderr: Some(output.stderr.text.clone()),
                        aggregated_output: Some(output.aggregated_output.text.clone()),
                        exit_code: Some(output.exit_code),
                        duration: Some(output.duration),
                        formatted_output: Some(format_exec_output_str(
                            &output,
                            turn_context.model_info().truncation_policy.into(),
                        )),
                    }),
                )
                .await;

            persist_user_shell_output(&session, turn_context.as_ref(), &raw_command, &output, mode)
                .await;
        }
        Ok(Err(err)) => {
            error!("user shell command failed: {err:?}");
            let message = format!("execution error: {err:?}");
            let exec_output = ExecToolCallOutput {
                exit_code: -1,
                stdout: StreamOutput::new(String::new()),
                stderr: StreamOutput::new(message.clone()),
                aggregated_output: StreamOutput::new(message.clone()),
                duration: Duration::ZERO,
                timed_out: false,
            };
            session
                .emit_turn_item_completed(
                    turn_context.as_ref(),
                    TurnItem::CommandExecution(CommandExecutionItem {
                        model_context: None,
                        id: call_id,
                        plugin_id: None,
                        script_path: None,
                        process_id: None,
                        command: display_command,
                        cwd: cwd.into(),
                        parsed_cmd,
                        source: ExecCommandSource::UserShell,
                        interaction_input: None,
                        status: CommandExecutionStatus::Failed,
                        stdout: Some(exec_output.stdout.text.clone()),
                        stderr: Some(exec_output.stderr.text.clone()),
                        aggregated_output: Some(exec_output.aggregated_output.text.clone()),
                        exit_code: Some(exec_output.exit_code),
                        duration: Some(exec_output.duration),
                        formatted_output: Some(format_exec_output_str(
                            &exec_output,
                            turn_context.model_info().truncation_policy.into(),
                        )),
                    }),
                )
                .await;
            persist_user_shell_output(
                &session,
                turn_context.as_ref(),
                &raw_command,
                &exec_output,
                mode,
            )
            .await;
        }
    }
}

async fn send_user_shell_error(session: &Session, turn_context: &TurnContext, message: &str) {
    session
        .send_event(
            turn_context,
            EventMsg::Error(ErrorEvent {
                misalignment: None,
                message: message.to_string(),
                codex_error_info: None,
            }),
        )
        .await;
}

fn prepare_user_shell_exec_command(
    display_command: &[String],
    shell: &Shell,
    shell_snapshot: Option<&AbsolutePathBuf>,
    shell_environment_set: &HashMap<String, String>,
    exec_env_map: &mut HashMap<String, String>,
) -> Vec<String> {
    #[cfg(unix)]
    {
        prepare_user_shell_exec_command_with_path_prepend(
            display_command,
            shell,
            shell_snapshot,
            shell_environment_set,
            exec_env_map,
            apply_package_path_prepend,
        )
    }

    #[cfg(not(unix))]
    {
        maybe_wrap_shell_lc_with_snapshot(
            display_command,
            shell,
            shell_snapshot,
            shell_environment_set,
            exec_env_map,
            // On non-Unix targets, arg0 has already prepended the package path
            // to the process PATH before create_env() builds exec_env_map.
            // RuntimePathPrepends is only needed for Unix shell snapshot replay.
            &RuntimePathPrepends::default(),
        )
    }
}

/// Prepares a user-shell command after adding runtime-owned PATH entries.
///
/// The callback mutates the live exec environment for commands that are not
/// wrapped with a shell snapshot and records only the runtime-owned entries so
/// snapshot wrapping can reapply them after restoring the user's snapshot PATH.
#[cfg(unix)]
fn prepare_user_shell_exec_command_with_path_prepend(
    display_command: &[String],
    shell: &Shell,
    shell_snapshot: Option<&AbsolutePathBuf>,
    shell_environment_set: &HashMap<String, String>,
    exec_env_map: &mut HashMap<String, String>,
    prepend_runtime_path: impl FnOnce(&mut HashMap<String, String>, &mut RuntimePathPrepends),
) -> Vec<String> {
    let explicit_env_overrides = shell_environment_set.clone();
    let mut runtime_path_prepends = RuntimePathPrepends::default();
    prepend_runtime_path(exec_env_map, &mut runtime_path_prepends);
    maybe_wrap_shell_lc_with_snapshot(
        display_command,
        shell,
        shell_snapshot,
        &explicit_env_overrides,
        exec_env_map,
        &runtime_path_prepends,
    )
}

async fn persist_user_shell_output(
    session: &Session,
    turn_context: &TurnContext,
    raw_command: &str,
    exec_output: &ExecToolCallOutput,
    mode: UserShellCommandMode,
) {
    let output_item = user_shell_command_record_item(raw_command, exec_output, turn_context);

    if mode == UserShellCommandMode::StandaloneTurn {
        session
            .record_conversation_items(
                turn_context,
                turn_context.model_info(),
                std::slice::from_ref(&output_item),
            )
            .await;
        // Standalone shell turns can run before any regular user turn, so
        // explicitly materialize rollout persistence after recording output.
        session
            .ensure_rollout_materialized(PersistContext::Standard)
            .await;
        return;
    }

    session
        .inject_no_new_turn(vec![output_item], Some(turn_context))
        .await;
}

#[cfg(all(test, unix))]
#[path = "user_shell_tests.rs"]
mod tests;