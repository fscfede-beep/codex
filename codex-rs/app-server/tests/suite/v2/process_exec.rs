use anyhow::Result;
use app_test_support::TestAppServer;
use app_test_support::create_mock_responses_server_sequence_unchecked;
use codex_app_server_protocol::ProcessSpawnParams;
use codex_app_server_protocol::RequestId;
use codex_exec_server::CODEX_EXEC_SERVER_URL_ENV_VAR;
use codex_utils_absolute_path::AbsolutePathBuf;
use pretty_assertions::assert_eq;
use std::path::Path;
use tempfile::TempDir;
use tokio::time::timeout;
use wiremock::MockServer;

use super::connection_handling_websocket::DEFAULT_READ_TIMEOUT;
use super::connection_handling_websocket::create_config_toml;

#[tokio::test]
async fn process_spawn_fails_closed_before_backend_creation() -> Result<()> {
    let codex_home = TempDir::new()?;
    let (_server, mut mcp) = initialized_mcp(codex_home.path()).await?;

    let probe_file = codex_home.path().join("process-created");
    let command = if cfg!(windows) {
        vec![
            "powershell.exe".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            format!("[IO.File]::WriteAllText('{}', 'process')", probe_file.display()),
        ]
    } else {
        vec![
            "sh".to_string(),
            "-lc".to_string(),
            format!("printf process > '{}'", probe_file.display()),
        ]
    };

    let request_id = mcp
        .send_process_spawn_request(ProcessSpawnParams {
            ..process_spawn_params(
                "blocked-process".to_string(),
                codex_home.path(),
                command,
            )?
        })
        .await?;

    let error = mcp
        .read_stream_until_error_message(RequestId::Integer(request_id))
        .await?;
    assert_eq!(
        error.error.message,
        "process/spawn is disabled because this RPC has no governed approval and sandbox authority"
    );
    assert!(!probe_file.exists());

    Ok(())
}

#[tokio::test]
async fn process_spawn_returns_error_when_local_environment_is_disabled() -> Result<()> {
    let codex_home = TempDir::new()?;
    let server = create_mock_responses_server_sequence_unchecked(Vec::new()).await;
    create_config_toml(codex_home.path(), &server.uri(), "never")?;
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home.path())
        .without_auto_env()
        .with_env_overrides(&[(CODEX_EXEC_SERVER_URL_ENV_VAR, Some("none"))])
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;

    let process_request_id = mcp
        .send_process_spawn_request(process_spawn_params(
            "disabled-process".to_string(),
            codex_home.path(),
            vec!["sh".to_string(), "-lc".to_string(), "true".to_string()],
        )?)
        .await?;
    let error = mcp
        .read_stream_until_error_message(RequestId::Integer(process_request_id))
        .await?;
    assert_eq!(error.error.message, "local environment is not configured");

    Ok(())
}

async fn initialized_mcp(codex_home: &Path) -> Result<(MockServer, TestAppServer)> {
    let server = create_mock_responses_server_sequence_unchecked(Vec::new()).await;
    create_config_toml(codex_home, &server.uri(), "never")?;
    let mut mcp = TestAppServer::builder()
        .with_codex_home(codex_home)
        .without_auto_env()
        .build()
        .await?;
    timeout(DEFAULT_READ_TIMEOUT, mcp.initialize()).await??;
    Ok((server, mcp))
}

fn process_spawn_params(
    process_handle: String,
    cwd: &Path,
    command: Vec<String>,
) -> Result<ProcessSpawnParams> {
    Ok(ProcessSpawnParams {
        command,
        process_handle,
        cwd: AbsolutePathBuf::try_from(cwd)?,
        tty: false,
        stream_stdin: false,
        stream_stdout_stderr: false,
        output_bytes_cap: None,
        timeout_ms: None,
        env: None,
        size: None,
    })
}
