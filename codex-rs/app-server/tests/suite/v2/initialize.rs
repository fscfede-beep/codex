    .await??;

    let JSONRPCMessage::Response(response) = message else {
        anyhow::bail!("expected initialize response, got {message:?}");
    };
    let InitializeResponse {
        user_agent,
        codex_home: response_codex_home,
        platform_family,
        platform_os,
        process_id,
    } = to_response::<InitializeResponse>(response)?;

    assert!(user_agent.starts_with("codex_vscode/"));
    assert!(process_id.is_some());
    assert_eq!(response_codex_home, expected_codex_home);
    assert_eq!(platform_family, std::env::consts::FAMILY);
    assert_eq!(platform_os, std::env::consts::OS);
    Ok(())
}

#[tokio::test]
async fn initialize_probe_does_not_override_originator() -> Result<()> {
    let responses = Vec::new();
    let server = create_mock_responses_server_sequence_unchecked(responses).await;
    let codex_home = TempDir::new()?;
    MockResponsesConfig::new(&server.uri())