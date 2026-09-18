    "TEST_SRCDIR",
    "TEST_WORKSPACE",
];

#[derive(Debug, PartialEq, Eq)]
struct SandboxCwd {
    uri: PathUri,
    native: AbsolutePathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct FileSystemSandboxRunner {
    runtime_paths: ExecServerRuntimePaths,
    helper_env: HashMap<String, String>,
}

impl FileSystemSandboxRunner {
    pub(crate) fn new(runtime_paths: ExecServerRuntimePaths) -> Self {
        Self {
            runtime_paths,
            helper_env: helper_env(),
        }
    }

    #[tracing::instrument(name = "fs.sandbox_request", skip_all)]
    pub(crate) async fn run(
        &self,
        sandbox: &FileSystemSandboxContext,
        request: FsHelperRequest,
    ) -> Result<FsHelperPayload, JSONRPCErrorError> {
        let allow_destructive = matches!(
            &request,
            FsHelperRequest::Remove(params) if params.destructive_capability
        );
        let command = self.sandbox_command_with_destructive_capability(
            sandbox,
            allow_destructive,
        )?;
        let request_json = serde_json::to_vec(&request).map_err(json_error)?;
        run_command(command, request_json).await
    }

    #[tracing::instrument(
        name = "fs.sandbox_prepare",
        skip_all,
        fields(permission_entries = tracing::field::Empty)
    )]
    pub(crate) fn sandbox_command(
        &self,
        sandbox: &FileSystemSandboxContext,
    ) -> Result<SandboxExecRequest, JSONRPCErrorError> {
        self.sandbox_command_with_destructive_capability(sandbox, false)
    }

    pub(crate) fn sandbox_command_with_destructive_capability(
        &self,
        sandbox: &FileSystemSandboxContext,
        allow_destructive_filesystem_effects: bool,
    ) -> Result<SandboxExecRequest, JSONRPCErrorError> {
        let cwd = sandbox_cwd(sandbox)?;
        let native_workspace_roots = sandbox
            .workspace_roots
            .iter()
            .map(native_workspace_root)
            .collect::<Result<Vec<_>, _>>()?;
        let workspace_roots = native_workspace_roots.as_slice();
        sandbox
            .validate_file_system_paths_for_current_host()
            .map_err(|err| invalid_request(err.to_string()))?;
        let native_permissions = sandbox
            .permissions
            .clone()
            .materialize_project_roots_with_workspace_roots(workspace_roots);
        let mut file_system_policy = native_permissions.file_system_sandbox_policy();
        tracing::Span::current().record("permission_entries", file_system_policy.entries.len());
        let helper_read_roots = if sandbox.use_legacy_landlock {
            Vec::new()
        } else {
            helper_read_roots(&self.runtime_paths)
        };
        add_helper_runtime_permissions(
            &mut file_system_policy,
            &helper_read_roots,
            cwd.native.as_path(),
        );
        // Linux resolves aliases in the sandbox helper. Doing it here also probes
        // unrelated permission roots synchronously on the executor's runtime thread.
        #[cfg(not(target_os = "linux"))]
        normalize_file_system_policy_root_aliases(&mut file_system_policy);
        #[cfg(windows)]
        bind_windows_cwd_relative_deny_read_globs(&mut file_system_policy, &cwd.uri)?;
        let network_policy = NetworkSandboxPolicy::Restricted;
        let permission_profile = PermissionProfile::from_runtime_permissions_with_enforcement(
            native_permissions.enforcement(),
            &file_system_policy,
            network_policy,
        );
        self.sandbox_exec_request(&permission_profile, &cwd, workspace_roots, sandbox)
    }

    fn sandbox_exec_request(
        &self,
        permission_profile: &PermissionProfile,
        cwd: &SandboxCwd,
        workspace_roots: &[AbsolutePathBuf],
        sandbox_context: &FileSystemSandboxContext,
        allow_destructive_filesystem_effects: bool,
    ) -> Result<SandboxExecRequest, JSONRPCErrorError> {
        let helper = &self.runtime_paths.codex_self_exe;
        let sandbox_manager = SandboxManager::for_file_system_helpers();
        #[cfg(target_os = "macos")]
        let sandbox_manager = sandbox_manager.with_allowed_symlinked_codex_home(
            self.runtime_paths.allowed_symlinked_codex_home.clone(),
        );
        let (sandbox, windows_sandbox_level) = crate::sandbox_selection::select_sandbox(
            &sandbox_manager,
            permission_profile,
            sandbox_context,
            /*has_managed_network_requirements*/ false,
        );
        if sandbox == SandboxType::None {
            return Err(invalid_request(
                "filesystem sandbox cannot be enforced on this executor".to_string(),
            ));
        }
        // Requests use absolute paths; the helper can start at the filesystem root even if
        // the policy cwd was removed. Keep its drive or share for Windows `:root` rules.
        let helper_cwd = cwd
            .native
            .ancestors()
            .last()
            .ok_or_else(|| invalid_request("filesystem sandbox cwd has no root".to_string()))?;
        let command = SandboxCommand {
            program: helper.as_path().as_os_str().to_owned(),
            args: vec![CODEX_FS_HELPER_ARG1.to_string()],
            cwd: PathUri::from_abs_path(&helper_cwd),
            env: self.helper_env.clone(),
            managed_network: None,
            additional_permissions: None,
        };
        sandbox_manager
.transform_for_direct_spawn(SandboxDirectSpawnTransformRequest {
                workspace_roots,
                windows_sandbox_proxy_settings_mode:
                    codex_sandboxing::WindowsSandboxProxySettingsMode::Preserve,
                transform: SandboxTransformRequest {
                    command,
                    permissions: permission_profile,
                    sandbox,
                    enforce_managed_network: false,
                    environment_id: None,
                    network: None,