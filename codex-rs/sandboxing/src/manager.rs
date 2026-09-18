                            } else {
                                "false"
                            },
                        )],
                    );
                }
                (argv, None, Some(pending))
            }
            #[cfg(not(target_os = "windows"))]
            SandboxType::WindowsRestrictedToken => (argv, None, Some(pending_sandboxed_request?)),
        };

        // Unsandboxed exec-server requests may have foreign cwd values that cannot be prepared
        // locally, but their effective permissions must still be preserved. In that case, carry
        // forward the base profile.
        let permission_profile = pending_sandboxed_request
            .map_or(base_effective_permission_profile, |pending| {
                pending.effective_permission_profile
            });

        Ok(SandboxExecRequest {
            command: argv,
            cwd: command.cwd,
            sandbox_policy_cwd: sandbox_policy_cwd.clone(),
            env: command.env,
            network: network.cloned(),
            network_environment_id: environment_id.map(str::to_string),
            sandbox,
            windows_sandbox_level,
            windows_sandbox_private_desktop,
            permission_profile,
            arg0: arg0_override,
            allow_destructive_filesystem_effects,
        })
    }

    pub fn transform_for_direct_spawn(
        &self,
        request: SandboxDirectSpawnTransformRequest<'_>,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        self.transform_for_direct_spawn_with_destructive_filesystem_effects(request, false)
    }

    pub fn transform_for_direct_spawn_with_destructive_filesystem_effects(
        &self,
        request: SandboxDirectSpawnTransformRequest<'_>,
        allow_destructive_filesystem_effects: bool,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        #[cfg(target_os = "windows")]
        if request.transform.sandbox == SandboxType::WindowsRestrictedToken {
            let codex_home = codex_utils_home_dir::find_codex_home()
                .map_err(|err| SandboxTransformError::WindowsSandboxPreparation(err.to_string()))?;
            return self.transform_for_direct_spawn_with_codex_home(
                request,
                codex_home.as_path(),
                allow_destructive_filesystem_effects,
            );
        }
        self.transform_with_destructive_filesystem_effects(
            request.transform,
            allow_destructive_filesystem_effects,
        )
    }

    #[cfg(target_os = "windows")]
    fn transform_for_direct_spawn_with_codex_home(
        &self,
        request: SandboxDirectSpawnTransformRequest<'_>,
        codex_home: &Path,
        allow_destructive_filesystem_effects: bool,
    ) -> Result<SandboxExecRequest, SandboxTransformError> {
        let workspace_roots = request.workspace_roots;
        let proxy_settings_mode = request.windows_sandbox_proxy_settings_mode;
        let mut request = self.transform_with_destructive_filesystem_effects(
            request.transform,
            allow_destructive_filesystem_effects,
        )?;
        if request.sandbox == SandboxType::WindowsRestrictedToken {
            wrap_windows_sandbox_exec_request_for_direct_spawn(
                &mut request,
                workspace_roots,
                codex_home,
                proxy_settings_mode,
            )?;
        }
        Ok(request)
    }
}

#[cfg(target_os = "windows")]
fn wrap_windows_sandbox_exec_request_for_direct_spawn(
    request: &mut SandboxExecRequest,
    workspace_roots: &[AbsolutePathBuf],
    codex_home: &Path,
    proxy_settings_mode: codex_windows_sandbox::WindowsSandboxProxySettingsMode,
) -> Result<(), SandboxTransformError> {
    // TODO(anp): Keep PathUri through the Windows sandbox wrapper boundary.
    let native_cwd =
        request
            .cwd
            .to_abs_path()
            .map_err(|source| SandboxTransformError::InvalidCommandCwd {
                cwd: request.cwd.clone(),
                source,
            })?;
    let native_sandbox_policy_cwd = request.sandbox_policy_cwd.to_abs_path().map_err(|source| {
        SandboxTransformError::InvalidSandboxPolicyCwd {
            cwd: request.sandbox_policy_cwd.clone(),
            source,
        }
    })?;
    let Some(program) = request.command.first_mut() else {
        return Err(SandboxTransformError::WindowsSandboxPreparation(
            "sandbox command was empty".to_string(),
        ));
    };
    let source = std::path::PathBuf::from(&program);
    let helper = codex_windows_sandbox::resolve_exe_for_launch(source.as_path(), codex_home);
    *program = helper.to_string_lossy().into_owned();

    let inner_command = std::mem::take(&mut request.command);
    let proxy_enforced = request.network.is_some();
    let network_proxy_restricting_sid = request
        .network
        .as_ref()
        .map(|network| {
            network
                .network_proxy_restricting_sid(request.network_environment_id.as_deref())
                .ok_or_else(|| {
                    SandboxTransformError::WindowsSandboxPreparation(
                        "managed Windows proxy route is missing its restricting SID".to_string(),
                    )
                })
        })
        .transpose()?;
    let use_elevated = windows_sandbox_uses_elevated_backend(request.windows_sandbox_level);
    let overrides = if use_elevated {
        resolve_windows_elevated_filesystem_overrides(
            request.sandbox,
            &request.permission_profile,
            &native_sandbox_policy_cwd,
            use_elevated,
        )
    } else {
        resolve_windows_restricted_token_filesystem_overrides(
            request.sandbox,
            &request.permission_profile,
            &native_sandbox_policy_cwd,
            request.windows_sandbox_level,
        )
    }
    .map_err(SandboxTransformError::WindowsSandboxPreparation)?;
    let empty_paths: &[AbsolutePathBuf] = &[];
    let read_roots_override = overrides
        .as_ref()
        .and_then(|overrides| overrides.read_roots_override.as_deref());
    let read_roots_include_platform_defaults = overrides
        .as_ref()
        .is_some_and(|overrides| overrides.read_roots_include_platform_defaults);
    let write_roots_override = overrides
        .as_ref()
        .and_then(|overrides| overrides.write_roots_override.as_deref());
    let deny_read_paths_override = overrides.as_ref().map_or(empty_paths, |overrides| {
        overrides.additional_deny_read_paths.as_slice()
    });
    let deny_write_paths_override = overrides.as_ref().map_or(empty_paths, |overrides| {
        overrides.additional_deny_write_paths.as_slice()
    });
    let mut wrapper_args =
        codex_windows_sandbox::create_windows_sandbox_command_args_for_permission_profile(
            inner_command,
            &native_cwd,
            workspace_roots,
            &request.env,
            &request.permission_profile,
            request.windows_sandbox_level,
            request.windows_sandbox_private_desktop,
            proxy_enforced,
            network_proxy_restricting_sid.as_deref(),
            proxy_settings_mode,
            read_roots_override,
            read_roots_include_platform_defaults,
            write_roots_override,
            deny_read_paths_override,
            deny_write_paths_override,
            codex_home,