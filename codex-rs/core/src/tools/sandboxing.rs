            )
    }

    pub(crate) fn network_proxy<'b>(
        &'b self,
        fallback: Option<&'b NetworkProxy>,
    ) -> Option<&'b NetworkProxy> {
        // Execution-only proxies need no fallback; offline attempts must not revive one.
        if self.enforce_managed_network {
            self.network_proxy.or(fallback)
        } else {
            None
        }
    }

    pub fn env_for(
        &self,
        command: SandboxCommand,
        options: ExecOptions,
        network: Option<&NetworkProxy>,
        environment_id: Option<&str>,
    ) -> Result<crate::sandboxing::ExecRequest, CodexErr> {
        let network = self.network_proxy(network);
        let request = self.manager.transform_with_destructive_filesystem_effects(
            SandboxTransformRequest {
                command,
                permissions: self.permissions,
                sandbox: self.sandbox,
                enforce_managed_network: self.enforce_managed_network,
                environment_id,
                network,
                sandbox_policy_cwd: self.sandbox_cwd,
                sandbox_exe: self.sandbox_exe.map(std::path::PathBuf::as_path),
                use_legacy_landlock: self.use_legacy_landlock,
                windows_sandbox_level: self.windows_sandbox_level,
                windows_sandbox_private_desktop: self.windows_sandbox_private_desktop,
            },
            self.allow_destructive_filesystem_effects,
        )
        .map_err(CodexErr::from)?;Err::from)?;
        let workspace_roots = self
            .workspace_roots
            .iter()
            .map(PathUri::to_abs_path)
            .collect::<std::io::Result<Vec<_>>>()?;
        crate::sandboxing::ExecRequest::from_sandbox_exec_request(request, options, workspace_roots)
    }

    pub fn env_for_exec_server(
        &self,