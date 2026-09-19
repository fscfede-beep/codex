        args,
        MacosSeatbeltProfile::Process,
        /*allowed_symlinked_codex_home*/ None,
    )
    .map_err(|err| err.to_string())
}

pub(crate) fn create_seatbelt_command_args_with_profile(
    args: CreateSeatbeltCommandArgsParams<'_>,
    profile: MacosSeatbeltProfile,
    allowed_symlinked_codex_home: Option<&AbsolutePathBuf>,
) -> Result<Vec<String>, SeatbeltPreparationError> {
    let CreateSeatbeltCommandArgsParams {
        command,
        file_system_sandbox_policy,
        network_sandbox_policy,
        sandbox_policy_cwd,
        enforce_managed_network,
        managed_network,
        environment_id,
        network,
        extra_allow_unix_sockets,
    } = args;

    let unreadable_roots =
        file_system_sandbox_policy.get_unreadable_roots_with_cwd(sandbox_policy_cwd);
    let writable_roots = file_system_sandbox_policy
        .get_writable_roots_with_cwd_preserving_mutable_paths(sandbox_policy_cwd);
    let allowed_symlinked_codex_home = allowed_symlinked_codex_home
        .cloned()
        .map(normalize_top_level_alias_for_sandbox)
        .transpose()?;
    // Protect ancestors of read-only paths so renaming a writable directory
    // cannot move its descendants outside their policy carveouts.
    let mut protected_ancestors = BTreeSet::new();
    for writable_root in &writable_roots {
        let root = normalize_path_for_sandbox(writable_root.root.as_path())
            .unwrap_or_else(|| writable_root.root.clone());
        for protected_directory in writable_root.read_only_subpaths.iter().filter_map(|path| {
            normalize_path_for_sandbox(path.as_path())
                .unwrap_or_else(|| path.clone())
                .parent()
        }) {
            for ancestor in protected_directory.ancestors() {
                if !ancestor.as_path().starts_with(root.as_path()) {
                    break;
                }
                protected_ancestors.insert(ancestor);
            }
        }
    }
    let protected_ancestor_params: Vec<(String, PathBuf)> = protected_ancestors
        .into_iter()
        .enumerate()
        .map(|(index, path)| (format!("PROTECTED_ANCESTOR_{index}"), path.into_path_buf()))
        .collect();
    let (file_write_policy, file_write_dir_params) =
        if file_system_sandbox_policy.has_full_disk_write_access() {
            if unreadable_roots.is_empty() {
                // Allegedly, this is more permissive than `(allow file-write*)`.
                (
                    r#"(allow file-write* (regex #"^/"))"#.to_string(),
                    Vec::new(),
                )
            } else {
                build_seatbelt_access_policy(
                    SeatbeltAccessKind::Write,
                    vec![SeatbeltAccessRoot {
                        root: root_absolute_path(),
                        excluded_subpaths: unreadable_roots.clone(),
                        protected_metadata_names: Vec::new(),
                    }],
                    /*allowed_symlinked_codex_home*/ None,
                )?
            }
        } else {
            build_seatbelt_access_policy(
                SeatbeltAccessKind::Write,
                writable_roots
                    .into_iter()
                    .map(|root| SeatbeltAccessRoot {
                        protected_metadata_names: protected_metadata_names_for_writable_root(
                            file_system_sandbox_policy,
                            &root,
                            sandbox_policy_cwd,
                        ),
                        root: root.root,
                        excluded_subpaths: root.read_only_subpaths,
                    })
                    .collect(),
                allowed_symlinked_codex_home.as_ref(),
            )?
        };

    let (file_read_policy, file_read_dir_params) =
        if file_system_sandbox_policy.has_full_disk_read_access() {
            if unreadable_roots.is_empty() {
                (
                    "; allow read-only file operations\n(allow file-read*)".to_string(),
                    Vec::new(),
                )
            } else {
                let (policy, params) = build_seatbelt_access_policy(
                    SeatbeltAccessKind::Read,
                    vec![SeatbeltAccessRoot {
                        root: root_absolute_path(),
                        excluded_subpaths: unreadable_roots,
                        protected_metadata_names: Vec::new(),
                    }],
                    /*allowed_symlinked_codex_home*/ None,
                )?;
                (
                    format!("; allow read-only file operations\n{policy}"),
                    params,
                )
            }
        } else {
            let (policy, params) = build_seatbelt_access_policy(
                SeatbeltAccessKind::Read,
                file_system_sandbox_policy
                    .get_readable_roots_with_cwd(sandbox_policy_cwd)
                    .into_iter()
                    .map(|root| SeatbeltAccessRoot {
                        excluded_subpaths: unreadable_roots
                            .iter()
                            .filter(|path| path.as_path().starts_with(root.as_path()))
                            .cloned()
                            .collect(),
                        protected_metadata_names: Vec::new(),
                        root,
                    })
                    .collect(),
                /*allowed_symlinked_codex_home*/ None,
            )?;
            if policy.is_empty() {
                (String::new(), params)
            } else {
                (
                    format!("; allow read-only file operations\n{policy}"),
                    params,
                )
            }
        };

    let proxy = proxy_policy_inputs(
        managed_network,
        network,
        environment_id,
        extra_allow_unix_sockets,
    )
    .map_err(SeatbeltPreparationError::EnvironmentNetworkProxy)?;
    let network_policy =
        dynamic_network_policy_for_network(network_sandbox_policy, enforce_managed_network, &proxy);

    let include_platform_defaults = file_system_sandbox_policy.include_platform_defaults();
    let deny_read_policy =
        build_seatbelt_unreadable_glob_policy(file_system_sandbox_policy, sandbox_policy_cwd);
    let destructive_delete_deny_policy = if profile == MacosSeatbeltProfile::Process {
        if file_system_sandbox_policy.has_full_disk_write_access() {
            "(deny file-write-unlink)".to_string()
        } else {
            file_system_sandbox_policy
                .get_writable_roots_with_cwd_preserving_mutable_paths(sandbox_policy_cwd)
                .into_iter()
                .map(|root| {
                    let path = root.root.to_string_lossy().replace('"', "\\"");
                    format!("(deny file-write-unlink (subpath \"{path}\"))")
                })
                .collect::<Vec<_>>()
                .join("\n")
        }
    } else {
        String::new()
    };
    let mut policy_sections = vec![
        MACOS_SEATBELT_BASE_POLICY.to_string(),
        file_read_policy,
        file_write_policy,
        network_policy,
    ];
    // Network grants and Unix-socket allowlists must never reopen the
    // privileged app-server RPC transport to filesystem-restricted commands.
    if !file_system_sandbox_policy.has_full_disk_write_access() {
        let directory = codex_uds::shared_daemon_socket_directory()
            .map_err(|error| SeatbeltPreparationError::FileSystem(error.to_string()))?;
        let directory = serde_json::to_string(&directory.to_string_lossy())
            .map_err(|error| SeatbeltPreparationError::FileSystem(error.to_string()))?;
        policy_sections.push(format!(
            "(deny file-read* file-write* (subpath {directory}))\n\
             (deny network-outbound (remote unix-socket (subpath {directory})))"
        ));
    }
    if file_system_sandbox_policy.has_full_disk_read_access() {
        policy_sections.push(MACOS_SEATBELT_PREFERENCES_POLICY.to_string());
    }
    if include_platform_defaults {
        policy_sections.push(MACOS_RESTRICTED_READ_ONLY_PLATFORM_DEFAULTS.to_string());
        if profile == MacosSeatbeltProfile::Process {
            policy_sections.push(MACOS_PROCESS_PLATFORM_DEFAULTS.to_string());
        }
    }
    policy_sections.push(deny_read_policy);
    // Process sandboxes retain ordinary file creation/modification but cannot
    // unlink or rename objects inside writable roots. The helper profile is
    // intentionally excluded because it is an internal filesystem service.
    if !destructive_delete_deny_policy.is_empty() {
        policy_sections.push(destructive_delete_deny_policy);
    }
    // Renaming an allowed ancestor relocates its protected descendants past
    // their pathname carveouts. Keep these denies last so no broader allowance
    // can reopen the unlink operation used by rename.
    policy_sections.extend(
        protected_ancestor_params.iter().map(|(key, _)| {
            format!(
                "(deny file-write-unlink (require-all (vnode-type DIRECTORY) (literal (param \"{key}\"))))"
            )
        }),
    );

    let full_policy = policy_sections.join("\n");

    let dir_params = [
        file_read_dir_params,
        file_write_dir_params,