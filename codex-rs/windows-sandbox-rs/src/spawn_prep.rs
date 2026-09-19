    cwd: &Path,
    allow_paths: impl IntoIterator<Item = PathBuf>,
    destructive: bool,
) -> Result<Vec<RootCapabilitySid>> {
    let mut roots: Vec<PathBuf> = allow_paths.into_iter().collect();
    roots.sort_by_key(|root| canonicalize_path(root.as_path()));
    roots.dedup_by(|a, b| canonicalize_path(a.as_path()) == canonicalize_path(b.as_path()));

    let mut out = Vec::with_capacity(roots.len());
    for root in roots {
        let sid_str = if destructive {
            destructive_cap_sid_for_root(codex_home, &root)?
        } else {
            workspace_write_cap_sid_for_root(codex_home, cwd, &root)?
        };
        let sid = LocalSid::from_string(&sid_str)?;
        out.push(RootCapabilitySid { root, sid, sid_str });
    }
    Ok(out)
}

fn matching_root_capability<'a>(
    path: &Path,
    root_sids: &'a [RootCapabilitySid],
) -> Option<&'a RootCapabilitySid> {
    root_sids
        .iter()
        .filter(|root_sid| workspace_write_root_contains_path(&root_sid.root, path))
        .max_by_key(|root_sid| workspace_write_root_specificity(&root_sid.root))
}

fn deny_root_capabilities_for_path<'a>(
    path: &Path,
    root_sids: &'a [RootCapabilitySid],
) -> Vec<&'a RootCapabilitySid> {
    let matching_root_sids = root_sids
        .iter()
        .filter(|root_sid| workspace_write_root_overlaps_path(&root_sid.root, path))
        .collect::<Vec<_>>();
    if matching_root_sids.is_empty() {
        root_sids.iter().collect()
    } else {
        matching_root_sids
    }
}

pub(crate) fn allow_null_device_for_workspace_write(is_workspace_write: bool) {
    if !is_workspace_write {
        return;
    }

    unsafe {
        if let Ok(base) = get_current_token_for_restriction() {
            if let Ok(bytes) = get_logon_sid_bytes(base) {
                let mut tmp = bytes;
                let psid = tmp.as_mut_ptr() as *mut c_void;
                allow_null_device(psid);
            }
            CloseHandle(base);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_legacy_session_acl_rules(
    permissions: &ResolvedWindowsSandboxPermissions,
    codex_home: &Path,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
    additional_deny_read_paths: &[PathBuf],
    additional_deny_write_paths: &[PathBuf],
    acl_sids: LegacyAclSids<'_>,
) -> Result<()> {
    apply_legacy_session_acl_rules_with_destructive(
        permissions,
        codex_home,
        current_dir,
        env_map,
        additional_deny_read_paths,
        additional_deny_write_paths,
        acl_sids,
        /*destructive*/ false,
    )
}

pub(crate) fn apply_legacy_session_acl_rules_with_destructive(
    permissions: &ResolvedWindowsSandboxPermissions,
    codex_home: &Path,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
    additional_deny_read_paths: &[PathBuf],
    additional_deny_write_paths: &[PathBuf],
    acl_sids: LegacyAclSids<'_>,
    destructive: bool,
) -> Result<()> {
    let AllowDenyPaths { allow, mut deny } =
        compute_allow_paths_for_permissions(permissions, current_dir, env_map);
    unsafe {
        for path in additional_deny_write_paths {
            if !path.exists() {
                std::fs::create_dir_all(path)
                    .with_context(|| format!("create deny-write path {}", path.display()))?;
            }
            deny.insert(path.clone());
        }
        if let Some(readonly_sid) = acl_sids.readonly_sid {
            for p in &allow {
                let _ = add_allow_ace(p, readonly_sid.as_ptr());
            }
        } else {
            for p in &allow {
                let Some(root_sid) = matching_root_capability(p, acl_sids.write_root_sids) else {
                    continue;
                };
                if destructive {
                    let _ = ensure_allow_destructive_aces(p, &[root_sid.sid.as_ptr()]);
                } else {
                    let _ = ensure_allow_write_aces(p, &[root_sid.sid.as_ptr()]);
                    // Ordinary workspace-write must never retain delete authority.
                    // Failure to install the deny is a safety failure, not a warning.
                    add_deny_delete_ace(p, root_sid.sid.as_ptr())?;
                }
            }
        }
        for p in &deny {
            for root_sid in deny_root_capabilities_for_path(p, acl_sids.write_root_sids) {
                let _ = add_deny_write_ace(p, root_sid.sid.as_ptr());
            }
        }
        if !additional_deny_read_paths.is_empty() {
            if let Some(readonly_sid) = acl_sids.readonly_sid {
                let Some(readonly_sid_str) = acl_sids.readonly_sid_str else {
                    anyhow::bail!("readonly capability SID string missing");
                };
                sync_persistent_deny_read_acls(
                    codex_home,
                    readonly_sid_str,
                    additional_deny_read_paths,
                    readonly_sid.as_ptr(),
                )?;
            } else {
                for root_sid in acl_sids.write_root_sids {
                    sync_persistent_deny_read_acls(
                        codex_home,
                        &root_sid.sid_str,
                        additional_deny_read_paths,
                        root_sid.sid.as_ptr(),
                    )?;
                }
            }
        }
        for root_sid in acl_sids.write_root_sids {
            allow_null_device(root_sid.sid.as_ptr());
        }
        if let Some(readonly_sid) = acl_sids.readonly_sid {
            allow_null_device(readonly_sid.as_ptr());
        }
        if !acl_sids.write_root_sids.is_empty()
            && let Some(workspace_sid) =
                matching_root_capability(current_dir, acl_sids.write_root_sids)
        {
            let canonical_cwd = canonicalize_path(current_dir);
            if is_command_cwd_root(&workspace_sid.root, &canonical_cwd) {
                let _ = protect_workspace_codex_dir(current_dir, workspace_sid.sid.as_ptr());
                let _ = protect_workspace_agents_dir(current_dir, workspace_sid.sid.as_ptr());
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_elevated_spawn_context_for_permissions(
    permissions: ResolvedWindowsSandboxPermissions,
    codex_home: &Path,
    cwd: &Path,
    env_map: &mut HashMap<String, String>,
    command: &[String],
    read_roots_override: Option<&[PathBuf]>,
    read_roots_include_platform_defaults: bool,
    write_roots_override: Option<&[PathBuf]>,
    deny_read_paths_override: &[PathBuf],
    deny_write_paths_override: &[PathBuf],