            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await;
        let failure = result.expect_err("write should fail");

        fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!failure.delta().is_exact());
    }

    #[tokio::test]
    async fn test_unreadable_destinations_return_inexact_delta() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("binary.dat");
        fs::write(dir.path().join("source.txt"), "before\n").unwrap();
        let cwd = PathUri::from_host_native_path(dir.path()).expect("absolute test path");

        for patch in [
            wrap_patch("*** Add File: binary.dat\n+text"),
            wrap_patch("*** Update File: source.txt\n*** Move to: binary.dat\n@@\n-before\n+after"),
        ] {
            fs::write(&path, [0xff, 0xfe, 0xfd]).unwrap();
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let delta = apply_patch(
                &patch,
                &cwd,
                &mut stdout,
                &mut stderr,
                LOCAL_FS.as_ref(),
                /*sandbox*/ None,
            )
            .await
            .unwrap();

            assert!(!delta.is_exact());
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_delete_symlink_returns_inexact_delta() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().unwrap();
        fs::write(dir.path().join("target.txt"), "target\n").unwrap();
        symlink(dir.path().join("target.txt"), dir.path().join("link.txt")).unwrap();
        let patch = wrap_patch("*** Delete File: link.txt");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let delta = apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();

        assert!(!delta.is_exact());
    }

    fn workspace_sandbox(cwd: &PathUri) -> FileSystemSandboxContext {
        FileSystemSandboxContext::from_permission_profile(
            PermissionProfile::workspace_write_with_path_uris(
                std::slice::from_ref(cwd),
                NetworkSandboxPolicy::Restricted,
                /*exclude_tmpdir_env_var*/ true,
                /*exclude_slash_tmp*/ true,
            ),
            cwd.clone(),
        )
    }

    #[tokio::test]
    async fn destructive_execution_rejects_missing_sandbox_even_with_targets() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = PathUri::from_host_native_path(dir.path()).expect("absolute cwd");
        let target = dir.path().join("delete.txt");
        std::fs::write(&target, "protected").unwrap();
        let sandbox = workspace_sandbox(&cwd);
        let patch = "*** Begin Patch\\n*** Delete File: delete.txt\\n*** End Patch";

        let action = match invocation::maybe_parse_apply_patch_verified(
            &["apply_patch".to_string(), patch.to_string()],
            &cwd,
            codex_exec_server::LOCAL_FS.as_ref(),
            Some(&sandbox),
        )
        .await
        {
            invocation::MaybeApplyPatchVerified::Body(action) => action,
            other => panic!("expected verified destructive patch, got {other:?}"),
        };

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = apply_patch_with_destructive_targets(
            patch,
            ApplyPatchOptions {
                update_file_mode: ApplyPatchFileUpdateMode::default(),
                follow_symlinks: false,
            },
            &cwd,
            &mut stdout,
            &mut stderr,
            codex_exec_server::LOCAL_FS.as_ref(),
            None,
            action.destructive_targets(),
        )
        .await
        .expect_err("destructive execution must fail without scoped sandbox");

        assert!(format!("{err}").contains("explicit filesystem sandbox"));
        assert_eq!(std::fs::read_to_string(target).unwrap(), "protected");
    }

    #[tokio::test]
    async fn destructive_target_appeared_after_authorization_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = PathUri::from_host_native_path(dir.path()).expect("absolute cwd");
        let target = dir.path().join("new.txt");
        let patch = "*** Begin Patch\\n*** Add File: new.txt\\n+approved\\n*** End Patch";
        let sandbox = workspace_sandbox(&cwd);

        let action = match invocation::maybe_parse_apply_patch_verified(
            &["apply_patch".to_string(), patch.to_string()],
            &cwd,
            codex_exec_server::LOCAL_FS.as_ref(),
            Some(&sandbox),
        )
        .await
        {
            invocation::MaybeApplyPatchVerified::Body(action) => action,
            other => panic!("expected verified destructive patch, got {other:?}"),
        };

        std::fs::write(&target, "attacker content").unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let err = apply_patch_with_destructive_targets(
            patch,
            ApplyPatchOptions {
                update_file_mode: ApplyPatchFileUpdateMode::default(),
                follow_symlinks: false,
            },
            &cwd,
            &mut stdout,
            &mut stderr,
            codex_exec_server::LOCAL_FS.as_ref(),
            Some(&sandbox),
            action.destructive_targets(),
        )
        .await
        .expect_err("target appearance must invalidate destructive authorization");

        assert!(format!("{err}").contains("target appeared after authorization"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "attacker content");
    }

    #[tokio::test]
    async fn destructive_target_requires_existing_immediate_parent() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = PathUri::from_host_native_path(dir.path()).expect("absolute cwd");
        let nested = dir.path().join("missing-parent").join("new.txt");
        let patch = "*** Begin Patch\\n*** Add File: missing-parent/new.txt\\n+approved\\n*** End Patch";
        let sandbox = workspace_sandbox(&cwd);

        let result = invocation::maybe_parse_apply_patch_verified(
            &["apply_patch".to_string(), patch.to_string()],
            &cwd,
            codex_exec_server::LOCAL_FS.as_ref(),
            Some(&sandbox),
        )
        .await;

        match result {
            invocation::MaybeApplyPatchVerified::CorrectnessError(error) => {
                assert!(format!("{error}").contains("existing parent"));
            }
            other => panic!("expected fail-closed parent validation, got {other:?}"),
        }
        assert!(!nested.exists());
    }

    
    #[cfg(unix)]
    #[tokio::test]
    async fn destructive_verify_rejects_hardlinked_target() {
        use std::os::unix::fs::hard_link;

        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let cwd = PathUri::from_host_native_path(dir.path()).expect("absolute cwd");
        let target = dir.path().join("target.txt");
        let outside_alias = outside.path().join("alias.txt");
        std::fs::write(&target, "protected").unwrap();
        hard_link(&target, &outside_alias).unwrap();

        let sandbox = workspace_sandbox(&cwd);
        let patch = "*** Begin Patch\n*** Delete File: target.txt\n*** End Patch";
        let result = invocation::maybe_parse_apply_patch_verified(
            &["apply_patch".to_string(), patch.to_string()],
            &cwd,
            codex_exec_server::LOCAL_FS.as_ref(),
            Some(&sandbox),
        )
        .await;

        match result {
            invocation::MaybeApplyPatchVerified::CorrectnessError(error) => {
                assert!(format!("{error}").contains("multiple hard links"));
            }
            other => panic!("expected hardlink rejection, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "protected");
        assert_eq!(std::fs::read_to_string(&outside_alias).unwrap(), "protected");
    }

}