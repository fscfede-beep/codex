    let ApplyPatchOptions {
        update_file_mode,
        follow_symlinks,
    } = options;
    if hunks.is_empty() {
        anyhow::bail!("No files were modified.");
    }

    let mut added: Vec<PathBuf> = Vec::new();
    let mut modified: Vec<PathBuf> = Vec::new();
    let mut deleted: Vec<PathBuf> = Vec::new();
    // A failed write can still have modified the target before surfacing an
    // error (for example by truncating before ENOSPC), so the accumulated
    // delta is no longer exact when a write fails.
    macro_rules! try_write {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(error) => {
                    delta.exact = false;
                    return Err(anyhow::Error::from(error));
                }
            }
        };
    }

    for hunk in hunks {
        let affected_path = hunk.path().to_path_buf();
        let path_uri = hunk.resolve_path(cwd)?;
        match hunk {
            Hunk::AddFile { contents, .. } => {
                let target = destructive_target_for_path(destructive_targets, &path_uri)?;
                revalidate_destructive_target(target, fs, sandbox).await?;
                let overwritten_content = read_optional_file_text_for_delta(
                    &path_uri,
                    fs,
                    follow_symlinks,
                    sandbox,
                    &mut delta.exact,
                )
                .await;
                revalidate_destructive_target(target, fs, sandbox).await?;
                try_write!(
                    write_file_with_missing_parent_retry(
                        fs,
                        &path_uri,
                        contents.clone().into_bytes(),
                        follow_symlinks,
                        sandbox,
                    )
                    .await
                );
                delta.changes.push(AppliedPatchChange {
                    path: path_uri,
                    change: AppliedPatchFileChange::Add {
                        content: contents.clone(),
                        overwritten_content,
                    },
                });
                added.push(affected_path);
            }
            Hunk::DeleteFile { .. } => {
                let target = destructive_target_for_path(destructive_targets, &path_uri)?;
                revalidate_destructive_target(target, fs, sandbox).await?;
                note_existing_path_delta_support(
                    &path_uri,
                    fs,
                    follow_symlinks,
                    sandbox,
                    &mut delta.exact,
                )
                .await;
                let deleted_content = fs
                    .read_file_text(&path_uri, ReadFileOptions { follow_symlinks }, sandbox)
                    .await
                    .ok();
                if deleted_content.is_none() {
                    delta.exact = false;
                }
                revalidate_destructive_target(target, fs, sandbox).await?;
                ensure_not_directory(&path_uri, fs, follow_symlinks, sandbox)
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to delete file {}",
                            path_uri.inferred_native_path_string()
                        )
                    })?;
                if let Err(error) = fs
                    .remove(
                        &path_uri,
                        RemoveOptions {
                            recursive: false,
                            force: false,
                            follow_symlinks,
                        },
                        sandbox,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "Failed to delete file {}",
                            path_uri.inferred_native_path_string()
                        )
                    })
                {
                    delta.exact &= remove_failure_was_side_effect_free(
                        &path_uri,
                        deleted_content.as_deref(),
                        fs,
                        follow_symlinks,
                        sandbox,
                    )
                    .await;
                    return Err(error);
                }
                if let Some(content) = deleted_content {
                    delta.changes.push(AppliedPatchChange {
                        path: path_uri,
                        change: AppliedPatchFileChange::Delete { content },
                    });
                }
                deleted.push(affected_path);
            }
            Hunk::UpdateFile {
                move_path, chunks, ..
            } => {
                note_existing_path_delta_support(
                    &path_uri,
                    fs,
                    follow_symlinks,
                    sandbox,
                    &mut delta.exact,
                )
                .await;
                let AppliedPatch {
                    original_contents,
                    new_contents,
                } = derive_new_contents_from_chunks(
                    &path_uri,
                    chunks,
                    update_file_mode,
                    fs,
                    follow_symlinks,
                    sandbox,
                )
                .await?;
                if let Some(dest) = move_path {
                    let dest_uri = cwd.join(&dest.to_string_lossy())?;
                    let dest_target = destructive_target_for_path(destructive_targets, &dest_uri)?;
                    revalidate_destructive_target(dest_target, fs, sandbox).await?;
                    let overwritten_move_content = read_optional_file_text_for_delta(
                        &dest_uri,
                        fs,
                        follow_symlinks,
                        sandbox,
                        &mut delta.exact,
                    )
                    .await;
                    revalidate_destructive_target(dest_target, fs, sandbox).await?;
                    try_write!(
                        write_file_with_missing_parent_retry(
                            fs,
                            &dest_uri,
                            new_contents.clone().into_bytes(),
                            follow_symlinks,
                            sandbox,
                        )
                        .await
                    );
                    let dest_write_change_index = delta.changes.len();
                    let source_target = destructive_target_for_path(destructive_targets, &path_uri)?;
                    revalidate_destructive_target(source_target, fs, sandbox).await?;
                    delta.changes.push(AppliedPatchChange {
                        path: dest_uri.clone(),
                        change: AppliedPatchFileChange::Add {
                            content: new_contents.clone(),
                            overwritten_content: overwritten_move_content.clone(),
                        },
                    });
                    ensure_not_directory(&path_uri, fs, follow_symlinks, sandbox)
                        .await
                        .with_context(|| {
                            format!(
                                "Failed to remove original {}",
                                path_uri.inferred_native_path_string()
                            )
                        })?;
                    if let Err(error) = fs
                        .remove(
                            &path_uri,
                            RemoveOptions {
                                recursive: false,
                                force: false,
                                follow_symlinks,
                            },
                            sandbox,
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "Failed to remove original {}",
                                path_uri.inferred_native_path_string()
                            )
                        })
                    {
                        delta.exact &= remove_failure_was_side_effect_free(
                            &path_uri,
                            Some(&original_contents),
                            fs,
                            follow_symlinks,
                            sandbox,
                        )
                        .await;