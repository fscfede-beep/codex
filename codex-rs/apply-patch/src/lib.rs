mod file_update;
mod invocation;
mod parser;
mod seek_sequence;
mod standalone_executable;
mod streaming_parser;
mod text_file;

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use codex_exec_server::CreateDirectoryOptions;
use codex_exec_server::ExecutorFileSystem;
use codex_exec_server::FileSystemSandboxContext;
use codex_exec_server::FileSystemObjectIdentity;
use codex_exec_server::GetMetadataOptions;
use codex_exec_server::ReadFileOptions;
use codex_exec_server::RemoveOptions;
use codex_exec_server::WriteFileOptions;
use codex_protocol::models::PermissionProfile;
use codex_protocol::models::SandboxEnforcement;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_path_uri::PathUri;
use codex_utils_path_uri::PathUriParseError;
pub use parser::Hunk;
pub use parser::ParseError;
use parser::ParseError::*;
pub use parser::UpdateFileChunk;
pub use parser::parse_patch;
pub use streaming_parser::StreamingPatchParser;
use thiserror::Error;

use file_update::AppliedPatch;
pub use file_update::ApplyPatchFileUpdate;
use file_update::derive_new_contents_from_chunks;
pub use file_update::unified_diff_from_chunks;
pub use file_update::unified_diff_from_chunks_with_context;
pub(crate) use file_update::unified_diff_from_chunks_with_mode;
pub use invocation::MaybeApplyPatch;
pub use invocation::maybe_parse_apply_patch;
pub use invocation::maybe_parse_apply_patch_verified;
pub use invocation::maybe_parse_apply_patch_verified_with_mode;
pub use invocation::verify_apply_patch_args;
pub use invocation::verify_apply_patch_args_with_mode;
pub use standalone_executable::main;

use crate::invocation::ExtractHeredocError;

/// Special argv[1] flag used when the Codex executable self-invokes to run the
/// internal `apply_patch` path.
///
/// Although this constant lives in `codex-apply-patch` (to avoid forcing
/// `codex-arg0` to depend on `codex-core`), it remains part of the "codex core"
/// process-invocation contract for the standalone `apply_patch` command
/// surface.
pub const CODEX_CORE_APPLY_PATCH_ARG1: &str = "--codex-run-as-apply-patch";

/// Internal environment variable used to carry the selected update mode
/// through the arg0-dispatched standalone executable.
pub const CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS_ENV_VAR: &str =
    "CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS";

/// Controls how updates reconstruct the target file after matching a patch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ApplyPatchFileUpdateMode {
    /// Preserve the historical behavior of normalizing updated files to LF.
    #[default]
    NormalizeToLf,
    /// Preserve existing line endings and use the file's preferred ending for new lines.
    PreserveLineEndings,
}

/// Policy for one patch application. Standalone callers follow symlinks by default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplyPatchOptions {
    pub update_file_mode: ApplyPatchFileUpdateMode,
    /// Whether filesystem operations may resolve symlinks in any path component.
    pub follow_symlinks: bool,
}

impl Default for ApplyPatchOptions {
    fn default() -> Self {
        Self {
            update_file_mode: ApplyPatchFileUpdateMode::default(),
            follow_symlinks: true,
        }
    }
}

/// Reads the update mode selected for an arg0-dispatched `apply_patch` process.
#[doc(hidden)]
pub fn apply_patch_file_update_mode_from_env() -> ApplyPatchFileUpdateMode {
    match std::env::var(CODEX_APPLY_PATCH_PRESERVE_LINE_ENDINGS_ENV_VAR).as_deref() {
        Ok("1") => ApplyPatchFileUpdateMode::PreserveLineEndings,
        _ => ApplyPatchFileUpdateMode::NormalizeToLf,
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum ApplyPatchError {
    #[error(transparent)]
    ParseError(#[from] ParseError),
    #[error(transparent)]
    IoError(#[from] IoError),
    /// Error that occurs while computing replacements when applying patch chunks
    #[error("{0}")]
    ComputeReplacements(String),
    /// A patch path could not be resolved as a path URI.
    #[error(transparent)]
    PathUri(#[from] PathUriParseError),
    /// A raw patch body was provided without an explicit `apply_patch` invocation.
    #[error(
        "patch detected without explicit call to apply_patch. Rerun as [\"apply_patch\", \"<patch>\"]"
    )]
    ImplicitInvocation,
}

impl From<std::io::Error> for ApplyPatchError {
    fn from(err: std::io::Error) -> Self {
        ApplyPatchError::IoError(IoError {
            context: "I/O error".to_string(),
            source: err,
        })
    }
}

impl From<&std::io::Error> for ApplyPatchError {
    fn from(err: &std::io::Error) -> Self {
        ApplyPatchError::IoError(IoError {
            context: "I/O error".to_string(),
            source: std::io::Error::new(err.kind(), err.to_string()),
        })
    }
}

#[derive(Debug, Error)]
#[error("{context}: {source}")]
pub struct IoError {
    context: String,
    #[source]
    source: std::io::Error,
}

impl PartialEq for IoError {
    fn eq(&self, other: &Self) -> bool {
        self.context == other.context && self.source.to_string() == other.source.to_string()
    }
}

/// Both the raw PATCH argument to `apply_patch` as well as the PATCH argument
/// parsed into hunks.
#[derive(Debug, PartialEq)]
pub struct ApplyPatchArgs {
    pub patch: String,
    pub hunks: Vec<Hunk>,
    pub workdir: Option<String>,
    pub environment_id: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum ApplyPatchFileChange {
    Add {
        content: String,
    },
    Delete {
        content: String,
    },
    Update {
        unified_diff: String,
        move_path: Option<PathUri>,
        /// new_content that will result after the unified_diff is applied.
        new_content: String,
    },
}

#[derive(Debug, PartialEq)]
pub enum MaybeApplyPatchVerified {
    /// `argv` corresponded to an `apply_patch` invocation, and these are the
    /// resulting proposed file changes.
    Body(ApplyPatchAction),
    /// `argv` could not be parsed to determine whether it corresponds to an
    /// `apply_patch` invocation.
    ShellParseError(ExtractHeredocError),
    /// `argv` corresponded to an `apply_patch` invocation, but it could not
    /// be fulfilled due to the specified error.
    CorrectnessError(ApplyPatchError),
    /// `argv` decidedly did not correspond to an `apply_patch` invocation.
    NotApplyPatch,
}

/// Expected filesystem state captured while a destructive patch is verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DestructivePatchTargetState {
    Existing(FileSystemObjectIdentity),
    MissingParent {
        parent: PathUri,
        identity: FileSystemObjectIdentity,
    },
}

/// One concrete target/parent precondition for a destructive patch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestructivePatchTarget {
    path: PathUri,
    state: DestructivePatchTargetState,
}

impl DestructivePatchTarget {
    pub(crate) fn existing(path: PathUri, identity: FileSystemObjectIdentity) -> Self {
        Self {
            path,
            state: DestructivePatchTargetState::Existing(identity),
        }
    }

    pub(crate) fn missing_parent(
        path: PathUri,
        parent: PathUri,
        identity: FileSystemObjectIdentity,
    ) -> Self {
        Self {
            path,
            state: DestructivePatchTargetState::MissingParent { parent, identity },
        }
    }

    pub(crate) fn path(&self) -> &PathUri {
        &self.path
    }

    pub(crate) fn state(&self) -> &DestructivePatchTargetState {
        &self.state
    }
}

/// Reconstruct a managed workspace-only scope before destructive patch verification or mutation.
pub(crate) fn destructive_patch_sandbox(
    hunks: &[Hunk],
    cwd: &PathUri,
    sandbox: Option<&FileSystemSandboxContext>,
) -> Result<Option<FileSystemSandboxContext>, ApplyPatchError> {
    let mut targets = Vec::new();
    for hunk in hunks {
        match hunk {
            Hunk::AddFile { .. } | Hunk::DeleteFile { .. } => {
                targets.push(hunk.resolve_path(cwd)?);
            }
            Hunk::UpdateFile {
                move_path: Some(move_path),
                ..
            } => {
                targets.push(hunk.resolve_path(cwd)?);
                targets.push(cwd.join(&move_path.to_string_lossy())?);
            }
            Hunk::UpdateFile {
                move_path: None, ..
            } => {}
        }
    }
    if targets.is_empty() {
        return Ok(None);
    }
    let Some(sandbox) = sandbox else {
        return Err(ParseError::InvalidPatchError(
            "destructive apply_patch requires an explicit filesystem sandbox".to_string(),
        )
        .into());
    };
    if matches!(&sandbox.permissions, PermissionProfile::External { .. }) {
        return Err(ParseError::InvalidPatchError(
            "destructive apply_patch requires Codex-managed filesystem scope".to_string(),
        )
        .into());
    }
    if sandbox.workspace_roots.is_empty() {
        return Err(ParseError::InvalidPatchError(
            "destructive apply_patch requires an explicit workspace root".to_string(),
        )
        .into());
    }
    let workspace_policy = FileSystemSandboxPolicy::workspace_write_with_path_uris(
        &sandbox.workspace_roots,
        /*exclude_tmpdir_env_var*/ true,
        /*exclude_slash_tmp*/ true,
    );
    let policy_context = sandbox.policy_context();
    for target in &targets {
        if !workspace_policy.can_write_path(target, &policy_context) {
            return Err(ParseError::InvalidPatchError(format!(
                "destructive apply_patch target is outside the workspace: {}",
                target.inferred_native_path_string()
            ))
            .into());
        }
    }
    let mut scoped = sandbox.clone();
    scoped.permissions = PermissionProfile::from_runtime_permissions_with_enforcement(
        SandboxEnforcement::Managed,
        &workspace_policy,
        NetworkSandboxPolicy::Restricted,
    );
    scoped.workspace_roots = sandbox.workspace_roots.clone();
    Ok(Some(scoped))
}

fn destructive_target_for_path<'a>(
    targets: &'a [DestructivePatchTarget],
    path: &PathUri,
) -> anyhow::Result<&'a DestructivePatchTarget> {
    targets
        .iter()
        .find(|target| target.path() == path)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "destructive apply_patch target was not present in the verified target set: {}",
                path.inferred_native_path_string()
            )
        })
}

async fn revalidate_destructive_target(
    target: &DestructivePatchTarget,
    fs: &dyn ExecutorFileSystem,
    sandbox: Option<&FileSystemSandboxContext>,
) -> anyhow::Result<()> {
    match target.state() {
        DestructivePatchTargetState::Existing(expected_identity) => {
            let metadata = fs
                .get_metadata(
                    target.path(),
                    GetMetadataOptions {
                        follow_symlinks: false,
                    },
                    sandbox,
                )
                .await?;
            if metadata.is_symlink || !metadata.is_file || metadata.is_directory {
                anyhow::bail!(
                    "destructive apply_patch target changed type: {}",
                    target.path().inferred_native_path_string()
                );
            }
            let actual_identity = fs
                .get_object_identity(target.path(), sandbox)
                .await?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "destructive apply_patch target identity is unavailable: {}",
                        target.path().inferred_native_path_string()
                    )
                })?;
            if &actual_identity != expected_identity {
                anyhow::bail!(
                    "destructive apply_patch target identity changed: {}",
                    target.path().inferred_native_path_string()
                );
            }
        }
        DestructivePatchTargetState::MissingParent { parent, identity } => {
            match fs
                .get_metadata(
                    target.path(),
                    GetMetadataOptions {
                        follow_symlinks: false,
                    },
                    sandbox,
                )
                .await
            {
                Ok(_) => anyhow::bail!(
                    "destructive apply_patch target appeared after authorization: {}",
                    target.path().inferred_native_path_string()
                ),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            let parent_metadata = fs
                .get_metadata(
                    parent,
                    GetMetadataOptions {
                        follow_symlinks: false,
                    },
                    sandbox,
                )
                .await?;
            if parent_metadata.is_symlink || !parent_metadata.is_directory {
                anyhow::bail!(
                    "destructive apply_patch parent changed type: {}",
                    parent.inferred_native_path_string()
                );
            }
            let actual_identity =
                fs.get_object_identity(parent, sandbox)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "destructive apply_patch parent identity is unavailable: {}",
                            parent.inferred_native_path_string()
                        )
                    })?;
            if &actual_identity != identity {
                anyhow::bail!(
                    "destructive apply_patch parent identity changed: {}",
                    parent.inferred_native_path_string()
                );
            }
        }
    }
    Ok(())
}

/// ApplyPatchAction is the result of parsing an `apply_patch` command. By
/// construction, all paths should be absolute paths.
#[derive(Debug, PartialEq)]
pub struct ApplyPatchAction {
    changes: HashMap<PathUri, ApplyPatchFileChange>,
    destructive_targets: Vec<DestructivePatchTarget>,


    update_file_mode: ApplyPatchFileUpdateMode,

    /// The raw patch argument that can be used to apply the patch. i.e., if the
    /// original arg was parsed in "lenient" mode with a
    /// heredoc, this should be the value without the heredoc wrapper.
    pub patch: String,

    /// The working directory that was used to resolve relative paths in the patch.
    pub cwd: PathUri,
}

impl ApplyPatchAction {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Returns the changes that would be made by applying the patch.
    pub fn changes(&self) -> &HashMap<PathUri, ApplyPatchFileChange> {
        &self.changes
    }

    pub fn destructive_targets(&self) -> &[DestructivePatchTarget] {
        &self.destructive_targets
    }

    /// Returns the update mode selected while the patch was verified.
    pub fn update_file_mode(&self) -> ApplyPatchFileUpdateMode {
        self.update_file_mode
    }

    /// True when applying this patch can delete or replace an existing filesystem object.
    ///
    /// AddFile is included because the current implementation writes the target path directly
    /// and therefore may overwrite an existing file.
    pub fn is_destructive(&self) -> bool {
        self.changes.iter().any(|(path, change)| match change {
            ApplyPatchFileChange::Delete { .. }
            | ApplyPatchFileChange::Update {
                move_path: Some(_),
                ..
            } => true,
            ApplyPatchFileChange::Add { .. } => self.destructive_targets.iter().any(|target| {
                target.path() == path
                    && matches!(target.state(), DestructivePatchTargetState::Existing(_))
            }),
            ApplyPatchFileChange::Update {
                move_path: None, ..
            } => false,
        })
    }

    /// Should be used exclusively for testing. (Not worth the overhead of
    /// creating a feature flag for this.)
    pub fn new_add_for_test(path: &PathUri, content: String) -> Self {
        #[expect(clippy::expect_used)]
        let filename = path.basename().expect("path should not be empty");
        let patch = format!(
            r#"*** Begin Patch
*** Update File: {filename}
@@
+ {content}
*** End Patch"#,
        );
        let changes = HashMap::from([(path.clone(), ApplyPatchFileChange::Add { content })]);
        #[expect(clippy::expect_used)]
        Self {
            changes,
            destructive_targets: Vec::new(),
            update_file_mode: ApplyPatchFileUpdateMode::default(),
            cwd: path.parent().expect("path should have parent"),
            patch,
        }
    }
}

/// Textual file changes that were actually committed while applying a patch.
#[derive(Clone, Debug, PartialEq)]
pub struct AppliedPatchDelta {
    changes: Vec<AppliedPatchChange>,
    exact: bool,
}

impl AppliedPatchDelta {
    fn new(changes: Vec<AppliedPatchChange>, exact: bool) -> Self {
        Self { changes, exact }
    }

    fn empty() -> Self {
        Self::new(Vec::new(), /*exact*/ true)
    }

    pub fn changes(&self) -> &[AppliedPatchChange] {
        &self.changes
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    pub fn is_exact(&self) -> bool {
        self.exact
    }

    /// Appends a later committed prefix while preserving the aggregate exactness.
    pub fn append(&mut self, other: Self) {
        self.changes.extend(other.changes);
        self.exact &= other.exact;
    }
}

impl Default for AppliedPatchDelta {
    fn default() -> Self {
        Self::empty()
    }
}

/// A committed file change, preserved in the order it was applied.
#[derive(Clone, Debug, PartialEq)]
pub struct AppliedPatchChange {
    pub path: PathUri,
    pub change: AppliedPatchFileChange,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AppliedPatchFileChange {
    Add {
        content: String,
        overwritten_content: Option<String>,
    },
    Delete {
        content: String,
    },
    Update {
        move_path: Option<PathUri>,
        old_content: String,
        overwritten_move_content: Option<String>,
        new_content: String,
    },
}

/// A failed patch application together with the textual mutations that were
/// definitely committed before the failure was observed.
#[derive(Debug, Error)]
#[error("{error}")]
pub struct ApplyPatchFailure {
    #[source]
    error: ApplyPatchError,
    delta: AppliedPatchDelta,
}

impl ApplyPatchFailure {
    fn new(error: ApplyPatchError, delta: AppliedPatchDelta) -> Self {
        Self { error, delta }
    }

    fn without_delta(error: ApplyPatchError) -> Self {
        Self::new(error, AppliedPatchDelta::empty())
    }

    pub fn delta(&self) -> &AppliedPatchDelta {
        &self.delta
    }

    pub fn into_parts(self) -> (ApplyPatchError, AppliedPatchDelta) {
        (self.error, self.delta)
    }
}

/// Applies the patch and prints the result to stdout/stderr.
pub async fn apply_patch(
    patch: &str,
    cwd: &PathUri,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
    fs: &dyn ExecutorFileSystem,
    sandbox: Option<&FileSystemSandboxContext>,
) -> Result<AppliedPatchDelta, ApplyPatchFailure> {
    apply_patch_with_options(
        patch,
        ApplyPatchOptions::default(),
        cwd,
        stdout,
        stderr,
        fs,
        sandbox,
    )
    .await
}

/// Applies the patch using the selected options and prints the result
/// to stdout/stderr.
pub async fn apply_patch_with_options(
    patch: &str,
    options: ApplyPatchOptions,
    cwd: &PathUri,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
    fs: &dyn ExecutorFileSystem,
    sandbox: Option<&FileSystemSandboxContext>,
) -> Result<AppliedPatchDelta, ApplyPatchFailure> {
    let hunks = match parse_patch(patch) {
        Ok(source) => source.hunks,
        Err(e) => {
            match &e {
                InvalidPatchError(message) => {
                    writeln!(stderr, "Invalid patch: {message}")
                        .map_err(ApplyPatchError::from)
                        .map_err(ApplyPatchFailure::without_delta)?;
                }
                InvalidHunkError {
                    message,
                    line_number,
                } => {
                    writeln!(
                        stderr,
                        "Invalid patch hunk on line {line_number}: {message}"
                    )
                    .map_err(ApplyPatchError::from)
                    .map_err(ApplyPatchFailure::without_delta)?;
                }
            }
            return Err(ApplyPatchFailure::without_delta(
                ApplyPatchError::ParseError(e),
            ));
        }
    };

    apply_hunks_with_options(&hunks, options, cwd, stdout, stderr, fs, sandbox).await
}

/// Executes a previously verified patch with destructive object-identity preconditions.
pub async fn apply_patch_with_destructive_targets(
    patch: &str,
    options: ApplyPatchOptions,
    cwd: &PathUri,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
    fs: &dyn ExecutorFileSystem,
    sandbox: Option<&FileSystemSandboxContext>,
    destructive_targets: &[DestructivePatchTarget],
) -> Result<AppliedPatchDelta, ApplyPatchFailure> {
    let hunks = match parse_patch(patch) {
        Ok(source) => source.hunks,
        Err(e) => {
            match &e {
                InvalidPatchError(message) => {
                    writeln!(stderr, "Invalid patch: {message}")
                        .map_err(ApplyPatchError::from)
                        .map_err(ApplyPatchFailure::without_delta)?;
                }
                InvalidHunkError { message, line_number } => {
                    writeln!(stderr, "Invalid patch hunk on line {line_number}: {message}")
                        .map_err(ApplyPatchError::from)
                        .map_err(ApplyPatchFailure::without_delta)?;
                }
            }
            return Err(ApplyPatchFailure::without_delta(ApplyPatchError::ParseError(e)));
        }
    };
    if hunks.iter().any(hunk_is_destructive) {
        if destructive_targets.is_empty() {
            return Err(ApplyPatchFailure::without_delta(ApplyPatchError::IoError(IoError {
                context: "destructive apply_patch authorization".to_string(),
                source: io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "destructive apply_patch requires verified object-identity preconditions",
                ),
            })));
        }

        // This API is a hard execution boundary too: a caller cannot pass approved
        // destructive targets and then drop the scoped sandbox before mutation.
        let scoped_sandbox = match destructive_patch_sandbox(&hunks, cwd, sandbox) {
            Ok(scoped_sandbox) => scoped_sandbox,
            Err(error) => return Err(ApplyPatchFailure::without_delta(error)),
        };
        let sandbox = scoped_sandbox.as_ref().or(sandbox);
        if sandbox.is_none() {
            return Err(ApplyPatchFailure::without_delta(ApplyPatchError::IoError(IoError {
                context: "destructive apply_patch sandbox".to_string(),
                source: io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "destructive apply_patch requires an enforceable scoped filesystem sandbox",
                ),
            })));
        }

        return apply_hunks_with_options_and_destructive_targets(
            &hunks,
            options,
            cwd,
            stdout,
            stderr,
            fs,
            sandbox,
            destructive_targets,
        )
        .await;
    }

    apply_hunks_with_options_and_destructive_targets(
        &hunks,
        options,
        cwd,
        stdout,
        stderr,
        fs,
        sandbox,
        destructive_targets,
    )
    .await
}

async fn apply_hunks_with_options_and_destructive_targets(
    hunks: &[Hunk],
    options: ApplyPatchOptions,
    cwd: &PathUri,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
    fs: &dyn ExecutorFileSystem,
    sandbox: Option<&FileSystemSandboxContext>,
    destructive_targets: &[DestructivePatchTarget],
) -> Result<AppliedPatchDelta, ApplyPatchFailure> {
    let mut delta = AppliedPatchDelta::empty();
    match apply_hunks_to_files(
        hunks,
        options,
        cwd,
        fs,
        sandbox,
        destructive_targets,
        &mut delta,
    )
    .await
    {
        Ok(affected_paths) => {
            print_summary(&affected_paths, stdout).map_err(|error| {
                ApplyPatchFailure::new(ApplyPatchError::from(error), delta.clone())
            })?;
            Ok(delta)
        }
        Err(error) => {
            let msg = error.to_string();
            writeln!(stderr, "{msg}").map_err(|error| {
                ApplyPatchFailure::new(ApplyPatchError::from(error), delta.clone())
            })?;
            let error = if let Some(io) = error.downcast_ref::<std::io::Error>() {
                ApplyPatchError::from(io)
            } else {
                ApplyPatchError::IoError(IoError {
                    context: msg,
                    source: std::io::Error::other(error),
                })
            };
            Err(ApplyPatchFailure::new(error, delta))
        }
    }
}

/// Applies hunks and continues to update stdout/stderr
pub async fn apply_hunks(
    hunks: &[Hunk],
    cwd: &PathUri,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
    fs: &dyn ExecutorFileSystem,
    sandbox: Option<&FileSystemSandboxContext>,
) -> Result<AppliedPatchDelta, ApplyPatchFailure> {
    apply_hunks_with_options(
        hunks,
        ApplyPatchOptions::default(),
        cwd,
        stdout,
        stderr,
        fs,
        sandbox,
    )
    .await
}

/// Applies hunks using the selected file-update mode and continues to update
/// stdout/stderr.
async fn apply_hunks_with_options(
    hunks: &[Hunk],
    options: ApplyPatchOptions,
    cwd: &PathUri,
    stdout: &mut impl std::io::Write,
    stderr: &mut impl std::io::Write,
    fs: &dyn ExecutorFileSystem,
    sandbox: Option<&FileSystemSandboxContext>,
) -> Result<AppliedPatchDelta, ApplyPatchFailure> {
    let mut delta = AppliedPatchDelta::empty();
    match apply_hunks_to_files(hunks, options, cwd, fs, sandbox, &[], &mut delta).await {
        Ok(affected_paths) => {
            print_summary(&affected_paths, stdout).map_err(|error| {
                ApplyPatchFailure::new(ApplyPatchError::from(error), delta.clone())
            })?;
            Ok(delta)
        }
        Err(error) => {
            let msg = error.to_string();
            writeln!(stderr, "{msg}").map_err(|error| {
                ApplyPatchFailure::new(ApplyPatchError::from(error), delta.clone())
            })?;
            let error = if let Some(io) = error.downcast_ref::<std::io::Error>() {
                ApplyPatchError::from(io)
            } else {
                ApplyPatchError::IoError(IoError {
                    context: msg,
                    source: std::io::Error::other(error),
                })
            };
            Err(ApplyPatchFailure::new(error, delta))
        }
    }
}

/// Applies each parsed patch hunk to the filesystem.
/// Returns an error if any of the changes could not be applied.
/// Tracks file paths affected by applying a patch, preserving the path spelling
/// from the patch for user-facing summaries.
pub struct AffectedPaths {
    pub added: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
    pub deleted: Vec<PathBuf>,
}

/// Apply the hunks to the filesystem, returning which files were added, modified, or deleted.
/// Returns an error if the patch could not be applied.
async fn apply_hunks_to_files(
    hunks: &[Hunk],
    options: ApplyPatchOptions,
    cwd: &PathUri,
    fs: &dyn ExecutorFileSystem,
    sandbox: Option<&FileSystemSandboxContext>,
    destructive_targets: &[DestructivePatchTarget],
    delta: &mut AppliedPatchDelta,
) -> anyhow::Result<AffectedPaths> {
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
                let target = destructive_targets
                    .iter()
                    .find(|target| target.path() == &path_uri);
                if let Some(target) = target {
                    revalidate_destructive_target(target, fs, sandbox).await?;
                } else {
                    match fs
                        .get_metadata(
                            &path_uri,
                            GetMetadataOptions {
                                follow_symlinks: false,
                            },
                            sandbox,
                        )
                        .await
                    {
                        Ok(_) => {
                            anyhow::bail!(
                                "apply_patch AddFile would overwrite an existing target without verified destructive authorization: {}",
                                path_uri.inferred_native_path_string()
                            );
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                let overwritten_content = read_optional_file_text_for_delta(
                    &path_uri,
                    fs,
                    follow_symlinks,
                    sandbox,
                    &mut delta.exact,
                )
                .await;
                if let Some(target) = target {
                    revalidate_destructive_target(target, fs, sandbox).await?;
                }
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
                if let Some(source_target) = destructive_source.as_ref() {
                    revalidate_destructive_target(source_target, fs, sandbox).await?;
                }
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
                        return Err(error);
                    }
                    delta.changes[dest_write_change_index] = AppliedPatchChange {
                        path: path_uri,
                        change: AppliedPatchFileChange::Update {
                            move_path: Some(dest_uri),
                            old_content: original_contents,
                            overwritten_move_content,
                            new_content: new_contents,
                        },
                    };
                    modified.push(affected_path);
                } else {
                    try_write!(
                        fs.write_file(
                            &path_uri,
                            new_contents.clone().into_bytes(),
                            WriteFileOptions { follow_symlinks },
                            sandbox,
                        )
                        .await
                        .with_context(|| format!(
                            "Failed to write file {}",
                            path_uri.inferred_native_path_string()
                        ))
                    );
                    delta.changes.push(AppliedPatchChange {
                        path: path_uri,
                        change: AppliedPatchFileChange::Update {
                            move_path: None,
                            old_content: original_contents,
                            overwritten_move_content: None,
                            new_content: new_contents,
                        },
                    });
                    modified.push(affected_path);
                }
            }
        }
    }
    Ok(AffectedPaths {
        added,
        modified,
        deleted,
    })
}

async fn ensure_not_directory(
    path: &PathUri,
    fs: &dyn ExecutorFileSystem,
    follow_symlinks: bool,
    sandbox: Option<&FileSystemSandboxContext>,
) -> io::Result<()> {
    let metadata = fs
        .get_metadata(path, GetMetadataOptions { follow_symlinks }, sandbox)
        .await?;
    if metadata.is_directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is a directory",
        ));
    }
    Ok(())
}

async fn remove_failure_was_side_effect_free(
    path: &PathUri,
    expected_content: Option<&str>,
    fs: &dyn ExecutorFileSystem,
    follow_symlinks: bool,
    sandbox: Option<&FileSystemSandboxContext>,
) -> bool {
    match expected_content {
        Some(expected_content) => fs
            .read_file_text(path, ReadFileOptions { follow_symlinks }, sandbox)
            .await
            .is_ok_and(|content| content == expected_content),
        None => false,
    }
}

async fn read_optional_file_text_for_delta(
    path: &PathUri,
    fs: &dyn ExecutorFileSystem,
    follow_symlinks: bool,
    sandbox: Option<&FileSystemSandboxContext>,
    exact: &mut bool,
) -> Option<String> {
    note_existing_path_delta_support(path, fs, follow_symlinks, sandbox, exact).await;
    match fs
        .read_file_text(path, ReadFileOptions { follow_symlinks }, sandbox)
        .await
    {
        Ok(content) => Some(content),
        Err(source) if source.kind() == io::ErrorKind::NotFound => None,
        Err(_) => {
            *exact = false;
            None
        }
    }
}

async fn note_existing_path_delta_support(
    path: &PathUri,
    fs: &dyn ExecutorFileSystem,
    follow_symlinks: bool,
    sandbox: Option<&FileSystemSandboxContext>,
    exact: &mut bool,
) {
    match fs
        .get_metadata(path, GetMetadataOptions { follow_symlinks }, sandbox)
        .await
    {
        Ok(metadata) if metadata.is_file && !metadata.is_symlink => {}
        Ok(_) => *exact = false,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(_) => *exact = false,
    }
}

async fn write_file_with_missing_parent_retry(
    fs: &dyn ExecutorFileSystem,
    path: &PathUri,
    contents: Vec<u8>,
    follow_symlinks: bool,
    sandbox: Option<&FileSystemSandboxContext>,
) -> anyhow::Result<()> {
    match fs
        .write_file(
            path,
            contents.clone(),
            WriteFileOptions { follow_symlinks },
            sandbox,
        )
        .await
    {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs.create_directory(
                    &parent,
                    CreateDirectoryOptions {
                        recursive: true,
                        follow_symlinks,
                    },
                    sandbox,
                )
                .await
                .with_context(|| {
                    format!(
                        "Failed to create parent directories for {}",
                        path.inferred_native_path_string()
                    )
                })?;
            }
            fs.write_file(
                path,
                contents,
                WriteFileOptions { follow_symlinks },
                sandbox,
            )
            .await
            .with_context(|| {
                format!(
                    "Failed to write file {}",
                    path.inferred_native_path_string()
                )
            })?;
            Ok(())
        }
        Err(err) => Err(err).with_context(|| {
            format!(
                "Failed to write file {}",
                path.inferred_native_path_string()
            )
        }),
    }
}

/// Print the summary of changes in git-style format.
/// Write a summary of changes to the given writer.
pub fn print_summary(
    affected: &AffectedPaths,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(out, "Success. Updated the following files:")?;
    for path in &affected.added {
        writeln!(out, "A {}", path.display())?;
    }
    for path in &affected.modified {
        writeln!(out, "M {}", path.display())?;
    }
    for path in &affected.deleted {
        writeln!(out, "D {}", path.display())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codex_exec_server::LOCAL_FS;
    use pretty_assertions::assert_eq;
    use std::fs;
    use tempfile::tempdir;

    /// Helper to construct a patch with the given body.
    fn wrap_patch(body: &str) -> String {
        format!("*** Begin Patch\n{body}\n*** End Patch")
    }

    #[tokio::test]
    async fn test_add_file_hunk_creates_file_with_contents() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("add.txt");
        let patch = wrap_patch(&format!(
            r#"*** Add File: {}
+ab
+cd"#,
            path.display()
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();
        // Verify expected stdout and stderr outputs.
        let stdout_str = String::from_utf8(stdout).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        let expected_out = format!(
            "Success. Updated the following files:\nA {}\n",
            path.display()
        );
        assert_eq!(stdout_str, expected_out);
        assert_eq!(stderr_str, "");
        let contents = fs::read_to_string(path).unwrap();
        assert_eq!(contents, "ab\ncd\n");
    }

    #[tokio::test]
    async fn test_apply_patch_hunks_accept_relative_and_absolute_paths() {
        let dir = tempdir().unwrap();
        let cwd = PathUri::from_host_native_path(dir.path()).expect("absolute test path");
        let relative_add = dir.path().join("relative-add.txt");
        let absolute_add = dir.path().join("absolute-add.txt");
        let relative_delete = dir.path().join("relative-delete.txt");
        let absolute_delete = dir.path().join("absolute-delete.txt");
        let relative_update = dir.path().join("relative-update.txt");
        let absolute_update = dir.path().join("absolute-update.txt");
        fs::write(&relative_delete, "delete relative\n").unwrap();
        fs::write(&absolute_delete, "delete absolute\n").unwrap();
        fs::write(&relative_update, "relative old\n").unwrap();
        fs::write(&absolute_update, "absolute old\n").unwrap();

        let patch = wrap_patch(&format!(
            r#"*** Add File: relative-add.txt
+relative add
*** Add File: {}
+absolute add
*** Delete File: relative-delete.txt
*** Delete File: {}
*** Update File: relative-update.txt
@@
-relative old
+relative new
*** Update File: {}
@@
-absolute old
+absolute new"#,
            absolute_add.display(),
            absolute_delete.display(),
            absolute_update.display(),
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        apply_patch(
            &patch,
            &cwd,
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();

        assert_eq!(fs::read_to_string(&relative_add).unwrap(), "relative add\n");
        assert_eq!(fs::read_to_string(&absolute_add).unwrap(), "absolute add\n");
        assert!(!relative_delete.exists());
        assert!(!absolute_delete.exists());
        assert_eq!(
            fs::read_to_string(&relative_update).unwrap(),
            "relative new\n"
        );
        assert_eq!(
            fs::read_to_string(&absolute_update).unwrap(),
            "absolute new\n"
        );
        assert_eq!(String::from_utf8(stderr).unwrap(), "");
        assert_eq!(
            String::from_utf8(stdout).unwrap(),
            format!(
                "Success. Updated the following files:\nA relative-add.txt\nA {}\nM relative-update.txt\nM {}\nD relative-delete.txt\nD {}\n",
                absolute_add.display(),
                absolute_update.display(),
                absolute_delete.display(),
            )
        );
    }

    #[tokio::test]
    async fn test_delete_file_hunk_removes_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("del.txt");
        fs::write(&path, "x").unwrap();
        let patch = wrap_patch(&format!("*** Delete File: {}", path.display()));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();
        let stdout_str = String::from_utf8(stdout).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        let expected_out = format!(
            "Success. Updated the following files:\nD {}\n",
            path.display()
        );
        assert_eq!(stdout_str, expected_out);
        assert_eq!(stderr_str, "");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn test_update_file_hunk_modifies_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("update.txt");
        fs::write(&path, "foo\nbar\n").unwrap();
        let patch = wrap_patch(&format!(
            r#"*** Update File: {}
@@
 foo
-bar
+baz"#,
            path.display()
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();
        // Validate modified file contents and expected stdout/stderr.
        let stdout_str = String::from_utf8(stdout).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        let expected_out = format!(
            "Success. Updated the following files:\nM {}\n",
            path.display()
        );
        assert_eq!(stdout_str, expected_out);
        assert_eq!(stderr_str, "");
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "foo\nbaz\n");
    }

    #[tokio::test]
    async fn test_update_file_hunk_can_move_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let dest = dir.path().join("dst.txt");
        fs::write(&src, "line\n").unwrap();
        let patch = wrap_patch(&format!(
            r#"*** Update File: {}
*** Move to: {}
@@
-line
+line2"#,
            src.display(),
            dest.display()
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();
        // Validate move semantics and expected stdout/stderr.
        let stdout_str = String::from_utf8(stdout).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        let expected_out = format!(
            "Success. Updated the following files:\nM {}\n",
            dest.display()
        );
        assert_eq!(stdout_str, expected_out);
        assert_eq!(stderr_str, "");
        assert!(!src.exists());
        let contents = fs::read_to_string(&dest).unwrap();
        assert_eq!(contents, "line2\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_failed_move_returns_committed_destination_delta() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let source_dir = dir.path().join("locked");
        let dest_dir = dir.path().join("out");
        fs::create_dir(&source_dir).unwrap();
        fs::create_dir(&dest_dir).unwrap();
        let src = source_dir.join("src.txt");
        let dest = dest_dir.join("dst.txt");
        fs::write(&src, "line\n").unwrap();
        fs::set_permissions(&source_dir, fs::Permissions::from_mode(0o555)).unwrap();

        let patch = wrap_patch(
            "*** Update File: locked/src.txt\n*** Move to: out/dst.txt\n@@\n-line\n+line2",
        );
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let failure = apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .expect_err("source removal should fail after destination write");

        fs::set_permissions(&source_dir, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains(&format!("Failed to remove original {}", src.display()))
        );
        assert_eq!(
            failure.delta(),
            &AppliedPatchDelta::new(
                vec![AppliedPatchChange {
                    path: PathUri::from_host_native_path(&dest).expect("absolute destination path"),
                    change: AppliedPatchFileChange::Add {
                        content: "line2\n".to_string(),
                        overwritten_content: None,
                    },
                }],
                /*exact*/ true,
            )
        );
        assert_eq!(fs::read_to_string(src).unwrap(), "line\n");
        assert_eq!(fs::read_to_string(dest).unwrap(), "line2\n");
    }

    /// Verify that a single `Update File` hunk with multiple change chunks can update different
    /// parts of a file and that the file is listed only once in the summary.
    #[tokio::test]
    async fn test_multiple_update_chunks_apply_to_single_file() {
        // Start with a file containing four lines.
        let dir = tempdir().unwrap();
        let path = dir.path().join("multi.txt");
        fs::write(&path, "foo\nbar\nbaz\nqux\n").unwrap();
        // Construct an update patch with two separate change chunks.
        // The first chunk uses the line `foo` as context and transforms `bar` into `BAR`.
        // The second chunk uses `baz` as context and transforms `qux` into `QUX`.
        let patch = wrap_patch(&format!(
            r#"*** Update File: {}
@@
 foo
-bar
+BAR
@@
 baz
-qux
+QUX"#,
            path.display()
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();
        let stdout_str = String::from_utf8(stdout).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();
        let expected_out = format!(
            "Success. Updated the following files:\nM {}\n",
            path.display()
        );
        assert_eq!(stdout_str, expected_out);
        assert_eq!(stderr_str, "");
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "foo\nBAR\nbaz\nQUX\n");
    }

    /// A more involved `Update File` hunk that exercises additions, deletions and
    /// replacements in separate chunks that appear in non‑adjacent parts of the
    /// file.  Verifies that all edits are applied and that the summary lists the
    /// file only once.
    #[tokio::test]
    async fn test_update_file_hunk_interleaved_changes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("interleaved.txt");

        // Original file: six numbered lines.
        fs::write(&path, "a\nb\nc\nd\ne\nf\n").unwrap();

        // Patch performs:
        //  • Replace `b` → `B`
        //  • Replace `e` → `E` (using surrounding context)
        //  • Append new line `g` at the end‑of‑file
        let patch = wrap_patch(&format!(
            r#"*** Update File: {}
@@
 a
-b
+B
@@
 c
 d
-e
+E
@@
 f
+g
*** End of File"#,
            path.display()
        ));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();

        let stdout_str = String::from_utf8(stdout).unwrap();
        let stderr_str = String::from_utf8(stderr).unwrap();

        let expected_out = format!(
            "Success. Updated the following files:\nM {}\n",
            path.display()
        );
        assert_eq!(stdout_str, expected_out);
        assert_eq!(stderr_str, "");

        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "a\nB\nc\nd\nE\nf\ng\n");
    }

    #[tokio::test]
    async fn test_pure_addition_chunk_followed_by_removal() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("panic.txt");
        fs::write(&path, "line1\nline2\nline3\n").unwrap();
        let patch = wrap_patch(&format!(
            r#"*** Update File: {}
@@
+after-context
+second-line
@@
 line1
-line2
-line3
+line2-replacement"#,
            path.display()
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();
        let contents = fs::read_to_string(path).unwrap();
        assert_eq!(
            contents,
            "line1\nline2-replacement\nafter-context\nsecond-line\n"
        );
    }

    /// Ensure that patches authored with ASCII characters can update lines that
    /// contain typographic Unicode punctuation (e.g. EN DASH, NON-BREAKING
    /// HYPHEN). Historically `git apply` succeeds in such scenarios but our
    /// internal matcher failed requiring an exact byte-for-byte match.  The
    /// fuzzy-matching pass that normalises common punctuation should now bridge
    /// the gap.
    #[tokio::test]
    async fn test_update_line_with_unicode_dash() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unicode.py");

        // Original line contains EN DASH (\u{2013}) and NON-BREAKING HYPHEN (\u{2011}).
        let original = "import asyncio  # local import \u{2013} avoids top\u{2011}level dep\n";
        std::fs::write(&path, original).unwrap();

        // Patch uses plain ASCII dash / hyphen.
        let patch = wrap_patch(&format!(
            r#"*** Update File: {}
@@
-import asyncio  # local import - avoids top-level dep
+import asyncio  # HELLO"#,
            path.display()
        ));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
            LOCAL_FS.as_ref(),
            /*sandbox*/ None,
        )
        .await
        .unwrap();

        // File should now contain the replaced comment.
        let expected = "import asyncio  # HELLO\n";
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, expected);

        // Ensure success summary lists the file as modified.
        let stdout_str = String::from_utf8(stdout).unwrap();
        let expected_out = format!(
            "Success. Updated the following files:\nM {}\n",
            path.display()
        );
        assert_eq!(stdout_str, expected_out);

        // No stderr expected.
        assert_eq!(String::from_utf8(stderr).unwrap(), "");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_apply_patch_fails_on_write_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let locked_dir = dir.path().join("locked");
        fs::create_dir(&locked_dir).unwrap();
        fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o555)).unwrap();

        let patch = wrap_patch("*** Add File: locked/new.txt\n+after");

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let result = apply_patch(
            &patch,
            &PathUri::from_host_native_path(dir.path()).expect("absolute test path"),
            &mut stdout,
            &mut stderr,
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

}