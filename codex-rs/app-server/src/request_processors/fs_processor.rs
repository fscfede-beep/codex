use crate::error_code::internal_error;
use crate::error_code::invalid_request;
use crate::fs_watch::FsWatchManager;
use crate::outgoing_message::ConnectionId;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use codex_app_server_protocol::FsCopyParams;
use codex_app_server_protocol::FsCopyResponse;
use codex_app_server_protocol::FsCreateDirectoryParams;
use codex_app_server_protocol::FsCreateDirectoryResponse;
use codex_app_server_protocol::FsGetMetadataParams;
use codex_app_server_protocol::FsGetMetadataResponse;
use codex_app_server_protocol::FsReadDirectoryEntry;
use codex_app_server_protocol::FsReadDirectoryParams;
use codex_app_server_protocol::FsReadDirectoryResponse;
use codex_app_server_protocol::FsReadFileParams;
use codex_app_server_protocol::FsReadFileResponse;
use codex_app_server_protocol::FsRemoveParams;
use codex_app_server_protocol::FsRemoveResponse;
use codex_app_server_protocol::FsUnwatchParams;
use codex_app_server_protocol::FsUnwatchResponse;
use codex_app_server_protocol::FsWatchParams;
use codex_app_server_protocol::FsWatchResponse;
use codex_app_server_protocol::FsWriteFileParams;
use codex_app_server_protocol::FsWriteFileResponse;
use codex_app_server_protocol::JSONRPCErrorError;
use codex_exec_server::CopyOptions;
use codex_exec_server::CreateDirectoryOptions;
use codex_exec_server::EnvironmentManager;
use codex_exec_server::ExecutorFileSystem;
use codex_exec_server::FileSystemSandboxContext;
use codex_exec_server::RemoveOptions;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_path_uri::PathUri;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct FsRequestProcessor {
    environment_manager: Arc<EnvironmentManager>,
    fs_watch_manager: FsWatchManager,
    managed_storage_root: PathBuf,
}

impl FsRequestProcessor {
    pub(crate) fn new(
        environment_manager: Arc<EnvironmentManager>,
        fs_watch_manager: FsWatchManager,
        codex_home: PathBuf,
    ) -> Self {
        Self {
            environment_manager,
            fs_watch_manager,
            managed_storage_root: codex_home.join("attachments"),
        }
    }

    fn file_system(&self) -> Result<Arc<dyn ExecutorFileSystem>, JSONRPCErrorError> {
        self.environment_manager
            .try_local_environment()
            .map(|environment| environment.get_filesystem())
            .ok_or_else(|| internal_error("local filesystem is not configured"))
    }

    pub(crate) async fn connection_closed(&self, connection_id: ConnectionId) {
        self.fs_watch_manager.connection_closed(connection_id).await;
    }

    fn validate_managed_storage_path(
    path: &Path,
    managed_root: &Path,
) -> Result<(), JSONRPCErrorError> {
    use std::path::Component;

    if path.components().any(|component| component == Component::ParentDir) {
        return Err(invalid_request(
            "filesystem mutation path contains parent traversal",
        ));
    }
    if !path.starts_with(managed_root) {
        return Err(invalid_request(
            "filesystem mutation is limited to Codex-managed attachments",
        ));
    }

    let Some(codex_home) = managed_root.parent() else {
        return Err(internal_error(
            "managed filesystem root has no CODEX_HOME parent",
        ));
    };
    let canonical_home = std::fs::canonicalize(codex_home).map_err(|err| {
        invalid_request(format!(
            "cannot establish CODEX_HOME safety root for filesystem mutation: {err}"
        ))
    })?;

    // The managed root itself must be a real directory, not a symlink/junction/reparse alias.
    let canonical_root = match std::fs::symlink_metadata(managed_root) {
        Ok(metadata) => {
            if !metadata.is_dir() || managed_root_is_alias(&metadata) {
                return Err(invalid_request(
                    "managed attachments root must be a real directory without reparse aliases",
                ));
            }
            std::fs::canonicalize(managed_root).map_err(|err| {
                invalid_request(format!(
                    "cannot canonicalize managed attachments root: {err}"
                ))
            })?
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let root_name = managed_root.file_name().ok_or_else(|| {
                invalid_request("managed filesystem root has no final path component")
            })?;
            canonical_home.join(root_name)
        }
        Err(err) => {
            return Err(invalid_request(format!(
                "cannot inspect managed attachments root: {err}"
            )));
        }
    };

    if !canonical_root.starts_with(&canonical_home) {
        return Err(invalid_request(
            "managed attachments root resolves outside CODEX_HOME",
        ));
    }

    let existing = closest_existing_ancestor(path).ok_or_else(|| {
        invalid_request("filesystem mutation target has no existing safety ancestor")
    })?;
    let canonical_existing = std::fs::canonicalize(existing).map_err(|err| {
        invalid_request(format!(
            "cannot canonicalize filesystem mutation safety ancestor: {err}"
        ))
    })?;

    // The security boundary is attachments itself, not the broader CODEX_HOME parent.
    if !canonical_existing.starts_with(&canonical_root) {
        return Err(invalid_request(
            "filesystem mutation path resolves outside managed attachments",
        ));
    }

    // Reject explicit aliases in the existing path chain. Unix uses canonical-vs-lexical
    // identity; Windows uses the native reparse-point bit so normal Win32 path normalization
    // does not cause false positives.
    if managed_storage_path_contains_alias(existing, &canonical_existing) {
        return Err(invalid_request(
            "filesystem mutation path contains an existing alias or reparse point",
        ));
    }

    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || managed_root_is_alias(&metadata))
    {
        return Err(invalid_request(
            "filesystem mutation target is not a supported regular filesystem object",
        ));
    }

    Ok(())
}

fn managed_storage_path_contains_alias(
    existing: &Path,
    canonical_existing: &Path,
) -> bool {
    #[cfg(unix)]
    {
        canonical_existing != existing
    }
    #[cfg(windows)]
    {
        std::fs::symlink_metadata(existing)
            .map(|metadata| managed_root_is_alias(&metadata))
            .unwrap_or(true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        canonical_existing != existing
    }
}

fn managed_root_is_alias(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return metadata.file_attributes() & 0x0400 != 0;
    }
    false
}

fn closest_existing_ancestor(path: &Path) -> Option<&Path> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if candidate.exists() {
            return Some(candidate);
        }
        current = candidate.parent();
    }
    None
}

fn ensure_managed_storage_root_exists(root_path: &Path) -> Result<(), JSONRPCErrorError> {
    std::fs::create_dir_all(root_path).map_err(|err| {
        invalid_request(format!(
            "cannot initialize managed attachments root for sandbox enforcement: {err}"
        ))
    })
}

fn managed_storage_sandbox_for_root(
    root_path: &Path,
) -> Result<FileSystemSandboxContext, JSONRPCErrorError> {
    let root = codex_utils_absolute_path::AbsolutePathBuf::from_absolute_path(root_path)
        .map_err(|err| invalid_request(format!("invalid CODEX_HOME attachments root: {err}")))?;
    let root_uri = PathUri::from_abs_path(&root);
    let permissions = PermissionProfile::workspace_write_with_path_uris(
        std::slice::from_ref(&root_uri),
        NetworkSandboxPolicy::Restricted,
        /*exclude_tmpdir_env_var*/ true,
        /*exclude_slash_tmp*/ true,
    );
    Ok(FileSystemSandboxContext::from_permission_profile(
        permissions,
        root_uri,
    ))
}

fn map_fs_error(err: io::Error) -> JSONRPCErrorError {
    if err.kind() == io::ErrorKind::InvalidInput {
        invalid_request(err.to_string())
    } else {
        internal_error(err.to_string())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn managed_storage_allows_only_codex_attachments() -> io::Result<()> {
        let home = tempdir()?;
        let managed_root = home.path().join("attachments");
        std::fs::create_dir_all(&managed_root)?;
        let inside = managed_root.join("id").join("file.txt");
        let outside = home.path().join("project").join("file.txt");

        assert!(validate_managed_storage_path(&inside, &managed_root).is_ok());
        assert!(validate_managed_storage_path(&outside, &managed_root).is_err());
        Ok(())
    }

    #[test]
    fn managed_storage_sandbox_is_managed_and_scoped() -> io::Result<()> {
        let home = tempdir()?;
        let managed_root = home.path().join("attachments");
        std::fs::create_dir_all(&managed_root)?;

        let sandbox = managed_storage_sandbox_for_root(&managed_root)?;
        assert!(matches!(
            sandbox.permissions,
            PermissionProfile::Managed { .. }
        ));
        assert!(sandbox.should_write_into_sandbox());
        assert_eq!(
            sandbox.workspace_roots,
            vec![PathUri::from_host_native_path(&managed_root)?]
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn managed_storage_rejects_symlink_escape() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let home = tempdir()?;
        let managed_root = home.path().join("attachments");
        let outside = home.path().join("outside");
        std::fs::create_dir_all(&managed_root)?;
        std::fs::create_dir_all(&outside)?;
        symlink(&outside, managed_root.join("escape"))?;

        let target = managed_root.join("escape").join("secret.txt");
        assert!(validate_managed_storage_path(&target, &managed_root).is_err());
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn managed_storage_rejects_alias_to_other_codex_home_subtree() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let home = tempdir()?;
        let managed_root = home.path().join("attachments");
        let other = home.path().join("other");
        std::fs::create_dir_all(&managed_root)?;
        std::fs::create_dir_all(&other)?;
        symlink(&other, managed_root.join("alias"))?;

        let target = managed_root.join("alias").join("file.txt");
        assert!(validate_managed_storage_path(&target, &managed_root).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn managed_storage_rejects_managed_root_symlink() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let home = tempdir()?;
        let real_root = home.path().join("real");
        let managed_root = home.path().join("attachments");
        std::fs::create_dir_all(&real_root)?;
        symlink(&real_root, &managed_root)?;

        let target = managed_root.join("file.txt");
        assert!(validate_managed_storage_path(&target, &managed_root).is_err());
        Ok(())
    }

}