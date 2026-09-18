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
use codex_exec_server::RemoveOptions;
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
        &self,
        path: &codex_utils_absolute_path::AbsolutePathBuf,
    ) -> Result<(), JSONRPCErrorError> {
        validate_managed_storage_path(path.as_path(), &self.managed_storage_root)
    }

    pub(crate) async fn read_file(
        &self,
        params: FsReadFileParams,
    ) -> Result<FsReadFileResponse, JSONRPCErrorError> {
        let path = PathUri::from_abs_path(&params.path);
        let bytes = self
            .file_system()?
            .read_file(&path, Default::default(), /*sandbox*/ None)
            .await
            .map_err(map_fs_error)?;
        Ok(FsReadFileResponse {
            data_base64: STANDARD.encode(bytes),
        })
    }

    pub(crate) async fn write_file(
        &self,
        params: FsWriteFileParams,
    ) -> Result<FsWriteFileResponse, JSONRPCErrorError> {
        let bytes = STANDARD.decode(params.data_base64).map_err(|err| {
            invalid_request(format!(
                "fs/writeFile requires valid base64 dataBase64: {err}"
            ))
        })?;
        self.validate_managed_storage_path(&params.path)?;
        let path = PathUri::from_abs_path(&params.path);
        self.file_system()?
            .write_file(&path, bytes, Default::default(), /*sandbox*/ None)
            .await
            .map_err(map_fs_error)?;
        Ok(FsWriteFileResponse {})
    }

    pub(crate) async fn create_directory(
        &self,
        params: FsCreateDirectoryParams,
    ) -> Result<FsCreateDirectoryResponse, JSONRPCErrorError> {
        self.validate_managed_storage_path(&params.path)?;
        let path = PathUri::from_abs_path(&params.path);
        self.file_system()?
            .create_directory(
                &path,
                CreateDirectoryOptions {
                    recursive: params.recursive.unwrap_or(true),
                    follow_symlinks: true,
                },
                /*sandbox*/ None,
            )
            .await
            .map_err(map_fs_error)?;
        Ok(FsCreateDirectoryResponse {})
    }

    pub(crate) async fn get_metadata(
        &self,
        params: FsGetMetadataParams,
    ) -> Result<FsGetMetadataResponse, JSONRPCErrorError> {
        let path = PathUri::from_abs_path(&params.path);
        let metadata = self
            .file_system()?
            .get_metadata(&path, Default::default(), /*sandbox*/ None)
            .await
            .map_err(map_fs_error)?;
        Ok(FsGetMetadataResponse {
            is_directory: metadata.is_directory,
            is_file: metadata.is_file,
            is_symlink: metadata.is_symlink,
            created_at_ms: metadata.created_at_ms,
            modified_at_ms: metadata.modified_at_ms,
        })
    }

    pub(crate) async fn read_directory(
        &self,
        params: FsReadDirectoryParams,
    ) -> Result<FsReadDirectoryResponse, JSONRPCErrorError> {
        let path = PathUri::from_abs_path(&params.path);
        let entries = self
            .file_system()?
            .read_directory(&path, /*sandbox*/ None)
            .await
            .map_err(map_fs_error)?;
        Ok(FsReadDirectoryResponse {
            entries: entries
                .into_iter()
                .map(|entry| FsReadDirectoryEntry {
                    file_name: entry.file_name,
                    is_directory: entry.is_directory,
                    is_file: entry.is_file,
                })
                .collect(),
        })
    }

    pub(crate) async fn remove(
        &self,
        _params: FsRemoveParams,
    ) -> Result<FsRemoveResponse, JSONRPCErrorError> {
        Err(invalid_request(
            "fs/remove is disabled: destructive filesystem deletion requires the governed approval and sandbox path",
        ))
    }

    pub(crate) async fn copy(
        &self,
        params: FsCopyParams,
    ) -> Result<FsCopyResponse, JSONRPCErrorError> {
        self.validate_managed_storage_path(&params.source_path)?;
        self.validate_managed_storage_path(&params.destination_path)?;
        let source_path = PathUri::from_abs_path(&params.source_path);
        let destination_path = PathUri::from_abs_path(&params.destination_path);
        self.file_system()?
            .copy(
                &source_path,
                &destination_path,
                CopyOptions {
                    recursive: params.recursive,
                },
                /*sandbox*/ None,
            )
            .await
            .map_err(map_fs_error)?;
        Ok(FsCopyResponse {})
    }

    pub(crate) async fn watch(
        &self,
        connection_id: ConnectionId,
        params: FsWatchParams,
    ) -> Result<FsWatchResponse, JSONRPCErrorError> {
        self.file_system()?;
        self.fs_watch_manager.watch(connection_id, params).await
    }

    pub(crate) async fn unwatch(
        &self,
        connection_id: ConnectionId,
        params: FsUnwatchParams,
    ) -> Result<FsUnwatchResponse, JSONRPCErrorError> {
        self.file_system()?;
        self.fs_watch_manager.unwatch(connection_id, params).await
    }
}

fn validate_managed_storage_path(path: &Path, managed_root: &Path) -> Result<(), JSONRPCErrorError> {
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

    let existing = closest_existing_ancestor(path).ok_or_else(|| {
        invalid_request("filesystem mutation target has no existing safety ancestor")
    })?;
    let canonical_existing = std::fs::canonicalize(existing).map_err(|err| {
        invalid_request(format!(
            "cannot canonicalize filesystem mutation safety ancestor: {err}"
        ))
    })?;
    if !canonical_existing.starts_with(&canonical_home) {
        return Err(invalid_request(
            "filesystem mutation path resolves outside CODEX_HOME",
        ));
    }

    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(invalid_request(
            "filesystem mutation does not follow symlink targets",
        ));
    }

    Ok(())
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

fn map_fs_error(err: io::Error) -> JSONRPCErrorError {
    if err.kind() == io::ErrorKind::InvalidInput {
        invalid_request(err.to_string())
    } else {
        internal_error(err.to_string())
    }
}