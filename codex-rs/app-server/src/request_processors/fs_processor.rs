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
use codex_utils_path_uri::PathUri;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const ATTACHMENTS_DIR_NAME: &str = "attachments";

#[derive(Clone)]
pub(crate) struct FsRequestProcessor {
    environment_manager: Arc<EnvironmentManager>,
    fs_watch_manager: FsWatchManager,
    codex_home: PathBuf,
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
            codex_home,
        }
    }

    fn file_system(&self) -> Result<Arc<dyn ExecutorFileSystem>, JSONRPCErrorError> {
        self.environment_manager
            .try_local_environment()
            .map(|environment| environment.get_filesystem())
            .ok_or_else(|| internal_error("local filesystem is not configured"))
    }

    fn validate_attachment_mutation(
        &self,
        path: &PathUri,
        operation: &str,
    ) -> Result<PathBuf, JSONRPCErrorError> {
        let path = path
            .to_abs_path()
            .map_err(|err| invalid_request(format!("fs/{operation} has an invalid path: {err}")))?
            .into_path_buf();
        validate_attachment_mutation_path(&self.codex_home, &path, operation)
    }

    fn validate_attachment_source(
        &self,
        path: &PathUri,
        operation: &str,
    ) -> Result<PathBuf, JSONRPCErrorError> {
        let native_path = self.validate_attachment_mutation(path, operation)?;
        let metadata = std::fs::symlink_metadata(&native_path).map_err(|err| {
            invalid_request(format!(
                "fs/{operation} source must exist inside CODEX_HOME/attachments: {err}"
            ))
        })?;
        if metadata.file_type().is_dir() || metadata.file_type().is_file() {
            Ok(native_path)
        } else {
            Err(invalid_request(format!(
                "fs/{operation} source must be a regular file or directory inside CODEX_HOME/attachments"
            )))
        }
    }

    pub(crate) async fn connection_closed(&self, connection_id: ConnectionId) {
        self.fs_watch_manager.connection_closed(connection_id).await;
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
        let path = PathUri::from_abs_path(&params.path);
        self.validate_attachment_mutation(&path, "writeFile")?;
        self.file_system()?
            .write_file(
                &path,
                bytes,
                codex_exec_server::WriteFileOptions {
                    follow_symlinks: false,
                },
                /*sandbox*/ None,
            )
            .await
            .map_err(map_fs_error)?;
        Ok(FsWriteFileResponse {})
    }

    pub(crate) async fn create_directory(
        &self,
        params: FsCreateDirectoryParams,
    ) -> Result<FsCreateDirectoryResponse, JSONRPCErrorError> {
        let path = PathUri::from_abs_path(&params.path);
        self.validate_attachment_mutation(&path, "createDirectory")?;
        self.file_system()?
            .create_directory(
                &path,
                CreateDirectoryOptions {
                    recursive: params.recursive.unwrap_or(true),
                    follow_symlinks: false,
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
            "fs/remove is disabled because this RPC has no scoped deletion authority",
        ))
    }

    pub(crate) async fn copy(
        &self,
        params: FsCopyParams,
    ) -> Result<FsCopyResponse, JSONRPCErrorError> {
        let source_path = PathUri::from_abs_path(&params.source_path);
        let destination_path = PathUri::from_abs_path(&params.destination_path);
        self.validate_attachment_source(&source_path, "copy")?;
        self.validate_attachment_mutation(&destination_path, "copy")?;
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

fn validate_attachment_mutation_path(
    codex_home: &Path,
    path: &Path,
    operation: &str,
) -> Result<PathBuf, JSONRPCErrorError> {
    let codex_home = std::fs::canonicalize(codex_home).map_err(|err| {
        invalid_request(format!(
            "fs/{operation} cannot establish canonical CODEX_HOME: {err}"
        ))
    })?;
    let attachments_root = codex_home.join(ATTACHMENTS_DIR_NAME);
    if path == attachments_root.as_path() || !path.starts_with(&attachments_root) {
        return Err(invalid_request(format!(
            "fs/{operation} is restricted to CODEX_HOME/attachments"
        )));
    }

    let mut ancestor = path.parent();
    while let Some(current) = ancestor {
        if current == codex_home.as_path() {
            break;
        }
        match std::fs::symlink_metadata(current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(invalid_request(format!(
                    "fs/{operation} rejects symlink/reparse-point ancestors"
                )));
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(invalid_request(format!(
                    "fs/{operation} cannot inspect mutation path: {err}"
                )));
            }
        }
        ancestor = current.parent();
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(invalid_request(format!(
            "fs/{operation} rejects symlink/reparse-point targets"
        ))),
        Ok(_) => {
            let canonical_target = std::fs::canonicalize(path).map_err(|err| {
                invalid_request(format!(
                    "fs/{operation} cannot canonicalize target: {err}"
                ))
            })?;
            let canonical_attachments = std::fs::canonicalize(&attachments_root).map_err(|err| {
                invalid_request(format!(
                    "fs/{operation} cannot establish canonical attachments root: {err}"
                ))
            })?;
            if !canonical_target.starts_with(&canonical_attachments) {
                return Err(invalid_request(format!(
                    "fs/{operation} target resolves outside CODEX_HOME/attachments"
                )));
            }
            Ok(path.to_path_buf())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let mut parent = path.parent().ok_or_else(|| {
                invalid_request(format!("fs/{operation} target has no parent"))
            })?;
            loop {
                match std::fs::symlink_metadata(parent) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(invalid_request(format!(
                            "fs/{operation} rejects symlink/reparse-point ancestors"
                        )));
                    }
                    Ok(_) => break,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        parent = parent.parent().ok_or_else(|| {
                            invalid_request(format!(
                                "fs/{operation} cannot find an existing parent"
                            ))
                        })?;
                    }
                    Err(err) => {
                        return Err(invalid_request(format!(
                            "fs/{operation} cannot inspect existing parent: {err}"
                        )));
                    }
                }
            }
            let canonical_parent = std::fs::canonicalize(parent).map_err(|err| {
                invalid_request(format!(
                    "fs/{operation} cannot canonicalize existing parent: {err}"
                ))
            })?;
            let canonical_attachments = std::fs::canonicalize(&attachments_root).map_err(|err| {
                invalid_request(format!(
                    "fs/{operation} cannot establish canonical attachments root: {err}"
                ))
            })?;
            if !canonical_parent.starts_with(&canonical_attachments) {
                return Err(invalid_request(format!(
                    "fs/{operation} parent resolves outside CODEX_HOME/attachments"
                )));
            }
            Ok(path.to_path_buf())
        }
        Err(err) => Err(invalid_request(format!(
            "fs/{operation} cannot inspect target: {err}"
        ))),
    }
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
    use super::validate_attachment_mutation_path;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn mutation_path_allows_only_attachments_tree() {
        let home = tempdir().expect("temp home");
        let attachments = home.path().join("attachments");
        fs::create_dir_all(&attachments).expect("attachments");
        let allowed = attachments.join("note.txt");
        let outside = home.path().join("outside.txt");
        assert!(validate_attachment_mutation_path(home.path(), &allowed, "writeFile").is_ok());
        assert!(validate_attachment_mutation_path(home.path(), &outside, "writeFile").is_err());
    }

    #[test]
    fn mutation_path_rejects_symlink_escape() {
        let home = tempdir().expect("temp home");
        let attachments = home.path().join("attachments");
        let outside = home.path().join("outside");
        fs::create_dir_all(&attachments).expect("attachments");
        fs::create_dir_all(&outside).expect("outside");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, attachments.join("escape")).expect("symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&outside, attachments.join("escape"))
            .expect("directory symlink");
        let escaped = attachments.join("escape").join("secret.txt");
        assert!(validate_attachment_mutation_path(home.path(), &escaped, "writeFile").is_err());
    }
}
