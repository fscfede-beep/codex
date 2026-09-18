pub struct WireFsWalkParams {
    path: PathUri,
    options: WalkOptions,
    sandbox: Option<WireFileSystemSandboxContext>,
}

pub type FsWalkResponse = WalkOutcome;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FsRemoveParams {
    pub path: PathUri,
    pub recursive: Option<bool>,
    pub force: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub follow_symlinks: Option<bool>,
    /// Internal launch capability. Only governed destructive removal may set true.
    #[serde(default)]
    pub destructive_capability: bool,
    pub sandbox: Option<FileSystemSandboxContext>,
}

/// Filesystem RPC wire request with legacy optional sandbox policy cwd.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireFsRemoveParams {
    path: PathUri,
    recursive: Option<bool>,
    force: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    follow_symlinks: Option<bool>,
    #[serde(default)]
    destructive_capability: bool,
    sandbox: Option<WireFileSystemSandboxContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FsRemoveResponse {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FsCopyParams {
    pub source_path: PathUri,
    pub destination_path: PathUri,
    pub recursive: bool,
    pub sandbox: Option<FileSystemSandboxContext>,
}

/// Filesystem RPC wire request with legacy optional sandbox policy cwd.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireFsCopyParams {
    source_path: PathUri,
    destination_path: PathUri,
    recursive: bool,
    sandbox: Option<WireFileSystemSandboxContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FsCopyResponse {}

/// Roots to inspect for plugin and skill capability manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityRootsDiscoverParams {
    pub roots: Vec<CapabilityRootDiscoverRequest>,
}

/// Executor ingress for capability roots whose sandbox policy cwd may be absent.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireCapabilityRootsDiscoverParams {
    roots: Vec<WireCapabilityRootDiscoverRequest>,
}