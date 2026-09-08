    /// Platform family for the running app-server target, for example
    /// `"unix"` or `"windows"`.
    pub platform_family: String,
    /// Operating system for the running app-server target, for example
    /// `"macos"`, `"linux"`, or `"windows"`.
    pub platform_os: String,
    /// OS process id of the app-server instance answering this initialize request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema, TS)]
#[serde(untagged)]
pub enum GetConversationSummaryParams {
    RolloutPath {
        #[serde(rename = "rolloutPath")]
        rollout_path: PathBuf,
    },