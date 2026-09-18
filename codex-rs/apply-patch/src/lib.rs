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

    /// Returns true when applying this action removes an object from its original
    /// location, either through DeleteFile or UpdateFile+Move.
    pub fn has_destructive_changes(&self) -> bool {
        self.changes.values().any(|change| {
            matches!(
                change,
                ApplyPatchFileChange::Delete { .. }
                    | ApplyPatchFileChange::Update {
                        move_path: Some(_),
                        ..
                    }
            )
        })
    }

    /// Returns the changes that would be made by applying the patch.
    pub fn changes(&self) -> &HashMap<PathUri, ApplyPatchFileChange> {
        &self.changes
    }

    /// Returns the update mode selected while the patch was verified.
    pub fn update_file_mode(&self) -> ApplyPatchFileUpdateMode {
        self.update_file_mode
    }

    /// Should be used exclusively for testing. (Not worth the overhead of
    /// creating a feature flag for this.)
    pub fn new_add_for_test(path: &PathUri, content: String) -> Self {
        #[expect(clippy::expect_used)]
        let filename = path.basename().expect("path should not be empty");
        let patch = format!(
            r#"*** Begin Patch
*** Update File: {filename}