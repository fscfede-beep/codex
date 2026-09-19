    /// Decide we can request an approval for no-sandbox execution.
    fn wants_no_sandbox_approval(&self, policy: AskForApproval) -> bool {
        match policy {
            AskForApproval::UnlessTrusted => true,
            AskForApproval::Never => false,
            AskForApproval::OnRequest => false,
            AskForApproval::Granular(granular_config) => granular_config.sandbox_approval,
        }
    }

    fn approval_action(&self, req: &Req, call_id: &str) -> std::io::Result<ApprovalAction>;
}

pub(crate) trait Sandboxable {
    fn sandbox_preference(&self) -> SandboxablePreference;
    fn escalate_on_failure(&self) -> bool {
        true
    }
}

pub(crate) struct ToolCtx {
    pub session: Arc<Session>,
    pub step_context: Arc<StepContext>,
    pub cancellation_token: CancellationToken,
    pub call_id: String,
    pub tool_name: ToolName,
}

#[derive(Debug)]
pub(crate) enum ToolError {
    Rejected(String),
    Codex(CodexErr),
}

pub(crate) trait ToolRuntime<Req, Out>: Approvable<Req> + Sandboxable {
    fn turn_environment<'a>(&self, req: &'a Req) -> &'a TurnEnvironment;

    /// Allows a runtime to make sandbox selection depend on the concrete request.
    /// Ordinary tools retain the static sandbox-preference behavior.
    fn sandbox_preference_for_request(&self, _req: &Req) -> SandboxablePreference {
        self.sandbox_preference()
    }

    /// Allows a runtime to disable sandbox-to-unsandboxed retry for a concrete request.
    fn escalate_on_failure_for_request(&self, _req: &Req) -> bool {
        self.escalate_on_failure()
    }

    fn uses_executor_managed_process_sandbox(&self, _req: &Req) -> bool {
        false
    }

    fn network_approval_spec(&self, _req: &Req, _ctx: &ToolCtx) -> Option<NetworkApprovalSpec> {
        None
    }

    fn sandbox_cwd<'a>(&self, _req: &'a Req) -> Option<&'a PathUri> {
        None
    }

    async fn run(
        &mut self,
        req: &Req,
        attempt: &SandboxAttempt<'_>,
        ctx: &ToolCtx,
    ) -> Result<Out, ToolError>;
}

pub(crate) struct SandboxAttempt<'a> {
    pub sandbox: SandboxType,
    /// Whether policy requested sandboxing, independent of this host's concrete wrapper.
    pub sandbox_requested: bool,