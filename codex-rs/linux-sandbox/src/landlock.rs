//! In-process Linux sandbox primitives: `no_new_privs` and seccomp.
//!
//! Filesystem restrictions are enforced by bubblewrap in `linux_run_main`.
//! Landlock helpers remain available here as legacy/backup utilities.
use std::collections::BTreeMap;
use std::path::Path;

use codex_network_proxy::ManagedNetworkSandboxContext;
use codex_protocol::error::CodexErr;
use codex_protocol::error::Result;
use codex_protocol::error::SandboxErr;
use codex_protocol::models::PermissionProfile;
use codex_protocol::protocol::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;

use landlock::ABI;
#[allow(unused_imports)]
use landlock::Access;
use landlock::AccessFs;
use landlock::CompatLevel;
use landlock::Compatible;
use landlock::Ruleset;
use landlock::RulesetAttr;
use landlock::RulesetCreatedAttr;
use seccompiler::BpfProgram;
use seccompiler::SeccompAction;
use seccompiler::SeccompCmpArgLen;
use seccompiler::SeccompCmpOp;
use seccompiler::SeccompCondition;
use seccompiler::SeccompFilter;
use seccompiler::SeccompRule;
use seccompiler::TargetArch;
use seccompiler::apply_filter;

/// Apply sandbox policies inside this thread so only the child inherits
/// them, not the entire CLI process.
///
/// This function is responsible for:
/// - enabling `PR_SET_NO_NEW_PRIVS` when restrictions apply, and
/// - installing seccomp restrictions for network isolation and VM sockets.
///
/// Filesystem restrictions are intentionally handled by bubblewrap.
pub(crate) fn apply_permission_profile_to_current_thread(
    permission_profile: &PermissionProfile,
    cwd: &Path,
    apply_landlock_fs: bool,
    managed_network: Option<&ManagedNetworkSandboxContext>,
    proxy_routing_active: bool,
    deny_destructive_filesystem: bool,
) -> Result<()> {
    let (file_system_sandbox_policy, network_sandbox_policy) =
        permission_profile.to_runtime_permissions();
    let network_seccomp_mode = network_seccomp_mode(
        network_sandbox_policy,
        managed_network.is_some(),
        proxy_routing_active,
    )
    .or_else(|| {
        // VM sockets can reach host services outside the filesystem sandbox.
        // In WSL2 they also allow Windows process launch through an alias of
        // the interop socket, even when /run/WSL is masked. Keep ordinary
        // network access while denying that host bridge.
        (!file_system_sandbox_policy.has_full_disk_write_access())
            .then_some(NetworkSeccompMode::VmSocketRestricted)
    });

    // `PR_SET_NO_NEW_PRIVS` is required for seccomp, but it also prevents
    // setuid privilege elevation. Many `bwrap` deployments rely on setuid, so
    // we avoid this unless we need seccomp or we are explicitly using the
    // legacy Landlock filesystem pipeline.
    if network_seccomp_mode.is_some()
        || deny_destructive_filesystem
        || (apply_landlock_fs && !file_system_sandbox_policy.has_full_disk_write_access())
    {
        set_no_new_privs()?;
    }

    if let Some(mode) = network_seccomp_mode {
        install_network_seccomp_filter_on_current_thread(mode, managed_network)?;
    }

    if deny_destructive_filesystem {
        install_delete_deny_landlock_on_current_thread()?;
    }

    if apply_landlock_fs && !file_system_sandbox_policy.has_full_disk_write_access() {
        if !file_system_sandbox_policy.has_full_disk_read_access() {
            return Err(CodexErr::UnsupportedOperation(
                "Restricted read-only access is not supported by the legacy Linux Landlock filesystem backend."
                    .to_string(),
            ));
        }

        let writable_roots = file_system_sandbox_policy
            .get_writable_roots_with_cwd(cwd)
            .into_iter()
            .map(|writable_root| writable_root.root)
            .collect();
        install_filesystem_landlock_rules_on_current_thread(writable_roots)?;
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkSeccompMode {
    Restricted,
    ProxyRouted,
    VmSocketRestricted,
}

fn should_install_network_seccomp(
    network_sandbox_policy: NetworkSandboxPolicy,
    allow_network_for_proxy: bool,
) -> bool {
    // Managed-network sessions should remain fail-closed even for policies that
    // would normally grant full network access (for example, DangerFullAccess).
    !network_sandbox_policy.is_enabled() || allow_network_for_proxy
}

fn network_seccomp_mode(
    network_sandbox_policy: NetworkSandboxPolicy,
    allow_network_for_proxy: bool,
    proxy_routed_network: bool,
) -> Option<NetworkSeccompMode> {
    if !should_install_network_seccomp(network_sandbox_policy, allow_network_for_proxy) {
        None
    } else if proxy_routed_network {
        Some(NetworkSeccompMode::ProxyRouted)
    } else {
        Some(NetworkSeccompMode::Restricted)
    }
}

/// Enable `PR_SET_NO_NEW_PRIVS` so seccomp can be applied safely.
fn set_no_new_privs() -> Result<()> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Denies filesystem removal/rename effects while leaving read/write creation intact.
fn install_delete_deny_landlock_on_current_thread() -> Result<()> {
    let abi = ABI::V5;
    let handled_access = AccessFs::RemoveDir | AccessFs::RemoveFile | AccessFs::Refer;
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(handled_access)?
        .create()?
        .set_no_new_privs(true);
    let status = ruleset.restrict_self()?;
    if status.ruleset == landlock::RulesetStatus::NotEnforced {
        return Err(CodexErr::Sandbox(SandboxErr::LandlockRestrict));
    }
    Ok(())
}

/// Installs Landlock file-system rules on the current thread allowing read
/// access to the entire file-system while restricting write access to
/// `/dev/null` and the provided list of `writable_roots`.
///
/// # Errors
/// Returns [`CodexErr::Sandbox`] variants when the ruleset fails to apply.
///
/// Note: this is currently unused because filesystem sandboxing is performed
/// via bubblewrap. It is kept for reference and potential fallback use.
fn install_filesystem_landlock_rules_on_current_thread(
    writable_roots: Vec<AbsolutePathBuf>,
) -> Result<()> {
    let abi = ABI::V5;
    // Workspace-write must not imply deletion. Landlock models unlink/rmdir and
    // rename/replace as dedicated rights, so leave those rights unhandled here.
    let access_rw =
        AccessFs::from_all(abi) & !AccessFs::RemoveDir & !AccessFs::RemoveFile & !AccessFs::Refer;
    let access_ro = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(access_rw)?
        .create()?
        .add_rules(landlock::path_beneath_rules(&["/"], access_ro))?
        .add_rules(landlock::path_beneath_rules(&["/dev/null"], access_rw))?
        .set_no_new_privs(true);

    if !writable_roots.is_empty() {
        ruleset = ruleset.add_rules(landlock::path_beneath_rules(&writable_roots, access_rw))?;
    }

    let status = ruleset.restrict_self()?;

    if status.ruleset == landlock::RulesetStatus::NotEnforced {
        return Err(CodexErr::Sandbox(SandboxErr::LandlockRestrict));
    }

    Ok(())
}

/// Installs a seccomp filter for Linux network sandboxing.
///
/// The filter is applied to the current thread so only the sandboxed child