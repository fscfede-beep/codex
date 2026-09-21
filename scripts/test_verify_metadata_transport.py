"""Check that the static audit fails closed rather than accepting test-only imports."""
import importlib.util
from pathlib import Path
import tempfile

module_path = Path(__file__).with_name('verify_metadata_transport.py')
spec = importlib.util.spec_from_file_location('verify_metadata_transport', module_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

with tempfile.TemporaryDirectory(prefix='rumbo-audit-fixture-') as temporary:
    root = Path(temporary)
    sample = {
        'codex-rs/tui/src/branch_summary.rs': '#[cfg(test)]\nuse std::collections::VecDeque;\nWorkspaceCommand::local_only_git(argv);\n#[cfg(test)]\nmod tests {}\n',
        'codex-rs/tui/src/workspace_command.rs': '"core.sshCommand="\n',
        'codex-rs/git-utils/src/info.rs': '#[cfg(test)]\nuse std::fs;\n.envs(crate::local_only_git_env());\n#[cfg(test)]\nmod tests {}\n',
        'codex-rs/git-utils/src/local_only.rs': '("GIT_ALLOW_PROTOCOL", ""), ("GIT_NO_LAZY_FETCH", "1")\n',
    }
    for name, content in sample.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')
    safe = mod.source_audit(root)
    assert len(safe) == 7 and all(safe.values()), safe
    tui = root / 'codex-rs/tui/src/branch_summary.rs'
    tui.write_text(sample['codex-rs/tui/src/branch_summary.rs'].replace(
        'WorkspaceCommand::local_only_git(argv);',
        'get_remote_default_branch_from_remote_show();\nWorkspaceCommand::local_only_git(argv);'), encoding='utf-8')
    assert mod.source_audit(root)['tui_no_transport_fallback'] is False
    tui.write_text(sample['codex-rs/tui/src/branch_summary.rs'], encoding='utf-8')
    info = root / 'codex-rs/git-utils/src/info.rs'
    info.write_text(sample['codex-rs/git-utils/src/info.rs'].replace(
        '.envs(crate::local_only_git_env());',
        'run_git_command_with_timeout(&["remote",\n"show", &remote], cwd);\n.envs(crate::local_only_git_env());'), encoding='utf-8')
    assert mod.source_audit(root)['git_utils_no_remote_show'] is False
    info.write_text('no test module boundary here\n', encoding='utf-8')
    try:
        mod.source_audit(root)
    except RuntimeError as exc:
        assert 'boundary' in str(exc)
    else:
        raise AssertionError('missing production boundary must fail closed')
    print('SELF_AUDIT=PASS safe_fixture=7/7 malicious_tui_detected=YES multiline_gitutils_detected=YES missing_boundary_fails_closed=YES')
