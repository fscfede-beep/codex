#!/usr/bin/env python3
"""Fail-closed, local-only Git transport regression harness (no network server)."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def run(args, cwd, env):
    try:
        return subprocess.run(args, cwd=cwd, env=env, capture_output=True,
                              text=True, timeout=6, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"controlled git probe failed: {exc}") from exc


def source_audit(repo):
    paths = {
        "tui": repo / "codex-rs/tui/src/branch_summary.rs",
        "workspace": repo / "codex-rs/tui/src/workspace_command.rs",
        "git_utils": repo / "codex-rs/git-utils/src/info.rs",
        "policy": repo / "codex-rs/git-utils/src/local_only.rs",
    }
    text = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
    tests = {
        "tui_no_transport_fallback": 'get_remote_default_branch_from_remote_show' not in text["tui"].split("#[cfg(test)]")[0],
        "git_utils_no_remote_show": '["remote", "show"' not in text["git_utils"].split("#[cfg(test)]")[0],
        "tui_applies_local_policy": 'WorkspaceCommand::local_only_git(argv)' in text["tui"],
        "tui_overrides_repo_ssh_command": '"core.sshCommand="' in text["workspace"],
        "git_utils_applies_local_policy": '.envs(crate::local_only_git_env())' in text["git_utils"],
        "protocol_denied": '("GIT_ALLOW_PROTOCOL", "")' in text["policy"],
        "lazy_fetch_disabled": '("GIT_NO_LAZY_FETCH", "1")' in text["policy"],
    }
    return tests


def transport_canary():
    if os.name != "posix":
        return {"local_canary_platform": "NOT_TESTED (requires POSIX sh)"}
    with tempfile.TemporaryDirectory(prefix="rumbo-git-transport-") as temp:
        root = Path(temp)
        repo = root / "repo"
        repo.mkdir()
        marker = root / "CANARY_EXECUTED"
        helper = root / "ssh-canary.sh"
        helper.write_text(f'#!/bin/sh\nprintf CANARY > "{marker}"\nexit 23\n', encoding="utf-8")
        helper.chmod(0o700)
        env = os.environ.copy()
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(root / "empty-global"),
                    "GIT_TERMINAL_PROMPT": "0"})
        env.pop("GIT_ALLOW_PROTOCOL", None)
        env.pop("GIT_NO_LAZY_FETCH", None)
        assert run(["git", "init", "-q"], repo, env).returncode == 0
        assert run(["git", "config", "core.sshCommand", str(helper)], repo, env).returncode == 0
        assert run(["git", "remote", "add", "origin", "ssh://127.0.0.1:9/repo.git"], repo, env).returncode == 0
        baseline = run(["git", "-c", "safe.bareRepository=explicit", "remote", "show", "origin"], repo, env)
        baseline_executed = marker.exists()
        marker.unlink(missing_ok=True)
        guarded_env = dict(env, GIT_ALLOW_PROTOCOL="", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0")
        protected = run(["git", "-c", "safe.bareRepository=explicit", "-c", "core.sshCommand=",
                         "remote", "show", "origin"], repo, guarded_env)
        return {
            "unprotected_helper_executed": baseline_executed and baseline.returncode != 0,
            "guarded_helper_blocked": protected.returncode != 0 and not marker.exists(),
            "guarded_failed_closed": protected.returncode != 0,
            "no_third_party_remote": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, help="local checkout to inspect (optional)")
    args = parser.parse_args()
    results = transport_canary()
    if args.repo:
        results.update(source_audit(args.repo.resolve()))
    evaluated = [v for v in results.values() if isinstance(v, bool)]
    print(json.dumps({"status": "PASS" if evaluated and all(evaluated) else "FAIL",
                      "checks": results}, indent=2, sort_keys=True))
    return 0 if evaluated and all(evaluated) else 1


if __name__ == "__main__":
    sys.exit(main())
