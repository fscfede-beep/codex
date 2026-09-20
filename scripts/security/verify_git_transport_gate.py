#!/usr/bin/env python3
"""Offline canary for Git transport and repository SSH-command containment.

This tests Git policy semantics, not Codex end-to-end execution. It never
contacts an external server or reads credentials. Requires Git on PATH.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile


def run(cwd: pathlib.Path, *argv: str, env: dict[str, str] | None = None):
    merged = os.environ.copy()
    for key in ("GIT_ALLOW_PROTOCOL", "GIT_NO_LAZY_FETCH", "GIT_CONFIG_COUNT",
                "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"):
        merged.pop(key, None)
    if env:
        merged.update(env)
    return subprocess.run(argv, cwd=cwd, env=merged, capture_output=True,
                          text=True, timeout=8, check=False)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="rumbo-git-local-only-") as tmp:
        root = pathlib.Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        init = run(repo, "git", "init", "-q")
        assert init.returncode == 0, init.stderr
        marker = root / "canary.marker"
        if os.name == "nt":
            helper = root / "canary.cmd"
            helper.write_text(f'@echo off\r\necho HIT>>"{marker}"\r\nexit /b 87\r\n')
        else:
            helper = root / "canary.sh"
            helper.write_text(f'#!/bin/sh\nprintf "HIT\\n" >> "{marker}"\nexit 87\n')
            helper.chmod(0o700)
        for argv in [
            ("git", "config", "core.sshCommand", f'"{helper}"'),
            ("git", "remote", "add", "origin", "ssh://127.0.0.1:9/repo.git"),
        ]:
            result = run(repo, *argv)
            assert result.returncode == 0, result.stderr

        # Negative control proves the fixture actually reaches the configured helper.
        unguarded = run(repo, "git", "remote", "show", "origin")
        assert unguarded.returncode != 0, "canary helper unexpectedly succeeded"
        assert marker.exists(), "NEGATIVE_CONTROL_FAIL: unguarded Git did not execute canary"
        marker.unlink()
        print("NEGATIVE_CONTROL: helper execution reproduced")

        # Upstream's shared local-only policy must block all transports.
        policy = {"GIT_ALLOW_PROTOCOL": "", "GIT_NO_LAZY_FETCH": "1"}
        guarded = run(repo, "git", "remote", "show", "origin", env=policy)
        assert guarded.returncode != 0, "unexpected remote success with transport denied"
        assert not marker.exists(), "FAIL: local-only policy executed repository helper"
        print("LOCAL_ONLY_POLICY: denied transport; canary absent")

        # Independent, explicit CLI override must also suppress core.sshCommand.
        overridden = run(repo, "git", "-c", "core.sshCommand=", "remote", "show", "origin")
        assert overridden.returncode != 0, "unexpected remote success after empty override"
        assert not marker.exists(), "FAIL: CLI override executed repository helper"
        print("SSH_CONFIG_OVERRIDE: canary absent")
        print("RESULT: PASS (Git behavior only; no Codex E2E claim)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, subprocess.TimeoutExpired) as exc:
        print(f"RESULT: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
