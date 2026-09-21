#!/usr/bin/env python3
"""Disposable local Git helper canary. No external host, credentials or repo writes."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def git(repo, env, *args):
    return subprocess.run(['git', *args], cwd=repo, env=env,
                          capture_output=True, text=True, timeout=7, check=False)


def main():
    with tempfile.TemporaryDirectory(prefix='rumbo-codex-r8-') as tmp:
        root = Path(tmp)
        repo = root / 'repo'
        repo.mkdir()
        home = root / 'home'
        home.mkdir()
        marker = root / 'HELPER_EXECUTED'
        helper = root / 'ssh-canary.sh'
        helper.write_text('#!/bin/sh\nprintf EXECUTED > "' + str(marker) + '"\nexit 23\n')
        helper.chmod(0o700)
        env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'LC_ALL': 'C',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_TERMINAL_PROMPT': '0'}
        setup = [git(repo, env, 'init', '-q'),
                 git(repo, env, 'config', 'core.sshCommand', str(helper)),
                 git(repo, env, 'remote', 'add', 'origin', 'ssh://127.0.0.1:9/repo.git')]
        assert all(p.returncode == 0 for p in setup), 'setup failed'
        def probe(argv, extra=None):
            marker.unlink(missing_ok=True)
            result = git(repo, {**env, **(extra or {})}, *argv)
            return {'helper_executed': marker.exists(),
                    'failed_closed': result.returncode != 0,
                    'exit_code': result.returncode}
        show = ['remote', 'show', 'origin']
        base = probe(show)
        cli = probe(['-c', 'core.sshCommand=', *show])
        deny = probe(show, {'GIT_ALLOW_PROTOCOL': '', 'GIT_NO_LAZY_FETCH': '1'})
        injected = {'GIT_SSH_COMMAND': str(helper)}
        env_baseline = probe(show, injected)
        env_cli_only = probe(['-c', 'core.sshCommand=', *show], injected)
        env_guarded = probe(['-c', 'core.sshCommand=', *show],
                            {**injected, 'GIT_ALLOW_PROTOCOL': '', 'GIT_NO_LAZY_FETCH': '1'})
        checks = {
            'core_canary_baseline_executes': base['helper_executed'],
            'core_cli_override_blocks': not cli['helper_executed'] and cli['failed_closed'],
            'protocol_deny_blocks_core_helper': not deny['helper_executed'] and deny['failed_closed'],
            'inherited_git_ssh_command_baseline_executes': env_baseline['helper_executed'],
            'cli_override_alone_not_sufficient_for_env_helper': env_cli_only['helper_executed'],
            'combined_policy_blocks_env_helper': not env_guarded['helper_executed'] and env_guarded['failed_closed'],
            'only_loopback_fake_remote': True,
        }
        print(json.dumps({'status': 'PASS' if all(checks.values()) else 'FAIL',
                          'checks': checks,
                          'observations': {'baseline': base, 'cli_only': cli,
                                           'protocol_only': deny, 'inherited_env': env_baseline,
                                           'env_cli_only': env_cli_only, 'env_combined': env_guarded}},
                         indent=2, sort_keys=True))
        return 0 if all(checks.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
