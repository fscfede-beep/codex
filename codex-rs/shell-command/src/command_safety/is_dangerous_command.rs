use crate::bash::parse_shell_lc_literal_commands;
#[path = "windows_dangerous_commands.rs"]
mod windows_dangerous_commands;

/// The platform whose command semantics should be used for safety checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DangerousCommandPlatform {
    /// POSIX command and path semantics.
    Posix,
    /// Windows command and path semantics.
    Windows,
}

impl DangerousCommandPlatform {
    /// Returns the platform where the classifier is running.
    pub fn host() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Posix
        }
    }
}

/// Identifies the dangerous-command rule matched by a command invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DangerousCommandMatch {
    /// An `rm` invocation includes the force option.
    ForcedRm,
    /// Another dangerous-command rule matched.
    Other,
}

const MAX_DANGEROUS_COMMAND_WRAPPER_DEPTH: usize = 8;

/// Returns the dangerous-command rule matched by an already-tokenized command.
pub fn dangerous_command_match(command: &[String]) -> Option<DangerousCommandMatch> {
    dangerous_command_match_for_platform(command, DangerousCommandPlatform::host())
}

/// Returns the dangerous-command rule matched using the target platform's semantics.
pub fn dangerous_command_match_for_platform(
    command: &[String],
    platform: DangerousCommandPlatform,
) -> Option<DangerousCommandMatch> {
    dangerous_command_match_with_depth(command, /*wrapper_depth*/ 0, platform)
}

fn dangerous_command_match_with_depth(
    command: &[String],
    wrapper_depth: usize,
    platform: DangerousCommandPlatform,
) -> Option<DangerousCommandMatch> {
    if wrapper_depth > MAX_DANGEROUS_COMMAND_WRAPPER_DEPTH {
        return Some(DangerousCommandMatch::Other);
    }

    if let Some(dangerous_match) =
        dangerous_command_match_for_exec(command, wrapper_depth, platform)
    {
        return Some(dangerous_match);
    }

    // Support shell scripts where any literal command might be dangerous,
    // including commands nested in control flow or substitutions.
    if let Some(dangerous_match) = parse_shell_lc_literal_commands(command).and_then(|commands| {
        commands.iter().find_map(|command| {
            dangerous_command_match_with_depth(command, wrapper_depth + 1, platform)
        })
    }) {
        return Some(dangerous_match);
    }

    if platform == DangerousCommandPlatform::Windows
        && windows_dangerous_commands::is_dangerous_command_windows(command)
    {
        return Some(DangerousCommandMatch::Other);
    }

    None
}

/// Returns the PowerShell-specific rule matched using the target platform's semantics.

/// Returns true when a command can delete filesystem objects under the selected platform semantics.
///
/// This intentionally does not depend on whether exec-policy already matched an allow rule.
/// The result is an effect classification used to force destructive operations through the
/// dedicated approval/sandbox path.
pub fn is_destructive_filesystem_command(command: &[String]) -> bool {
    is_destructive_filesystem_command_for_platform(command, DangerousCommandPlatform::host())
}

/// Returns true when a command can delete filesystem objects under explicit platform semantics.
pub fn is_destructive_filesystem_command_for_platform(
    command: &[String],
    platform: DangerousCommandPlatform,
) -> bool {
    is_destructive_filesystem_command_with_depth(command, /*wrapper_depth*/ 0, platform)
}

fn is_destructive_filesystem_command_with_depth(
    command: &[String],
    wrapper_depth: usize,
    platform: DangerousCommandPlatform,
) -> bool {
    if wrapper_depth > MAX_DANGEROUS_COMMAND_WRAPPER_DEPTH {
        return true;
    }

    if is_destructive_command_for_exec(command, platform) {
        return true;
    }

    if parse_shell_lc_literal_commands(command).is_some_and(|commands| {
        commands.iter().any(|command| {
            is_destructive_filesystem_command_with_depth(command, wrapper_depth + 1, platform)
        })
    }) {
        return true;
    }

    platform == DangerousCommandPlatform::Windows
        && (windows_dangerous_commands::is_dangerous_command_windows(command)
            || windows_dangerous_commands::is_dangerous_powershell_words(command))
}

fn is_destructive_sudo_command(
    command: &[String],
    wrapper_depth: usize,
    platform: DangerousCommandPlatform,
) -> bool {
    let mut index = 1usize;
    while let Some(arg) = command.get(index) {
        if arg == "--" {
            index += 1;
            break;
        }

        if matches!(
            arg.as_str(),
            "-u" | "--user"
                | "-g"
                | "--group"
                | "-h"
                | "--host"
                | "-r"
                | "--chroot"
                | "-C"
                | "--chdir"
        ) {
            index += 2;
            continue;
        }

        if arg.starts_with('-') {
            const FLAGS: &[&str] = &[
                "-A",
                "-b",
                "-E",
                "-H",
                "-i",
                "-K",
                "-k",
                "-n",
                "-P",
                "-S",
                "-s",
                "--askpass",
                "--background",
                "--preserve-env",
                "--remove-timestamp",
                "--reset-timestamp",
                "--stdin",
                "--non-interactive",
                "--shell",
            ];
            if FLAGS.contains(&arg.as_str()) {
                index += 1;
                continue;
            }

            let attached_name = arg.split_once('=').map(|(name, _)| name);
            let attached_value = matches!(
                attached_name,
                Some("--user" | "--group" | "--host" | "--chroot" | "--chdir")
            ) || (arg.starts_with("-u") && arg.len() > 2)
                || (arg.starts_with("-g") && arg.len() > 2)
                || (arg.starts_with("-r") && arg.len() > 2);
            if attached_value {
                index += 1;
                continue;
            }

            return true;
        }

        return is_destructive_filesystem_command_with_depth(
            &command[index..],
            wrapper_depth + 1,
            platform,
        );
    }
    false
}

fn is_destructive_command_for_env(
    command: &[String],
    wrapper_depth: usize,
    platform: DangerousCommandPlatform,
) -> bool {
    let mut command_index = 1;
    while let Some(argument) = command.get(command_index) {
        if argument == "--" {
            command_index += 1;
            break;
        }
        if matches!(argument.as_str(), "-i" | "--ignore-environment")
            || argument
                .split_once('=')
                .is_some_and(|(name, _)| !name.is_empty() && !name.starts_with('-'))
        {
            command_index += 1;
            continue;
        }
        break;
    }
    is_destructive_filesystem_command_with_depth(
        &command[command_index..],
        wrapper_depth + 1,
        platform,
    )
}

fn is_destructive_command_for_exec(
    command: &[String],
    platform: DangerousCommandPlatform,
) -> bool {
    let Some(name) = command
        .first()
        .and_then(|raw| executable_name_lookup_key(raw, platform))
    else {
        return false;
    };
    let args = &command[1..];

    match name.as_str() {
        "rm" | "unlink" | "rmdir" | "rd" | "del" | "erase" | "remove-item" => {
            !args.is_empty()
        }
        "find" => args.iter().any(|arg| arg == "-delete" || arg == "--delete"),
        "git" => {
            matches!(args.first().map(String::as_str), Some("clean"))
                && args.iter().skip(1).any(|arg| {
                    arg == "--force"
                        || arg
                            .strip_prefix('-')
                            .is_some_and(|flags| !flags.starts_with('-') && flags.contains('f'))
                })
        }
        "sudo" => is_destructive_sudo_command(command, wrapper_depth, platform),
        "env" => is_destructive_command_for_env(command, wrapper_depth, platform),
        _ => false,
    }
}

pub fn dangerous_powershell_words_match(
    command: &[String],
    platform: DangerousCommandPlatform,
) -> Option<DangerousCommandMatch> {
    if platform == DangerousCommandPlatform::Windows {
        windows_dangerous_commands::is_dangerous_powershell_words(command)
            .then_some(DangerousCommandMatch::Other)
    } else {
        None
    }
}

fn executable_name_lookup_key(raw: &str, platform: DangerousCommandPlatform) -> Option<String> {
    match platform {
        DangerousCommandPlatform::Posix => raw
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .map(str::to_owned),
        DangerousCommandPlatform::Windows => {
            let name = raw
                .rsplit(['/', '\\'])
                .next()
                .filter(|name| !name.is_empty())?;
            let name = match name.as_bytes() {
                [drive, b':', ..] if drive.is_ascii_alphabetic() => &name[2..],
                _ => name,
            };
            let name = name.to_ascii_lowercase();
            for suffix in [".exe", ".cmd", ".bat", ".com"] {
                if let Some(stripped) = name.strip_suffix(suffix) {
                    return Some(stripped.to_string());
                }
            }
            (!name.is_empty()).then_some(name)
        }
    }
}

fn dangerous_command_match_for_exec(
    command: &[String],
    wrapper_depth: usize,
    platform: DangerousCommandPlatform,
) -> Option<DangerousCommandMatch> {
    let cmd0 = command
        .first()
        .and_then(|command| executable_name_lookup_key(command, platform));

    match cmd0.as_deref() {
        Some("rm") if rm_args_include_force_option(&command[1..]) => {
            Some(DangerousCommandMatch::ForcedRm)
        }

        // For sudo <cmd>, simply check <cmd>.
        Some("sudo") => {
            dangerous_command_match_with_depth(&command[1..], wrapper_depth + 1, platform)
        }

        // Skip environment assignments before checking the command run by env.
        Some("env") => dangerous_command_match_for_env(command, wrapper_depth, platform),

        // A trap action is shell source stored in the first operand.
        Some("trap") => dangerous_command_match_for_trap(command, wrapper_depth, platform),

        // ── anything else ─────────────────────────────────────────────────
        _ => None,
    }
}

fn dangerous_command_match_for_env(
    command: &[String],
    wrapper_depth: usize,
    platform: DangerousCommandPlatform,
) -> Option<DangerousCommandMatch> {
    let mut command_index = 1;
    while let Some(argument) = command.get(command_index) {
        if argument == "--" {
            command_index += 1;
            break;
        }
        if matches!(argument.as_str(), "-i" | "--ignore-environment")
            || argument
                .split_once('=')
                .is_some_and(|(name, _)| !name.is_empty() && !name.starts_with('-'))
        {
            command_index += 1;
            continue;
        }