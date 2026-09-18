    unsafe extern "system" {
        fn OpenProcessToken(
            ProcessHandle: HANDLE,
            DesiredAccess: u32,
            TokenHandle: *mut HANDLE,
        ) -> i32;
    }
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), desired, &mut h) };
    if ok == 0 {
        return Err(anyhow!("OpenProcessToken failed: {}", GetLastError()));
    }
    Ok(h)
}

/// An owned token group, including attributes such as enabled and deny-only.
#[derive(Debug, PartialEq, Eq)]
pub struct TokenGroup {
    pub sid: Vec<u8>,
    pub attributes: u32,
}

/// Queries groups without filtering membership or retaining pointers into Windows' buffer.
///
/// # Safety
/// `token` must remain a valid token handle with `TOKEN_QUERY` access during this call.
pub unsafe fn token_groups(token: HANDLE, max_bytes: u32) -> Result<Vec<TokenGroup>> {
    let mut needed = 0;
    GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
    ensure!(
        needed > 0 && needed <= max_bytes,
        "invalid token group size"
    );
    let mut buffer = vec![0u8; needed as usize];
    if GetTokenInformation(
        token,
        TokenGroups,
        buffer.as_mut_ptr().cast(),
        needed,
        &mut needed,
    ) == 0
    {
        return Err(anyhow!(
            "GetTokenInformation(TokenGroups) failed: {}",
            GetLastError()
        ));
    }
    ensure!(
        needed as usize <= buffer.len(),
        "invalid token group result size"
    );
    decode_token_groups(&buffer[..needed as usize])
}

fn decode_token_groups(buffer: &[u8]) -> Result<Vec<TokenGroup>> {
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    let stride = std::mem::size_of::<SID_AND_ATTRIBUTES>();
    ensure!(buffer.len() >= offset, "truncated token group header");
    let count = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) } as usize;
    ensure!(
        count <= (buffer.len() - offset) / stride,
        "truncated token groups"
    );
    let mut groups = Vec::with_capacity(count);
    for index in 0..count {
        let entry = unsafe {
            std::ptr::read_unaligned(
                buffer
                    .as_ptr()
                    .add(offset + index * stride)
                    .cast::<SID_AND_ATTRIBUTES>(),
            )
        };
        // Bound the header and every subauthority before calling a SID API.
        let sid_offset = (entry.Sid as usize).wrapping_sub(buffer.as_ptr() as usize);
        ensure!(
            sid_offset <= buffer.len().saturating_sub(8),
            "invalid token group SID pointer"
        );
        ensure!(buffer[sid_offset] == 1, "invalid token group SID revision");
        let sid_len = 8 + usize::from(buffer[sid_offset + 1]) * 4;
        ensure!(
            sid_len <= 68 && sid_len <= buffer.len() - sid_offset,
            "invalid token group SID size"
        );
        ensure!(
            unsafe { IsValidSid(entry.Sid) } != 0,
            "invalid token group SID"
        );
        let mut sid = vec![0u8; sid_len];
        ensure!(
            unsafe { CopySid(sid_len as u32, sid.as_mut_ptr().cast(), entry.Sid) } != 0,
            "invalid token group SID"
        );
        groups.push(TokenGroup {
            sid,
            attributes: entry.Attributes,
        });
    }
    Ok(groups)
}

pub unsafe fn get_logon_sid_bytes(h_token: HANDLE) -> Result<Vec<u8>> {
    unsafe fn scan_token_groups_for_logon(h: HANDLE) -> Option<Vec<u8>> {
        token_groups(h, u32::MAX)
            .ok()?
            .into_iter()
            .find(|group| group.attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
            .map(|group| group.sid)
    }

    if let Some(v) = scan_token_groups_for_logon(h_token) {
        return Ok(v);
    }

    #[repr(C)]
    struct TOKEN_LINKED_TOKEN {
        linked_token: HANDLE,
    }
    const TOKEN_LINKED_TOKEN_CLASS: i32 = 19; // TokenLinkedToken
    let mut ln_needed: u32 = 0;
    GetTokenInformation(
        h_token,
        TOKEN_LINKED_TOKEN_CLASS,
        std::ptr::null_mut(),
        0,
        &mut ln_needed,
    );
    if ln_needed >= std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32 {
        let mut ln_buf: Vec<u8> = vec![0u8; ln_needed as usize];
        let ok = GetTokenInformation(
            h_token,
            TOKEN_LINKED_TOKEN_CLASS,
            ln_buf.as_mut_ptr() as *mut c_void,
            ln_needed,
            &mut ln_needed,
        );
        if ok != 0 {
            let lt: TOKEN_LINKED_TOKEN =
                std::ptr::read_unaligned(ln_buf.as_ptr() as *const TOKEN_LINKED_TOKEN);
            if lt.linked_token != 0 {
                let res = scan_token_groups_for_logon(lt.linked_token);
                CloseHandle(lt.linked_token);
                if let Some(v) = res {
                    return Ok(v);
                }
            }
        }
    }

    Err(anyhow!("Logon SID not present on token"))
}

pub(crate) use crate::token_user::get_user_sid_bytes;

unsafe fn enable_single_privilege(h_token: HANDLE, name: &str) -> Result<()> {
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let ok = LookupPrivilegeValueW(std::ptr::null(), to_wide(name).as_ptr(), &mut luid);
    if ok == 0 {
        return Err(anyhow!("LookupPrivilegeValueW failed: {}", GetLastError()));
    }
    let mut tp: TOKEN_PRIVILEGES = std::mem::zeroed();
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED
    let ok2 = AdjustTokenPrivileges(
        h_token,
        0,
        &tp,
        0,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    if ok2 == 0 {
        return Err(anyhow!("AdjustTokenPrivileges failed: {}", GetLastError()));
    }
    let err = GetLastError();
    if err != 0 {
        return Err(anyhow!("AdjustTokenPrivileges error {err}"));
    }
    Ok(())
}

/// # Safety
/// Caller must close the returned token handle.
pub unsafe fn create_readonly_token_with_cap(
    psid_capability: *mut c_void,
) -> Result<(HANDLE, *mut c_void)> {
    let base = get_current_token_for_restriction()?;
    let res = create_readonly_token_with_cap_from(base, psid_capability);
    CloseHandle(base);
    res
}

/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
pub unsafe fn create_readonly_token_with_cap_from(
    base_token: HANDLE,
    psid_capability: *mut c_void,
) -> Result<(HANDLE, *mut c_void)> {
    let new_token = create_token_with_caps_from(base_token, &[psid_capability], &[])?;
    Ok((new_token, psid_capability))
}

/// Create a restricted token that includes all provided capability SIDs.
///
/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
pub unsafe fn create_workspace_write_token_with_caps_from(
    base_token: HANDLE,
    psid_capabilities: &[*mut c_void],
) -> Result<HANDLE> {
    create_token_with_caps_from(base_token, psid_capabilities, &[])
}

/// Create a workspace-write restricted token carrying additional restrictive
/// SIDs. These SIDs are requirements, not grants; they are used for effects
/// such as root-scoped DELETE denial.
pub unsafe fn create_workspace_write_token_with_caps_and_restrictions_from(
    base_token: HANDLE,
    psid_capabilities: &[*mut c_void],
    additional_restricting_sids: &[*mut c_void],
) -> Result<HANDLE> {
    create_token_with_caps_from(
        base_token,
        psid_capabilities,
        additional_restricting_sids,
    )
}

/// Create a restricted token that includes all provided capability SIDs, the token user SID, and
/// any additional restricting SIDs.
///
/// This is intended for the elevated sandbox backend, where the token user is the dedicated
/// sandbox account rather than the real signed-in user.
///
/// # Safety
/// Caller must close the returned token handle; base_token must be a valid primary token.
pub unsafe fn create_workspace_write_token_with_caps_and_user_from(
    base_token: HANDLE,
    psid_capabilities: &[*mut c_void],
    additional_restricting_sids: &[*mut c_void],
) -> Result<HANDLE> {
    create_token_with_caps_user_and_additional_restrictions_from(
        base_token,
        psid_capabilities,
        additional_restricting_sids,
    )
}

/// Create a restricted token that includes all provided capability SIDs.
///