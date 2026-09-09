rule apt_malware_js_longtale: LONGTALE JungleBamboo
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-08"
    description = "Detection for LONGTALE, a chrome extension malware."
    hash1 = "5eb5645511b00e4f4d73125654eeb3a3930fcf09c65685dc7f03f725331492e3"
    os = "all"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20260908B"
    last_modified = "2026-09-08T20:00:22Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13428
    version = 2

  strings:
    $f1 = "getPublicIP" ascii
    $f2 = "captureCookies" ascii
    $f3 = "recordFetch" ascii
    $f4 = "injectRecorder" ascii
    $f5 = "captureVisibleTab" ascii
    $f6 = "buildIngestPayload" ascii

    $case1 = "SET_KEYWORDS"
    $case2 = "GET_KEYWORDS"
    $case3 = "SCREENSHOT_NOW"
    $case4 = "FETCH_HISTORY"
    $case5 = "CAPTURE_STORAGE"
    $case6 = "CAPTURE_COOKIES"
    $case7 = "TOGGLE_RECORDING"

  condition:
    all of ($f*) or
    all of ($case*)
}
rule apt_malware_win_superstomp: JungleBamboo SUPERSTOMP
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-08"
    description = "Detection for the SUPERSTOMP malware used by JungleBamboo."
    hash1 = "5eb5645511b00e4f4d73125654eeb3a3930fcf09c65685dc7f03f725331492e3"
    os = "win"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20260908B"
    last_modified = "2026-09-08T16:47:56Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13427
    version = 3

  strings:
    $stomp_ua = "stomp/1.0" wide
    $stomp_pem = "stomp_ext_key.pem" wide
    $stomp_spki = "stomp_ext_key.spki" wide
    $stomp_bak = "stomp.bak" wide

    $xor_key = { 5a c3 17 8e f0 2b 96 41 7d 0a e8 33 b5 64 1f da }

    $browser_secpref = "Secure Preferences" wide
    $browser_extsettings = "extensions.settings." ascii
    $browser_devmode = "extensions.ui.developer_mode" ascii
    $browser_taskkill = "cmd.exe /c taskkill /F /IM " wide
    $browser_restore = "--restore-last-session" wide

  condition:
    3 of ($stomp*) or
    $xor_key or
    all of ($browser*)
}
rule apt_malware_win_uta0560_grimwedge_loader: UTA0560
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-04"
    description = "Detects UTA0560 MSI installers that contain the GRIMWEDGE RAT loader."
    hash = "56eda0ac82e06ee609b034306025e67df161c5877399c305c8eaea136e80c951"
    os = "win"
    os_arch = "all"
    scan_context = "file"
    severity = "high"
    report1 = "TIB-20260908"
    last_modified = "2026-09-08T20:01:22Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13424
    version = 3

  strings:
    // Advanced Installer inline-script custom action structure.
    $msi_action = "ExecuteScriptCode" ascii
    $js_activex = "new ActiveXObject" ascii
    $js_getobject = "GetObject(" ascii

    // WMI LocalTime event query used as the RAT polling timer.
    $timer_plain = "__InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_LocalTime'" ascii
    $timer_obfuscated_1 = "'Inst','Modi','Even','THIN'" ascii
    $timer_obfuscated_2 = "'getI','nsta','nce\\x20','ISA\\x20','32_L','Time'" ascii

    // Synchronous WinHTTP request and response processing.
    $http_plain = "WinHttp.WinHttpRequest.5.1" ascii nocase
    $http_obfuscated = "'ttp.','WinH','ttpR','eque','st.5'" ascii
    $response_plain = "ResponseText" ascii
    $response_obfuscated = "'Resp','onse','Text'" ascii

    // Two tab delimiters separate state, victim identity, and output.
    $protocol_tab = { 2B 27 5C 78 30 39 27 2B }
    $handler_eval = /eval\([A-Za-z_$][A-Za-z0-9_$]*\[(0x)?7\]\)/ ascii

  condition:
    filesize > 100KB and filesize < 5MB and
    uint32be(0) == 0xD0CF11E0 and
    $msi_action and
    all of ($js_*) and
    (
      $timer_plain or
      all of ($timer_obfuscated_*)
    ) and
    (
      $http_plain or
      $http_obfuscated
    ) and
    (
      $response_plain or
      $response_obfuscated
    ) and
    #protocol_tab >= 2 and
    $handler_eval
}
rule apt_malware_win_uta0560_wscdll: UTA0560
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-03"
    description = "Detects close variants of the x86 UTA0560 wsc.dll downloader used in an AVG DLL side-loading chain."
    hash = "5984343880792fd0dbb3968fe6db894d699831a4c009e8ff14a140cec9b61114"
    os = "win"
    os_arch = "x86"
    scan_context = "file"
    severity = "high"
    report1 = "TIB-20260908"
    last_modified = "2026-09-08T16:02:13Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13423
    version = 2

  strings:
    // The exported entry point is the stable side-loading contract.
    $export_run = "_run@4" ascii fullword

    // The malware resolves this process and file API set at run time.
    $api_expand_environment = "ExpandEnvironmentStringsW" ascii fullword
    $api_get_file_attributes = "GetFileAttributesW" ascii fullword
    $api_create_process = "CreateProcessW" ascii fullword
    $api_wait_for_process = "WaitForSingleObject" ascii fullword
    $api_get_exit_code = "GetExitCodeProcess" ascii fullword
    $api_terminate_process = "TerminateProcess" ascii fullword
    $api_close_handle = "CloseHandle" ascii fullword
    $api_get_module_filename = "GetModuleFileNameW" ascii fullword

    // Resolver thunks at RVA 0x1020 onward call LoadLibraryW and
    // GetProcAddress, then save each result. Image addresses vary.
    $code_api_resolver = {
      68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ??
      50 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? C3 CC CC CC
    }

    // The task-check function builds "schtasks /query /tn \"" as UTF-16
    // DWORD immediates. Stack offsets vary between compiler builds.
    $code_task_query = {
      C7 45 ?? 73 00 63 00 [0-8] C7 45 ?? 68 00 74 00
      C7 45 ?? 61 00 73 00 C7 45 ?? 6B 00 73 00
      C7 45 ?? 20 00 2F 00 C7 45 ?? 71 00 75 00
      C7 45 ?? 65 00 72 00 C7 45 ?? 79 00 20 00
      C7 45 ?? 2F 00 74 00 C7 45 ?? 6E 00 20 00
    }

    // The main routine builds "schtasks /create /sc MINUTE /tn \"" as
    // UTF-16 immediates. Frame displacements and setup code vary.
    $code_task_create = {
      C7 85 ?? ?? ?? ?? 73 00 63 00
      [0-20] C7 85 ?? ?? ?? ?? 68 00 74 00
      [0-12] C7 85 ?? ?? ?? ?? 61 00 73 00
      C7 85 ?? ?? ?? ?? 6B 00 73 00
      C7 85 ?? ?? ?? ?? 20 00 2F 00
      C7 85 ?? ?? ?? ?? 63 00 72 00
      C7 85 ?? ?? ?? ?? 65 00 61 00
      C7 85 ?? ?? ?? ?? 74 00 65 00
      C7 85 ?? ?? ?? ?? 20 00 2F 00
      C7 85 ?? ?? ?? ?? 73 00 63 00
      C7 85 ?? ?? ?? ?? 20 00 4D 00
      C7 85 ?? ?? ?? ?? 49 00 4E 00
      C7 85 ?? ?? ?? ?? 55 00 54 00
      C7 85 ?? ?? ?? ?? 45 00 20 00
      C7 85 ?? ?? ?? ?? 2F 00 74 00
      C7 85 ?? ?? ?? ?? 6E 00 20 00
    }

    // The main routine builds "cmd.exe /c curl -f -sS -o \"" as UTF-16
    // immediates. Stack offsets and two short setup regions vary.
    $code_curl_download = {
      C7 45 ?? 63 00 6D 00 [0-8] C7 45 ?? 64 00 2E 00
      [0-8] C7 45 ?? 65 00 78 00 C7 45 ?? 65 00 20 00
      C7 45 ?? 2F 00 63 00 C7 45 ?? 20 00 63 00
      C7 45 ?? 75 00 72 00 C7 45 ?? 6C 00 20 00
      C7 45 ?? 2D 00 66 00 C7 45 ?? 20 00 2D 00
      C7 45 ?? 73 00 53 00 C7 45 ?? 20 00 2D 00
      C7 45 ?? 6F 00 20 00 C7 45 ?? 22 00 00 00
    }

  condition:
    filesize > 30KB and
    filesize < 1MB and
    uint16be(0) == 0x4D5A and
    uint32(uint32(0x3C)) == 0x00004550 and
    uint16(uint32(0x3C) + 0x04) == 0x014C and
    uint16(uint32(0x3C) + 0x18) == 0x010B and
    (uint16(uint32(0x3C) + 0x16) & 0x2000) == 0x2000 and
    $export_run and
    6 of ($api_*) and
    #code_api_resolver >= 7 and
    all of ($code_task_*) and
    $code_curl_download
}
rule apt_malware_win_uta0560_downloader: UTA0560
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-03"
    description = "Detects close variants of the x86 UTA0560 downloader DLL that stages an MSI and creates scheduled-task persistence."
    hash = "3b71d721c39fad92a44ddd764bbb34afeae44a5db886d0a4827a399a5fbd367f"
    os = "win"
    os_arch = "x86"
    scan_context = "file"
    severity = "high"
    report1 = "TIB-20260908"
    last_modified = "2026-09-08T16:02:19Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13422
    version = 2

  strings:
    // The malware resolves this process and file API set at run time.
    $api_expand_environment = "ExpandEnvironmentStringsW" ascii fullword
    $api_get_file_attributes = "GetFileAttributesW" ascii fullword
    $api_create_process = "CreateProcessW" ascii fullword
    $api_wait_for_process = "WaitForSingleObject" ascii fullword
    $api_get_exit_code = "GetExitCodeProcess" ascii fullword
    $api_terminate_process = "TerminateProcess" ascii fullword
    $api_close_handle = "CloseHandle" ascii fullword
    $api_get_module_filename = "GetModuleFileNameW" ascii fullword

    // Resolver stubs at 0x10001020-0x10001100 call LoadLibraryW and
    // GetProcAddress, then save the result. All absolute addresses vary.
    $code_api_resolver = {
      68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ??
      50 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? C3 CC CC CC
    }

    // mw_check_schtask_exists at 0x10001440 builds the UTF-16 command
    // "schtasks /query /tn \"" from DWORD immediates. The one bounded
    // gap covers a LEA; stack offsets vary.
    $code_task_query = {
      C7 45 ?? 73 00 63 00 [0-8] C7 45 ?? 68 00 74 00
      C7 45 ?? 61 00 73 00 C7 45 ?? 6B 00 73 00
      C7 45 ?? 20 00 2F 00 C7 45 ?? 71 00 75 00
      C7 45 ?? 65 00 72 00 C7 45 ?? 79 00 20 00
      C7 45 ?? 2F 00 74 00 C7 45 ?? 6E 00 20 00
    }

    // mw_main_logic at 0x10001689 builds "%TEMP%\\Temp.txt". The one
    // bounded gap covers a LEA. Stack offsets vary, and the path is
    // supporting evidence because a variant can change its stage name.
    $code_temp_path = {
      C7 45 ?? 25 00 54 00 [0-8] C7 45 ?? 45 00 4D 00
      C7 45 ?? 50 00 25 00 C7 45 ?? 5C 00 54 00
      C7 45 ?? 65 00 6D 00 C7 45 ?? 70 00 2E 00
      C7 45 ?? 74 00 78 00 C7 45 ?? 74 00 00 00
    }

    // mw_main_logic at 0x1000187F builds the campaign URL suffix
    // "/chrome/%COMPUTERNAME%.txt". The domain is intentionally omitted.
    // C7 85 and C7 45 are the compiler's long and short stack forms.
    $code_victim_url_path = {
      C7 85 ?? ?? ?? ?? 2F 00 63 00
      C7 85 ?? ?? ?? ?? 68 00 72 00
      C7 85 ?? ?? ?? ?? 6F 00 6D 00
      C7 85 ?? ?? ?? ?? 65 00 2F 00
      C7 45 ?? 25 00 43 00 C7 45 ?? 4F 00 4D 00
      C7 45 ?? 50 00 55 00 C7 45 ?? 54 00 45 00
      C7 45 ?? 52 00 4E 00 C7 45 ?? 41 00 4D 00
      C7 45 ?? 45 00 25 00 C7 45 ?? 2E 00 74 00
      C7 45 ?? 78 00 74 00
    }

    // mw_main_logic at 0x10001B42 builds
    // "cmd.exe /c curl -f -sS -o \"". Two bounded gaps cover setup
    // instructions before the contiguous command writes.
    $code_curl_download = {
      C7 45 ?? 63 00 6D 00 [0-8] C7 45 ?? 64 00 2E 00
      [0-8] C7 45 ?? 65 00 78 00 C7 45 ?? 65 00 20 00
      C7 45 ?? 2F 00 63 00 C7 45 ?? 20 00 63 00
      C7 45 ?? 75 00 72 00 C7 45 ?? 6C 00 20 00
      C7 45 ?? 2D 00 66 00 C7 45 ?? 20 00 2D 00
      C7 45 ?? 73 00 53 00 C7 45 ?? 20 00 2D 00
      C7 45 ?? 6F 00 20 00 C7 45 ?? 22 00 00 00
    }

    // mw_main_logic at 0x10001DA0 builds "msiexec /i \"". The bounded
    // gaps cover setup instructions; stack offsets vary.
    $code_msi_install = {
      C7 45 ?? 6D 00 73 00 [0-16] C7 45 ?? 69 00 65 00
      [0-12] C7 45 ?? 78 00 65 00 C7 45 ?? 63 00 20 00
      C7 45 ?? 2F 00 69 00 C7 45 ?? 20 00 22 00
    }

    // mw_main_logic at 0x100020A1 builds
    // "schtasks /create /sc MINUTE /tn \"". The first two bounded gaps
    // cover setup instructions. Stack offsets vary. The task name is
    // omitted so renamed variants can match.
    $code_task_create = {
      C7 85 ?? ?? ?? ?? 73 00 63 00
      [0-20] C7 85 ?? ?? ?? ?? 68 00 74 00
      [0-12] C7 85 ?? ?? ?? ?? 61 00 73 00
      C7 85 ?? ?? ?? ?? 6B 00 73 00
      C7 85 ?? ?? ?? ?? 20 00 2F 00
      C7 85 ?? ?? ?? ?? 63 00 72 00
      C7 85 ?? ?? ?? ?? 65 00 61 00
      C7 85 ?? ?? ?? ?? 74 00 65 00
      C7 85 ?? ?? ?? ?? 20 00 2F 00
      C7 85 ?? ?? ?? ?? 73 00 63 00
      C7 85 ?? ?? ?? ?? 20 00 4D 00
      C7 85 ?? ?? ?? ?? 49 00 4E 00
      C7 85 ?? ?? ?? ?? 55 00 54 00
      C7 85 ?? ?? ?? ?? 45 00 20 00
      C7 85 ?? ?? ?? ?? 2F 00 74 00
      C7 85 ?? ?? ?? ?? 6E 00 20 00
      C7 85 ?? ?? ?? ?? 22 00 57 00
    }

  condition:
    filesize > 30KB and
    filesize < 1MB and
    uint16be(0) == 0x4D5A and
    uint32(uint32(0x3C)) == 0x00004550 and
    uint16(uint32(0x3C) + 0x04) == 0x014C and
    uint16(uint32(0x3C) + 0x18) == 0x010B and
    (uint16(uint32(0x3C) + 0x16) & 0x2000) == 0x2000 and
    6 of ($api_*) and
    #code_api_resolver >= 6 and
    3 of ($code_task_query, $code_temp_path, $code_victim_url_path,
      $code_curl_download, $code_msi_install, $code_task_create)
}
rule apt_malware_win_uta0560_dropper: UTA0560
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-03"
    description = "Detects close variants of the x86 UTA0560 resource dropper used to install an AVG DLL side-loading pair."
    hash = "69c1603f3f9015beb0097d0a3bb0f17400c314e2eae65a7eceacd3b93ea570dc"
    os = "win"
    os_arch = "x86"
    scan_context = "file"
    severity = "high"
    report1 = "TIB-20260908"
    last_modified = "2026-09-08T16:02:32Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13421
    version = 4

  strings:
    // The dropper resolves this resource-to-process API set at run time.
    $api_find_resource = "FindResourceW" ascii fullword
    $api_size_resource = "SizeofResource" ascii fullword
    $api_load_resource = "LoadResource" ascii fullword
    $api_lock_resource = "LockResource" ascii fullword
    $api_create_file = "CreateFileW" ascii fullword
    $api_write_file = "WriteFile" ascii fullword
    $api_create_process = "CreateProcessW" ascii fullword
    $api_get_file_attributes = "GetFileAttributesW" ascii fullword

    // The initialization region contains 11 padded LoadLibraryW and
    // GetProcAddress thunks. Absolute data and function addresses vary.
    $code_api_resolver = {
      68 ?? ?? ?? ?? 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ??
      50 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? C3 CC CC CC
    }

    // extract_resource_to_file at 0x4014D0 maps one resource, gets its
    // size and bytes, then passes them to the file-writing path. Absolute
    // function-pointer addresses and failure-branch targets vary.
    $code_extract_resource = {
      52 0F B7 C1 50 6A 00 FF 15 ?? ?? ?? ??
      8B F8 85 FF 0F 84 ?? ?? ?? ??
      57 6A 00 FF 15 ?? ?? ?? ??
      8B D8 85 DB 0F 84 ?? ?? ?? ??
      57 6A 00 FF 15 ?? ?? ?? ??
      53 8B F8 FF 15 ?? ?? ?? ??
    }

    // main calls the same extraction helper for resource IDs 101 and
    // 103. Stack offsets and relative call targets can change at link time.
    $code_extract_resource_pair = {
      50 8D 55 ?? B9 65 00 00 00 E8 ?? ?? ?? ??
      8D 45 ?? B9 67 00 00 00 50 8D 55 ??
      E8 ?? ?? ?? ?? 83 C4 08
    }

    // main builds the misspelled UTF-16 name "wsc_updata.exe" from
    // immediate values. Stack offsets and short scheduling gaps vary.
    $code_build_drop_name = {
      C7 85 ?? ?? FF FF 77 00 73 00 [0-8]
      C7 85 ?? ?? FF FF 63 00 5F 00 [0-8]
      C7 85 ?? ?? FF FF 75 00 70 00 [0-8]
      C7 85 ?? ?? FF FF 64 00 61 00 [0-8]
      C7 85 ?? ?? FF FF 74 00 61 00 [0-8]
      C7 85 ?? ?? FF FF 2E 00 65 00 [0-8]
      C7 85 ?? ?? FF FF 78 00 65 00
    }

  condition:
    filesize > 100KB and
    filesize < 5MB and
    uint16be(0) == 0x4D5A and
    uint32(uint32(0x3C)) == 0x00004550 and
    uint16(uint32(0x3C) + 0x04) == 0x014C and
    (uint16(uint32(0x3C) + 0x16) & 0x2000) == 0 and
    7 of ($api_*) and
    #code_api_resolver >= 6 and
    $code_extract_resource and
    (
      $code_extract_resource_pair or
      $code_build_drop_name
    )
}
rule apt_exploit_win_alpc_lpe_sep26: CVE_2026_85046
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-03"
    description = "Detects variants of the x64 WNF and ALPC local privilege-escalation DLL."
    hash = "51462a23ac25e1bd0e49b7cae7f3a71f8d2201e22d45175b587e4740b49863cc"
    os = "win"
    os_arch = "x64"
    scan_context = "file"
    severity = "high"
    report2 = "TIB-20260908"
    report1 = "TIB-20260908B"
    last_modified = "2026-09-09T09:44:14Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13420
    version = 4

  strings:
    // The exploit sprays and queries WNF objects. Require most of the
    // low-level API set so minor import changes do not prevent a match.
    $api_wnf_create_name = "NtCreateWnfStateName" ascii fullword
    $api_wnf_delete_data = "NtDeleteWnfStateData" ascii fullword
    $api_wnf_delete_name = "NtDeleteWnfStateName" ascii fullword
    $api_wnf_query_data = "NtQueryWnfStateData" ascii fullword
    $api_wnf_update_data = "NtUpdateWnfStateData" ascii fullword

    // ALPC resource reserves shape the kernel pool and provide the
    // type-confused object used by the read/write primitive.
    $api_alpc_create_port = "NtAlpcCreatePort" ascii fullword
    $api_alpc_create_reserve = "NtAlpcCreateResourceReserve" ascii fullword
    $api_alpc_delete_reserve = "NtAlpcDeleteResourceReserve" ascii fullword
    $api_alpc_disconnect = "NtAlpcDisconnectPort" ascii fullword
    $api_alpc_send_receive = "NtAlpcSendWaitReceivePort" ascii fullword

    // These calls implement the large-SACL trigger and mutant spray.
    $api_trigger_create_directory = "NtCreateDirectoryObjectEx" ascii fullword
    $api_trigger_create_mutant = "NtCreateMutant" ascii fullword
    $api_trigger_set_security = "NtSetSecurityObject" ascii fullword

    // Fake WNF and ALPC object headers retain the pool tags. The first
    // four bytes encode the exploit's selected object-header fields.
    $structure_fake_wnf_header = {
      00 00 11 03 57 6E 66 20 00 00 00 00 00 00 00 00
    }
    $structure_fake_alpc_header = {
      00 00 11 03 41 6C 48 61 00 00 00 00 00 00 00 00
    }
    $structure_mutant_alphabet = "123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" ascii fullword

    // The DACL builder grants access to the Null SID and the All
    // Restricted Application Packages SID for AppContainer execution.
    $sid_null = "S-1-0-0" ascii fullword
    $sid_restricted_packages = "S-1-15-2-2" ascii fullword

    // token_elevate writes and then verifies a read-primitive sentinel.
    // The stack displacement and short branch can change after linking.
    $code_kernel_read_sentinel = {
      48 B8 BE BA FE CA EF BE AD DE
      48 39 44 24 ?? 74 ?? 41 FF C7
    }

    // kernel_rw_primitive_setup validates the corrupted WNF pool tag.
    // Stack offsets and the relative failure branch are not stable.
    $code_validate_wnf_pool_tag = {
      48 8B 85 ?? ?? ?? ?? 48 C1 E8 20
      48 3D 57 6E 66 20 0F 85 ?? ?? ?? ??
    }

    // The same primitive confirms that pool shaping replaced the WNF
    // allocation with the expected ALPC resource-reserve object.
    $code_validate_alpc_pool_tag = {
      48 8B 8D ?? ?? ?? ?? B8 FD FF FF FF
      48 C1 E9 20 48 81 F9 41 6C 48 61 0F 44 C7
    }

    // exploit_core deletes every 24th sprayed WNF object between the
    // fixed spray bounds. RIP-relative displacements and calls vary.
    $code_wnf_hole_punch = {
      BF 87 66 00 00 48 8D 35 ?? ?? ?? ?? 90 48 63 C7
      49 8D 8D ?? ?? ?? ?? 33 D2 48 8D 0C C1
      FF 15 ?? ?? ?? ?? 85 C0 75 ?? C6 06 01
      83 C7 18 48 83 C6 18 81 FF C7 68 00 00 7C ??
    }

  condition:
    filesize > 20KB and
    filesize < 2MB and
    uint16be(0) == 0x4D5A and
    uint32(uint32(0x3C)) == 0x00004550 and
    uint16(uint32(0x3C) + 0x04) == 0x8664 and
    (uint16(uint32(0x3C) + 0x16) & 0x2000) == 0x2000 and
    4 of ($api_wnf_*) and
    3 of ($api_alpc_*) and
    2 of ($api_trigger_*) and
    (
      2 of ($code_*) or
      (all of ($structure_*) and all of ($sid_*))
    )
}
rule apt_malware_win_UTA0560_recon: UTA0560
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-03"
    description = "Detects variants of the x64 UTA0560 host-reconnaissance DLL."
    hash = "b7b0cd6539464ab39c6526e499f86d611faa21c5af945535ebaf187cec543af1"
    os = "win"
    os_arch = "x64"
    scan_context = "file"
    severity = "high"
    report1 = "TIB-20260908"
    last_modified = "2026-09-08T16:02:28Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13419
    version = 3

  strings:
    // The module serializes a detailed CPU and hypervisor profile.
    $cpuid_basic_max = "basic_max" ascii fullword
    $cpuid_leaf_ext_1 = "leaf_ext_1" ascii fullword
    $cpuid_leaf_hv_1 = "leaf_hv_1" ascii fullword
    $cpuid_leaf_hv_2 = "leaf_hv_2" ascii fullword
    $cpuid_leaf_hv_3 = "leaf_hv_3" ascii fullword

    // These keys record OS versions and low-level security state.
    $system_nt_version_usd = "nt_version_usd" ascii fullword
    $system_kernelbase_version = "kernelbase_version" ascii fullword
    $system_kva_shadow = "kva_shadow" ascii fullword
    $system_ci_options = "ci_options" ascii fullword
    $system_idt_addr = "idt_addr" ascii fullword

    // These keys record detailed process-token security properties.
    $token_restricted_sids = "restricted_sids" ascii fullword
    $token_integrity_level = "integrity_level" ascii fullword
    $token_mandatory_policy = "mandatory_policy" ascii fullword
    $token_is_app_container = "is_app_container" ascii fullword
    $token_app_container_number = "app_container_number" ascii fullword
    $token_open_error = "OpenProcessToken_error" ascii fullword

    // This API combination supports the three collection groups above.
    $api_nt_query_system_ex = "NtQuerySystemInformationEx" ascii fullword
    $api_get_file_version_size = "GetFileVersionInfoSizeW" ascii fullword
    $api_ver_query_value = "VerQueryValueW" ascii fullword
    $api_open_process_token = "OpenProcessToken" ascii fullword

  condition:
    filesize < 1MB and
    uint16be(0) == 0x4D5A and
    uint32(uint32(0x3C)) == 0x00004550 and
    uint16(uint32(0x3C) + 0x04) == 0x8664 and
    (uint16(uint32(0x3C) + 0x16) & 0x2000) == 0x2000 and
    3 of ($cpuid_*) and
    3 of ($system_*) and
    4 of ($token_*) and
    2 of ($api_*)
}
rule apt_exploit_js_v8_renderer_bug: CVE_2026_85046
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-03"
    description = "Detects variants of a V8 renderer exploit page used in a Chrome -> Win 0-day exploit campaign."
    hash = "7a52ff23949edee8faa61ce0def6dbca8b7e5943c54d23376cc190762ea3985c"
    os = "win"
    os_arch = "x64"
    scan_context = "file"
    severity = "high"
    report2 = "TIB-20260908"
    report1 = "TIB-20260908B"
    last_modified = "2026-09-09T09:44:10Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13418
    version = 6

  strings:
    // Runtime messages expose the renderer exploit's fake-object and
    // WebAssembly code-space read/write stages without using build IDs.
    $exploit_tier_up = "primitive tier-up failed" ascii
    $exploit_fake_object = "fakeobj/pivot failed" ascii
    $exploit_calibration = "calibration: no confusion" ascii
    $exploit_jump_table = "codeK verification failed: not a jump table" ascii
    $exploit_fixed_array = "entries not a FixedArray" ascii

    // This combination implements the WebAssembly exception/table type
    // confusion. Individual terms also occur in benign V8 test code.
    $wasm_try_table = "kExprTryTable" ascii
    $wasm_catch_no_ref = "kCatchNoRef" ascii
    $wasm_js_tag = "WebAssembly.JSTag" ascii
    $wasm_exception = "WebAssembly.Exception" ascii
    $wasm_instance_layout = "memory_bases_and_sizes" ascii

    // These identifiers implement the embedded native-payload decoder,
    // runtime patching, and staging into WebAssembly donor code.
    $payload_container = "PAYLOADS_B64" ascii
    $payload_patcher = "applyRuntimePayloadPatches" ascii
    $payload_stage = "payload: staging " ascii
    $payload_command = "fillPpCmdline" ascii
    $payload_donor = "DONOR_ITERS" ascii

    // The page runs its inert embedded bundle in a generated worker.
    $wrapper_bundle = "id=\"bundle-src\"" ascii
    $wrapper_worker = "id=\"worker-glue-src\"" ascii
    $wrapper_profile = "CVE_EXP_NO_D8_DRIVER" ascii

  condition:
    filesize < 5MB and
    3 of ($exploit_*) and
    3 of ($wasm_*) and
    3 of ($payload_*) and
    1 of ($wrapper_*)
}

rule apt_malware_js_vm_loader_bug_sep26: CVE_2026_85046
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-03"
    description = "Detects the VM-obfuscated JavaScript loader used in a Chrome -> Win 0-day exploit campaign."
    hash1 = "337b48c1cd6dd6e7b8073327082a60e149517fa084ba17b180e041fffa3b130d"
    os = "win"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report2 = "TIB-20260908"
    report1 = "TIB-20260908B"
    last_modified = "2026-09-09T09:44:12Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13417
    version = 4

  strings:
    // The six-character suffixes change between builds.
    $vm_identifier_runtime = /vmT_[0-9a-f]{6}/ ascii
    $vm_identifier_entry = /vmN_[0-9a-f]{6}/ ascii
    $vm_internal_property = /_\$[A-Za-z0-9]{6}/ ascii

    // This resolver is at the start of the generated VM runtime.
    $vm_global_resolver = "typeof globalThis!=='undefined'?globalThis:typeof window!=='undefined'?window:typeof global!=='undefined'?global:typeof self!=='undefined'?self:void 0x0" ascii

    // These constants implement string masking, record loading, slot
    // scrambling, and bytecode layout selection.
    $magic_string_mask = "0x9e3779b1" ascii nocase
    $magic_flags_xor = "0x9459cffb" ascii nocase
    $magic_slot_1 = "0xdbca3d28" ascii nocase
    $magic_slot_2 = "0x4de7321d" ascii nocase
    $magic_slot_3 = "0x7990561b" ascii nocase
    $magic_layout = "0xe4ed" ascii nocase

    // These errors expose unused parts of the general-purpose VM runtime.
    $runtime_error_1 = "Unexpected\\x20yield\\x20in\\x20async\\x20context" ascii
    $runtime_error_2 = "Unexpected\\x20signal\\x20in\\x20generator" ascii
    $runtime_error_3 = "Unexpected\\x20signal\\x20in\\x20async\\x20generator" ascii
    $runtime_error_4 = "Iterator\\x20result\\x20is\\x20not\\x20an\\x20object" ascii

    // The loader mirrors these values into the VM closure environment.
    $config_url = "CONFIG_URL" ascii
    $config_daily_limit = "CONFIG_DAILY_LIMIT" ascii

  condition:
    $vm_global_resolver and
    all of ($vm_identifier_*) and
    #vm_internal_property > 20 and
    5 of ($magic_*) and
    2 of ($runtime_error_*) and
    all of ($config_*)
}