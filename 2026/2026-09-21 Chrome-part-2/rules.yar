rule apt_malware_win_CLEANGULP_memoryonly: CLEANGULP
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-09-16"
    description = "CLEANGULP: Detects decoded runtime strings associated with command-and-control, tasking, and persistence."
    os = "win"
    os_arch = "all"
    scan_context = "memory"
    severity = "high"
    last_modified = "2026-09-16T18:46:05Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13450
    version = 1

  strings:
    $protocol_pre_register = "%s/beacon/pre-register" ascii
    $protocol_register = "%s/beacon/register" ascii
    $protocol_registration = "{\"uuid\":\"%s\",\"username\":\"%s\",\"computer\":\"%s\",\"internal_ip\":\"%s\",\"process\":\"%s\",\"pid\":%d,\"arch\":\"%s\",\"is_admin\":%s}" ascii
    $protocol_file_transfer = "{\"task_id\":\"%s\",\"filename\":\"%s\",\"data\":\"%s\",\"size\":%ld,\"chunk\":%d,\"total_chunks\":%d,\"file_transfer\":true}" ascii

    $capability_help = "Available: shell, ps, ls, upload, download, sleep, exit, help, bof" ascii
    $capability_upload = "[-] Usage: upload <server_filename>:<target_path>" ascii
    $capability_bof = "[-] Usage: bof <encoded_bof>:<encoded_args>" ascii

  condition:
    2 of ($protocol*) or
    2 of ($capability*)
}