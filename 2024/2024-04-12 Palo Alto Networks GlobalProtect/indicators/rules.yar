rule apt_malware_py_upstyle : UTA0218
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-11"
        description = "Detect the UPSTYLE webshell."
        hash1 = "3de2a4392b8715bad070b2ae12243f166ead37830f7c6d24e778985927f9caac"
        hash2 = "0d59d7bddac6c22230187ef6cf7fa22bca93759edc6f9127c41dc28a2cea19d8"
        hash3 = "4dd4bd027f060f325bf6a90d01bfcf4e7751a3775ad0246beacc6eb2bad5ec6f"
        os = "linux"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file,memory"
        last_modified = "2024-04-12T13:05Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10429
        version = 2

    strings:
        $stage1_str1 = "/opt/pancfg/mgmt/licenses/PA_VM"
        $stage1_str2 = "exec(base64."

        $stage2_str1 = "signal.signal(signal.SIGTERM,stop)"
        $stage2_str2 = "exec(base64."

        $stage3_str1 = "write(\"/*\"+output+\"*/\")"
        $stage3_str2 = "SHELL_PATTERN"

    condition:
        all of ($stage1*) or
        all of ($stage2*) or
        all of ($stage3*)
}
rule susp_any_gost_arguments
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Looks for common arguments passed to the hacktool GOST that are sometimes used by attackers in scripts (for example cronjobs etc)."
        os = "all"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file"
        last_modified = "2024-04-12T13:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10425
        version = 2

    strings:
        $s1 = "-L=socks5://" ascii
        $s2 = "-L rtcp://" ascii

    condition:
        filesize < 10KB and
        any of them
}
rule susp_any_jarischf_user_path
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Detects paths embedded in samples in released projects written by Ferdinand Jarisch, a pentester in AISEC. These tools are sometimes used by attackers in real world intrusions."
        hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        os = "all"
        os_arch = "all"
        report = "TIB-20240412"
        scan_context = "file,memory"
        last_modified = "2024-04-12T13:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10424
        version = 4

    strings:
        $proj_1 = "/home/jarischf/"

    condition:
        any of ($proj_*)
}
rule hacktool_golang_reversessh_fahrj
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-04-10"
        description = "Detects a reverse SSH utility available on GitHub. Attackers may use this tool or similar tools in post-exploitation activity."
        hash1 = "161fd76c83e557269bee39a57baa2ccbbac679f59d9adff1e1b73b0f4bb277a6"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/Fahrj/reverse-ssh"
        report = "TIB-20240412"
        scan_context = "file,memory"
        last_modified = "2024-04-12T13:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10423
        version = 5

    strings:
        $fun_1 = "createLocalPortForwardingCallback"
        $fun_2 = "createReversePortForwardingCallback"
        $fun_3 = "createPasswordHandler"
        $fun_4 = "createPublicKeyHandler"
        $fun_5 = "createSFTPHandler"
        $fun_6 = "dialHomeAndListen"
        $fun_7 = "createExtraInfoHandler"
        $fun_8 = "createSSHSessionHandler"
        $fun_9 = "createReversePortForwardingCallback"

        $proj_1 = "github.com/Fahrj/reverse-ssh"

    condition:
        any of ($proj_*) or
        4 of ($fun_*)
}
