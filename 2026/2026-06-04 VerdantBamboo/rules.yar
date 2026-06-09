rule apt_malware_any_dotnet_aot_plenet: VerdantBamboo PLENET
{
    meta:
        author = "threatintel@volexity.com"
        date = "2025-09-22"
        description = "Detect PLENET, a multiplatform malware compile with native AOT."
        hash1 = "eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e"
        os = "all"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        report1 = "TIB-20251104"
        last_modified = "2025-10-30T17:13:27Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 12367
        version = 4

    strings:
        $str1 = "[!] Bad dat" wide
        $str2 = "[!] Connection error. Kill Pty" wide
        $str3 = "[!] Error : Plexor is nul" wide
        $str4 = "[!] Unkown message type" wide
        $str5 = "[*] Disposing.." wide
        $str6 = "Lack port ':" wide
        $str7 = "IPv6 port error ':" wide
        $str8 = "this.existingPipeGiven." wide
        $str9 = "port must within 0~6553" wide

    condition:
        4 of them
}
rule apt_malware_elf_VerdantBamboo_paths: VerdantBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2025-09-22"
        description = "Detection for VerdantBamboo related malware based on paths from local machines observed in binaries."
        hash1 = "eb141a43958802727a6c813452450c10b92704bea4474ee5fd87c0a1be326e2e"
        os = "linux"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        report1 = "TIB-20251104"
        last_modified = "2026-01-27T15:36:32Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 12361
        version = 3

    strings:
        $s1 = "bin/Release/net8.0/linux-x64/native/server" ascii

    condition:
        $s1
}

rule apt_malware_golang_brickstorm_b: VerdantBamboo BRICKSTORM
{
  meta:
    author = "threatintel@volexity.com"
    date = "2025-09-05"
    description = "Detection for the BRICKSTORM malware family."
    hash1 = "aa688682d44f0c6b0ed7f30b981a609100107f2d414a3a6e5808671b112d1878"
    os = "all"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20251104"
    last_modified = "2026-06-09T16:12:33Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 12299
    version = 6

  strings:
    $method1 = "UnPackHeaderData"
    $method2 = "handleRelay"
    $method3 = "NewWebSocketClient"
    $method4 = "createDnsMessage"
    $method5 = "GetFileOwnerInfo"

    $err1 = "dns rcode: %v"
    $err2 = "readFull error"
    $err3 = "tagAuth error"
    $err4 = "error: Auth: %s"

    $ws1 = "<a style='text-decoration: none;'  href='javascript:history.go(-1);'><h5>Back</h5></a>"
    $ws2 = "Mon, 02 Jan 2006 15:04:05 GMT"

    $doh = "https://1.0.0.1/dns-queryhttps://1.1.1.1/dns-queryhttps://8.8.4.4/dns-queryhttps://8.8.8.8/dns-query"

  condition:
    4 of ($method*) or
    3 of ($err*) or
    all of ($ws*) or
    (
      $doh and
      3 of ($method*, $err*, $ws*, $doh)
    )
}

rule apt_malware_golang_brickstorm: VerdantBamboo BRICKSTORM
{
    meta:
        author = "threatintel@volexity.com"
        date = "2025-09-04"
        description = "Detects the BRICKSTORM backdoor using common strings."
        hash1 = "40d264cf9c73923932c3dfd52d20f46ff602be3fea8dc6ecc71aca46e6067bf5"
        hash2 = "e981fc4eaaa6417e6034e21438e55c0360773674a6fc0b63c1b95026449e5254"
        os = "all"
        os_arch = "all"
        reference = "https://blog.nviso.eu/wp-content/uploads/2025/04/NVISO-BRICKSTORM-Report.pdf"
        scan_context = "file,memory"
        severity = "critical"
        report1 = "TIB-20251104"
        last_modified = "2025-10-30T17:14:18Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 12298
        version = 7

    strings:
        $dns1 = "https://1.1.1.1/dns-query" ascii
        $dns2 = "https://8.8.4.4/dns-query" ascii
        $dns3 = "https://8.8.8.8/dns-query" ascii

        $pack1 = "wsshell/core" ascii
        $pack2 = "wssoft/core" ascii

        $s1 = "github.com/hashicorp/yamux" ascii
        $s2 = "winbindd:" ascii
        $s3 = "WEE1=true" ascii
        $s4 = "WEE2=true" ascii

    condition:
        all of ($dns*) and
        all of ($s*) and
        any of ($pack*)
}
rule apt_malware_py_agentpsd: VerdantBamboo AGENTPSD
{
    meta:
        author = "threatintel@volexity.com"
        date = "2025-09-05"
        description = "Detection for AgentPSD, a python-based malware typically delivered within PyInstaller-built binaries."
        hash1 = "ee41e06ed96182ce80cd4544a6abd5d7719c4a5c0e5ddb266a83842d39b99b0a"
        os = "all"
        os_arch = "all"
        scan_context = "memory"
        severity = "critical"
        report1 = "TIB-20251104"
        last_modified = "2025-10-30T17:14:31Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 12297
        version = 5

    strings:
        $s1 = "g_strPhpUrl" ascii
        $s2 = "g_nSleepMinits" ascii
        $s3 = "g_nDuringTime" ascii

        $func1 = "startwork" ascii
        $func2 = "ifrunning" ascii
        $func3 = "getsysinfo" ascii
        $func4 = "getcmdfromweb" ascii
        $func5 = "ParseCmdFromResponse" ascii
        $func6 = "PostDataToServer" ascii
        $func7 = "DealWithBuildinCommand" ascii
        $func8 = "PostBuildinResultToWeb" ascii

    condition:
        2 of ($s*) or
        4 of ($func*)
}

rule apt_malware_any_brickstorm_rust: VerdantBamboo BRICKSTORM
{
    meta:
        author = "threatintel@volexity.com"
        date = "2026-02-24"
        description = "Detects Rust variants of the BRICKSTORM malware."
        hash1 = "45313a6745803a7f57ff35f5397fdf117eaec008a76417e6e2ac8a6280f7d830"
        os = "linux"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        report1 = "MAR-20260224"
        last_modified = "2026-02-24T15:29:52Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 12816
        version = 2

    strings:
        $package1 = "Yamux"
        $package2 = "/lib.rs"

        $str1 = "/opt/vmware/bin/vmisupport"
        $str2 = "Socks5CmdNotSupported"
        $str3 = "/dev/ptmx"
        $str4 = "8tr9y8e4df1h6515fthderth"

    condition:
        all of ($package*) and
        3 of ($str*)
}