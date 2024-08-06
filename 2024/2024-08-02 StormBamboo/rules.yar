import "pe"
import "hash"

rule apt_malware_any_reloadext_plugin : StormBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-02-23"
        description = "Detection for RELOADEXT, a Google Chrome extension malware."
        hash1 = "9d0928b3cc21ee5e1f2868f692421165f46b5014a901636c2a2b32a4c500f761"
        os = "all"
        os_arch = "all"
        report = "TIB-20240227"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-08-02T10:30:15.944063Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10282
        version = 4

    strings:
        $man1 = "Reload page with Internet Explorer compatible mode."
        $man2 = "\"http://*/*\""

        $code1 = ";chrome["
        $code2 = "XMLHttpRequest(),_"
        $code3 = "0x400*0x400"

    condition:
        all of ($man*) or
        (
            #code1 > 8 and
            #code2 >= 2 and
            #code3 >= 2
        )
}
rule apt_malware_macos_reloadext_installer : StormBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-02-23"
        description = "Detect the RELOADEXT installer."
        hash1 = "07e3b067dc5e5de377ce4a5eff3ccd4e6a2f1d7a47c23fe06b1ededa7aed1ab3"
        os = "darwin"
        os_arch = "all"
        report = "TIB-20240227"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-08-02T10:29:51.112346Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10281
        version = 2

    strings:
        $str1 = "/CustomPlug1n/"
        $str2 = "Chrome NOT installed."
        $str3 = "-f force kill Chrome"
        $str4 = "/*} &&cp -rf ${"

    condition:
        3 of them
}

rule apt_malware_any_macma_a: StormBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-11-12"
        description = "Detects variants of the MACMA backdoor, variants of MACMA have been discovered for Windows, macOS and android."
        hash1 = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"
        hash2 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
        hash3 = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
        hash4 = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
        os = "all"
        os_arch = "all"
        reference = "https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/"
        report1 = "TIB-20231221"
        report2 = "TIB-20240227"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-08-02T10:29:06.363756Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6114
        version = 8

    strings:
        $magic1 = "curl -o %s http://cgi1.apnic.net/cgi-bin/my-ip.php" fullword ascii
        $magic2 = "[FST%d]: WhyUserCancel UNKNOW: %d" fullword ascii
        $magic3 = "[FST%d]: wait C2 prepare ready TIMEOUT, fd: %d" fullword ascii
        $magic4 = "[FST%d]: wait C2 ack file content TIMEOUT, fd: %d" fullword ascii
        $magic5 = "[FST%d]: TIMER_CHECK_CANCEL WhyUserCancel UNKNOW: %d" fullword ascii
        $magic6 = "[FST%d]: encrypt file info key=%s, crc v1=0x%p, v2=0x%p" fullword ascii

        $s1 = "auto bbbbbaaend:%d path %s" fullword ascii
        $s2 = "0keyboardRecirderStopv"fullword ascii
        $s3 = "curl begin..." fullword ascii
        $s4 = "curl over!" fullword ascii
        $s5 = "kAgent fail" fullword ascii
        $s6 = "put !!!!" fullword ascii
        $s7 = "vret!!!!!! %d" fullword ascii
        $s8 = "save Setting Success" fullword ascii
        $s9 = "Start Filesyste Search."  fullword ascii
        $s10 = "./SearchFileTool"  fullword ascii
        $s11 = "put unknow exception in MonitorQueue" fullword ascii
        $s12 = "./netcfg2.ini" fullword ascii
        $s13 = ".killchecker_" fullword ascii
        $s14 = "./param.ini" fullword ascii

    condition:
        any of ($magic*) or
        7 of ($s*)
}
rule apt_malware_macOS_gimmick: StormBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the macOS port of the GIMMICK malware."
        date = "2021-10-18"
        hash1 = "2a9296ac999e78f6c0bee8aca8bfa4d4638aa30d9c8ccc65124b1cbfc9caab5f"
        os = "darwin"
        os_arch = "all"
        report = "TIB-20240227"
        reference = "https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-08-02T10:28:38.849737Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6022
        version = 8

    strings:
        // Also seen in DAZZLESPY // MACMA
        $s1 = "http://cgi1.apnic.net/cgi-bin/my-ip.php --connect-timeout 10 -m 20" wide ascii

        $json1 = "base_json" ascii wide
        $json2 = "down_json" ascii wide
        $json3 = "upload_json" ascii wide
        $json4 = "termin_json" ascii wide
        $json5 = "request_json" ascii wide
        $json6 = "online_json" ascii wide
        $json7 = "work_json" ascii wide

        $msg1 = "bash_pid: %d, FDS_CHILD: %d, FDS_PARENT: %d" ascii wide
        $msg2 = "pid %d is dead" ascii wide
        $msg3 = "exit with code %d" ascii wide
        $msg4 = "recv signal %d" ascii wide

        $cmd1 = "ReadCmdQueue" ascii wide
        $cmd2 = "read_cmd_server_timer" ascii wide
        $cmd3 = "enableProxys" ascii wide
        $cmd4 = "result_block" ascii wide
        $cmd5 = "createDirLock" ascii wide
        $cmd6 = "proxyLock" ascii wide
        $cmd7 = "createDirTmpItem" ascii wide
        $cmd8 = "dowfileLock" ascii wide
        $cmd9 = "downFileTmpItem" ascii wide
        $cmd10 = "filePathTmpItem" ascii wide
        $cmd11 = "uploadItems" ascii wide
        $cmd12 = "downItems" ascii wide
        $cmd13 = "failUploadItems" ascii wide
        $cmd14 = "failDownItems" ascii wide
        $cmd15 = "downloadCmds" ascii wide
        $cmd16 = "uploadFiles" ascii wide
        $cmd17 = "bash callback...." ascii wide

    condition:
        $s1 or
        5 of ($json*) or
        3 of ($msg*) or
        9 of ($cmd*)
}

rule apt_malware_win_dustpan_apihashes: StormBamboo
{
    
    meta:
        author = "threatintel@volexity.com"
        date = "2023-08-17"
        // NOTE, that the Volexity name 'DUSTPAN' refers to a different malware family to the 
        // Mandiant malware of the same name.
        description = "Detects DUSTPAN malware using API hashes used to resolve functions at runtime."
        hash1 = "b77bcfb036f5a6a3973fdd68f40c0bd0b19af1246688ca4b1f9db02f2055ef9d"
        os = "win"
        os_arch = "all"
        report1 = "MAR-20230818"
        report2 = "TIB-20231221"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-08-02T10:46:54.205126Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9591
        version = 3

    strings:
        $h1 = {9c 5b 9f 0b}
        $h2 = {4c 8f 3e 08}
        $h3 = {b4 aa f2 06}
        $h4 = {dc cb ca 09}
        $h5 = {d4 33 07 0e}
        $h6 = {27 89 d6 0a}
        $h7 = {b5 7d ae 09}
        $h8 = {4e 64 eb 0b}
        $h9 = {be 17 d9 08}

        $magic = "SMHM"

    condition:
        6 of ($h*) and
        $magic
}

rule apt_malware_win_pocostick_jul23: StormBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-07-24"
        description = "Detects the July 2023 POCOSTICK variant. These strings are only visible in memory after several rounds of shellcode decryption."
        hash1 = "ec3e787c369ac4b28447e7cacc44d70a595e39d47f842bacb07d19b12cab6aad"
        os = "win"
        os_arch = "all"
        report = "TIB-20231221"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-08-02T10:45:28.197138Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9542
        version = 3

    strings:
        $str1 = "Folder PATH listing form volume" wide
        $str2 = "Volume serial number is 0000-1111" wide
        $str3 = "Type:Error" wide
        $str4 = "Type:Desktop" wide
        $str5 = "Type:Laptop" wide
        $str6 = "Type:Vitual" wide
        $str7 = ".unicode.tmp" wide
        $str8 = "EveryOne" wide

    condition:
        6 of them
}

rule apt_malware_py_dustpan_pyloader: StormBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-07-21"
        // NOTE, that the Volexity name 'DUSTPAN' refers to a different malware family to the 
        // Mandiant malware of the same name.
        description = "Detects Python script used by KPlayer to update, modified by attackers to download a malicious payload."
        os = "all"
        os_arch = "all"
        report = "TIB-20231221"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-08-02T10:43:21.783375Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9530
        version = 4

    strings:
        $s_1 = "def count_md5(src)"
        $s_2 = "urllib.request.urlretrieve(image_url,main)"
        $s_3 = "m1 != '4c8a326899272d2fe30e818181f6f67f'"
        $s_4 = "os.path.split(os.path.realpath(__file__))[0]"
        $s_5 = "r_v = os.system('curl '+ini_url+cc)"
        $s_6 = "b41ef5f591226a0d5adce99cb2e629d8"
        $s_7 = "1df495e7c85e59ad0de1b9e50912f8d0"
        $s_8 = "tasklist | findstr mediainfo.exe"

        $url_1 = "http://dl1.5kplayer.com/youtube/youtube_dl.png"
        $url_2 = "http://dl1.5kplayer.com/youtube/youtube.ini?fire="

        $path_1 = "C:\\\\ProgramData\\\\Digiarty\\\\mediainfo.exe"
    condition:
        3 of ($s_*) or
        any of ($url_*) or
        $path_1
}

rule apt_malware_win_pocostick_b: StormBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-07-08"
        description = "Detects the POCOSTICK family, variant B."
        hash = "1e81fb62cb57a3231642f66fee3e10d28a7c81637e4d6a03515f5b95654da585"
        os = "win"
        os_arch = "all"
        report = "TIB-20231221"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-08-02T10:36:51.060620Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 1678
        version = 6

    strings:
        $a1 = "AVCAesUtil@@" ascii
        $a2 = "AVencrypt_base@@" ascii
        $a3 = "AVCCmdTarget@@" ascii
        $a4 = "AVCWinThread@@" ascii

    condition:
        all of ($a*) or
        for any resource in pe.resources:
            // icon
            (
                hash.sha256(resource.offset, resource.length) == "b098afd3657b956edbace77499e5e20414ab595a17ffc437b9dadc791eff1cfa" or
                hash.sha256(resource.offset, resource.length) == "2e53e960d45d657d8ba9929f6c8b34e90b2ae15b879768099474678dd1864f3b"
            )
}
rule apt_malware_elf_catchdns_aug20_memory: DriftingBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-08-20"
        description = "Looks for strings from CatchDNS component used to intercept and modify DNS responses, and likely also intercept/monitor http. This rule would only match against memory in the example file analyzed by Volexity."
        hash = "4f3d35f4f8b810362cbd4c59bfe5a961e559fe5713c9478294ccb3af2d306515"
        os = "linux"
        os_arch = "all"
        report1 = "MAR-20221222"
        report2 = "TIB-20231221"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-08-02T10:40:24.805247Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 227
        version = 10

    strings:
        $os1 = "current thread policy=%d" ascii wide
        $os2 = "OS_CreatShareMem %s-->%x" ascii wide
        $os3 = "sem_open fail" ascii wide
        $os4 = "int OS_GetCurRunPath(char*, int)" ascii wide
        $os5 = "int OS_GetCurModName(char*, int)" ascii wide
        $os6 = "int OS_StrToTime(char*, time_t*)" ascii wide
        $os7 = "int OS_TimeToStr(time_t, char*)" ascii wide
        $os8 = "int OS_TimeToStrYearMothDay(time_t, char*)" ascii wide
        $os9 = "bool OS_Access(const char*)" ascii wide
        $os10 = "int OS_Memicmp(const void*, const void*, unsigned int)" ascii wide
        $os11 = "int OS_Mkdir(char*)" ascii wide
        $os12 = "OS_ConnectSem" ascii wide

        $msg1 = "client: last send packet iseq: %x, the ack :%x" ascii wide
        $msg2 = "server: last send packet iseq: %x, the iseq :%x" ascii wide
        $msg3 = "send packet failed!" ascii wide
        $msg4 = "will hijack dns:%s, ip:%s " ascii wide
        $msg5 = "dns send ok:%s" ascii wide
        $msg6 = "tcp send ok" ascii wide
        $msg7 = "FilePath:%s;" ascii wide
        $msg8 = "Line:%d,Fun:%s,ErrorCode:%u;" ascii wide
        $msg9 = "Description:%s;" ascii wide
        $msg10 = "Line:%d,Fun:%s,ErrorCode:%u;" ascii wide
        $msg11 = "get msg from ini is error" ascii wide
        $msg12 = "on build eth send_msg or payload is null" ascii wide
        $msg13 = "on build udp send_msg or payload is null" ascii wide

        $conf1 = "%d.%d.%d.%d" ascii wide
        $conf2 = "%s.tty" ascii wide
        $conf3 = "dns.ini" ascii wide

        $netw1 = "LISTEN_DEV" ascii wide
        $netw2 = "SEND_DEV" ascii wide
        $netw3 = "SERVER_IP" ascii wide
        $netw4 = "DNSDomain" ascii wide
        $netw5 = "IpLimit" ascii wide
        $netw6 = "HttpConfig" ascii wide
        $netw7 = "buildhead" ascii wide
        $netw8 = "sendlimit" ascii wide
        $netw9 = "content-type" ascii wide
        $netw10 = "otherhead_" ascii wide
        $netw11 = "configfile" ascii wide

        $apache = {48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D 0A 53 65 72 76 65 72 3A 20 41 70 61 63 68 65 0D 0A 43 6F 6E 6E 65 63 74 69 6F 6E 3A 20 63 6C 6F 73 65 0D 0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 25 73 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 25 64 0D 0A}

        $cpp1 = "src/os.cpp"
        $cpp2 = "src/test_catch_dns.cpp"

    condition:
        9 of ($os*) or
        3 of ($msg*) or
        all of ($conf*) or
        all of ($netw*) or
        $apache or
        all of ($cpp*)
}