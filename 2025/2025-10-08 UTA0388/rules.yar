rule apt_malware_golang_govershell_strings_beacon_variant: UTA0388
{
    meta:
        author = "threatintel@volexity.com"
        date = "2025-09-20"
        description = "This rule detects strings related to the Beacon inspired variant of the GOVERSHELL malware family employed by UTA0388. The variant was likely developed with LLM assistance and is coded in Golang. The malware is usually delivered in an archive file where it is sideloaded by a legitimate executable."
        hash1 = "126c3d21a1dae94df2b7a7d0b2f0213eeeec3557c21717e02ffaed690c4b1dbd"
        os = "all"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2025-10-08T09:21:04Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 12410
        version = 1

    strings:
        $s1 = "/US-MA-0911/New-Client/te64"
        $s2 = "te64/payload"
        $s3 = "payload.beaconID"
        $s4 = "payload.generateBeaconID"
        $s5 = "payload.StartBeacon"
        $s6 = "/payload.executePowerShell"
        $s7 = "/payload.parseCommandTLV"
        $s8 = "/payload.doRegisterOnce"
        $s9 = ":/Users/Dev/Desktop/US-"

    condition:
        uint16be(0) == 0x4D5A and
        3 of ($s*)
}
rule apt_malware_win_early_govershell_variant: UTA0388
{
    meta:
        author = "threatintel@volexity.com"
        date = "2025-06-30"
        description = "This rule detects an early variant of the GOVERSHELL malware family employed by UTA0388 in H1 2025. The malware family overlaps with the Golang GOVERSHELL implants used by UTA0388 in terms of design and infrastructure, but is not written in Golang. The implants are peDLLs that are side-loaded by a legitimate executable file."
        hash1 = "4ee77f1261bb3ad1d9d7114474a8809929f4a0e7f9672b19048e1b6ac7acb15c"
        hash2 = "9b2cbcf2e0124d79130c4049f7b502246510ab681a3a84224b78613ef322bc79"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2025-10-08T09:21:38Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 11994
        version = 6

    strings:
        $a1 = "cmd.exe /c %s"
        $a2 = "randomDir"
        $a3 = "C:\\ProgramData\\"
        $a4 = "*.dll"
        $a5 = ".\\%s"
        $a6 = "%s\\%s"
        $a7 = "SystemHealthMonitor"
        $a8 = "C:\\ProgramData\\%s"
        $a9 = "mysecretkey"
        $a10 = "destExe"
        $a11 = "selfPath"
        $a12 = "srcPath"
        $a13 = "findData"
        $a14 = "exitCode"
        $a15 = "exePathW"
        $a16 = "cmdSize"
        $a17 = "httpsSize"
        $a18 = "newExePathW"
        $a19 = "currentExePath"

    condition:
        uint16be(0) == 0x4D5A and
        8 of ($a*)
}
rule apt_malware_golang_govershell_strings_UTA0388: UTA0388
{
    meta:
        author = "threatintel@volexity.com"
        date = "2025-06-30"
        description = "This rule detects multiple variants of the GOVERSHELL malware family employed by UTA0388 via unique strings. The implant is side-loaded by a legitimate executable and uses various network protocol to communicate with the C2 server."
        hash1 = "a5ee55a78d420dbba6dec0b87ffd7ad6252628fd4130ed4b1531ede960706d2d"
        hash2 = "fbade9d8a040ed643b68e25e19cba9562d2bd3c51d38693fe4be72e01da39861"
        os = "win"
        os_arch = "all"
        report = "TIB-20250708B"
        report2 = "MAR-20250930"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2025-10-08T09:24:04Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 11993
        version = 10

    strings:
        $a1 = "/lib/te64/"
        $a2 = "te64/payload."
        $a3 = "payload.sendAuthRequest.Println.func1"
        $a4 = "sendAuthRequest.deferwrap"
        $a5 = ".ensureSingleInstance.Printf."
        $a6 = "httpslike.NewHttpsLikeConn"
        $a7 = "main.Execute.Println."
        $a8 = "C:/Users/Dev/Desktop/20250608"
        $a9 = "/lib/te64/httpslike/httpslike.go"
        $a10 = "/lib/te64/payload/payload.go"
        $a11 = "/lib/te64/main.go"
        $a12 = "'rootFolderObj"
        $a13 = "'triggersObj"
        $a14 = "'repetitionObj"
        $a15 = "httpslike"
        $a16 = "main.CopySelf.copyDir."

        $s1 = "C:/Users/Make/Downloads/te250608/lib/te64/payload"
        $s2 = "te64/payload."
        $s3 = "C:/Users/Make/Desktop/lib/"
        $s4 = "CreateUserTask.deferwrap"
        $s5 = "main.generateRandomDir"
        $s6 = "te64.dll"
        $s7 = "payload.NewHttpClient.ProxyURL."
        $s8 = "payload.normalizeProxyURL"

        // All null terminated to avoid FPs
        $b1 = {27 70 72 6f 67 72 61 6d 44 61 74 61 00} //'programData
        $b2 = {27 72 61 6e 64 6f 6d 44 69 72 00} //'randomDir
        $b3 = {27 74 61 72 67 65 74 44 69 72 00} //'targetDir
        $b4 = {27 65 78 65 50 61 74 68 00} //'exePath
        $b5 = {27 63 75 72 72 65 6e 74 44 69 72 00} //'currentDir
        $b6 = {27 65 78 65 4e 61 6d 65 00} //'exeName
        $b7 = {27 74 61 72 67 65 74 45 78 65 00} //'targetExe
        $b8 = {27 72 65 6c 50 61 74 68 00} //'relPath

    condition:
        4 of ($a*)
        or 5 of ($s*)
        or 3 of ($b*)
}