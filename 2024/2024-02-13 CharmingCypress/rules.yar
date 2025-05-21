import "pe"
import "hash"
import "math"

rule apt_malware_ps1_korku_loader: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-01-04"
        description = "Detection for a simple PowerShell loader used by CharmingCypress."
        hash1 = "fdc5d6caaaa4fb14e62bd42544e8bb8e9b02220e687d5936a6838a7115334c51"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        report = "TIB-20240111"
        last_modified = "2025-02-18T17:16:00Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10042
        version = 5

    strings:
        $korku = "$KorkuItems" wide ascii

        $s1 = "/\" + $Env:UserName" wide ascii
        $s2 = "Start-Sleep -Seconds 5" wide ascii
        $s3 = "while($true)" wide ascii
        $s4 = " = (^);" wide ascii

    condition:
        filesize < 15KB and
        (
            $korku or
            all of ($s*)
        )
}
rule apt_delivery_lnk_charmingcypress_dec23: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-01-04"
        description = "Detects an LNK format used by CharmingCypress in attacks in December 2023."
        hash1 = "f6f0f682668f78dbecfc30a0e0c76b6a3d86298869fb44b39adf19fdcdca5762"
        os = "win"
        os_arch = "all"

        scan_context = "file"
        severity = "critical"
        last_modified = "2024-01-11T15:28:54Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10040
        version = 3
        report = "TIB-20240111"
    strings:
        $s1 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe"  wide
        $s2 = "..\\..\\..\\..\\Windows\\System32\\cmd.exe" wide
        $s3 = "/c set" wide

        $desktop = "desktop-b24ekvp" ascii

    condition:
        uint32be(0) == 0x4C000000 and
        (
            all of ($s*) or
            $desktop
        )
}
rule apt_malware_vbs_basicstar_a: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-01-04"
        description = "VBS backdoor which bares architectural similarity to the POWERSTAR malware family."
        hash1 = "c6f91e5585c2cbbb8d06b7f239e30b271f04393df4fb81815f6556fa4c793bb0"
        os = "win"
        os_arch = "all"
        report = "TIB-20240111"
        report2 = "TIB-20240126"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2025-05-21T14:53:37Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10037
        version = 8

    strings:
        $s1 = "Base64Encode(EncSess)" ascii wide
        $s2 = "StrReverse(PlainSess)" ascii wide
        $s3 = "ComDecode, \"Module\"" ascii wide
        $s4 = "ComDecode, \"SetNewConfig\"" ascii wide
        $s5 = "ComDecode, \"kill\"" ascii wide

        $magic = "cmd /C start /MIN curl --ssl-no-revoke -s -d " ascii wide

    condition:
        3 of ($s*) or
        $magic
}
rule apt_malware_ps1_powerless_b: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-10-25"
        description = "Detects POWERLESS malware."
        hash1 = "62de7abb39cf4c47ff120c7d765749696a03f4fa4e3e84c08712bb0484306ae1"
        os = "win"
        os_arch = "all"
        reference = "https://research.checkpoint.com/2023/educated-manticore-iran-aligned-threat-actor-targeting-israel-via-improved-arsenal-of-tools/"
        report = "TIB-20231027"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-29T13:02:52Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9794
        version = 5

    strings:
        $fun_1 = "function verifyClickStorke"
        $fun_2 = "function ConvertTo-SHA256"
        $fun_3 = "function Convert-Tobase" fullword
        $fun_4 = "function Convert-Frombase" fullword
        $fun_5 = "function Send-Httppacket"
        $fun_6 = "function Generat-FetchCommand"
        $fun_7 = "function Create-Fetchkey"
        $fun_8 = "function Run-Uploader"
        $fun_9 = "function Run-Shot" fullword
        $fun_10 = "function ShotThis("
        $fun_11 = "function File-Manager"
        $fun_12 = "function zip-files"
        $fun_13 = "function Run-Stealer"
        $fun_14 = "function Run-Downloader"
        $fun_15 = "function Run-Stro" fullword
        $fun_16 = "function Run-Tele" fullword
        $fun_17 = "function Run-Voice"

        $s_1 = "if($commandtype -eq \"klg\")"
        $s_2 = "$desrilizedrecievedcommand"
        $s_3 = "$getAsyncKeyProto = @"
        $s_4 = "$Global:BotId ="
        $s_5 = "$targetCLSID = (Get-ScheduledTask | Where-Object TaskName -eq"
        $s_6 = "$burl = \"$Global:HostAddress/"
        $s_7 = "$hashString = [System.BitConverter]::ToString($hash).Replace('-','').ToLower()"
        $s_8 = "$Global:UID = ((gwmi win32_computersystemproduct).uuid -replace '[^0-9a-z]').substring("
        $s_9 = "$rawpacket = \"{`\"MId`\":`\"$Global:MachineID`\",`\"BotId`\":`\"$basebotid`\"}\""
        $s_12 = "Runned Without any Error"
        $s_13 = "$commandresponse = (Invoke-Expression $instruction -ErrorAction Stop) | Out-String"
        $s_14 = "Operation started successfuly"
        $s_15 = "$t_path = (Get-WmiObject Win32_Process -Filter \"name = '$process'\" | Select-Object CommandLine).CommandLine"
        $s_16 = "?{ $_.DisplayName -match \"Telegram Desktop\" } | %{$app_path += $_.InstallLocation }"
        $s_17 = "$chlids = get-ChildItem $t -Recurse -Exclude \"$t\\tdata\\user_data\""
        $s_18 = "if($FirsttimeFlag -eq $True)"
        $s_19 = "Update-Conf -interval $inter -url $url -next_url $next -conf_path $conf_path -key $config_key"
    condition:
        3 of ($fun_*) or
        any of ($s_*)
}
rule apt_malware_noknok_base64_encoded_bash : CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-10-25"
        description = "Detects base64 script execution technique used by CharmingCypress to decode and execute NOKNOK."
        hash1 = "42477f0236e648f6e981db279406ca5f2a37a26cdf2baf472c41cb7f85f046e8"
        hash2 = "a437876ae60ddeb8a59f88b7a5af82ca95cb16446a3f6aea8b811402da31cd8a"
        hash3 = "ec14d1d4a30a9e11bb7360f46d3154fc4117b5b161a2a87afa8d0a730d017b69"
        hash4 = "dab8a955a8bc3c3fb2643fcde9b184073b104840db8842cf10f755c9e46e0633"
        os = "darwin,linux"
        os_arch = "all"
        report = "TIB-20231027"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-09-30T16:40:53Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9792
        version = 4

    strings:
        $start = "bash -c bash -c \"$(base64 -d <<< \"" nocase
        $end = /"\)"; bash "\$@"$/

    condition:
        filesize < 100KB and
        for any i in (0..math.min(#start, 32)):
            (
                $end in (@start[i]..@start[i]+10240)
            )
}
rule apt_malware_macos_noknok_stage_1: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-10-25"
        description = "Detects first script used to fetch NOKNOK payload from a server and execute it."
        hash1 = "1690cff04de44a26440d4fd15d0a0c11f64d3db670607ef658938690436b6636"
        os = "darwin,linux"
        os_arch = "all"
        reference = "https://www.proofpoint.com/us/blog/threat-insight/welcome-new-york-exploring-ta453s-foray-lnks-and-mac-malware"
        scan_context = "file"
        severity = "critical"
        last_modified = "2023-10-27T14:26:50Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9791
        version = 3

    strings:
        $s_1 = "/bin/bash -c while sleep 0;do { url=$(curl http"
        $s_2 = "-d \"Id="
        $s_3 = "-k $url/DMPR);"
        $s_4 = "\"$resp\" == *\"base64 -d\"* || \"$resp\" == *\"Session\"*"

        $url_pattern = "/diablo/dom.txt"

    condition:
        filesize < 100KB and
        (
            2 of ($s_*) or
            $url_pattern
        )
}
rule apt_malware_win_powerless_persistence_exe: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-10-20"
        description = "Detects binary downloaded from host by PowerLess and written as a persistence mechanism."
        hash1 = "37bb42720bfc1cf5d0e9d7b66be134b6431055ed8bdfd384f61ab7ac061d26eb"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2023-10-20T08:45:51Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9779
        version = 2

    strings:
        $s_1 = "Not able to set the registry value ."
        $s_2 = "is set"

    condition:
        filesize < 1MB and
        uint16be(0) == 0x4d5a and
        all of them
}
rule apt_malware_macos_vpnclient_cc_oct23: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-10-17"
        description = "Detection for fake macOS VPN client used by CharmingCypress."
        hash1 = "11f0e38d9cf6e78f32fb2d3376badd47189b5c4456937cf382b8a574dc0d262d"
        os = "darwin,linux"
        os_arch = "all"
        parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
        report = "TIB-20231027"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2023-10-27T16:17:54Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9770
        version = 3

    strings:
        $s1 = "networksetup -setsocksfirewallproxystate wi-fi off" ascii
        $s2 = "networksetup -setsocksfirewallproxy wi-fi ___serverAdd___ ___portNum___; networksetup -setsocksfirewallproxystate wi-fi on" ascii
        $s3 = "New file imported successfully." ascii
        $s4 = "Error in importing the File." ascii

    condition:
        2 of ($s*)
}
rule apt_malware_charmingcypress_openvpn_configuration: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-10-17"
        description = "Detection for a .ovpn file used in a malicious VPN client on victim machines by CharmingCypress."
        hash1 = "d6d043973d8843a82033368c785c362f51395b1a1d475fa4705aff3526e15268"
        parent_hash = "31ca565dcbf77fec474b6dea07101f4dd6e70c1f58398eff65e2decab53a6f33"
        os = "all"
        os_arch = "all"
        report = "TIB-20231027"
        scan_context = "file"
        severity = "high"
        last_modified = "2023-10-27T16:17:48Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9769
        version = 3

    strings:
        $remote = "remote-cert-tls server" ascii
        $ip = "Ip: "
        $tls = "<tls_auth>"

    condition:
        all of them
}
rule apt_delivery_win_charming_openvpn_client: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-10-17"
        description = "Detects a fake OpenVPN client developed by CharmingCypress."
        hash1 = "2d99755d5cd25f857d6d3aa15631b69f570d20f95c6743574f3d3e3e8765f33c"
        os = "win"
        os_arch = "all"
        report = "TIB-20231027"
        scan_context = "file"
        severity = "critical"
        last_modified = "2023-10-27T16:17:32Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9768
        version = 2

    strings:
        $s1 = "DONE!"
        $s2 = "AppCore.dll"
        $s3 = "ultralight@@"

    condition:
        all of ($s*)
}
rule apt_malware_ps1_powerstar_generic: CharmingCypress
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects POWERSTAR modules based on common HTTP functions used across modules."
        date = "2023-06-02"
        os = "win"
        os_arch = "all"
        report = "TIB-20240126"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-26T15:44:55Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9356
        version = 3

    strings:
        $http1 = "Send_Upload" ascii wide
        $http2 = "Send_Post_Data" ascii wide

        $json1 = "{\"OS\":\"" ascii wide
        $json2 = "{\"ComputerName\":\"' + $env:COMPUTERNAME + '\"}" ascii wide
        $json3 = "{\"Token\"" ascii wide
        $json4 = "{\"num\":\"" ascii wide

    condition:
        all of ($http*) or
        all of ($json*)
}
