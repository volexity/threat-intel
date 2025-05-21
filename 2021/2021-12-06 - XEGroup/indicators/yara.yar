import "pe"

rule malware_win_backwash_cpp: WheeledAsh
{
    meta:
        author = "threatintel@volexity.com"
        description = "CPP loader for the Backwash malware."
        date = "2021-11-17"
        hash1 = "0cf93de64aa4dba6cec99aa5989fc9c5049bc46ca5f3cb327b49d62f3646a852"
        os = "win"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2023-11-13T17:16:53Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6147
        version = 2

    strings:
        $s1 = "cor1dbg.dll" wide
        $s2 = "XEReverseShell.exe" wide
        $s3 = "XOJUMAN=" wide

    condition:
        2 of them
}
rule malware_win_iis_shellsave: WheeledAsh
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects an AutoIT backdoor designed to run on IIS servers and to install a webshell."
        date = "2021-11-17"
        hash1 = "21683e02e11c166d0cf616ff9a1a4405598db7f4adfc87b205082ae94f83c742"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2023-08-17T13:50:00Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6146
        version = 4

    strings:
        $s1 = "getdownloadshell" ascii
        $s2 = "deleteisme" ascii
        $s3 = "sitepapplication" ascii
        $s4 = "getapplicationpool" ascii

    condition:
        all of them
}
rule malware_win_backwash_iis_scout: WheeledAsh
{
    meta:
        author = "threatintel@volexity.com"
        description = "Simple backdoor which collects information about the IIS server it is installed on. It appears to the attacker refers to this components as 'XValidate' - i.e. to validate infected machines."
        date = "2021-11-17"
        hash1 = "6f44a9c13459533a1f3e0b0e698820611a18113c851f763797090b8be64fd9d5"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2023-08-17T13:50:27Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6145
        version = 3

    strings:
        $s1 = "SOAPRequest" ascii
        $s2 = "requestServer" ascii
        $s3 = "getFiles" ascii
        $s4 = "APP_POOL_CONFIG" wide
        $s5 = "<virtualDirectory" wide
        $s6 = "stringinstr" ascii
        $s7 = "504f5354" wide
        $s8 = "XValidate" ascii
        $s9 = "XEReverseShell" ascii
        $s10 = "XERsvData" ascii

    condition:
        6 of them
}
rule malware_js_xeskimmer: WheeledAsh
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects JScript code using in skimming credit card details."
        date = "2021-11-17"
        hash1 = "92f9593cfa0a28951cae36755d54de63631377f1b954a4cb0474fa0b6193c537"
        os = "win"
        os_arch = "all"
        reference1 = "https://blog.malwarebytes.com/threat-analysis/2020/07/credit-card-skimmer-targets-asp-net-sites/"
        reference2 = "https://github.com/MBThreatIntel/skimmers/blob/master/null_gif_skimmer.js"
        scan_context = "file"
        severity = "critical"
        last_modified = "2023-11-14T09:49:42Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6144
        version = 4

    strings:
        $s1 = ".match(/^([3456]\\d{14,15})$/g" ascii
        $s2 = "^(p(wd|ass(code|wd|word)))" ascii

        $b1 = "c('686569676874')" ascii
        $b2 = "c('7769647468')" ascii

        $c1 = "('696D67')" ascii
        $c2 = "('737263')" ascii

        $magic = "d=c.charCodeAt(b),a+=d.toString(16);"

    condition:
        all of ($s*) or
        all of ($b*) or
        all of ($c*) or
        $magic
}
rule malware_win_xe_backwash: WheeledAsh
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "The BACKWASH malware family, which acts as a reverse shell on the victim machine."
        hash = "815d262d38a26d5695606d03d5a1a49b9c00915ead1d8a2c04eb47846100e93f"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2023-09-22T13:12:05Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 515
        version = 6

    strings:
        $a1 = "RunServer" ascii
        $a2 = "writeShell" ascii
        $a3 = "GetIP" ascii

        $b1 = "xequit" wide
        $b2 = "setshell" wide

    condition:
        (
            all of ($a*) or
            all of ($b*)
        ) and
        filesize < 40KB
}
rule malware_win_pngexe: WheeledAsh
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "Detects PNGEXE, a simple reverse shell."
        hash = "72f7d4d3b9d2e406fa781176bd93e8deee0fb1598b67587e1928455b66b73911"
        hash2 = "4d913ecb91bf32fd828d2153342f5462ae6b84c1a5f256107efc88747f7ba16c"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-08-16T15:34:12Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 455
        version = 8

    strings:
        $a1 = "amd64.png" ascii
        $a2 = "x86.png" ascii

    condition:
        filesize < 50MB and
        uint16be(0) == 0x4D5A and
        (
            (
                any of ($a*) and
                filesize > 30KB and
                filesize < 200KB
            ) or
          pe.imphash() == "ca41f83b03cf3bb51082dbd72e3ba1ba" or
          pe.imphash() == "e93abc400902e72707edef1f717805f0" or
          pe.imphash() == "83a5d4aa20a8aca2a9aa6fc2a0aa30b0"
         )
}
rule malware_win_backwash_iis: WheeledAsh
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "Variant of the BACKWASH malware family with IIS worm functionality."
        hash = "98e39573a3d355d7fdf3439d9418fdbf4e42c2e03051b5313d5c84f3df485627"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2023-08-17T13:50:43Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 231
        version = 6

    strings:
        $a1 = "GetShell" ascii
        $a2 = "smallShell" ascii
        $a3 = "createSmallShell" ascii
        $a4 = "getSites" ascii
        $a5 = "getFiles " ascii

        $b1 = "action=saveshell&domain=" ascii wide
        $b2 = "&shell=backsession.aspx" ascii wide

    condition:
        all of ($a*) or
        any of ($b*)
}
