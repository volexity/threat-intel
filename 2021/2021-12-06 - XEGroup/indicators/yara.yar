import "pe"

rule trojan_win_backwash_cpp : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "CPP loader for the Backwash malware."
        date = "2021-11-17"
        hash1 = "0cf93de64aa4dba6cec99aa5989fc9c5049bc46ca5f3cb327b49d62f3646a852"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "cor1dbg.dll" wide
        $s2 = "XEReverseShell.exe" wide
        $s3 = "XOJUMAN=" wide
        
    condition:
        2 of them
}

rule trojan_win_iis_shellsave : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects an AutoIT backdoor designed to run on IIS servers and to install a webshell. This rule will only work against memory samples."
        date = "2021-11-17"
        hash1 = "21683e02e11c166d0cf616ff9a1a4405598db7f4adfc87b205082ae94f83c742"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "getdownloadshell" ascii
        $s2 = "deleteisme" ascii 
        $s3 = "sitepapplication" ascii 
        $s4 = "getapplicationpool" ascii

    condition:
        all of them
}

rule trojan_backwash_iis_scout : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Simple backdoor which collects information about the IIS server it is installed on. It appears to the attacker refers to this components as 'XValidate' - i.e. to validate infected machines."
        date = "2021-11-17"
        hash1 = "6f44a9c13459533a1f3e0b0e698820611a18113c851f763797090b8be64fd9d5"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

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

rule web_js_xeskimmer : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects JScript code using in skimming credit card details."
        date = "2021-11-17"
        hash1 = "92f9593cfa0a28951cae36755d54de63631377f1b954a4cb0474fa0b6193c537"
        reference1 = "https://blog.malwarebytes.com/threat-analysis/2020/07/credit-card-skimmer-targets-asp-net-sites/"
        reference2 = "https://github.com/MBThreatIntel/skimmers/blob/master/null_gif_skimmer.js"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

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

rule trojan_win_xe_backwash : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "The BACKWASH malware family, which acts as a reverse shell on the victim machine."
        hash = "815d262d38a26d5695606d03d5a1a49b9c00915ead1d8a2c04eb47846100e93f"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $pdb1 = "x:\\MultiOS_ReverseShell-master\\Multi-OS_ReverseShell\\obj\\Release\\XEReverseShell.pdb"
        $pdb2 = "\\Release\\XEReverseShell.pdb"

        $a1 = "RunServer" ascii
        $a2 = "writeShell" ascii
        $a3 = "GetIP" ascii

        $b1 = "xequit" wide
        $b2 = "setshell" wide

    condition:
        any of ($pdb*) or
        (
            (
                all of ($a*) or 
                all of ($b*)
            ) and     
            filesize < 40KB 
        )
}


rule trojan_win_pngexe : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "Detects PNGEXE, a simple reverse shell loader."
        hash = "72f7d4d3b9d2e406fa781176bd93e8deee0fb1598b67587e1928455b66b73911"
        hash2 = "4d913ecb91bf32fd828d2153342f5462ae6b84c1a5f256107efc88747f7ba16c"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $a1 = "amd64.png" ascii
        $a2 = "x86.png" ascii
        
    condition:
    	uint16(0) == 0x5A4D and 
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

rule trojan_win_backwash_iis : XEGroup
{
    meta:
        author = "threatintel@volexity.com"
        date = "2020-09-04"
        description = "Variant of the BACKWASH malware family with IIS worm functionality."
        hash = "98e39573a3d355d7fdf3439d9418fdbf4e42c2e03051b5313d5c84f3df485627"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

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
