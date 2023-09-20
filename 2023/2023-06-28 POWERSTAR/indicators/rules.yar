rule apt_win_powerstar_persistence_batch : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects the batch script used to persist PowerStar via Startup."
        hash1 = "9777f106ac62829cd3cfdbc156100fe892cfc4038f4c29a076e623dc40a60872"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s_1 = "e^c^h^o o^f^f"
        $s_2 = "powershertxdll.ertxdxe"
        $s_3 = "Get-Conrtxdtent -Prtxdath"
        $s_4 = "%appdata%\\Microsrtxdoft\\Windortxdws\\"
        $s_5 = "&(gcm i*x)$"
    condition:
        3 of them
}
rule apt_win_powerstar_memonly : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects the initial stage of the memory only variant of PowerStar."
        hash1 = "977cf5cc1d0c61b7364edcf397e5c67d910fac628c6c9a41cf9c73b3720ce67f"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s_1 = "[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($in.substring(3)))"
        $s_2 = "[Convert]::ToByte(([Convert]::ToString(-bnot ($text_bytes[$i])"
        $s_3 = "$Exec=[System.Text.Encoding]::UTF8.GetString($text_bytes)"
        $s_4 = "((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})"
        $f_1 = "function Gorjol{"
        $f_2 = "Borjol \"$"
        $f_3 = "Gorjol -text"
        $f_4 = "function Borjoly{"
        $f_6 = "$filename = $env:APPDATA+\"\\Microsoft\\Windows\\DocumentPreview.pdf\";"
        $f_7 = "$env:APPDATA+\"\\Microsoft\\Windows\\npv.txt\""
        $f_8 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\brt8ts74e.bat"
        $f_9 = "\\Microsoft\\Windows\\s7qe52.txt"
        $f_10 = "$yeolsoe2 = $yeolsoe"
        $f_11 = "setRequestHeader(\"Content-DPR\""
        $f_12 = "getResponseHeader(\"Content-DPR\")"
        $f_13 = {24 43 6f 6d 6d 61 6e 64 50 61 72 74 73 20 3d 24 53 65 73 73 69 6f 6e 52 65 73 70 6f 6e 73 65 2e 53 70 6c 69 74 28 22 b6 22 29}
        $f_14 = "$language -like \"*shar*\""
        $f_15 = "$language -like \"*owers*\""
        $alias_1 = "(gcm *v????E?P?e*)"
        $alias_2 = "&(gcm *ke-e*) $Command"
        $key = "T2r0y1M1e1n1o0w1"
        $args_1 = "$sem.Close()"
        $args_2 = "$cem.Close()"
        $args_3 = "$mem.Close()"
        $command_1 = "_____numone_____"
        $command_2 = "_____mac2_____"
        $command_3 = "_____yeolsoe_____"
    condition:
        2 of ($s_*) or
        any of ($f_*) or
        2 of ($alias_*) or
        $key or
        all of ($args_*) or
        any of ($command_*)
}
rule apt_win_powerstar_logmessage : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects interesting log message embedded in memory only version of PowerStar."
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s_1 = "wau, ije ulineun mueos-eul halkkayo?"
    condition:
        all of them
}
rule apt_win_powerstar_lnk : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects LNK command line used to install PowerStar."
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $p_1 = "-UseBasicParsing).Content; &(gcm i*x)$"

        $c_1 = "powershecde43ell.ecde43exe"
        $c_2 = "wgcde43eet -Ucde43eri"
        $c_3 = "-UseBasicde43ecParsing).Contcde43eent; &(gcm i*x)$"
    condition:
        any of them
}
rule apt_win_powerstar_decrypt_function : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-05-16"
        description = "Detects PowerStar decrypt function, potentially downloaded standalone and then injected."
        hash1 = "b79d28fe5e3c988bb5aadb12ce442d53291dbb9ede0c7d9d64eec078beba5585"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $f_1 = "function Borjol{"

        $s_1 = "$global:Domain = \""
        $s_2 = "$global:IP = \""
        $s_3 = "$global:yeolsoe"
        $s_4 = "$semii.Close()"
        $s_5 = "$cemii.Close()"
        $s_6 = "$memii.Close()"
    condition:
        any of ($f_*) or
        2 of ($s_*)

}
rule apt_win_powerstar : CharmingKitten
{
    meta:
        author = "threatintel@volexity.com"
        description = "Custom PowerShell backdoor used by Charming Kitten."
        date = "2021-10-13"
        hash1 = "de99c4fa14d99af791826a170b57a70b8265fee61c6b6278d3fe0aad98e85460"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $appname = "[AppProject.Program]::Main()" ascii wide // caller for C# code

        $langfilters1 = "*shar*" ascii wide
        $langfilters2 = "*owers*" ascii wide

        $definitions1 = "[string]$language" ascii wide
        $definitions2 = "[string]$Command" ascii wide
        $definitions3 = "[string]$ThreadName" ascii wide
        $definitions4 = "[string]$StartStop" ascii wide

        $sess = "$session = $v + \";;\" + $env:COMPUTERNAME + $mac;" ascii wide

    condition:
        $appname or
        all of ($langfilters*) or
        all of ($definitions*) or
        $sess
}