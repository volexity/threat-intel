rule apt_ico_uta0040_b64_c2 : UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of malicious ICO files used in 3CX compromise."
        date = "2023-03-30"
        hash1 = "a541e5fc421c358e0a2b07bf4771e897fb5a617998aa4876e0e1baa5fbb8e25c"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $IEND_dollar = {49 45 4e 44 ae 42 60 82 24} // IEND.B`.$
        $IEND_nodollar = {49 45 4e 44 ae 42 60 82 } // IEND.B`.

    condition:
        uint16be(0) == 0x0000 and
        filesize < 120KB and
        (
            $IEND_dollar in (filesize-500..filesize) and not
            $IEND_nodollar in (filesize-20..filesize) and
            for any k in (1..#IEND_dollar):
                (
                for all i in (1..4):
                    (
                        // in range [0-9a-zA-Z]
                        uint8(@IEND_dollar[k]+!IEND_dollar[k] + i ) < 123 and
                        uint8(@IEND_dollar[k]+!IEND_dollar[k] + i) > 47
                    )
                )
        )
}
rule apt_mac_iconic: UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detects the MACOS version of the ICONIC loader."
        hash1 = "a64fa9f1c76457ecc58402142a8728ce34ccba378c17318b3340083eeb7acc67"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $str1 = "3CX Desktop App" xor(0x01-0xff)
        $str2 = "__tutma=" xor(0x01-0xff)
        $str3 = "Mozilla/5.0" xor(0x01-0xff)

    condition:
        all of them
}
rule apt_win_iconicstealer: UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detect the ICONICSTEALER malware family."
        hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $str1 = "\\3CXDesktopApp\\config.json" wide
        $str2 = "url, title FROM urls" wide
        $str3 = "url, title FROM moz_places" wide

    condition:
        all of them
}
rule apt_win_iconic: UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detect the ICONIC loader."
        hash1 = "f79c3b0adb6ec7bcc8bc9ae955a1571aaed6755a28c8b17b1d7595ee86840952"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $internal_name =  "samcli.dll"

        $str1 = "gzip, deflate, br"
        $str2 = "__tutma"
        $str3 = "__tutmc"
        $str4 = "ChainingModeGCM" wide
        $str5 = "ChainingMode" wide
        $str6 = "icon%d.ico" wide

    condition:
        all of them
}
rule apt_win_3cx_backdoored_lib: UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detects the malicious library delivered in the backdoored 3CX installer."
        hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $shellcode =  {
                        44 8D 4A ??
                        44 8D 92 ?? ?? ?? ??
                        45 85 C9
                        45 0F 49 D1
                        41 81 E2 00 FF FF FF
                        41 F7 DA
                        44 01 D2
                        FF C2
                        4C 63 CA
                        46 8A 94 0C ?? ?? ?? ??
                        45 00 D0
                        45 0F B6 D8
                        42 8A AC 1C ?? ?? ?? ??
                        46 88 94 1C ?? ?? ?? ??
                        42 88 AC 0C ?? ?? ?? ??
                        42 02 AC 1C ?? ?? ?? ??
                        44 0F B6 CD
                        46 8A 8C 0C ?? ?? ?? ??
                        45 30 0C 0E
                        48 FF C1
                        48 39 C8
                        75 ??
                }

    condition:
        all of them
}
rule informational_win_3cx_msi : UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detects 3CX installers created in March 2023, 3CX was known to be compromised at this time."
        hash1 = "aa124a4b4df12b34e74ee7f6c683b2ebec4ce9a8edcf9be345823b4fdcf5d868"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 0
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $cert =  { 1B 66 11 DF 9C 9A 4D 6E CC 8E D5 0C 9B 91 78 73 }
        $app = "3CXDesktopApp.exe"
        $data = "202303"

    condition:
        all of them
}