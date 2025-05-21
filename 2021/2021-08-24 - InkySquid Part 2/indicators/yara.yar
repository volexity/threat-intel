rule apt_malware_rb_rokrat_loader: InkyPine
{
    meta:
        author = "threatintel@volexity.com"
        description = "Ruby loader seen loading the ROKRAT malware family."
        date = "2021-06-22"
        hash1 = "5bc52f6c1c0d0131cee30b4f192ce738ad70bcb56e84180f464a5125d1a784b2"
        os = "win"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-08-22T09:36:05Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 5598
        version = 7

    strings:
        $magic1 = "'https://update.microsoft.com/driverupdate?id=" ascii wide
        $magic2 = "sVHZv1mCNYDO0AzI';" ascii wide
        $magic3 = "firoffset..scupd.size" ascii wide
        $magic4 = /alias UrlFilter[0-9]{2,5} eval;"/

        // Original: 'Fiddle::Pointer' (Reversed)
        $s1 = "clRnbp9GU6oTZsRGZpZ"
        $s2 = "RmlkZGxlOjpQb2ludGVy"
        $s3 = "yVGdul2bQpjOlxGZklmR"
        $s4 = "XZ05WavBlO6UGbkRWaG"

    condition:
        any of ($magic*) or
        any of ($s*)
}
rule apt_malware_py_bluelight_ldr: InkyPine
{
    meta:
        author = "threatintel@volexity.com"
        description = "Python Loader used to execute the BLUELIGHT malware family."
        date = "2021-06-22"
        hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
        os = "win"
        os_arch = "all"
        reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
        scan_context = "file"
        severity = "high"
        last_modified = "2025-02-18T12:58:34Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 5600
        version = 6

    strings:
        $s1 = "\"\".join(chr(ord(" ascii
        $s2 = "import ctypes" ascii
        $s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
        $s4 = "ctypes.memmove" ascii

        $magic = "writelines(\"python ended\")" ascii

    condition:
        all of ($s*) or
        $magic
}
rule apt_malware_win_decrok: InkyPine
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-06-23"
        description = "The DECROK malware family, which uses the victim's hostname to decrypt and execute an embedded payload."
        hash = "6a452d088d60113f623b852f33f8f9acf0d4197af29781f889613fed38f57855"
        os = "win"
        os_arch = "x86"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2023-09-28T10:00:41Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 5606
        version = 4

    strings:
        $v1 = {C7 ?? ?? ?? 01 23 45 67 [2-20] C7 ?? ?? ?? 89 AB CD EF C7 ?? ?? ?? FE DC BA 98}

        $av1 = "Select * From AntiVirusProduct" wide
        $av2 = "root\\SecurityCenter2" wide

        $func1 = "CreateThread"
        $format = "%02x"

    condition:
        all of them and
        $func1 in (@format..@format+10)
}
rule apt_malware_win_rokload: InkyPine
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-06-23"
        description = "A shellcode loader used to decrypt and run an embedded executable."
        hash = "85cd5c3bb028fe6931130ccd5d0b0c535c01ce2bcda660a3b72581a1a5382904"
        os = "win"
        os_arch = "x64"
        scan_context = "file"
        severity = "high"
        last_modified = "2025-05-21T15:26:47Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 5603
        version = 4

    strings:
        $bytes00 = { 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 57 41 54 41 55 41 56 41 57 48 ?? ?? ?? b9 ?? ?? ?? ?? 33 ff e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 4c 8b e8 e8 ?? ?? ?? ?? 4c 8b f0 41 ff d6 b9 ?? ?? ?? ?? 44 8b f8 e8 ?? ?? ?? ?? 4c 8b e0 e8 ?? ?? ?? ?? 48 }

    condition:
        $bytes00 at 0
}
