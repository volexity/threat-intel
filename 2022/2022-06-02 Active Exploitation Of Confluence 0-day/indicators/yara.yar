rule webshell_jsp_converge
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects CONVERGE - a file upload webshell observed in incident involving compromise of Confluence server via CVE-2022-26134."
        date = "2022-06-01"
        os = "all"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-09-20T10:58:26Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6788
        version = 5

    strings:
        $s1 = "if (request.getParameter(\"name\")!=null && request.getParameter(\"name\").length()!=0){" ascii

    condition:
        $s1
}
rule susp_jsp_possible_tiny_fileuploader
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects small .jsp files which likely have a capability to handle file uploads. These may or may not be malicious, but are often the initial webshell of choice when initially breaching a webserver."
        date = "2022-06-01"
        hash1 = "4addb9bc9e5e1af8fda63589f6b3fc038ccfd651230fa3fa61814ad080e95a12"
        os = "win,linux"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-07-30T09:45:42Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6787
        version = 2

    strings:
        // read a req parameter of some sort
        $required1 = "request." ascii
        // write a file
        $required2 = "java.io.FileOutputStream" ascii
        $required3 = ".write" ascii

        $encoding1 = "java.util.Base64" ascii
        $encoding2 = "crypto.Cipher" ascii
        $encoding3 = ".misc.BASE64Decoder" ascii

    condition:
        (
            filesize < 4KB and
            all of ($required*) and
            any of ($encoding*)
        )
        or
        (
            filesize < 600 and
            all of ($required*)
        )
}
rule webshell_java_realcmd
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the RealCMD webshell, one of the payloads for BEHINDER."
        date = "2022-06-01"
        hash1 = "a9a30455d6f3a0a8cd0274ae954aa41674b6fd52877fafc84a9cb833fd8858f6"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/Freakboy/Behinder/blob/master/src/main/java/vip/youwe/sheller/payload/java/RealCMD.java"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-07-30T08:32:55Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6786
        version = 4

    strings:
        $fn1 = "runCmd" wide ascii fullword
        $fn2 = "RealCMD" ascii wide fullword
        $fn3 = "buildJson" ascii wide fullword
    condition:
        all of ($fn*)
}
