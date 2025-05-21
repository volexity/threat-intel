import "math"

rule apt_webshell_pl_complyshell: UTA0178
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-12-13"
        description = "Detection for the COMPLYSHELL webshell."
        hash1 = "8bc8f4da98ee05c9d403d2cb76097818de0b524d90bea8ed846615e42cb031d2"
        os = "linux"
        os_arch = "all"
        report = "TIB-20231215"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-12T17:32:31Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9995
        version = 4

    strings:
        $s = "eval{my $c=Crypt::RC4->new("

    condition:
        $s
}
rule apt_webshell_aspx_glasstoken: UTA0178
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-12-12"
        description = "Detection for a custom webshell seen on Exchange server. The webshell contains two functions, the first is to act as a Tunnel, using code borrowed from reGeorg, the second is custom code to execute arbitrary .NET code."
        hash1 = "26cbb54b1feb75fe008e36285334d747428f80aacdb57badf294e597f3e9430d"
        os = "win"
        os_arch = "all"
        report = "TIB-20231215"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-09-30T18:48:20Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 9994
        version = 6

    strings:
        $s1 = "=Convert.FromBase64String(System.Text.Encoding.Default.GetString(" ascii
        $re = /Assembly\.Load\(errors\)\.CreateInstance\("[a-z0-9A-Z]{4,12}"\).GetHashCode\(\);/

    condition:
        for any i in (0..math.min(#s1,100)):
            (
                $re in (@s1[i]..@s1[i]+512)
            )
}
rule webshell_aspx_regeorg
{
    meta:
        author = "threatintel@volexity.com"
        date = "2018-08-29"
        description = "Detects the reGeorg webshell based on common strings in the webshell. May also detect other webshells which borrow code from ReGeorg."
        hash = "9d901f1a494ffa98d967ee6ee30a46402c12a807ce425d5f51252eb69941d988"
        os = "win"
        os_arch = "all"
        reference = "https://github.com/L-codes/Neo-reGeorg/blob/master/templates/tunnel.aspx"
        report = "TIB-20231215"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-09T10:04:58Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 410
        version = 7

    strings:
        $a1 = "every office needs a tool like Georg" ascii
        $a2 = "cmd = Request.QueryString.Get(\"cmd\")" ascii
        $a3 = "exKak.Message" ascii

        $proxy1 = "if (rkey != \"Content-Length\" && rkey != \"Transfer-Encoding\")"

        $proxy_b1 = "StreamReader repBody = new StreamReader(response.GetResponseStream(), Encoding.GetEncoding(\"UTF-8\"));" ascii
        $proxy_b2 = "string rbody = repBody.ReadToEnd();" ascii
        $proxy_b3 = "Response.AddHeader(\"Content-Length\", rbody.Length.ToString());" ascii

    condition:
        any of ($a*) or
        $proxy1 or
        all of ($proxy_b*)
}
rule hacktool_py_pysoxy
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-01-09"
        description = "SOCKS5 proxy tool used to relay connections."
        hash1 = "e192932d834292478c9b1032543c53edfc2b252fdf7e27e4c438f4b249544eeb"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/MisterDaneel/pysoxy/blob/master/pysoxy.py"
        report = "TIB-20240109"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-01-09T13:45:28Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10065
        version = 3

    strings:
        $s1 = "proxy_loop" ascii
        $s2 = "connect_to_dst" ascii
        $s3 = "request_client" ascii
        $s4 = "subnegotiation_client" ascii
        $s5 = "bind_port" ascii

    condition:
        all of them
}
