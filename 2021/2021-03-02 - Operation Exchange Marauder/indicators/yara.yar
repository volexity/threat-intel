rule webshell_aspx_simpleseesharp
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "ASPX Webshell allowing CRUD of files and cmd execution."
        hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-11-12T16:45:07Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 4969
        version = 6

    strings:
        $header = "<%@ Page Language=\"C#\" %>"
        $body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

    condition:
        filesize < 1KB and
        $header at 0 and
        $body
}
rule webshell_aspx_reGeorgTunnel
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-02"
        description = "A variation of the reGeorgtunnel open-source webshell."
        hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
        os = "win"
        os_arch = "all"
        reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2024-10-18T13:43:52Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 4979
        version = 4

    strings:
        $s1 = "System.Net.Sockets"
        $s2 = "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"

        $t1 = ".Split('|')"
        $t2 = "Request.Headers.Get"
        $t3 = ".Substring("
        $t4 = "new Socket("
        $t5 = "IPAddress ip;"

    condition:
        all of ($s*) or
        all of ($t*)
}
rule apt_webshell_aspx_sportsball
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "The SPORTSBALL webshell, observed in targeted Microsoft Exchange attacks."
        hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
        os = "win"
        os_arch = "all"
        reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-07-30T10:43:34Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 4968
        version = 5

    strings:
        $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
        $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="

        $s1 = "Result.InnerText = string.Empty;"
        $s2 = "newcook.Expires = DateTime.Now.AddDays("
        $s3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
        $s4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
        $s5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
        $s6 = "<input type=\"submit\" value=\"Upload\" />"

    condition:
        any of ($uniq*) or
        all of ($s*)
}
