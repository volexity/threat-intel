rule webshell_aspx_simpleseesharp : Webshell Unclassified
{

    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
        hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $header = "<%@ Page Language=\"C#\" %>"
        $body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

    condition:
        $header at 0 and
        $body and
        filesize < 1KB
}

rule webshell_aspx_reGeorgTunnel : Webshell Commodity
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "variation on reGeorgtunnel"
        hash = "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        reference = "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"

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

rule webshell_aspx_sportsball : Webshell
{
    meta:
        author = "threatintel@volexity.com"
        date = "2021-03-01"
        description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
        hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
        $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE=" 

        $var1 = "Result.InnerText = string.Empty;"
        $var2 = "newcook.Expires = DateTime.Now.AddDays("
        $var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process()"
        $var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
        $var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
        $var6 = "<input type=\"submit\" value=\"Upload\" />" 

    condition:
        any of ($uniq*) or
        all of ($var*)
}
