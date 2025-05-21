rule webshell_jsp_godzilla
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the JSP implementation of the Godzilla Webshell."
        date = "2021-11-08"
        hash1 = "2786d2dc738529a34ecde10ffeda69b7f40762bf13e7771451f13a24ab7fc5fe"
        os = "win,linux"
        os_arch = "all"
        reference = "https://github.com/BeichenDream/Godzilla"
        reference2 = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-07-30T09:08:00Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6100
        version = 6

    strings:
        $s1 = ".getWriter().write(base64Encode(" wide ascii
        $s2 = ".getAttribute(" ascii wide
        $s3 = "java.security.MessageDigest" ascii wide

        $auth1 = /String xc=\"[a-f0-9]{16}\"/ ascii wide
        $auth2 = "String pass=\"" ascii wide

        $magic = "class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q"
        $magic2 = "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class"

    condition:
        all of ($s*) or
        all of ($auth*) or
        any of ($magic*)
}
rule susp_jsp_general_runtime_exec_req
{
    meta:
        author = "threatintel@volexity.com"
        description = "Looks for a common design pattern in webshells where a request attribute is passed as an argument to exec()."
        date = "2022-02-02"
        hash1 = "4935f0c50057e28efa7376c734a4c66018f8d20157b6584399146b6c79a6de15"
        os = "win,linux"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "high"
        last_modified = "2024-07-30T09:38:54Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6450
        version = 3

    strings:
        $s1 = "Runtime.getRuntime().exec(request." ascii

    condition:
        $s1
}
rule webshell_jsp_reGeorg
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the reGeorg webshells' JSP version."
        date = "2022-03-08"
        hash1 = "f9b20324f4239a8c82042d8207e35776d6777b6305974964cd9ccc09d431b845"
        os = "win"
        os_arch = "all"
        reference = "https://github.com/SecWiki/WebShell-2/blob/master/reGeorg-master/tunnel.jsp"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-09-20T10:44:33Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 6575
        version = 5

    strings:
        $magic = "socketChannel.connect(new InetSocketAddress(target, port))" ascii

        $a1 = ".connect(new InetSocketAddress" ascii
        $a2 = ".configureBlocking(false)" ascii
        $a3 = ".setHeader(" ascii
        $a4 = ".getHeader(" ascii
        $a5 = ".flip();" ascii

    condition:
        $magic or
        all of ($a*)
}
