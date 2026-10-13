rule exploit_log_ivanti_rce: CVE_2026_104935
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-10-12"
    description = "Identifies files or memory regions containing request headers matching RCE vulnerability for Ivanti."
    os = "linux"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20261012"
    last_modified = "2026-10-12T19:35:53Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13503
    version = 1

  strings:
    $s1 = "X-DSCGI-PATH: /home/webserver/htdocs/dana/fb/smb/wu.cgi" ascii

  condition:
    $s1
}

rule exploit_py_ivanti_oct26: CVE_2026_104935 UTA0576
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-10-10"
    description = "Detection for EoP vuln implementation in Python used by UTA0576."
    hash1 = "25b95f47359c327e3a5ae5ac5cd147f8d9afd98092faf136822ee287e25e3dc8"
    os = "linux"
    os_arch = "all"
    scan_context = "memory"
    severity = "critical"
    report1 = "TIB-20261012"
    last_modified = "2026-10-12T19:36:10Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13500
    version = 3

  strings:
    $magic1 = "target dsinvoked broker is busy; stop retries and clear its current child" ascii
    $magic2 = "PATCH_LOCATOR arch=%s offset=%s sha256=%s encoding=%s open=%s call=%s evidence=%s"

    $pycombo1 = "import os,socket,time,_frozen_importlib_external as ie"
    $pycombo2 = "def say(*x): print(*x,flush=True)"

  condition:
    any of ($magic*) or
    all of ($pycombo*)
}