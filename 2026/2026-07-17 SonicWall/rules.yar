rule apt_webshell_java_orangetail_b: UTA0533 ORANGETAIL
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Detection for the accept logic of ORANGETAIL, a custom Java webshell used by UTA0533."
    hash1 = "1e1e68bbb899450a57274a8b12082ed4e2040a2aae77014f20431689d2b4edee"
    hash2 = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
    os = "all"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20260714B"
    last_modified = "2026-07-14T09:45:38Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13240
    version = 6

  strings:
    $s1 = ".equals($1.getHeader(\"User-Agent\"))) {  javax.servlet.jsp.JspFactory" ascii
    $s2 = " $2.setStatus(404);  $2.setContentLength(0);  $2.flushBuffer();  return;" ascii

  condition:
    all of them
}
rule apt_webshell_java_orangetail: UTA0533 ORANGETAIL
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Detection for ORANGETAIL, a custom Java webshell used by UTA0533."
    hash1 = "ea9154e374e4f77bc2cf54282e23543573980342a85bc888cb23f20b8bbba081"
    os = "all"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20260714B"
    last_modified = "2026-07-14T09:45:31Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13239
    version = 5

  strings:
    $s1 = "agentmain called args="
    $s2 = "tryInject="
    $s3 = "agentmain ex:"
    $s4 = "javassist="
    $s5 = "tryInject exception"
    $s6 = "found loaded class:"

  condition:
    4 of ($s*)
}
rule apt_malware_any_uta0533_ua: UTA0533
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Identify any blob containing a bogus user-agent used in different components of an attack attributed to UTA0533."
    hash1 = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
    os = "all"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "critical"
    report1 = "TIB-20260714B"
    last_modified = "2026-07-14T09:45:26Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13237
    version = 3

  strings:
    $s1 = "Mozilla/6.0 (Windows NT 11.0; Win64; x64) AppleWebKit/1537.136 (KHTML, like Gecko) Chrome/149.0.0.1 Safari/1537.136" ascii

  condition:
    $s1
}
rule apt_malware_python_knuckleball: UTA0533 KNUCKLEBALL
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Detects KNUCKLEBALL, a python based injector malware, using string patterns."
    hash1 = "8c470301dcb7278f73e622f1950073567b34011c64b60cdfbb0f89803923a5a3"
    os = "linux"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "high"
    report1 = "TIB-20260714B"
    last_modified = "2026-07-14T09:45:44Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13233
    version = 5

  strings:
    $s1 = "/tmp/.java_pid{pid}" ascii
    $s2 = "/tmp/.attach_pid{pid}" ascii
    $s3 = "timeout waiting for JVMTI attach socket" ascii
    $s4 = "workplace.startup.CommandStartup" ascii
    $s5 = "/var/run/control.unit.sock" ascii

    $func1 = "unit_put(" ascii
    $func2 = "check_gate(" ascii
    $func3 = "inject_jar(" ascii
    $func4 = "find_wp_pid(" ascii

  condition:
    2 of ($s*) or
    3 of ($func*)
}
rule apt_malware_linux_rootrun: UTA0533 ROOTRUN
{
  meta:
    author = "threatintel@volexity.com"
    date = "2026-07-06"
    description = "Detects rootrun a setuid privilege escalation utility for Linux written in C using strings."
    hash1 = "81a9af3846bad3a1107164ff7cf0a08e020b31a3b32fd17866e17d4c1565f7f2"
    os = "linux"
    os_arch = "all"
    scan_context = "file,memory"
    severity = "high"
    last_modified = "2026-07-14T08:18:49Z"
    license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
    rule_id = 13232
    version = 4

  strings:
    $s1 = "rootrun" ascii
    $s2 = "execlp" ascii
    $s3 = "Usage: rootrun rootrun <command>\n" ascii
    $s4 = "Failed to setuid" ascii

  condition:
    all of them
}