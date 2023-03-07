rule apt_win_avburner : SnakeCharmer
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-01-02"
        description = "Detects AVBurner based on a combination of API calls used, hard-coded strings and bytecode patterns."
        hash = "4b1b1a1293ccd2c0fd51075de9376ebb55ab64972da785153fcb0a4eb523a5eb"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        reference = "https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html"

    strings:
        // Note that in theory, this could hit on various other tools trying to do similar things to
        // AVBurner
        $api1 = "PspCreateProcessNotifyRoutineAddress" wide
        $api2 = "PspCreateThreadNotifyRoutineAddress" wide
        $api3 = "PspLoadImageNotifyRoutineAddress" wide

        $str1 = "\\\\.\\RTCORE64" wide
        $str2 = "\\\\%ws/pipe/%ws" wide
        $str3 = "CreateServerW Failed %u" wide
        $str4 = "OpenSCManager Failed %u" wide
        $str5 = "Get patternAddress" wide

        $pattern1 = { 4C 8B F9 48 8D 0C C1 E8 }
        $pattern2 = { 48 8D 0C DD 00 00 00 00  45 33 C0 49 03 CD 48 8B }
        $pattern3 = { 48 8D 04 C1 48 89 45 70 48 8B C8 E8 }
        $pattern4 = { 49 8D 0C FC 45 33 C0 48 8B D6 E8 00 00 00 00 00}
        $pattern5 = { 45 33 C0 48 8D 0C D9 48 8B D7 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        $pattern6 = { 41 0F BA 6D 00 0A BB 01 00 00 00 4C 8B F2 4C 8B F9 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

    condition:
        all of ($api*) or
        all of ($str*) or
        all of ($pattern*)
}