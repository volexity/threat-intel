rule apt_malware_linux_disgomoji_modules: UTA0137
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-02-22"
        description = "Detects DISGOMOJI modules based on strings in the ELF."
        hash1 = "2abaae4f6794131108adf5b42e09ee5ce24769431a0e154feabe6052cfe70bf3"
        report = "TIB-20240228"
        os = "linux"
        os_arch = "all"
        scan_context = "file,memory"
        last_modified = "2024-02-27T14:01Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10270
        version = 3

    strings:
        $s1 = "discord-c2/test/main/finalizing/Deliveries/ob_Delivery.go" wide ascii
        $s2 = "discord-c2/test/main/finalizing/WAN_Conf.go" wide ascii

    condition:
        any of them
}

rule apt_malware_linux_disgomoji_loader : UTA0137
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-02-22"
        description = "Detects the DISGOMOJI loader using strings in the ELF."
        hash1 = "51a372fee89f885741515fa6fdf0ebce860f98145c9883f2e3e35c0fe4432885"
        report = "TIB-20240228"
        os = "linux"
        os_arch = "all"
        scan_context = "file,memory"
        last_modified = "2024-02-27T14:01Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10269
        version = 3

    strings:
        $s1 = "discord-c2/test/main/delievery.go" wide ascii

    condition:
        $s1
}

rule apt_malware_linux_disgomoji_debug_string: UTA0137
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-02-22"
        description = "Detects the DISGOMOJI malware using strings in the ELF."
        hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
        report = "TIB-20240228"
        os = "linux"
        os_arch = "all"
        scan_context = "file,memory"
        last_modified = "2024-02-27T14:02Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10268
        version = 5

    strings:
        $s1 = "discord-c2/test/main/payload.go" wide ascii

    condition:
        $s1
}

rule apt_malware_linux_disgomoji_2 : UTA0137
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-02-22"
        description = "Detects the DISGOMOJI malware using strings in the ELF."
        hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
        report = "TIB-20240228"
        os = "linux"
        os_arch = "all"
        scan_context = "file,memory"
        last_modified = "2024-02-27T14:03Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10266
        version = 5

    strings:
        $s1 = "downloadFileFromURL" wide ascii
        $s2 = "createCronJob" wide ascii
        $s3 = "findAndSendFiles" wide ascii
        $s4 = "updateLogFile" wide ascii
        $s5 = "handleZipFile" wide ascii
        $s6 = "takeScreenshot" wide ascii
        $s7 = "zipFirefoxProfile" wide ascii
        $s8 = "zipDirectoryWithParts" wide ascii
        $s9 = "uploadAndSendToOshi" wide ascii
        $s10 = "uploadAndSendToLeft" wide ascii

    condition:
        7 of them
}

rule apt_malware_linux_disgomoji_1: UTA0137
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-02-22"
        description = "Detects the DISGOMOJI malware using strings in the ELF."
        hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
        report = "TIB-20240228"
        os = "linux"
        os_arch = "all"
        scan_context = "file,memory"
        last_modified = "2024-02-27T14:02Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10265
        version = 4

    strings:
        $s1 = "Session *%s* opened!" wide ascii
        $s2 = "uevent_seqnum.sh" wide ascii
        $s3 = "Error downloading shell script: %v" wide ascii
        $s4 = "Error setting execute permissions: %v" wide ascii
        $s5 = "Error executing shell script: %v" wide ascii
        $s6 = "Error creating Discord session" wide ascii

    condition:
        4 of them
}

rule apt_malware_linux_disgomoji_bogus_strings: UTA0137
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-03-14"
        description = "Detects the DISGOMOJI malware using bogus strings introduced in the newer versions."
        hash1 = "8c8ef2d850bd9c987604e82571706e11612946122c6ab089bd54440c0113968e"
        report = "TIB-20240318"
        os = "linux"
        os_arch = "all"
        scan_context = "file"
        last_modified = "2024-03-14T11:37Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10341
        version = 3

    strings:
        $s1 = "Graphics Display Rendering" wide ascii
        $s2 = "Error fetching Repository Key: %v" wide ascii
        $s3 = "Error reading Repository Key: %v" wide ascii
        $s4 = "Error fetching dpkg: %v" wide ascii
        $s5 = "GNU Drivers Latest version v1.4.2" wide ascii
        $s6 = "ps_output.txt" wide ascii

    condition:
        all of them
}

rule apt_malware_linux_disgomoji_script_uevent_seqnum : UTA0137
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-03-07"
        description = "Detects a script deployed as part of DISGOMOJI malware chain."
        hash1 = "98b24fb7aaaece7556aea2269b4e908dd79ff332ddaa5111caec49123840f364"
        report = "TIB-20240318"
        os = "linux"
        os_arch = "all"
        scan_context = "file"
        last_modified = "2024-03-14T11:37Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10314
        version = 3

    strings:
        $s1 = "USB_DIR=\"/media/$USER\"" wide ascii
        $s2 = "RECORD_FILE=\"record.txt\"" wide ascii
        $s3 = "copy_files()" wide ascii
        $s4 = "Check for connected USB drives" wide ascii
        $s5 = "Check if filename already exists in record.txt" wide ascii
        $s6 = "Function to copy files from USB drive to destination folder" wide ascii

    condition:
        3 of them
}

rule apt_malware_linux_disgomoji_script_lan_conf : UTA0137
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-03-07"
        description = "Detects a script deployed as part of DISGOMOJI malware chain."
        hash1 = "0b5cf9bd917f0af03dd694ff4ce39b0b34a97c9f41b87feac1dc884a684f60ef"
        report = "TIB-20240318"
        os = "linux"
        os_arch = "all"
        scan_context = "file"
        last_modified = "2024-03-14T11:36Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10312
        version = 4

    strings:
        $s1 = "add_lan_conf_cron_if_not_exists" wide ascii
        $s2 = "download_if_not_exists" wide ascii
        $s3 = "add_cron_if_not_exists" wide ascii
        $s4 = "uevent_seqnum.sh" wide ascii
        $s5 = "$HOME/.x86_64-linux-gnu" wide ascii
        $s6 = "lanConfScriptPath" wide ascii

    condition:
        4 of them
}

rule malware_golang_discordc2_bmdyy_1
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-03-28"
        description = "Detects a opensource malware available on github using strings in the ELF. DISGOMOJI used by UTA0137 is based on this malware."
        hash1 = "de32e96d1f151cc787841c12fad88d0a2276a93d202fc19f93631462512fffaf"
        os = "all"
        os_arch = "all"
        reference = "https://github.com/bmdyy/discord-c2"
        report = "TIB-20240229"
        scan_context = "file,memory"
        last_modified = "2024-03-28T11:40Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10390
        version = 2

    strings:
        $s1 = "File is bigger than 8MB" wide ascii
        $s2 = "Uploaded file to" wide ascii
        $s3 = "sess-%d" wide ascii
        $s4 = "Session *%s* opened" wide ascii
        $s5 = "%s%d_%dx%d.png" wide ascii

    condition:
        4 of them
}

rule malware_golang_discordc2_bmdyy
{
    meta:
        author = "threatintel@volexity.com"
        date = "2024-02-22"
        description = "Detects a opensource malware available on github using strings in the ELF. DISGOMOJI used by UTA0137 is based on this malware."
        hash1 = "d9f29a626857fa251393f056e454dfc02de53288ebe89a282bad38d03f614529"
        report = "TIB-20240229"
        reference = "https://github.com/bmdyy/discord-c2"
        os = "all"
        os_arch = "all"
        scan_context = "file,memory"
        last_modified = "2024-03-28T11:14Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10264
        version = 10

    strings:
        $s1 = "**IP**: %s\n**User**: %s\n**Hostname**: %s\n**OS**: %s\n**CWD**" wide ascii

    condition:
        $s1
}