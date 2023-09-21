rule apt_malware_apk_evilbamboo_datacollection_Jun23: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of the the BADSOLAR and BADBAZAAR data collection files, which are shared by both malware families."
        date = "2023-06-08"
        hash1 = "8448f5cf984e9871966893f0604d9b6d70672c38ff1138a03377848b85a5fcaf"
        hash2 = "bf5f7fbf42236e89bcf663d2822d54bee89abaf3f247a54f371bf156e0e03629"
        scan_context = "file"
        last_modified = "2023-06-08T10:25Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "osv" fullword
        $s2 = "adid" fullword
        $s3 = "mac" fullword
        $s4 = "operator" fullword
        $s5 = "version" fullword
        $s6 = "dvw" fullword
        $s7 = "dvh" fullword
        $s8 = "density" fullword
        $s9 = "vendor" fullword
        $s10 = "model" fullword
        $s11 = "lan" fullword
        $s12 = "imei" fullword
        $s13 = "pn" fullword
        $s14 = "imsi" fullword
        $s15 = "iccid" fullword
        $s16 = "pnb" fullword
        $s17 = "tzone" fullword
        $s18 = "accounts" fullword
        $s19 = "wifiinfo" fullword

        $o1 = "46000" fullword
        $o2 = "46001" fullword
        $o3 = "46002" fullword
        $o4 = "46003" fullword
        $o5 = "46007" fullword
        $o6 = "CHINA MOBILE" fullword
        $o7 = "China Unicom" fullword
        $o8 = "China Telecom" fullword

    condition:
        (
            // dex
            uint32be(0) == 0x6465780a or 
            // pk
            uint16be(0) == 0x504b
        ) 
        and filesize < 75KB
        and 
        (
            16 of ($s*)
            or 
            (
                all of ($o*) and 
                6 of ($s*)
            )
        )
}

rule apt_malware_apk_badsolar_2ndstage_Jun23: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-06-07"
        description = "Detect the BADSOLAR 2nd stage implant, usually a JAR file."
        hash1 = "8448f5cf984e9871966893f0604d9b6d70672c38ff1138a03377848b85a5fcaf"
        scan_context = "file"
        last_modified = "2023-06-13T12:07Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $solar = "com.solarcs.executor"

        $s1 = "After take picture !"
        $s2 = "PhotoTaker"
        $s3 = "FileDownloadHandler"
        $s4 = "AdvancedSystemInfo"
        $s5 = "CallLogLister"
        $s6 = "SMSLister"

    condition:
        uint16be(0) == 0x504b
        and $solar 
        and 4 of ($s*)
}

rule apt_malware_apk_badsolar_loader_Jun23: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of the the BADSOLAR android malware first stage loader."
        date = "2023-05-25"
        hash1 = "f7132750db2a8ca8eb9e9e5a32377aa506395d02bacbb918f835041f5f035c4c"
        scan_context = "file"
        last_modified = "2023-06-16T09:27Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "yhnrfv" ascii fullword
        $s2 = "efef0231e5c3b44a002b2628ebef3c4c"
        $s3 = "onDestroy: into"
        $s4 = "com.solarcs.executor.CommandHandler"
        $s5 = "!QAZ2wsx" ascii fullword
        $s6 = "onStartCommand: intent == null"

    condition:
        (
            // dex
            uint32be(0) == 0x6465780a or 
            // pk
            uint16be(0) == 0x504b
        ) 
        and 2 of ($s*)
}

rule apt_malware_apk_badsignal_Jun23_d: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-06-16"
        description = "Detect three BADSIGNAL variants."
        hash1 = "daf3d2cb6f1bbb7c8d1cfb5fc0db23afc304a622ebb24aa940228be691bcda2d"
        hash2 = "549d726fe2b775cfdd1304c2d689dfd779731336a3143225dc3c095440f69ed0"
        hash3 = "0fea799ce00c7d6f26ccb52a2ecbe6b9605cfb9910f2a309a841caedf3b102d7"
        scan_context = "file"
        last_modified = "2023-06-16T08:37Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $api1 = "/api/clientlogin" nocase
        $api2 = "/api/proxy" nocase
        $api3 = "/api/values" nocase
        $api4 = "/api/uploadfile?imei=" nocase

        $json1 = "ramimei" fullword
        $json2 = "operator" fullword

        $extra1 = "Timezon id:"
        $extra2 = "cat /sys/class/net/"

        $operator1 = "CHINA MOBILE"
        $operator2 = "China Unicom"
        $operator3 = "China Telecom"

    condition:
        (
            // dex
            uint32be(0) == 0x6465780a or 
            // pk
            uint16be(0) == 0x504b
        ) 
        and any of ($api*)
        and any of ($extra*)
        and all of ($operator*)
        and all of ($json*)
}

rule apt_malware_apk_badsignal_Jun23_c: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of the android variant of the BADSIGNAL malware."
        date = "2023-06-15"
        hash1 = "f0bf154d1e90491199b66ab95c1a4071669f3322c55f3643e36c20a9fb63eb56"
        scan_context = "file"
        last_modified = "2023-06-15T14:50Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $s1 = "clientlogin" fullword
        $s2 = "TibetOne" fullword
        $s3 = "Success,picture saved at" fullword
        $s4 = "Failed,please try again" fullword
        $s5 = ":4432"
        $s6 = "DeviceInfo" fullword
        $s7 = "com.holy.tibetone"

        $info1 = "imeiinfo" fullword
        $info2 = "raimei" fullword
        $info3 = "imei" fullword
        $info4 = "latitude" fullword
        $info5 = "longitude" fullword
        $info6 = "altitude" fullword
        $info7 = "wifiinfo" fullword
        $info8 = "dns1" fullword
        $info9 = "dns2" fullword
        $info10 = "wifi not open " fullword //space intentional
        $info11 = "bssid" fullword
        $info12 = "CHINA MOBILE" fullword

    condition:
        (
            // dex
            uint32be(0) == 0x6465780a or 
            // pk
            uint16be(0) == 0x504b
        ) 
        and 3 of ($s*)
        and 6 of ($info*)
}

rule apt_malware_apk_badsignal_Jun23_b: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-06-08"
        description = "Detect the BADSIGNAL Android malware."
        hash1 = "549d726fe2b775cfdd1304c2d689dfd779731336a3143225dc3c095440f69ed0"
        scan_context = "file"
        last_modified = "2023-06-13T12:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $api1 = "Location?imei="
        $api2 = "clientLogin?imei="
        $api3 = "QRCode?imei="

    condition:
        (
            // dex
            uint32be(0) == 0x6465780a or 
            // pk
            uint16be(0) == 0x504b
        )
        and all of them
}

rule apt_malware_apk_badbazaar_common_certificate: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of the common.cer file used for a large BADBAZAAR malware cluster for its certificate pinning for the C2 communication."
        date = "2023-06-01"
        hash1 = "6aefc2b33e23f6e3c96de51d07f7123bd23ff951d67849a9bd32d446e76fb405"
        scan_context = "file"
        last_modified = "2023-06-13T12:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $b1 = {30 82 03 61 30 82 02 49 a0 03 02 01 02 02 04 2b 6e df 67 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b} //bytes from start of the file

        $s1 = "california1"
        $s2 = "los1"
        $s3 = "tech1"
        $s4 = "common1"
        $s5 = "common0"
        $s6 = "220401234506Z"
        $s7 = "470326234506Z0a1"

    condition:
        $b1 at 0
        or all of ($s*)
}

rule apt_malware_apk_badbazaar_stage2_implant_May23: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of the second stage capability of the BadBazaar android malware that has the main malicious capabilities. Will gather various info about the user/phone and routinely send this to the C2."
        date = "2023-05-25"
        hash1 = "bf5f7fbf42236e89bcf663d2822d54bee89abaf3f247a54f371bf156e0e03629"
        scan_context = "file"
        last_modified = "2023-08-30T10:35Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $c1 = "%{\"command\":\"%s\",\"path\":\"%s\",\"files\":["
        $c2 = "{\"name\":\"%s\",\"dirs\":\"%d\",\"files\":\"%d\",\"isfolder\":\"%d\",\"path\":\"%s\"},"

        $s1 = "Timezon id:"
        $s2 = "China Telecom"
        $s3 = "China Unicom"
        $s4 = "ConfigPipe"
        $s5 = "ForwordTo"
        $s6 = "can't get camera content"
        $s7 = "cat /sys/class/net/wlan0/address"
        $s8 = "_preferences_light"
        $s9 = "registration_jid"

    condition:
        1 of ($c*)
        or 5 of ($s*)
}

rule apt_malware_apk_badbazaar_loader_updater_May23: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of BadBazaar android malware that will attempt to download and execute a JAR from the C2. This rule is looking for the updater functionality contained in newer variants of the malware."
        date = "2023-05-25"
        hash1 = "fa9154eaa3df4ff4464b21c45362fd1c7fb5e68108ab350c05f2ca9f60263988"
        scan_context = "file"
        last_modified = "2023-06-13T12:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $w1 = "whoscaller.net"
        $w2 = "Whsocall Update" //note typo

        $s1 = "file is==>"
        $s2 = "new version is downloading"
        $s3 = "android.intent.action.DOWNLOAD_COMPLETE"
        $s4 = "re_version"

    condition:
        (
            // dex
            uint32be(0) == 0x6465780a or 
            // pk
            uint16be(0) == 0x504b
        )
        and 
        (
            1 of ($w*) or
            all of ($s*)
        )
}
rule apt_malware_apk_badbazaar_loader_May23_a: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detection of BadBazaar android malware that will attempt to download and execute a JAR from the C2."
        date = "2023-05-25"
        hash1 = "c5e8476fc6938a36438a433b48e80213e2251b1d4b20a9469912d628a86198b3"
        scan_context = "file"
        last_modified = "2023-06-13T12:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $c1 = "common.jar"
        $c2 = "^common[a-zA-Z0-9_]*\\.jar"
        $c3 = "common.cer"

        $s1 = "com.whatsapp.common.Community"
        $s2 = "ConfigPipe"
        $s3 = "ForwordTo"
        $s4 = "expected non-empty set of trusted certificates"
        $s5 = "Unexpected default trust managers:"
        $s6 = "DT3d2hvLmdvbGRwbHVzYXBwLm5ldA==" //b64 of C2 (remove DT3 off front)
        $s7 = "DT3Z2dsLndob3NjYWxsZXIubmV0" //b64 of C2 (remove DT3 off front)

    condition:
        (
            // dex
            uint32be(0) == 0x6465780a or 
            // pk
            uint16be(0) == 0x504b
        )
        and 2 of ($c*)
        and 3 of ($s*)
}

rule apt_malware_apk_badbazaar_variant2: EvilBamboo
{
  meta:
        author = "threatintel@volexity.com"
        date = "2022-11-29"
        description = "Strings based detection for APK malware 'BadBazaar' stage one downloader, variant two - based on metasploit stager code."
        hash1 = "28560642fe99b3e611510f5559a12eb41112f3e2b3005432f7343cb79ff47a34"
        reference = "https://www.lookout.com/blog/uyghur-surveillance-campaign-badbazaar-moonshine"
        scan_context = "file"
        last_modified = "2023-06-13T12:06Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

  strings:
        //function names
        $f1 = "copyDexFile"
        $f2 = "GetDexpath"
        $f3 = "acquireWakeLock"
        $f4 = "DexClassLoader"
        $f5 = "readAndRunStage"
        $f6 = "runStagefromTCP"
        $f7 = "initHttpsCertificates"
        $f8 = "startAsync"
        $f9 = "diagnosticshelper"
        $f10 = "ShellService"
        $f11 = "AlarmReceiver"

        //interesting strings
        $s1 = "com.whatsapp.common.Community"
        $s2 = "ConfigPipe"
        $s3 = "ForwordTo"
        //AlarmReceiver
        $s4 = "android.intent.action.BOOT_COMPLETED"
        $s5 = "android.intent.action.USER_PRESENT"
        $s6 = "android.intent.action.SCREEN_ON"
        //ShellService 2nd stage jar method execution
        $s7 = "HandleMessage"
        //ModifyConfig
        $s8 = "ModifyConfig"
        $s9 = "address"
        $s10 = "port1"
        $s11 = "port2"

  condition:
        (
            // dex
            uint32be(0) == 0x6465780a or 
            // pk
            uint16be(0) == 0x504b
        )
        and 6 of ($f*)
        and any of ($s*)
}

rule apt_delivery_web_js_jmask_str_array_variant: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-06-27"
        description = "Detects the JMASK profiling script in an obfuscated format using a string array and an offset."
        hash1 = "7995c382263f8dbbfc37a9d62392aef8b4f89357d436b3dd94dea842f9574ecf"
        scan_context = "file"
        last_modified = "2023-09-21T09:38Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $array_1 = "http://eular.github.io"
        $array_2 = "stun:stun.services.mozilla.com"
        $array_3 = "\xE6\x9C\xAA\xE5\xAE\x89\xE8\xA3\x85MetaMask"
        $array_4 = "/jquery/jquery.min.js"
        $array_5 = "onicecandidate"

        $ios_1 = "['a7', '640x1136', [_0x"
        $ios_2 = "['a7', _0x"
        $ios_3 = "['a8', _0x"
        $ios_4 = "['a8', '750x1334', ['iPhone\\x206']]"
        $ios_5 = "['a8', '1242x2208', ['iPhone\\x206\\x20Plus']]"
        $ios_6 = "['a8', _0x"
        $ios_7 = "['a9', _0x"
        $ios_8 = "['a9', '750x1334', [_0x"
        $ios_9 = "['a9', '1242x2208', ['iPhone\\x206s\\x20Plus']]"
        $ios_10 = "['a9x', '2048x2732', ['iPad\\x20Pro\\x20(1st\\x20gen\\x2012.9-inch)']]"
        $ios_11 = "['a10x', '1668x2224', [_0x"

        $header = "info = {}, finished = 0x0;"

    condition:
        3 of ($array_*) or
        5 of ($ios_*) or
        $header
}

rule apt_delivery_web_js_jmask: EvilBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the JMASK profiling script in its minified // obfuscated format."
        date = "2023-06-15"
        hash1 = "efea95720853e0cd2d9d4e93a64a726cfe17efea7b17af7c4ae6d3a6acae5b30"
        scan_context = "file"
        last_modified = "2023-09-21T09:38Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $rev0 = "oi.buhtig.ralue//:ptth" ascii
        $rev1 = "lairA' xp41" ascii
        $rev2 = "dnuof ton ksaMateM" ascii

        $unicode1 = "document[\"\\u0063\\u0075\\u0072\\u0072\\u0065\\u006e\\u0074\\u0053\\u0063\\u0072\\u0069\\u0070\\u0074\"]" ascii
        $unicode2 = "\\u0061\\u0070\\u0070\\u006c\\u0069\\u0063\\u0061\\u0074\\u0069\\u006f\\u006e\\u002f\\u006a\\u0073\\u006f\\u006e" ascii
        $unicode3 = "\\u0063\\u006c\\u0069\\u0065\\u006e\\u0074\\u0057\\u0069\\u0064\\u0074\\u0068" ascii
        $unicode4 = "=window[\"\\u0073\\u0063\\u0072\\u0065\\u0065\\u006e\"]" ascii

        $header = "(function(){info={};finished=" ascii
    condition:
        all of ($rev*) or
        all of ($unicode*) or
        $header
}