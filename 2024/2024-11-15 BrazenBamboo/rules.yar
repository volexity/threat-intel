rule apt_malware_win_deepdata_module: BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects modules used by DEEPDATA based on the required export names used by those modules."
        date = "2024-07-30"
        hash1 = "c782346bf9e5c08a0c43a85d4991f26b0b3c99c054fa83beb4a9e406906f011e"
        os = "win"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-11-14T11:42:20Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10868
        version = 2

    strings:
        $str1 = "ExecuteCommand"
        $str2 = "GetPluginCommandID"
        $str3 = "GetPluginName"
        $str4 = "GetPluginVersion"

    condition:
        all of them
}
rule apt_malware_macos_lightspy_orchestrator_decoded_log_strings : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the decoded LIGHTSPY orchestrator used for macOS samples. This is the core component of the malware that loads and executes the malicious plugins. This rule focuses on the unique log strings present in the binary."
        date = "2024-02-20"
        hash1 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
        os = "darwin"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-07-03T13:28:27Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10254
        version = 2

    strings:
        $s1 = "+[Db updateTable:]"
        $s2 = "[%s][%s][%d]Enter createConfigTable"
        $s3 = "+[DbConfig"
        $s4 = "[%s][%s][%d]Init Db ERROR"
        $s5 = "Enter Start!!!!!" fullword
        $s6 = "select * from t_config where key=\"%@\""
        $s7 = "+[DeviceID"
        $s8 = "***********Enter LoadPluginList*************" fullword
        $s9 = "***********Leave LoadPluginList*************" fullword
        $s10 = "+[PluginAdapter"
        $s11 = "Load Plugin List error!" fullword
        $s12 = "[%s][%s][%d]down load file err:%@"
        $s13 = "+[DbCommandPlan"
        $s14 = "select * from t_command_plan"
        $s15 = "[%s][%s][%d]****seek=%zu****" fullword
        $s16 = "+[LightLog" fullword
        $s17 = "[%s][%s][%d]*******start sendCommnadOver*****************"

    condition:
        uint32(0) == 0xfeedfacf
        and 4 of ($s*)
}
rule apt_malware_macos_lightspy_orchestrator_decoded : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the decoded LIGHTSPY orchestrator used for macOS samples. This is the core component of the malware that loads and executes the malicious plugins."
        date = "2024-02-20"
        hash1 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
        os = "darwin"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-07-03T13:28:30Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10253
        version = 2

    strings:
        $s1 = "start:ipaddr:port:param:" fullword
        $s2 = "sendLogWithCmd:" fullword
        $s3 = "Destroyexe" fullword
        $s4 = "DealExeCommand" fullword
        $s5 = "uploadPluginVersion" fullword
        $s6 = "DealCommandPlan" fullword
        $s7 = "getMobileInfoJsonData" fullword
        $s8 = "updateDormantConfig" fullword
        $s9 = "lightPermission" fullword
        $s10 = "wss://%@:%@/android_ws/%@/%@/S10|%@"
        $s11 = "lightCmd:" fullword
        $s12 = "DownPluginTask" fullword
        $s13 = "LoadALLPlugin" fullword
        $s14 = "getUpdateSuccessPlugin" fullword
        $s15 = "{\"cmd\":%d,\"data\":%@}"
        $s16 = "wss://%@:%@/android_ws/%@/%@/S10|%@"

        $typo = "forceUpdatePligin"

        $dev1 = "/Users/air/work/"
        $dev2 = "F_Warehouse/mac/frame/framework/framework/"
        $dev3 = "com.myapp.udid.light" fullword

    condition:
        uint32(0) == 0xfeedfacf
        and (
            1 of ($typo*)
            or 1 of ($dev*)
            or 4 of ($s*)
        )
}
rule apt_malware_macos_lightspy_lightloader_decoded : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the decoded LIGHTSPYLOADER used for macOS samples. Based on the strings this seems to contain substantial copy and paste from a previous malware loader related to IRC."
        date = "2024-02-20"
        hash1 = "24cf61f172c94943079970af57f25ae50fee5f54797be045ef6eeeaefeaf4582"
        os = "darwin"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-07-03T13:28:24Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10252
        version = 3

    strings:
        $s1 = "macircloader"
        $s2 = "IrcFrameworkInfo"
        $s3 = "-[FrameworkLoader" //followed by the 5 below strings, tokenising for better matching
        $s4 = "downloadFramework:]"
        $s5 = "onDownloadVersionFileFinished:path:]"
        $s6 = "unloadFrameworkInternal]"
        $s7 = "loadFrameworkInternalFromPath:]"
        $s8 = "moveFrameworkFile:]"
        $s9 = "\"fileName\"@\"NSString\""
        $s10 = "dlclose framework error: %s"

        $dev1 = "/Users/air/work/znf_ios/mac/frame/macircloader/macircloader/Downloader.mm"

    condition:
        uint32(0) == 0xfeedfacf
        and $dev1
        or 4 of ($s*)
}
rule apt_malware_macos_lightspy_plist : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the plist file created by the macOS variant of LIGHTSPY as part of its execution."
        date = "2024-02-20"
        hash1 = "23d0b9ae73145106cffe56719526801e024092cd6d25b9628ae3d9995b0b5395"
        os = "darwin"
        os_arch = "all"
        scan_context = "file"
        severity = "high"
        last_modified = "2024-07-03T13:28:33Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10251
        version = 2

    strings:
        $s1 = "com.apple.update_tmp_agent"
        $s2 = "/Applications/AppleUpdates/update"
        $s3 = "<key>RunAtLoad</key>"

    condition:
        filesize < 1KB
        and all of ($s*)
}
rule apt_malware_macos_lightspy_json_version : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the JSON version file used by the macOS variant of the LightSpy malware family."
        date = "2024-02-15"
        hash1 = "862ab98280ced3f1dcf63699a1b690be4039e848dc0f440b8b306cf63c474090"
        os = "all"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-07-03T13:28:36Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10249
        version = 2

    strings:
        $date = {7b 22 64 61 74 65 22 3a 22 32 30} //{"date":"20
        $filename = {22 2c 22 66 69 6c 65 6e 61 6d 65 22 3a 22} //","filename":"

    condition:
        filesize < 1KB
        and $date at 0
        and $filename
}
rule apt_malware_macos_lightspy_json_manifest : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the JSON manifest file used by the macOS variant of the LightSpy malware family."
        date = "2024-02-15"
        hash1 = "0482a09ed546229c691c659498ffba2d2164de792dea74fdc3a373be22f940dd"
        os = "darwin"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-07-03T13:28:39Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10248
        version = 2

    strings:
        $cmd = {7b 22 73 74 61 74 75 73 22 3a 20 22 30 22 2c 20 22 63 6d 64 22 3a 20 22 3?} //{"status": "0", "cmd": "[1-9]

    condition:
        filesize < 5KB
        and $cmd at 0
}
rule apt_malware_win_lightspy_json_manifest_decoded : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the decoded JSON manifest file used by the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server."
        date = "2024-02-15"
        hash1 = "f8f90f1f96679f583bea6592b20980acfe2d402be79fc7cf55b78e06b0afc3e6"
        os = "all"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-07-03T13:28:41Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10247
        version = 2

    strings:
        $cmd = {7b22636d64223a3?} //{"cmd":[1-9]

    condition:
        filesize < 5KB
        and $cmd at 0
}
rule apt_malware_win_lightspy_orchestrator_decoded_core : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the decoded orchestrator for the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server and is used as the core component of this malware family, loading additional plugins from the C2 whilst managing all the C2 communication etc."
        date = "2024-02-15"
        hash1 = "80c0cdb1db961c76de7e4efb6aced8a52cd0e34178660ef34c128be5f0d587df"
        os = "win"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-07-03T13:31:30Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10246
        version = 2

    strings:
        $s1 = "Enter RunWork......."
        $s2 = "it's running......."
        $s3 = "select ret = socket_error."
        $s4 = "%s\\\\account.bin"
        $s5 = "[CtrlLink]: get machine sn err:%d"
        $s6 = "wmic path Win32_VideoController get CurrentHorizontalResolution,CurrentVerticalResolution /format:list | findstr /v \\\"^$\\\""
        $s7 = "wmic csproduct get vendor,version /format:list | findstr /v \\\"^$\\\""
        $s8 = "local ip get sockname error=%d"
        $s9 = "connect goole dns error=%d"
        $s10 = "%s/api/terminal/upsert/"
        $s11 = "/963852741/windows/plugin/manifest"
        $s12 = "Hello deepdata."
        $s13 = "Start Light."
        $s14 = "InitialPluginManager Error."
        $s15 = "InitialCommandExe Error."
        $s16 = "ws open, and send logon info."
        $s17 = "plugin_replay_handler"
        $s18 = "light_x86.dll"

        $pdb1 = "\\light\\bin\\light_x86.pdb" // D:\\tmpWork\\light\\bin\\light_x86.pdb
        $pdb2 = "\\light\\bin\\plugin" // D:\tmpWork\light\bin\plugin\x64\SoftInfo.pdb
        $pdb3 = "D:\\tmpWork\\"

    condition:
        1 of ($pdb*)
        or 5 of ($s*)
}
rule apt_malware_win_lightspy_orchestrator_decoded_C2_strings: BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the decoded orchestrator for the Windows variant of the LightSpy malware family. This file is normally stored in an encoded state on the C2 server and is used as the core component of this malware family, loading additional plugins from the C2 whilst managing all the C2 communication etc."
        date = "2024-02-15"
        hash1 = "80c0cdb1db961c76de7e4efb6aced8a52cd0e34178660ef34c128be5f0d587df"
        os = "win"
        os_arch = "all"
        scan_context = "file,memory"
        severity = "critical"
        last_modified = "2024-11-14T11:48:37Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10245
        version = 4

    strings:
        $s1 = "[WsClient][Error]:"
        $s2 = "[WsClient][Info]:"
        $s3 = "[WsClient]:WsClient"
        $s4 = "[WsClient][Info]:Ws"
        $s5 = "WsClient Worker Thread ID=%d"
        $s6 = "[LightWebClient]:"
        $s7 = "LightHttpGet err:%s"
        $s8 = "User-Agent: Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.145 Safari/537.36"
        $s9 = "KvList Err:%s"
        $s10 = "dataMultiPart malloc err:%d"

        $ctrl1 = "CTRL_HEART_BEAT"
        $ctrl2 = "CTRL_NET_CONFIG"
        $ctrl3 = "CTRL_COMMAND_PLAN"
        $ctrl4 = "CTRL_MODIFY_NET_CONFIG"
        $ctrl5 = "CTRL_UPLOAD_PLUGIN_STATUS"
        $ctrl6 = "CTRL_PLUGIN_EXECUTE_COMMAND"
        $ctrl7 = "CTRL_PLUGIN_COMMAND_STATUS"
        $ctrl8 = "CTRL_PLUGIN_STOP_COMMAND"
        $ctrl9 = "CTRL_GET_SLEEP_CONFIG"
        $ctrl10 = "CTRL_MODIFY_SLEEP_CONFIG"
        $ctrl11 = "CTRL_SLEEP_STATUS"
        $ctrl12 = "CTRL_UPDATE_PLUGIN"
        $ctrl13 = "CTRL_DESTROY"
        $ctrl14 = "CTRL_RECONFIG_REBOUNT_ADDRESS"
        $ctrl15 = "CTRL_AUTO_UPLOUD_FILE_CONFIG"
        $ctrl16 = "CTRL_UPLOUD_DEVICE_INFO"
        $ctrl17 = "CTRL_TEST_VPDN_ACCOUNT"

     condition:
        3 of ($s*)
        or 5 of ($ctrl*)
}
rule apt_malware_windows_deepdata_plugin : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects generic strings across multiple DEEPDATA plugins, a malware family from the BrazenBamboo threat actor."
        date = "2024-08-13"
        hash1 = "55e2dbb906697dd1aff87ccf275efd06ee5e43bb21ea7865aef59513a858cf9f"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-08-14T14:20:07Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10907
        version = 1

    strings:

        $s1 = "[ExecuteCommand]do not support this command %d."
        $s2 = "[ExecuteCommand]input cmd %d error."
        $s3 = "[ExecuteCommand]ExecuteCommand start."

    condition:
        uint16be(0) == 0x4d5a
        and 2 of ($s*)
}
rule apt_malware_windows_deepdata_outlook_plugin : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the Outlook plugin used by the DEEPDATA malware family from the BrazenBamboo threat actor. This rule focusses on unique strings contained within the binary."
        date = "2024-08-13"
        hash1 = "2bfb82a43bb77127965a4011a87de845242b1fb98fd09085885be219e0499073"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-11-14T11:49:09Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10906
        version = 2

    strings:
        $outlook1 = "[Export]Initialize Outlook Client Fail.%x"
        $outlook2 = "%s\\contacts.json"
        $outlook3 = "%s\\%d.eml"
        $outlook4 = "zyx test uninitialize start"
        $outlook5 = "Content-Type: multipart/mixed; boundary=\"----=_Part_230455_121547330.1338211917447\";"
        $outlook6 = "Initialize Outlook Client Fail"
        $outlook7 = "[ExecuteCommand]OutLook Plugin command exectue %d success"
        $outlook8 = "[read folder message list succeed; message number:"

    condition:
        uint16be(0) == 0x4d5a
        and 4 of ($outlook*)
}
rule apt_malware_windows_deepdata_accountinfo_plugin : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the AccountInfo plugin used by the DEEPDATA malware family from the BrazenBamboo threat actor. Sometimes called the Pass plugin. This rule focused on unique strings contained within the binary."
        date = "2024-08-13"
        hash1 = "041c13a29d3bee8d2e4bd9d8bde8152b5ac8305c1efcc198244b224e33635282"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-08-14T14:18:29Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10905
        version = 1

    strings:
        $account1 = "[InitForwardAndCall]"
        $account2 = "[InitRemoteCall]"
        $account3 = "[GetBaiduNetDiskLoginUrl]"
        $account4 = "[Cmd_BaiduNetDisk_GetLoginUrl]"
        $account5 = "[DBVisualizer.GetAccountsInfo]"
        $account6 = "[Cmd_DBVisualizer_GetAccountsInfo]"
        $account7 = "[Cmd_FoxMail_GetAccountsInfo]"
        $account8 = "[Cmd_KeePass_GetAccountsInfo]"
        $account9 = "[KeePass.SaveFileFromResource]"
        $account10 = "[Cmd_Windows_GetInfo]"
        $account11 = "SELECT hex(value) FROM AccountConfig WHERE"
        $account12 = "[Cmd_MailMaster_GetAccountsInfo]"
        $account13 = "[Cmd_OneDrive_GetToken]"
        $account14 = "[OpenSSH.GetAccountsInfo]"
        $account15 = "[Cmd_UploadAccountInfo]"
        $account16 = "api/third/windows/accountInfo/upload/"
        $account17 = "[Cmd_QQ_GetAccountsInfo]"
        $account18 = "[SquirrelSQL.GetAccountsInfo]"

    condition:
        uint16be(0) == 0x4d5a
        and 4 of ($account*)
}
rule apt_malware_win_deepdata_socialsoft_plugin : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the SocialSoft plugin used by the DEEPDATA malware family from the BrazenBamboo threat actor. This rule focused on unique strings contained within the binary."
        date = "2024-08-13"
        hash1 = "c3995f28476f7a775f4c1e8be47c64a300e0f16535dc5ed665ba796f05f19f73"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2025-01-29T16:27:27Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10904
        version = 2

    strings:
        $social1 = "execute cmd=%d, detail=%s in module."
        $social2 = "CommSocialSoft do not support this command %d"
        $social3 = "execute cmd=%d complete."
        $social4 = "get user dingding root dir error."
        $social5 = "Feishu software FindUserDirOnApp error."
        $social6 = "startTime=%u,stopTime=%u,maxFileSize=%u,fileExt=%s"
        $social7 = "open wechat.exe error=%d."
        $social8 = "rundll32.exe %s TelegramKey64"
        $social9 = "Enter UploadQQFileData."
        $social10 = "SHGetFolderPathW, get user skype dir error=%d."
        $social11 = "PackDirFileToZipEx_Call para error."
        $social12 = "BruteFindWxKey find wx key error=%d."
        $social13 = "GetWechatBaseInfo success, WxID=%s."
        $social14 = "TelegramKey64"

    condition:
        uint16be(0) == 0x4d5a
        and 4 of ($social*)
}
rule apt_malware_windows_deepdata_systeminfo_plugin : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the SystemInfo plugin used by the DEEPDATA malware family from the BrazenBamboo threat actor. This rule focused on unique strings contained within the binary."
        date = "2024-08-13"
        hash1 = "213520170fc7113ac8f5e689f154f5c8074dd972584b56d820c19d84b7e5b477"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-08-14T14:17:25Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10903
        version = 1

    strings:
        $sysinfo1 = "[GetSessionListJSON]cJSON_CreateArray sessionList fail."
        $sysinfo2 = "[GetDriverListJSON]EnumDeviceDrivers failed:%d"
        $sysinfo3 = "[CMD_GetDriverListJSON]get driver list start"
        $sysinfo4 = "[Cmd_KeePass_GetAccountsInfo] SaveFileFromResource exe error"
        $sysinfo5 = "[CMD_GetEventLogListJSON]"
        $sysinfo6 = "[GetPortListJSON]CreateToolhelp32Snapshot error:%d"
        $sysinfo7 = "PrimaryWinsServerAddr"
        $sysinfo8 = "[ExecuteGetServiceList]schManager is NULL, ErrorCode:%d"
        $sysinfo9 = "[ExecuteStartService]service is stop."
        $sysinfo10 = "SocialSoftTest"
        $sysinfo11 = "[GetEventLogJSON_Merge]RegOpenKeyEx call failed : %ws, error code:%d"

        $api1 = "api/third/windows/driver/list/"
        $api2 = "api/third/windows/ipconfigall/list/"
        $api3 = "api/third/windows/session/list/"
        $api4 = "api/third/windows/port/list/"
        $api5 = "api/third/windows/process/list/"
        $api6 = "aapi/third/windows/service/list/"
        $api7 = "api/third/windows/user/list/"

    condition:
        uint16be(0) == 0x4d5a
        and (
            4 of ($sysinfo*)
            or 3 of ($api*)
        )
}
rule apt_malware_win_deepdata_tdmonitor_plugin: BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the Tdmonitor plugin used by the DEEPDATA malware family from the BrazenBamboo threat actor. This rule focused on unique strings contained within the binary."
        date = "2024-08-13"
        hash1 = "3927220878bae3a39bed8d9f2db27d2856a752d132ec10a9e4b58703185196f5"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2025-01-29T16:27:20Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10902
        version = 2

    strings:
        $tdm1 = "{\"cmd\":65002,\"status\":2}"
        $tdm2 = "%s send cmd over,reason: %s"
        $tdm3 = "td-pl-manager"
        $tdm4 = "%s try connect to plugin"
        $tdm5 = "%s s0 Telegram process not found."
        $tdm6 = "%s s2 target process is X"
        $tdm7 = "%s s3 Telegram process has been injected"
        $tdm8 = "%s s4 dll load addr: %llx"
        $tdm9 = "%s account dir is not finished: %s, db: %d,cache: %d,finish: %d"
        $tdm10 = "%s dll download failed,version suffix: %s,try again"
        $tdm11 = "%s start execute td cmd id: %d,cmd: %s,cwd: %s"
        $tdm12 = "%s command content too short,cancel"
        $tdm13 = "td plugin Soft UnInitial"

    condition:
        uint16be(0) == 0x4d5a
        and 4 of ($tdm*)
}
rule apt_malware_windows_deepdata_webbrowser_plugin : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the WebBrowser plugin used by the DEEPDATA malware family from the BrazenBamboo threat actor. This rule focused on unique strings contained within the binary."
        date = "2024-08-13"
        hash1 = "b523cdd1669dbd7ab68b43fd20f30a790ec0351876a0610958b9405468753a10"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-08-14T14:16:15Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10901
        version = 1

    strings:
        $webbrowser1 = "SELECT name, encrypted_value, host_key, path, creation_utc, expires_utc, last_access_utc, is_secure, is_httponly, has_expires, is_persistent FROM cookies"
        $webbrowser2 = "encrypted_key_with_header_len <= 0:%s"
        $webbrowser3 = "%s\\ChromeCookies.db"
        $webbrowser4 = "Cookies File is not exist:%s."
        $webbrowser5 = "force copy file %s error=%d,process_name=%s."
        $webbrowser6 = "%s\\ChromeHistory.db"
        $webbrowser7 = "[GetChromeBrowerHistory] file is not exist:%s"
        $webbrowser8 = "[GetChromeBrowerPassword] file is not exist:%s"
        $webbrowser9 = "[GetChromeBrowerData] SpecialFolderPath = %s"
        $webbrowser10 = "[GetFirefoxBrowerCookies] cookies path is not exist:%s"
        $webbrowser11 = "[GetFirefoxBrowerHistory] history path is not exist:%s"
        $webbrowser12 = "[WebBrowser] Start to Get FireFox Browser Info"

    condition:
        uint16be(0) == 0x4d5a
        and 4 of ($webbrowser*)
}
rule apt_malware_windows_deepdata_wifilist_plugin : BrazenBamboo
{
    meta:
        author = "threatintel@volexity.com"
        description = "Detects the WifiList plugin used by the DEEPDATA malware family from the BrazenBamboo threat actor. This rule focused on unique strings contained within the binary."
        date = "2024-08-13"
        hash1 = "460f1a00002e1c713a7753293b4737e65d27d0b65667b109d66afca873c23894"
        os = "win"
        os_arch = "all"
        scan_context = "file"
        severity = "critical"
        last_modified = "2024-08-14T14:15:41Z"
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
        rule_id = 10900
        version = 1

    strings:
        $wifi1 = "WiFi Tool GetPluginCommandID"
        $wifi2 = "Commom Social Soft" //Various commands follow this string
        $wifi3 = "WiFi Tool ExecuteCommand"
        $wifi4 = "Start get wifi key list."
        $wifi5 = "Start get nearby wifi list"
        $wifi6 = "%s\\%s_wifiList.json"
        $wifi7 = "Waiting for scan nearby wifi.(4s)"
        $wifi8 = "Getting wifi key list wrong."
        $wifi9 = "Couldnot negotiaite client version" //note typos

    condition:
        uint16be(0) == 0x4d5a
        and 4 of ($wifi*)
}
