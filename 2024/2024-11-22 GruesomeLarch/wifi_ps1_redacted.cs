Add-Type -Language CSharp @""
using System;
using System.Runtime.InteropServices;

namespace a1
{
    public static class a2
    {
        [DllImport(""Wlanapi.dll"")]
        public static extern uint WlanOpenHandle(
            uint dwClientVersion,
            IntPtr pReserved,
            out uint pdwNegotiatedVersion,
            out IntPtr phClientHandle
        );

        [DllImport(""Wlanapi.dll"")]
        public static extern uint WlanEnumInterfaces(
            IntPtr hClientHandle,
            IntPtr pReserved,
            out IntPtr ppInterfaceList
        );

        [DllImport(""wlanapi.dll"")]
        public static extern int WlanSetProfileEapXmlUserData(
            [In] IntPtr clientHandle,
            [In, MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid,
            [In, MarshalAs(UnmanagedType.LPWStr)] string profileName,
            uint dwFlags,
            [In, MarshalAs(UnmanagedType.LPWStr)] string userDataXML,
            IntPtr reservedPtr
        );

        public enum WLAN_INTERFACE_STATE
        {
            wlan_interface_state_not_ready = 0,
            wlan_interface_state_connected = 1,
            wlan_interface_state_ad_hoc_network_formed = 2,
            wlan_interface_state_disconnecting = 3,
            wlan_interface_state_disconnected = 4,
            wlan_interface_state_associating = 5,
            wlan_interface_state_discovering = 6,
            wlan_interface_state_authenticating = 7
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WLAN_INTERFACE_INFO
        {
            public Guid InterfaceGuid;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strInterfaceDescription;

            public WLAN_INTERFACE_STATE isState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WLAN_INTERFACE_INFO_LIST
        {
            public uint dwNumberOfItems;
            public uint dwIndex;
            public WLAN_INTERFACE_INFO[] InterfaceInfo;

            public WLAN_INTERFACE_INFO_LIST(IntPtr ppInterfaceList)
            {
                dwNumberOfItems = (uint)Marshal.ReadInt32(ppInterfaceList, 0);
                dwIndex = (uint)Marshal.ReadInt32(ppInterfaceList, 4);
                InterfaceInfo = new WLAN_INTERFACE_INFO[dwNumberOfItems];

                for (int i = 0; i < dwNumberOfItems; i++)
                {
                    var interfaceInfo = new IntPtr(ppInterfaceList.ToInt64() + 8 + (Marshal.SizeOf<WLAN_INTERFACE_INFO>() * i));
                    InterfaceInfo[i] = Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(interfaceInfo);
                }
            }
        }

        public static void a3()
        {
            var clientHandle = IntPtr.Zero;
            var interfaceList = IntPtr.Zero;
            uint negotiatedVersion;

            System.Console.Write("{0}\n", WlanOpenHandle(2, IntPtr.Zero, out negotiatedVersion, out clientHandle));
            System.Console.Write("{0}\n", WlanEnumInterfaces(clientHandle, IntPtr.Zero, out interfaceList));

            if (interfaceList == IntPtr.Zero) return;

            var interfaceInfoList = new WLAN_INTERFACE_INFO_LIST(interfaceList);
            string userXML = System.IO.File.ReadAllText("[REDACTED_PATH]\\acc.xml");

            System.Console.Write("{0}\n", WlanSetProfileEapXmlUserData(
                clientHandle, 
                interfaceInfoList.InterfaceInfo[0].InterfaceGuid, 
                "[REDACTED_WIFI_NETWORK_NAME]", 
                0, 
                userXML, 
                IntPtr.Zero
            ));
        }
    }
}
""@
