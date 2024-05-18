// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>

extern "C" BOOL WINAPI _DllMainCRTStartup(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH &&
        GetProcAddress(hModule, "DLLHijackTest_PostBuild") == NULL)
    {
        WCHAR szWho[MAX_PATH];
        GetModuleFileName(hModule, szWho, MAX_PATH);
        int ret = MessageBoxW(NULL,
            L"Shit happens. Do you want to know the details?", szWho, MB_YESNOCANCEL);
        // Loader lock issues can happen, but installers can also silently kill threads.
        // Therefore, go without a dedicated thread for the UACSelfElevation dialog.
        return ret != IDYES ? ret == IDNO :
            wWinMain(hModule, NULL, lstrcpyW(szWho, L"DLLHijackTest"), SW_SHOWNORMAL) != IDABORT;
    }
    return TRUE;
}

static void CreateProxyFor(LPCSTR name)
{
    char path[MAX_PATH];
    char *end = path + GetSystemDirectoryA(path, MAX_PATH);
    *end++ = '\\';
    lstrcpyA(end, name);

    if (HMODULE const hModule = LoadLibraryExA(path, NULL, LOAD_LIBRARY_AS_DATAFILE))
    {
        BYTE* const pORG = reinterpret_cast<BYTE*>(reinterpret_cast<INT_PTR>(hModule) & ~1);
        IMAGE_DOS_HEADER const* const pMZ = reinterpret_cast<IMAGE_DOS_HEADER const*>(pORG);
        IMAGE_NT_HEADERS const* const pPE = reinterpret_cast<IMAGE_NT_HEADERS const*>(pORG + pMZ->e_lfanew);

        if (pPE->FileHeader.SizeOfOptionalHeader != sizeof pPE->OptionalHeader)
            FatalAppExitA(0, "mismatched bitness");

        IMAGE_SECTION_HEADER const* pSH = IMAGE_FIRST_SECTION(pPE);
        WORD nSH = pPE->FileHeader.NumberOfSections;
        DWORD offset = pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        // Search for the section which contains the offset at hand
        while ((pSH->VirtualAddress > offset || pSH->VirtualAddress + pSH->Misc.VirtualSize <= offset) && --nSH)
            ++pSH;

        if (nSH == 0)
            FatalAppExitA(0, "section not found");

        BYTE const* const pRD = pORG == reinterpret_cast<BYTE*>(hModule) ? pORG : pORG + pSH->PointerToRawData - pSH->VirtualAddress;
        IMAGE_EXPORT_DIRECTORY const* const pEAT = reinterpret_cast<IMAGE_EXPORT_DIRECTORY const*>(pRD + offset);
        ULONG const* const rgAddressOfNames = reinterpret_cast<ULONG const*>(pRD + pEAT->AddressOfNames);
        USHORT const* const rgAddressOfNameOrdinals = reinterpret_cast<USHORT const*>(pRD + pEAT->AddressOfNameOrdinals);
        BYTE* const rgfUsedOrdinals = static_cast<BYTE*>(LocalAlloc(LPTR, USHRT_MAX + 1));

        char* dot = end;
        while (*dot != '.') ++dot;
        dot[1] = 'c';
        dot[2] = '\0';

        char cmd[1024];
        wsprintfA(cmd, "cl %s /link /dll /out:%s dllmain.obj "
            "CppUACSelfElevation.obj CppUACSelfElevation.res "
            "kernel32.lib user32.lib advapi32.lib", end, name);

        HFILE file = _lcreat(end, 0);
        dot[1] = '\0';

        while (end > path) if (*--end == '\\') *end = '/';

        for (DWORD i = 0; i < pEAT->NumberOfNames; ++i)
        {
            name = reinterpret_cast<LPCSTR>(pRD + rgAddressOfNames[i]);
            DWORD j = rgAddressOfNameOrdinals[i];
            rgfUsedOrdinals[j] = TRUE;
            char line[1024];
            int length = wsprintfA(line, "#pragma comment(linker, \"/export:%s=%s%s,@%u\")\n", name, path, name, j + pEAT->Base);
            _lwrite(file, line, length);
        }

        // Ensure a consecutive sequence of ordinals by filling in the gaps
        for (DWORD j = 0; j < pEAT->NumberOfFunctions; ++j)
        {
            if (rgfUsedOrdinals[j])
                continue;
            char line[1024];
            int length = wsprintfA(line, "#pragma comment(linker, \"/export:%u=KERNEL32.DebugBreak,@%u\")\n", j, j + pEAT->Base);
            _lwrite(file, line, length);
        }

        _lclose(file);

        LocalFree(rgfUsedOrdinals);

        WinExec(cmd, SW_SHOWNORMAL);
    }
}

void WINAPI DLLHijackTest_PostBuild(HWND, HINSTANCE, LPSTR lpCmdLine, int)
{
    if (IsDebuggerPresent())
    {
        CreateProxyFor(lpCmdLine);
        return;
    }

    SetCurrentDirectoryA(lpCmdLine);
    CreateProxyFor("authz.dll");
    CreateProxyFor("bcrypt.dll");
    CreateProxyFor("d3d9.dll");
    CreateProxyFor("d3d11.dll");
    CreateProxyFor("d3d12.dll");
    CreateProxyFor("dwmapi.dll");
    CreateProxyFor("DWrite.dll");
    CreateProxyFor("dxgi.dll");
    CreateProxyFor("IPHLPAPI.DLL");
    CreateProxyFor("MPR.DLL");
    CreateProxyFor("ncrypt.dll");
    CreateProxyFor("setupapi.dll");
    CreateProxyFor("sfc.dll");
    CreateProxyFor("userenv.dll");
    CreateProxyFor("uxtheme.dll");
    CreateProxyFor("version.dll");
    CreateProxyFor("winhttp.dll");
    CreateProxyFor("winmm.dll");
}
