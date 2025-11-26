#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectNameInformation = 1,
    ObjectTypeInformation = 2,
    ObjectTypesInformation = 3,
    ObjectHandleFlagInformation = 4,
    ObjectSessionInformation = 5,
    ObjectSessionObjectInformation = 6,
    MaxObjectInfoClass
} OBJECT_INFORMATION_CLASS;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION {
    BOOLEAN Inherit;
    BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, * POBJECT_HANDLE_FLAG_INFORMATION;

typedef NTSTATUS(NTAPI* PNtSetInformationObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength
    );

DWORD FindNotepadPID()
{
    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(pe);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"notepad.exe") == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    return 0;
}

int main()
{
    DWORD pid = FindNotepadPID();
    if (!pid) {
        printf("notepad.exe not found.\n");
        return 1;
    }

    printf("[+] notepad PID = %lu\n", pid);

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Got PROCESS_ALL_ACCESS handle: %p\n", h);

    // resolve NtSetInformationObject
    PNtSetInformationObject NtSetInformationObject = (PNtSetInformationObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationObject");

    if (!NtSetInformationObject) {
        printf("GetProcAddress for NtSetInformationObject failed.\n");
        return 1;
    }

    OBJECT_HANDLE_FLAG_INFORMATION info = { 0 };
    info.Inherit = FALSE;
    info.ProtectFromClose = TRUE;

    NTSTATUS status = NtSetInformationObject(h, ObjectHandleFlagInformation, &info, sizeof(info));

    if (status != 0) {
        printf("NtSetInformationObject failed: 0x%08X\n", status);
        CloseHandle(h);
        return 1;
    }

    printf("[+] ProtectFromClose ENABLED on handle %p\n", h);

    // getchar();
    printf("[*] Testing CloseHandle...\n");
    BOOL ok = CloseHandle(h);
    // getchar();

    printf("CloseHandle returned: %d, GetLastError=%lu\n", ok, GetLastError());
    printf("Expected failure: STATUS_HANDLE_NOT_CLOSABLE\n");

    return 0;
}
