#include <Windows.h>
#include <winternl.h>

#ifndef TO_LOWERCASE
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
#endif

// enhanced version of LDR_DATA_TABLE_ENTRY
typedef struct _LDR_DATA_TABLE_ENTRY1
{
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    ULONG   SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG   Flags;
    SHORT   LoadCount;
    SHORT   TlsIndex;
    HANDLE  SectionHandle;
    ULONG   CheckSum;
    ULONG   TimeDateStamp;
} LDR_DATA_TABLE_ENTRY1, * PLDR_DATA_TABLE_ENTRY1;

static __forceinline LPVOID get_module_by_name(WCHAR* module_name)
{
    PEB* peb;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif
    PEB_LDR_DATA* ldr = peb->Ldr;

    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* current = head->Flink; current != head; current = current->Flink)
    {
        LDR_DATA_TABLE_ENTRY1* entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY1, InMemoryOrderLinks);
        if (!entry || !entry->DllBase) break;

        WCHAR* curr_name = entry->BaseDllName.Buffer;
        if (!curr_name) continue;

        size_t i;
        for (i = 0; i < entry->BaseDllName.Length; i++)
        {
            // if any of the strings finished:
            if (module_name[i] == 0 || curr_name[i] == 0)
            {
                break;
            }
            WCHAR c1, c2;
            TO_LOWERCASE(c1, module_name[i]);
            TO_LOWERCASE(c2, curr_name[i]);
            if (c1 != c2) break;
        }
        // both of the strings finished, and so far they were identical:
        if (module_name[i] == 0 && curr_name[i] == 0)
        {
            return entry->DllBase;
        }
    }

    return NULL;
}

static __forceinline LPVOID get_func_by_name(LPVOID module, char* func_name)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return NULL;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (!exportsDir->VirtualAddress)
    {
        return NULL;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++)
    {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++)
        {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0)
        {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return NULL;
}

void main()
{
    typedef HMODULE(WINAPI* _LoadLibraryW)(LPCSTR);
    typedef BOOL(WINAPI* _GetUserNameA)(LPSTR, LPDWORD);
    typedef LSTATUS(WINAPI* _RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
    typedef LSTATUS(WINAPI* _RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD);
    typedef LSTATUS(WINAPI* _RegCloseKey)(HKEY);
    typedef size_t(*_strlen)(const char*);

    HMODULE hKernel32;
    HMODULE hMsvcrt;
    HMODULE hAdvapi32;
    HKEY h_key;

    DWORD buf_len = 32;
    char user_name[32];

    WCHAR module1_name[13]; // kernel32.dll

    module1_name[0] = 'k'; module1_name[1] = 'e'; module1_name[2] = 'r';
    module1_name[3] = 'n'; module1_name[4] = 'e'; module1_name[5] = 'l';
    module1_name[6] = '3'; module1_name[7] = '2'; module1_name[8] = '.';
    module1_name[9] = 'd'; module1_name[10] = 'l'; module1_name[11] = 'l';
    module1_name[12] = '\0';

    WCHAR module2_name[11]; // msvcrt.dll

    module2_name[0] = 'm'; module2_name[1] = 's'; module2_name[2] = 'v';
    module2_name[3] = 'c'; module2_name[4] = 'r'; module2_name[5] = 't';
    module2_name[6] = '.'; module2_name[7] = 'd'; module2_name[8] = 'l';
    module2_name[9] = 'l'; module2_name[10] = '\0';

    WCHAR module3_name[13]; // advapi32.dll

    module3_name[0] = 'A'; module3_name[1] = 'd'; module3_name[2] = 'v';
    module3_name[3] = 'a'; module3_name[4] = 'p'; module3_name[5] = 'i';
    module3_name[6] = '3'; module3_name[7] = '2'; module3_name[8] = '.';
    module3_name[9] = 'd'; module3_name[10] = 'l'; module3_name[11] = 'l';
    module3_name[12] = '\0';

    char func0[13] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', '\0' }; // LoadLibraryW
    
    char func1[13] = { 'G', 'e', 't', 'U', 's', 'e', 'r', 'N', 'a', 'm', 'e', 'A', '\0' }; // GetUserNameA
    char func2[16] = { 'R', 'e', 'g', 'C', 'r', 'e', 'a', 't', 'e', 'K', 'e', 'y', 'E', 'x', 'A', '\0' }; // RegCreateKeyExA
    char func3[15] = { 'R', 'e', 'g', 'S', 'e', 't', 'V', 'a', 'l', 'u', 'e', 'E', 'x', 'A', '\0' }; // RegSetValueExA
    char func4[12] = { 'R', 'e', 'g', 'C', 'l', 'o', 's', 'e', 'K', 'e', 'y', '\0' }; // RegCloseKey
    char func5[7] = { 's', 't', 'r', 'l', 'e', 'n', '\0' }; // strlen

    hKernel32 = (HMODULE)get_module_by_name(module1_name);

    _LoadLibraryW pLoadLibraryW = (_LoadLibraryW)get_func_by_name(hKernel32, func0);
    
    // hMsvcrt = (HMODULE)get_module_by_name(module2_name);

    hMsvcrt = pLoadLibraryW(module2_name);

    hAdvapi32 = pLoadLibraryW(module3_name);

    _GetUserNameA pGetUserNameA = (_GetUserNameA)get_func_by_name(hAdvapi32, func1);
    _RegCreateKeyExA pRegCreateKeyExA = (_RegCreateKeyExA)get_func_by_name(hKernel32, func2);
    _RegSetValueExA pRegSetValueExA = (_RegSetValueExA)get_func_by_name(hKernel32, func3);
    _RegCloseKey pRegCloseKey = (_RegCloseKey)get_func_by_name(hKernel32, func4);
    _strlen pStrlen = (_strlen)get_func_by_name(hMsvcrt, func5);

    char reg_path[21] = {
        'S', 'O', 'F', 'T', 'W', 'A', 'R', 'E', '\\',
        'M', 'y', 'S', 'h', 'e', 'l', 'l', 'c', 'o', 'd', 'e', '\0'
    }; // SOFTWARE\MyShellcode

    char value_name[9] = { 'U', 's', 'e', 'r', 'n', 'a', 'm', 'e', '\0' }; // Username

    pGetUserNameA(user_name, &buf_len);
    pRegCreateKeyExA(HKEY_CURRENT_USER, reg_path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &h_key, NULL);
    pRegSetValueExA(h_key, value_name, 0, REG_SZ, (BYTE*)user_name, pStrlen(user_name) + 1);
    pRegCloseKey(h_key);
}