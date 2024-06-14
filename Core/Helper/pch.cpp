#define _CRT_SECURE_NO_WARNINGS

#include "pch.h"


struct offsets {
    long  block_size;
    char  block_type[2]; // "lf" "il" "ri"
    short count;
    long  first;
    long  hash;
};

struct key_block {
    long  block_size;
    char  block_type[2]; // "nk"
    char  dummya[18];
    int   subkey_count;
    char  dummyb[4];
    int   subkeys;
    char  dummyc[4];
    int   value_count;
    int   offsets;
    char  dummyd[28];
    short len;
    short du;
    char  name;
};

struct value_block {
    long  block_size;
    char  block_type[2]; // "vk"
    short name_len;
    long  size;
    long  offset;
    long  value_type;
    short flags;
    short dummy;
    char  name;
};

LPWSTR walk(char* path, key_block* key, char* targetKey, int targetKeyLen, char* targetValue, bool firstLoop) {
    static  char* root, * full;
    if (firstLoop) {
        root = (char*)key - 0x20;
        full = path;
    }

    // add current key name to printed path
    memcpy(path++, "\\", 2); memcpy(path, &key->name, key->len); path += key->len;

    *path = 0;

    int pathLen = strlen(full);

    if (pathLen >= 6 && (pathLen - 6 > targetKeyLen || !(_strnicmp(full + 6, targetKey, pathLen - 6) == 0)))
        return NULL;

    if (pathLen < 6 || pathLen - 6 < targetKeyLen || !(_strnicmp(full + 6, targetKey, targetKeyLen) == 0)) {
        // for simplicity we can imagine keys as directories in filesystem and values
        // as files.
        // and since we already dumped values for this dir we will now iterate 
        // thru subdirectories in the same way

        offsets* item = (offsets*)(root + key->subkeys);

        for (int i = 0;i < item->count;i++) {
            // in case of too many subkeys this list contain just other lists
            offsets* subitem = (offsets*)((&item->first)[i] + root);

            // usual directory traversal  
            if (item->block_type[1] == 'f' || item->block_type[1] == 'h') {
                // for now we skip hash codes (used by regedit for faster search)
                LPWSTR result = walk(path, (key_block*)((&item->first)[i * 2] + root), targetKey, targetKeyLen, targetValue, false);
                if (result != NULL)
                    return result;
                
            }
            else for (int j = 0;j < subitem->count;j++) {
                // also ms had chosen to skip hashes altogether in this case 
                LPWSTR result = walk(path, (key_block*)((&subitem->first)[item->block_type[1] == 'i' ? j * 2 : j] + root), targetKey, targetKeyLen, targetValue, false);
                if (result != NULL)
                    return result;
            }
        }

        return NULL;
    }

    long totalSize = 0;
    for (int o = 0; targetValue == NULL && o < key->value_count;o++) {
        value_block* val = (value_block*)(((int*)(key->offsets + root + 4))[o] + root);

        int length = val->size & 0xffff;
        totalSize += length;
    }

    // print all contained values
    wchar_t* unicodeResult = targetValue == NULL ? new wchar_t[totalSize] {0} : NULL;

    for (int o = 0;o < key->value_count;o++) {

        value_block* val = (value_block*)(((int*)(key->offsets + root + 4))[o] + root);

        // we skip nodes without values
        if (!val->offset)  continue;

        // data are usually in separate blocks without types
        char* data = root + val->offset + 4;
        // but for small values MS added optimization where 
        // if bit 31 is set data are contained wihin the key itself to save space
        if (val->size & 1 << 31) {
            data = (char*)&val->offset;
        }

        // notice that we use memcopy for key/value names everywhere instead of strcat
        // reason is that malware/wiruses often write non nulterminated strings to
        // hide from win32 api
        //*path = '\\'; if (!val->name_len) *path = ' ';
        //memcpy(path + 1, &val->name, val->name_len); path[val->name_len + 1] = 0;

        //printf("%s [%d] = ", full, val->value_type);

        int length = val->size & 0xffff;

        //printf("%i\n", val->value_type);

        if (val->value_type != 1 && val->value_type != 7 &&
            val->value_type != 4 && val->value_type != 11)
            continue;

        if (targetValue == NULL) {
            // print types 1 and 7 as unicode strings  
            if (val->value_type == 1 || val->value_type == 7) {
                
                char* ansiResult = new char[length + 1] {0};

                for (int i = 0; i < length; i++) {
                    char concat[1];
                    sprintf(concat, "%c", data[i]);
                    strcat(ansiResult, concat);
                }


                size_t size = strlen(ansiResult) + 1;
                wchar_t* unicodePart = new wchar_t[size];

                size_t outSize;
                mbstowcs_s(&outSize, unicodePart, size, ansiResult, size - 1);

                char* name = new char[val->name_len + 1] {0};
                memcpy(name, &val->name, val->name_len); name[val->name_len] = 0;
                
                size_t nameSize = strlen(name) + 1;
                wchar_t* unicodeName = new wchar_t[nameSize] {0};
                mbstowcs_s(&outSize, unicodeName, nameSize, name, nameSize - 1);

                if (o != 0)
                    wcscat(unicodeResult, L"\n");

                wcscat(unicodeResult, unicodeName);
                wcscat(unicodeResult, L":|:");
                wcscat(unicodeResult, unicodePart);

                delete[] ansiResult;
                delete[] unicodePart;
                delete[] name;
                delete[] unicodeName;
            }
            else {
                char* ansiResult = new char[(length * 2) + 1] {0};

                unsigned int bits[4];
                unsigned int longBits[8];

                bool skip = false;

                int i;
                for (i = 0; i < length; i++) {
                    if (length == 4) {
                        bits[i] = data[i];
                        continue;
                    }
                    if (length == 8) {
                        longBits[i] = data[i];
                        continue;
                    }

                    skip = true;
                    delete[] ansiResult;
                    break;
                    char concat[12];
                    sprintf(concat, "%02X", data[i]);
                    strcat(ansiResult, concat);
                }
                if (skip)
                    continue;

                if (length == 4) {
                    unsigned int result = (bits[0] << 24) | (bits[1] << 16) | (bits[2] << 8) | bits[3];

                    unsigned int resultat = 0;
                    char* source, * destination;
                    int i;

                    source = (char*)&result;
                    destination = ((char*)&resultat) + sizeof(unsigned int);
                    for (i = 0; i < sizeof(unsigned int); i++)
                        *(--destination) = *(source++);

                    sprintf(ansiResult, "%X", resultat);
                }
                else if (length == 8) {
                    unsigned int shortPart = (longBits[0] << 24) | (longBits[1] << 16) | (longBits[2] << 8) | longBits[3];
                    unsigned int longPart = (longBits[4] << 24) | (longBits[5] << 16) | (longBits[6] << 8) | longBits[7];
                    unsigned long long result = (long long)shortPart << 32 | longPart;

                    unsigned long long resultat = 0;
                    char* source, * destination;
                    int i;

                    source = (char*)&result;
                    destination = ((char*)&resultat) + sizeof(unsigned long long);
                    for (i = 0; i < sizeof(unsigned long long); i++)
                        *(--destination) = *(source++);

                    sprintf(ansiResult, "%I64X", resultat);
                }

                size_t size = strlen(ansiResult) + 1;
                wchar_t* unicodePart = new wchar_t[size];

                size_t outSize;
                mbstowcs_s(&outSize, unicodePart, size, ansiResult, size - 1);

                char* name = new char[val->name_len + 1] {0};
                memcpy(name, &val->name, val->name_len); name[val->name_len] = 0;

                size_t nameSize = strlen(name) + 1;
                wchar_t* unicodeName = new wchar_t[nameSize] {0};
                mbstowcs_s(&outSize, unicodeName, nameSize, name, nameSize - 1);

                if (o != 0)
                    wcscat(unicodeResult, L"\n");

                wcscat(unicodeResult, unicodeName);
                wcscat(unicodeResult, L":|:");
                wcscat(unicodeResult, unicodePart);

                delete[] ansiResult;
                delete[] unicodePart;
                delete[] name;
                delete[] unicodeName;
            }
        }
        else if (_strnicmp(targetValue, &val->name, val->name_len) == 0) {
            // print types 1 and 7 as unicode strings  
            if (val->value_type == 1 || val->value_type == 7) {
                char* ansiResult = new char[length + 1] {0};

                for (int i = 0; i < length; i++) {
                    char concat[1];
                    sprintf(concat, "%c", data[i]);
                    strcat(ansiResult, concat);
                }

                
                size_t size = strlen(ansiResult) + 1;
                unicodeResult = new wchar_t[size] {0};

                size_t outSize;
                mbstowcs_s(&outSize, unicodeResult, size, ansiResult, size - 1);

                delete[] ansiResult;
                
                return unicodeResult;
            }
            else {
                char* ansiResult = new char[(length * 2) + 1] {0};

                unsigned int bits[4];
                unsigned int longBits[8];

                int i;
                for (i = 0; i < length; i++) {
                    if (length == 4) {
                        bits[i] = data[i];
                        continue;
                    }
                    if (length == 8) {
                        longBits[i] = data[i];
                        continue;
                    }
                    delete[] ansiResult;
                    return NULL;
                }

                if (length == 4) {
                    unsigned int result = (bits[0] << 24) | (bits[1] << 16) | (bits[2] << 8) | bits[3];

                    unsigned int resultat = 0;
                    char* source, * destination;
                    int i;

                    source = (char*)&result;
                    destination = ((char*)&resultat) + sizeof(unsigned int);
                    for (i = 0; i < sizeof(unsigned int); i++)
                        *(--destination) = *(source++);

                    sprintf(ansiResult, "%X", resultat);
                }
                else if (length == 8) {
                    unsigned int shortPart = (longBits[0] << 24) | (longBits[1] << 16) | (longBits[2] << 8) | longBits[3];
                    unsigned int longPart = (longBits[4] << 24) | (longBits[5] << 16) | (longBits[6] << 8) | longBits[7];
                    unsigned long long result = (long long)shortPart << 32 | longPart;

                    unsigned long long resultat = 0;
                    char* source, * destination;
                    int i;

                    source = (char*)&result;
                    destination = ((char*)&resultat) + sizeof(unsigned long long);
                    for (i = 0; i < sizeof(unsigned long long); i++)
                        *(--destination) = *(source++);

                    sprintf(ansiResult, "%I64X", resultat);
                }
                size_t size = strlen(ansiResult) + 1;
                unicodeResult = new wchar_t[size] {0};
                
                size_t outSize;
                mbstowcs_s(&outSize, unicodeResult, size, ansiResult, size - 1);
                
                delete[] ansiResult;
                
                return unicodeResult;
            }
        }
    }
    return unicodeResult;
}



#pragma comment(lib, "rpcrt4.lib")

#define SAFE_RELEASE(x)     if (x) { x->Release(); x = NULL; }
#define SAFE_FREE(x)        if (x) { CoTaskMemFree(x); }

BSTR GetVdsDiskInterface(
    DWORD driveIndex,
    const IID InterfaceIID,
    void** pInterfaceInstance
)
{
    wchar_t result[256] = L"Unknown error.";

    HRESULT hr;

    IVdsServiceLoader* pLoader;
    IVdsService* pService;
    IUnknown* pUnk;
    IVdsAsync* pAsync;
    IEnumVdsObject* pEnum;
    ULONG ulFetched;

    wchar_t physicalName[24];
    swprintf(physicalName, ARRAYSIZE(physicalName), L"\\\\?\\PhysicalDrive%lu", driveIndex);

    // Create a loader instance
    hr = CoCreateInstance(CLSID_VdsLoader,
        NULL,
        CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
        IID_IVdsServiceLoader,
        (void**)&pLoader
    );

    wcsncpy(result, L"CoCreateInstance failed.", 256);
    if (SUCCEEDED(hr))
    {
        // Load the service on the machine.
        hr = pLoader->LoadService(NULL, &pService);
        SAFE_RELEASE(pLoader);
        pLoader = NULL;

        wcsncpy(result, L"LoadService failed.", 256);
        if (SUCCEEDED(hr))
        {
            pService->WaitForServiceReady();

            hr = pService->QueryProviders(VDS_QUERY_SOFTWARE_PROVIDERS, &pEnum);
            pService->Release();
            if (SUCCEEDED(hr)) {
                while (pEnum->Next(1, &pUnk, &ulFetched) == S_OK) {
                    IVdsProvider* pProvider;
                    IVdsSwProvider* pSwProvider;
                    IEnumVdsObject* pEnumPack;
                    IUnknown* pPackUnk;

                    hr = pUnk->QueryInterface(IID_IVdsProvider, (void**)&pProvider);
                    pUnk->Release();
                    if (SUCCEEDED(hr)) {
                        hr = pProvider->QueryInterface(IID_IVdsSwProvider, (void**)&pSwProvider);
                        pProvider->Release();
                        if (SUCCEEDED(hr)) {
                            hr = pSwProvider->QueryPacks(&pEnumPack);
                            pSwProvider->Release();
                            if (SUCCEEDED(hr)) {
                                while (pEnumPack->Next(1, &pPackUnk, &ulFetched) == S_OK) {
                                    IVdsPack* pPack;
                                    IEnumVdsObject* pEnumDisk;
                                    IUnknown* pDiskUnk;

                                    hr = pPackUnk->QueryInterface(IID_IVdsPack, (void**)&pPack);
                                    pPackUnk->Release();
                                    if (SUCCEEDED(hr)) {
                                        hr = pPack->QueryDisks(&pEnumDisk);
                                        pPack->Release();
                                        if (SUCCEEDED(hr)) {
                                            while (pEnumDisk->Next(1, &pDiskUnk, &ulFetched) == S_OK) {
                                                VDS_DISK_PROP prop;
                                                IVdsDisk* pDisk;

                                                hr = pDiskUnk->QueryInterface(IID_IVdsDisk, (void**)&pDisk);
                                                pDiskUnk->Release();
                                                if (SUCCEEDED(hr)) {
                                                    hr = pDisk->GetProperties(&prop);
                                                    if ((hr != S_OK) && (hr != VDS_S_PROPERTIES_INCOMPLETE)) {
                                                        pDisk->Release();
                                                        continue;
                                                    }

                                                    hr = (HRESULT)_wcsicmp(physicalName, prop.pwszName);
                                                    CoTaskMemFree(prop.pwszName);

                                                    if (hr == S_OK) {
                                                        hr = pDisk->QueryInterface(InterfaceIID, pInterfaceInstance);
                                                        pDisk->Release();

                                                        if (SUCCEEDED(hr)) {
                                                            pEnumDisk->Release();
                                                            pEnumPack->Release();
                                                            pEnum->Release();
                                                            return SysAllocString(L"Success");
                                                        }
                                                    }
                                                    pDisk->Release();
                                                }
                                            }
                                            pEnumDisk->Release();
                                        }
                                    }
                                }
                                pEnumPack->Release();
                            }
                        }
                    }
                }
                pEnum->Release();
            }
        }
    }

    return result;
}

BSTR RefreshVds(
) {
    wchar_t result[256] = L"Unknown error.";

    HRESULT hr = S_FALSE;
    IVdsServiceLoader* pLoader;
    IVdsService* pService;

    hr = CoInitialize(NULL); // Will fail when called from C# since thread was already initialized from there

    if (true)
    {
        // Create a loader instance
        hr = CoCreateInstance(CLSID_VdsLoader,
            NULL,
            CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
            IID_IVdsServiceLoader,
            (void**)&pLoader
        );

        wcsncpy(result, L"CoCreateInstance failed.", 256);
        if (SUCCEEDED(hr))
        {
            // Load the service on the machine.
            hr = pLoader->LoadService(NULL, &pService);
            SAFE_RELEASE(pLoader);

            wcsncpy(result, L"LoadService failed.", 256);
            if (SUCCEEDED(hr))
            {
                pService->WaitForServiceReady();

                HRESULT hr1 = pService->Refresh();
                HRESULT hr2 = pService->Reenumerate();

                Sleep(1500);

                pService->Release();

                if (SUCCEEDED(hr1) && SUCCEEDED(hr2))
                    return SysAllocString(L"Success");
                if (!SUCCEEDED(hr1) && !SUCCEEDED(hr2))
                    return SysAllocString(L"Failed to refresh and renumerate disks.");
                if (!SUCCEEDED(hr1))
                    return SysAllocString(L"Failed to refresh disks.");
                if (!SUCCEEDED(hr2))
                    return SysAllocString(L"Failed to reenumerate disks.");
            }
        }
    }

    return SysAllocString(result);
}

BSTR CombineBSTRs(
    BSTR bstr1,
    BSTR bstr2,
    BOOL freeInput
)
{
    _bstr_t wrap1 = bstr1;
    _bstr_t wrap2 = bstr2;

    _bstr_t result = wrap1 + wrap2;

    if (freeInput) {
        SysFreeString(bstr1);
        SysFreeString(bstr2);
    }

    return result;
}

extern "C" {
    __declspec(dllexport) BSTR DeletePartitions(
        DWORD driveIndex
    ) 
    {
        //wchar_t result[256] = L"Unknown error.";

        HRESULT hr = S_FALSE;
        VDS_PARTITION_PROP* prop_array = NULL;
        LONG i, prop_array_size;
        IVdsAdvancedDisk* pAdvancedDisk = NULL;

        BSTR getResult = GetVdsDiskInterface(driveIndex, IID_IVdsAdvancedDisk, (void**)&pAdvancedDisk);
        if (wcscmp(getResult, L"Success") != 0)
            return CombineBSTRs(SysAllocString(L"Could not get VDS disk interface: "), getResult, true);
        if (pAdvancedDisk == NULL) {
            BSTR refreshResult = RefreshVds();
            SysFreeString(refreshResult);
            SysFreeString(getResult);
            getResult = GetVdsDiskInterface(driveIndex, IID_IVdsAdvancedDisk, (void**)&pAdvancedDisk);
            if (wcscmp(getResult, L"Success") != 0 || pAdvancedDisk == NULL) {
                return CombineBSTRs(SysAllocString(L"Could not get VDS disk interface after refresh: "), getResult, true);
            }
        }

        char erroredPartitions[128];
        BOOLEAN error = false;
        BSTR errorString = NULL;
        hr = pAdvancedDisk->QueryPartitions(&prop_array, &prop_array_size);
        if (SUCCEEDED(hr))
        {
            for (i = 0; i < prop_array_size; i++) {
                if (!SUCCEEDED(pAdvancedDisk->DeletePartition(prop_array[i].ullOffset, TRUE, TRUE))) {
                    if (!error)
                        errorString = SysAllocString(L"Could not remove partitions: ");

                    wchar_t partitionSize[256];
                    _swprintf(partitionSize, L"\n%d - %llu MB", i, (prop_array[i].ullSize / 1024) / 1024);

                    errorString = CombineBSTRs(errorString, SysAllocString(partitionSize), true);
                    error = true;
                }
            }
        }

        CoTaskMemFree(prop_array);
        pAdvancedDisk->Release();

        return error ? errorString : SysAllocString(L"Success");

    }

    __declspec(dllexport) BSTR FormatVolume(
        LPCWSTR letter,
        LPWSTR pwszFileSystemTypeName,
        UINT32 ulDesiredUnitAllocationSize,
        LPWSTR pwszLabel)
    {
        wchar_t result[256] = L"Unknown error.";

        HRESULT hr;
        HRESULT hrAsync;

        IVdsServiceLoader* pLoader;
        IVdsService* pService;
        IUnknown* pUnk;
        IVdsVolume* pVolume;
        IVdsVolumeMF3* pVolumeMF3;
        IVdsAsync* pAsync;

        VDS_ASYNC_OUTPUT AsyncOut;

        if (letter == NULL || pwszFileSystemTypeName == NULL)
        {
            return ::SysAllocString(L"Invalid parameters.");
        }

        // Convert drive letter from widechar
        char driveLetter;
        int bytesConverted;
        int res = wctomb_s(&bytesConverted, &driveLetter, sizeof(driveLetter), letter[0]);
        if (res != 0)
            return ::SysAllocString(L"Error converting letter.");

        hr = CoInitialize(NULL); // Will fail when called from C# since thread was already initialized from there

        if (true)
        {
            // Create a loader instance
            hr = CoCreateInstance(CLSID_VdsLoader,
                NULL,
                CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER,
                IID_IVdsServiceLoader,
                (void**)&pLoader
            );

            wcsncpy(result, L"CoCreateInstance failed.", 256);
            if (SUCCEEDED(hr))
            {
                // Load the service on the machine.
                hr = pLoader->LoadService(NULL, &pService);
                SAFE_RELEASE(pLoader);
                pLoader = NULL;

                wcsncpy(result, L"LoadService failed.", 256);
                if (SUCCEEDED(hr))
                {
                    pService->WaitForServiceReady();

                    // Access to volume interface via drive letter
                    VDS_DRIVE_LETTER_PROP mDriveLetterPropArray[1];
                    hr = pService->QueryDriveLetters(driveLetter, 1, mDriveLetterPropArray);
                    wcsncpy(result, L"QueryDriveLetters access failed.", 256);

                    if (SUCCEEDED(hr))
                    {
                        hr = pService->GetObject(mDriveLetterPropArray->volumeId, VDS_OT_VOLUME, &pUnk);

                        /*
                        WCHAR str[256];
                        StringFromGUID2(mDriveLetterPropArray->volumeId, str, _countof(str));
                        wprintf(str);
                        printf("\r\n%lu\r\n", hr);
                        printf("%lu\r\n", GetLastError());
                        */

                        wcsncpy(result, L"UuidFromString failed.", 256);
                        if (SUCCEEDED(hr))
                        {
                            hr = pUnk->QueryInterface(IID_IVdsVolume, (void**)&pVolume);
                            wcsncpy(result, L"QueryInterface failed.", 256);
                            if (SUCCEEDED(hr))
                            {
                                // Access volume format interface
                                hr = pVolume->QueryInterface(IID_IVdsVolumeMF3, (void**)&pVolumeMF3);
                                wcsncpy(result, L"QueryInterface MF3 failed.", 256);
                                if (SUCCEEDED(hr))
                                {
                                    // Execute format operation
                                    hr = pVolumeMF3->FormatEx2(
                                        pwszFileSystemTypeName,
                                        1,
                                        ulDesiredUnitAllocationSize,
                                        pwszLabel,
                                        VDS_FSOF_QUICK | VDS_FSOF_FORCE,
                                        &pAsync);
                                    hr = pAsync->Wait(&hrAsync, &AsyncOut);
#pragma region Error handling
                                    if (FAILED(hr))
                                    {
                                        wcsncpy(result, L"Failed to wait for asynchronous volume format completion.", 256);
                                    }
                                    else if (FAILED(hrAsync))
                                    {
                                        switch (hrAsync)
                                        {
                                        case VDS_E_NOT_SUPPORTED:
                                            wcsncpy(result, L"The operation is not supported by the object.", 256);
                                            break;
                                        case VDS_E_ACCESS_DENIED:
                                            wcsncpy(result, L"Access denied.", 256);
                                            break;
                                        case VDS_E_ACTIVE_PARTITION:
                                            break;
                                        default:
                                            wcsncpy(result, L"Error occurred in FormatEx2.", 256);
                                            break;
                                        }
                                    } else if (SUCCEEDED(hr))
                                    {
                                        wcsncpy(result, L"Success", 256);
                                    }
#pragma endregion
                                    SAFE_RELEASE(pVolumeMF3);
                                }

                                SAFE_RELEASE(pVolume);
                            }

                            SAFE_RELEASE(pUnk);
                        }
                    }

                    SAFE_RELEASE(pService);
                }
            }
            CoUninitialize();
        }

        return SysAllocString(result);
    }

    __declspec(dllexport) BSTR GetValue(
        char* data,
        LPWSTR key,
        LPWSTR valueName)
    {
        char keyBuffer[256];
        wcstombs(keyBuffer, key, 256);

        char valueBuffer[128];
        wcstombs(valueBuffer, valueName, 128);

        /*
        char memBuffer[30000];
        memcpy(memBuffer, data, sizeof(char) * 10000);

        memBuffer[sizeof(char) * 10000 - 1] = '\0';

        printf("\n");

        fwrite(memBuffer, sizeof(char), 10000, stdout);
        printf("\n");
        */

        char path[0x1000] = { 0 };

        // we just skip 1k header and start walking root key tree
        LPWSTR result = walk(path, (key_block*)(data + 0x1020), keyBuffer, strlen(keyBuffer), valueBuffer, true);

        if (result == NULL) {
            wcsncpy(result, L"NOT FOUND", 256);
        }
        BSTR returnValue = ::SysAllocString(result);
        delete[] result;

        return returnValue;
    }
    __declspec(dllexport) BSTR GetValues(
        char* data,
        LPWSTR key)
    {
        char keyBuffer[256];
        wcstombs(keyBuffer, key, 256);

        /*
        char memBuffer[30000];
        memcpy(memBuffer, data, sizeof(char) * 10000);

        memBuffer[sizeof(char) * 10000 - 1] = '\0';

        printf("\n");
        
        fwrite(memBuffer, sizeof(char), 10000, stdout);
        printf("\n");
        */

        char path[0x1000] = { 0 };

        // we just skip 1k header and start walking root key tree
        LPWSTR result = walk(path, (key_block*)(data + 0x1020), keyBuffer, strlen(keyBuffer), NULL, true);

        if (result == NULL) {
            wcsncpy(result, L"NOT FOUND", 256);
        }

        BSTR returnValue = ::SysAllocString(result);
        delete[] result;

        return returnValue;
    }
}
