#include <iostream>
#include <Windows.h>
#include <shellapi.h>
#include <string>

class Regedit {
private:
    HKEY hKey;
    std::wstring regeditPath;

public:
    Regedit(const std::wstring& path) : regeditPath(path) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regeditPath.c_str(), 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
        }
    }

    std::wstring Read(const std::wstring& keyName) {
        DWORD bufferSize = MAX_PATH;
        WCHAR value[MAX_PATH];
        if (RegQueryValueExW(hKey, keyName.c_str(), nullptr, nullptr, (LPBYTE)value, &bufferSize) == ERROR_SUCCESS) {
            return value;
        }
        return L"ERR";
    }

    bool Write(const std::wstring& keyName, const std::wstring& value) {
        if (RegSetValueExW(hKey, keyName.c_str(), 0, REG_SZ, (const BYTE*)value.c_str(), (DWORD)(value.length() * sizeof(WCHAR))) == ERROR_SUCCESS) {
            return true;
        }
        return false;
    }

    ~Regedit() {
        RegCloseKey(hKey);
    }
};

class Spoofer {
public:
    static bool Spoof() {
        Regedit regeditOBJ_Hwid(L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001");
        Regedit regeditOBJ_PcGuid(L"SOFTWARE\\Microsoft\\Cryptography");
        Regedit regeditOBJ_PcName(L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName");
        Regedit regeditOBJ_ProductId(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");

        std::wstring oldValue;

        oldValue = regeditOBJ_Hwid.Read(L"HwProfileGuid");
        bool resultHwid = regeditOBJ_Hwid.Write(L"HwProfileGuid", L"{" + GenerateString(36) + L"}");

        oldValue = regeditOBJ_PcGuid.Read(L"MachineGuid");
        bool resultPcGuid = regeditOBJ_PcGuid.Write(L"MachineGuid", GenerateGuidString());

        oldValue = regeditOBJ_PcName.Read(L"ComputerName");
        bool resultPcName = regeditOBJ_PcName.Write(L"ComputerName", L"DESKTOP-" + GenerateString(15));

        oldValue = regeditOBJ_ProductId.Read(L"ProductID");
        bool resultProductId = regeditOBJ_ProductId.Write(L"ProductID", GenerateProductID());

        if (resultHwid && resultPcGuid && resultPcName && resultProductId) {
            std::wcout << L"  [SPOOFER] HWID Changed from " << oldValue << L" to " << regeditOBJ_Hwid.Read(L"HwProfileGuid") << std::endl;
            std::wcout << L"  [SPOOFER] Guid Changed from " << oldValue << L" to " << regeditOBJ_PcGuid.Read(L"MachineGuid") << std::endl;
            std::wcout << L"  [SPOOFER] Computer Name Changed from " << oldValue << L" to " << regeditOBJ_PcName.Read(L"ComputerName") << std::endl;
            std::wcout << L"  [SPOOFER] Computer ProductID Changed from " << oldValue << L" to " << regeditOBJ_ProductId.Read(L"ProductID") << std::endl;
            return true;
        }
        else {
            std::wcout << L"  [SPOOFER] Error accessing the Registry... Maybe run as admin" << std::endl;
            return false;
        }
    }

    static std::wstring GenerateString(int size) {
        const wchar_t alphabet[] = L"ABCDEF0123456789";
        std::wstring result;
        for (int i = 0; i < size; i++) {
            result += alphabet[rand() % (sizeof(alphabet) - 1)];
        }
        return result;
    }

    static std::wstring GenerateGuidString() {
        const wchar_t alphabet[] = L"abcdef0123456789";
        std::wstring result;
        for (int i = 0; i < 32; i++) {
            if (i == 8 || i == 12 || i == 16 || i == 20) {
                result += L'-';
            }
            result += alphabet[rand() % (sizeof(alphabet) - 1)];
        }
        return result;
    }

    static std::wstring GenerateProductID() {
        return GenerateString(5) + L"-" + GenerateString(5) + L"-" + GenerateString(5) + L"-" + GenerateString(5);
    }
};

bool IsAdmin() {
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        return false;
    }
    BOOL bIsAdmin = FALSE;
    if (!CheckTokenMembership(NULL, AdministratorsGroup, &bIsAdmin)) {
        bIsAdmin = FALSE;
    }
    FreeSid(AdministratorsGroup);
    return (bIsAdmin != 0);
}

void FlushNetwork() {

    std::wcout << L"Do you want to flush network settings? (Type 'Yes' to proceed): ";
    std::wstring userInput;
    std::getline(std::wcin, userInput);

    if (userInput == L"Yes" || userInput == L"yes") {

        system("ipconfig /flushdns");
        std::wcout << L"Network settings have been flushed." << std::endl;
    }
    else {
        std::wcout << L"Network settings were not flushed." << std::endl;
    }
}

int main() {
    if (!IsAdmin()) {
        // Relaunch as administrator
        WCHAR moduleName[MAX_PATH];
        GetModuleFileName(NULL, moduleName, MAX_PATH);
        SHELLEXECUTEINFO info = { sizeof(SHELLEXECUTEINFO) };
        info.lpFile = moduleName;
        info.nShow = SW_NORMAL;
        info.lpVerb = L"runas";

        if (ShellExecuteEx(&info) != ERROR_SUCCESS) {
            std::wcout << L"Failed to relaunch as administrator." << std::endl;
            return 1;
        }

        return 0;
    }

    if (Spoofer::Spoof()) {
        std::wcout << L"Success! Please restart your  machine to finish the spoofing." << std::endl;
    }
    else {
        std::wcout << L"Error: Spoofing failed. Make sure to run the program as an administrator." << std::endl;
    }

    FlushNetwork();

    std::wcout << L"Press any key to exit...";
    std::wcin.get();

    return 0;
}
