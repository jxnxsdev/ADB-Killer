#include <windows.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#pragma comment(lib, "urlmon.lib")

std::wstring StringToWString(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return isAdmin;
}

void ElevatePermissions() {
    WCHAR exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        MessageBoxW(NULL, L"Failed to retrieve the executable path. Exiting.", L"Error", MB_ICONERROR);
        exit(1);
    }

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        MessageBoxW(NULL, L"Failed to elevate permissions. Exiting.", L"Error", MB_ICONERROR);
        exit(1);
    }

    exit(0);
}

bool ShowDisclaimer() {
    int result = MessageBoxW(
        NULL,
        L"PLEASE READ CAREFULLY!!\n\nThis program will force kill the Android Debug Bridge process! Please make sure to review what programs will be killed before pressing kill so you can save your work!!\n\nI will not take responsiblity for lost work due to the execution of this program. You have been warned.\n\nKein Backup, Kein Mitleid.",
        L"DISCLAIMER",
        MB_ICONWARNING | MB_OKCANCEL
    );
    return result == IDOK;
}

bool IsProcessRunning(const std::string& processName, DWORD& pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, StringToWString(processName).c_str()) == 0) {
                pid = pe.th32ProcessID;
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return false;
}

std::vector<std::string> FetchKillList(const std::string& url) {
    const std::string tempFile = "killlist.txt";
    HRESULT hr = URLDownloadToFileW(
        NULL,
        StringToWString(url).c_str(),
        StringToWString(tempFile).c_str(),
        0,
        NULL
    );

    std::vector<std::string> processNames;

    if (SUCCEEDED(hr)) {
        std::ifstream file(tempFile);
        if (!file.is_open()) {
            MessageBoxW(NULL, L"Failed to read the killist!", L"Error", MB_ICONERROR);
            return processNames;
        }

        std::string line;
        bool validFile = true;

        while (std::getline(file, line)) {
            if (line.find("HTTP") != std::string::npos) {
                validFile = false;
                break;
            }
            if (!line.empty()) processNames.push_back(line);
        }

        file.close();
        DeleteFileW(StringToWString(tempFile).c_str());

        if (!validFile) {
            MessageBoxW(NULL, L"The download was unsuccessful. Please check your internet connection! Exiting.", L"Error", MB_ICONERROR);
            processNames.clear();
        }
    }
    else {
        MessageBoxW(NULL, L"Failed to download the kill list. Plase check your internet connection! Exiting.", L"Error", MB_ICONERROR);
    }
    return processNames;
}

void KillProcessByPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
}

std::vector<DWORD> GetParentProcesses(DWORD pid) {
    std::vector<DWORD> parentPIDs;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return parentPIDs;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                parentPIDs.push_back(pe.th32ParentProcessID);
                pid = pe.th32ParentProcessID;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return parentPIDs;
}

int main() {
    if (!IsRunningAsAdmin()) {
        ElevatePermissions();
    }

    if (!ShowDisclaimer()) {
        return 0;
    }

    DWORD adbPid = 0;
    if (!IsProcessRunning("adb.exe", adbPid)) {
        MessageBoxW(NULL, L"ADB is not running. Exiting.", L"Info", MB_ICONINFORMATION);
        return 0;
    }

    std::vector<DWORD> parentPIDs = GetParentProcesses(adbPid);
    std::vector<std::string> killList = FetchKillList("https://jxnxsdev.me/cdn/killlist.txt");

    if (killList.empty()) {
        MessageBoxW(NULL, L"No processes to kill or an error occurred while fetching the kill list.", L"Error", MB_ICONERROR);
        return 0;
    }

    std::wstring killListSummary = L"The following processes will be killed:\n";
    killListSummary += L"ADB.exe (PID: " + std::to_wstring(adbPid) + L")\n";

    for (const auto& pid : parentPIDs) {
        killListSummary += L"Parent Process (PID: " + std::to_wstring(pid) + L")\n";
    }

    for (const auto& process : killList) {
        killListSummary += StringToWString(process) + L"\n";
    }

    killListSummary += L"\nDo you want to proceed?";
    int result = MessageBoxW(NULL, killListSummary.c_str(), L"Confirmation", MB_ICONWARNING | MB_OKCANCEL);
    if (result != IDOK) {
        return 0;
    }
    for (const auto& pid : parentPIDs) {
        KillProcessByPID(pid);
    }
    for (const auto& process : killList) {
        DWORD pid = 0;
        if (IsProcessRunning(process, pid)) {
            KillProcessByPID(pid);
        }
    }
    KillProcessByPID(adbPid);

    MessageBoxW(NULL, L"ADB and related processes were killed successfully.", L"Success", MB_ICONINFORMATION);

    return 0;
}
