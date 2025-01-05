/*
    =============================
            ADB-KILLER
    =============================

    GitHub: https://github.com/jxnxsdev/ADB-Killer

	A Program which Kills ADB (Android Debug Bridge), it's parent processes and other processes specified in a kill list.
	This program is fully annotated with comments so you should be easily able to understand what it does.

	=============================
			DISCLAIMER
	=============================
	PLEASE READ CAREFULLY!!
	This program will force kill the Android Debug Bridge process! It'll also search for parent processes and other known
	processes specified in a kill list and kill them as well. Please make sure to review what programs get killed before
    pressing the kill button. 
	I will not take responsibility for lost work due to the execution of this program. You have been warned.
	Kein Backup, Kein Mitleid.
*/


// Include the necessary headers. These are libaries used to interact with the Windows API, download files from the internet, 
// and other standard C++ libraries.
#include <windows.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <codecvt>

// Link the necessary libraries. These are required to compile the program.
#pragma comment(lib, "urlmon.lib")

/* 
    This is a simple function that converts a std::string to a std::wstring.The Windows api uses wide strings(wchar_t) for unicode support
	while this program uses std::string for simplicity.
*/
std::wstring StringToWString(const std::string& str) {
    return std::wstring(str.begin(), str.end());
}

// This is the opposite of the previous function. It converts a std::wstring to a std::string.
std::string WStringToString(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

/*
	This function checks if the program is running with admin privileges. It does this by checking the token of the current process.
	If the token is elevated, the program is running as admin. Admin privileges are required to kill processes running as admin.
*/
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

/*
	This function elevates the permissions of the program. It does this by running the program again with the "runas" verb.
	This will prompt the user to run the program as an administrator. If the user accepts, the program will be run with admin privileges.
*/
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

// I guess this explains itself. All it does is show a disclaimer to the user.
bool ShowDisclaimer() {
    int result = MessageBoxW(
        NULL,
        L"PLEASE READ CAREFULLY!!\n\nThis program will force kill the Android Debug Bridge process! Please make sure to review what programs will be killed before pressing kill so you can save your work!!\n\nI will not take responsiblity for lost work due to the execution of this program. You have been warned.\n\nKein Backup, Kein Mitleid.",
        L"DISCLAIMER",
        MB_ICONWARNING | MB_OKCANCEL
    );
    return result == IDOK;
}

/*
    This checks if a process (in this case identified by a name and process id) is running
*/
bool IsProcessRunning(const std::string& processName, DWORD& pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            std::string exeFile = WStringToString(pe.szExeFile);
            std::transform(exeFile.begin(), exeFile.end(), exeFile.begin(), ::tolower);
            std::string lowerProcessName = processName;
            std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);

            if (exeFile.find(lowerProcessName) != std::string::npos) {
                pid = pe.th32ProcessID;
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return false;
}

/*
	This function fetches the kill list from a URL. The kill list is a list of processes that the program will kill.
	The kill list is a simple text file with one process name per line.
*/
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

// This function kills a process by its process id.
void KillProcessByPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess) {
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }
}

/*
	This function checks if a process has any parent processes. It does this by iterating through the process list and checking the parent process id.
	It returns a vector of parent process ids.
*/
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

/*
	This function gets the processes from the kill list. It does this by iterating through the process list and checking if the process name is in the kill list.
	It returns a vector of pairs containing the process name and process id.
*/
std::vector<std::pair<std::string, DWORD>> GetProcessesFromKillList(const std::vector<std::string>& killList) {
    std::vector<std::pair<std::string, DWORD>> processesToKill;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return processesToKill;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            for (const auto& processName : killList) {
                std::string exeFile = WStringToString(pe.szExeFile);
                std::transform(exeFile.begin(), exeFile.end(), exeFile.begin(), ::tolower);
                std::string lowerProcessName = processName;
                std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::tolower);

                if (exeFile.find(lowerProcessName) != std::string::npos) {
                    processesToKill.push_back({ exeFile, pe.th32ProcessID });
                    break;
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);

    return processesToKill;
}

// The main function of the program. Basically the entry point.
int main() {
	// Check for if the program is running as admin. If not, the program will elevate the permissions.
    if (!IsRunningAsAdmin()) {
        ElevatePermissions();
    }

	// Show the disclaimer to the user. If the user doesn't agree, the program exits.
    if (!ShowDisclaimer()) {
        return 0;
    }
       
	// Check if ADB is running. If not, a message box is shown and the program exits.
    DWORD adbPid = 0;
    if (!IsProcessRunning("adb.exe", adbPid)) {
        MessageBoxW(NULL, L"ADB is not running. Exiting.", L"Info", MB_ICONINFORMATION);
        return 0;
    }
       
	// Get the parent processes of ADB. This is done to kill the parent processes as well.
    std::vector<DWORD> parentPIDs = GetParentProcesses(adbPid);

	// Fetch the kill list from the URL. If the kill list is empty, a message box is shown and the program exits.
    std::vector<std::string> killList = FetchKillList("https://raw.githubusercontent.com/jxnxsdev/ADB-Killer/refs/heads/main/killlist.txt");
       
	// Also self explanatory. If the kill list is empty, a message box is shown and the program exits.
    if (killList.empty()) {
        MessageBoxW(NULL, L"No processes to kill or an error occurred while fetching the kill list.", L"Error", MB_ICONERROR);
        return 0;
    }

	// This creates a summary of the processes that will be killed.
    std::wstring killListSummary = L"The following processes will be killed:\n";

    // Adds ADB to the summary
    killListSummary += L"ADB.exe (PID: " + std::to_wstring(adbPid) + L")\n";

    // Adds all kill list process and parents to the summary.
    std::vector<std::pair<std::string, DWORD>> killListProcesses = GetProcessesFromKillList(killList);
    for (const auto& process : killListProcesses) {
        killListSummary += L"Kill List Process: " + StringToWString(process.first) + L" (PID: " + std::to_wstring(process.second) + L")\n";
    }

    // Shows a message box with all the process and asks the user if they want to proceed. If not, the program exits.
    killListSummary += L"\nDo you want to proceed?";
    int result = MessageBoxW(NULL, killListSummary.c_str(), L"Confirmation", MB_ICONWARNING | MB_OKCANCEL);
    if (result != IDOK) {
        return 0;
    }

    // Iterates through the parent processes and kills each one of them.
    for (const auto& pid : parentPIDs) {
        KillProcessByPID(pid);
    }

	// Iterates through all the processes on the kill list and kills each one of them.
    for (const auto& process : killListProcesses) {
        KillProcessByPID(process.second);
    }

	// Kills the ADB process.
    KillProcessByPID(adbPid);

	// Shows a message box to the user that all processes were killed successfully.
    MessageBoxW(NULL, L"ADB and related processes were killed successfully.", L"Success", MB_ICONINFORMATION);
    return 0;
}
