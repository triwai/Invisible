#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <initguid.h>
#include <devguid.h>   // GUID_DEVCLASS_IMAGE
#include <tlhelp32.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>

// リンカでWindows標準ライブラリとだけリンクする
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")

// =====================================================
// アプリ情報 (一部定数)
// =====================================================
static const wchar_t* kAppTitle = L"Invisible - カメラ対策";
static const wchar_t* kRunKey   = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
static const wchar_t* kRunValue = L"Invisible";

// コントロールID
#define IDC_BTN_ON       1001
#define IDC_BTN_OFF      1002
#define IDC_BTN_INSTALL  1003
#define IDC_BTN_UNINSTALL 1004
#define IDC_LBL_STATUS   1101
#define ID_TRAYICON      1201
#define WM_TRAY          (WM_APP + 1)

// 保護状態
enum class ProtectState { Unknown, On, Off };
static std::atomic<ProtectState> g_state{ProtectState::Unknown};

// UI関連
static HWND g_hWnd     = NULL;
static HWND g_btnOn    = NULL;
static HWND g_btnOff   = NULL;
static HWND g_btnInstall    = NULL;
static HWND g_btnUninstall  = NULL;
static HWND g_lbl      = NULL;
static HFONT g_fontBold= NULL;
static NOTIFYICONDATAW g_nid{};

// スレッド関連
static std::atomic<bool> g_running{true};
static std::thread g_detectThread;
static std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> g_lastPrompt;
static std::mutex g_promptMutex;

// =====================================================
// ユーティリティ (UAC/Runキーなど)
// =====================================================

// EXEパス取得
static std::wstring GetExePath() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(NULL, path, MAX_PATH);
    return path;
}

// 管理者権限チェック
static bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev{};
        DWORD sz = sizeof(elev);
        if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &sz)) {
            elevated = elev.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return elevated;
}

// runas で自身を引数付き再実行 -> 終了コードを待って戻す
static bool RelaunchElevatedAndWait(const wchar_t* args, DWORD* outExitCode = nullptr) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask  = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.lpParameters = args;
    sei.nShow = SW_HIDE;

    if (!ShellExecuteExW(&sei)) {
        return false; // UAC拒否など
    }
    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, INFINITE);
        if (outExitCode) {
            DWORD code=1;
            GetExitCodeProcess(sei.hProcess, &code);
            *outExitCode = code;
        }
        CloseHandle(sei.hProcess);
    }
    return true;
}

// =====================================================
// カメラデバイス無効/有効 (Image + Cameraクラス)
// =====================================================

// StringToGuid
static bool StringToGuid(const wchar_t* s, GUID* out) {
    if (!s || !out) return false;
    return SUCCEEDED(IIDFromString(s, out));
}

// 代表的なクラス (GUID_DEVCLASS_IMAGE, GUID_DEVCLASS_CAMERA)
static std::vector<GUID> GetCameraRelatedClassGuids() {
    std::vector<GUID> guids;
    guids.push_back(GUID_DEVCLASS_IMAGE);
    GUID cam{};
    if (StringToGuid(L"{CA3E7AB9-B4C3-4AE6-8251-579EF933890F}", &cam)) {
        guids.push_back(cam);
    }
    return guids;
}

// ToggleByClass
static bool ToggleByClass(const GUID& cls, bool enable) {
    HDEVINFO hInfo = SetupDiGetClassDevsW(&cls, NULL, NULL, DIGCF_PRESENT);
    if (hInfo == INVALID_HANDLE_VALUE) return true; // クラスデバイスが無いならOK
    SP_DEVINFO_DATA di{};
    di.cbSize = sizeof(di);
    bool allOk = true;

    for (DWORD idx=0; SetupDiEnumDeviceInfo(hInfo, idx, &di); idx++) {
        SP_PROPCHANGE_PARAMS change{};
        change.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        change.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        change.Scope = DICS_FLAG_GLOBAL;
        change.HwProfile = 0;
        change.StateChange = enable ? DICS_ENABLE : DICS_DISABLE;

        if (!SetupDiSetClassInstallParamsW(hInfo, &di, &change.ClassInstallHeader, sizeof(change))) {
            allOk = false;
            continue;
        }
        if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hInfo, &di)) {
            allOk = false;
            continue;
        }
    }
    SetupDiDestroyDeviceInfoList(hInfo);
    return allOk;
}

// 本体
static bool SetCamerasEnabledAdmin(bool enable) {
    auto guids = GetCameraRelatedClassGuids();
    bool result = true;
    for (auto& g : guids) {
        result = ToggleByClass(g, enable) && result;
    }
    return result;
}

// 権限チェックし、足りなければ昇格再実行
static bool SetCamerasEnabled(bool enable) {
    if (IsElevated()) {
        return SetCamerasEnabledAdmin(enable);
    } else {
        DWORD code=1;
        std::wstring arg = enable ? L"--do=enable" : L"--do=disable";
        if (!RelaunchElevatedAndWait(arg.c_str(), &code)) {
            return false;
        }
        return (code == 0);
    }
}

// =====================================================
// スタートアップ登録 (Runキー)
// =====================================================
static bool SetAutoRunGUI(bool enable) {
    // HKCU\...\Run に exeパスを書き込む/削除する
    HKEY hKey{};
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRunKey, 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        // キーが無い場合は作る
        if (RegCreateKeyExW(HKEY_CURRENT_USER, kRunKey, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
            return false;
        }
    }
    bool ok;
    if (enable) {
        std::wstring exe = GetExePath();
        auto err = RegSetValueExW(hKey, kRunValue, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(exe.c_str()),
            (DWORD)((exe.size()+1)*sizeof(wchar_t)));
        ok = (err == ERROR_SUCCESS);
    } else {
        RegDeleteValueW(hKey, kRunValue);
        ok = true;
    }
    RegCloseKey(hKey);
    return ok;
}

// =====================================================
// 昇格専用コマンド
// =====================================================
static int ElevatedDo(const std::wstring& arg) {
    // --do=disable => カメラ無効
    if (arg == L"--do=disable") {
        bool ok = SetCamerasEnabledAdmin(false);
        return ok?0:2;
    } else if (arg == L"--do=enable") {
        bool ok = SetCamerasEnabledAdmin(true);
        return ok?0:3;
    }
    return 1; // 不明な引数
}

// =====================================================
// トレイ＆メインウィンドウ
// =====================================================
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Globalデータ
static HBRUSH g_bgBrush = nullptr;
static COLORREF g_colorText = RGB(255,255,255);

// トレイ初期化
static void TrayInit(HWND hWnd) {
    ZeroMemory(&g_nid, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hWnd;
    g_nid.uID  = ID_TRAYICON;
    g_nid.uFlags = NIF_MESSAGE|NIF_ICON|NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    lstrcpynW(g_nid.szTip, kAppTitle, ARRAYSIZE(g_nid.szTip));
    Shell_NotifyIconW(NIM_ADD, &g_nid);
    // バージョン指定 (新しい機能)
    g_nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
}

// トレイ削除
static void TrayDestroy() {
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

// 状態表示ラベル更新
static void SetStatus(const wchar_t* txt) {
    SetWindowTextW(g_lbl, txt);
}
static void RefreshStatus() {
    switch (g_state.load()) {
    case ProtectState::On:  SetStatus(L"状態: 保護ON（カメラ無効化）");  break;
    case ProtectState::Off: SetStatus(L"状態: 保護OFF（カメラ有効化）"); break;
    default:                SetStatus(L"状態: 不明"); break;
    }
}

// 太字フォント
static void ApplyFontBold(HWND ctrl) {
    if (!g_fontBold) {
        LOGFONTW lf{};
        lf.lfHeight = -20;
        lf.lfWeight = FW_BOLD;
        lstrcpynW(lf.lfFaceName, L"Segoe UI", 31);
        g_fontBold = CreateFontIndirectW(&lf);
    }
    SendMessageW(ctrl, WM_SETFONT, (WPARAM)g_fontBold, TRUE);
}

// =====================================================
// 自動検知スレッド
// =====================================================
static bool IsWatchedProcess(const std::wstring& exe) {
    static const wchar_t* watchList[] = {
        L"chrome.exe", L"msedge.exe", L"firefox.exe",
        L"zoom.exe", L"teams.exe", L"skype.exe", L"discord.exe",
        L"obs64.exe", L"obs32.exe", L"vlc.exe", L"camera.exe"
    };
    for (auto& name : watchList) {
        if (_wcsicmp(exe.c_str(), name) == 0) return true;
    }
    return false;
}

// スレッドループ
static void DetectThreadFunc() {
    using namespace std::chrono;
    auto cool = minutes(5);

    while (g_running.load()) {
        if (g_state.load() == ProtectState::On) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe{};
                pe.dwSize = sizeof(pe);
                if (Process32FirstW(snap, &pe)) {
                    do {
                        std::wstring exe = pe.szExeFile;
                        if (IsWatchedProcess(exe)) {
                            auto now = steady_clock::now();
                            bool prompt = false;
                            {
                                std::lock_guard<std::mutex> lk(g_promptMutex);
                                auto it = g_lastPrompt.find(exe);
                                if (it==g_lastPrompt.end() || now - it->second > cool) {
                                    g_lastPrompt[exe] = now;
                                    prompt = true;
                                }
                            }
                            if (prompt) {
                                int r = MessageBoxW(NULL,
                                    (L"「" + exe + L"」がカメラを使用しようとしています。\n一時的に許可しますか？(5分)").c_str(),
                                    kAppTitle,
                                    MB_YESNO|MB_ICONQUESTION|MB_SYSTEMMODAL
                                );
                                if(r==IDYES){
                                    if(SetCamerasEnabled(true)){
                                        g_state.store(ProtectState::Off);
                                        std::thread([]{
                                            std::this_thread::sleep_for(minutes(5));
                                            SetCamerasEnabled(false);
                                            g_state.store(ProtectState::On);
                                        }).detach();
                                    }
                                }
                            }
                        }
                    } while(Process32NextW(snap, &pe));
                }
                CloseHandle(snap);
            }
        }
        std::this_thread::sleep_for(seconds(3));
    }
}

// =====================================================
// イベントハンドラ
// =====================================================
static void DoProtectOn() {
    if (SetCamerasEnabled(false)) {
        g_state.store(ProtectState::On);
        RefreshStatus();
    } else {
        MessageBoxW(g_hWnd, L"保護ONに失敗しました。", kAppTitle, MB_ICONERROR);
    }
}
static void DoProtectOff() {
    if (SetCamerasEnabled(true)) {
        g_state.store(ProtectState::Off);
        RefreshStatus();
    } else {
        MessageBoxW(g_hWnd, L"保護OFFに失敗しました。", kAppTitle, MB_ICONERROR);
    }
}
static void DoInstall() {
    if (SetAutoRunGUI(true)) {
        MessageBoxW(g_hWnd, L"インストール完了。次回ログオン時に自動起動します。", kAppTitle, MB_OK|MB_ICONINFORMATION);
    } else {
        MessageBoxW(g_hWnd, L"インストール失敗。", kAppTitle, MB_ICONERROR);
    }
}
static void DoUninstall() {
    bool ok = SetAutoRunGUI(false);
    if (!IsElevated()) {
        // カメラを有効へ戻す
        DWORD code=1;
        RelaunchElevatedAndWait(L"--do=enable",&code);
    } else {
        SetCamerasEnabledAdmin(true);
    }
    g_state.store(ProtectState::Off);
    RefreshStatus();
    MessageBoxW(g_hWnd, ok?L"アンインストール完了。カメラも有効化しました。":L"アンインストール失敗。",
                kAppTitle, ok?MB_OK|MB_ICONINFORMATION:MB_OK|MB_ICONWARNING);
}

// =====================================================
// ウィンドウプロシージャ
// =====================================================
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // 背景色(ダークグレー)
        g_bgBrush = CreateSolidBrush(RGB(80,80,80));

        g_lbl = CreateWindowExW(0, L"STATIC", L"状態: 初期化中",
            WS_VISIBLE|WS_CHILD|SS_CENTER, 30,20, 620,30, hWnd, (HMENU)IDC_LBL_STATUS, NULL, NULL);
        g_btnOn= CreateWindowExW(0, L"BUTTON", L"保護 ON（カメラ無効化）",
            WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 30,70,620,80, hWnd,(HMENU)IDC_BTN_ON, NULL, NULL);
        g_btnOff=CreateWindowExW(0,L"BUTTON",L"保護 OFF（カメラ有効化）",
            WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON, 30,170,620,80, hWnd,(HMENU)IDC_BTN_OFF,NULL,NULL);
        g_btnInstall=CreateWindowExW(0,L"BUTTON",L"インストール（スタートアップ）",
            WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,30,270,620,70,hWnd,(HMENU)IDC_BTN_INSTALL,NULL,NULL);
        g_btnUninstall=CreateWindowExW(0,L"BUTTON",L"アンインストール（解除）",
            WS_VISIBLE|WS_CHILD|BS_PUSHBUTTON,30,350,620,70,hWnd,(HMENU)IDC_BTN_UNINSTALL,NULL,NULL);

        ApplyFontBold(g_lbl);
        ApplyFontBold(g_btnOn);
        ApplyFontBold(g_btnOff);
        ApplyFontBold(g_btnInstall);
        ApplyFontBold(g_btnUninstall);

        // トレイアイコン
        TrayInit(hWnd);

        // デフォルト保護ON
        if (SetCamerasEnabled(false)) g_state.store(ProtectState::On);
        else g_state.store(ProtectState::Unknown);
        RefreshStatus();

        // 検知スレッドStart
        g_running.store(true);
        g_detectThread = std::thread(DetectThreadFunc);
        return 0;
    }
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN: {
        // コントロールの背景 & 文字色を統一
        HDC dc = (HDC)wParam;
        SetBkColor(dc, RGB(80,80,80));
        SetTextColor(dc, g_colorText);
        return (LRESULT)g_bgBrush;
    }
    case WM_COMMAND: {
        switch(LOWORD(wParam)) {
        case IDC_BTN_ON:       DoProtectOn(); return 0;
        case IDC_BTN_OFF:      DoProtectOff();return 0;
        case IDC_BTN_INSTALL:  DoInstall();   return 0;
        case IDC_BTN_UNINSTALL:DoUninstall(); return 0;
        }
        break;
    }
    case WM_SIZE: {
        RECT rc; GetClientRect(hWnd, &rc);
        int w = rc.right - rc.left;
        int margin=30;
        int bw = w - margin*2;
        MoveWindow(g_lbl, margin,20, bw,30, TRUE);
        MoveWindow(g_btnOn, margin,70, bw,80, TRUE);
        MoveWindow(g_btnOff, margin,170, bw,80, TRUE);
        MoveWindow(g_btnInstall, margin,270, bw,70, TRUE);
        MoveWindow(g_btnUninstall, margin,350, bw,70, TRUE);
        return 0;
    }
    case WM_TRAY: {
        if (LOWORD(lParam)==WM_LBUTTONUP) {
            ShowWindow(hWnd, SW_SHOWNORMAL);
            SetForegroundWindow(hWnd);
        } else if (LOWORD(lParam)==WM_RBUTTONUP || LOWORD(lParam)==WM_CONTEXTMENU) {
            // トレイ右クリックメニュー
            HMENU menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, 1, L"表示");
            AppendMenuW(menu, MF_STRING, 2, L"保護 ON");
            AppendMenuW(menu, MF_STRING, 3, L"保護 OFF");
            AppendMenuW(menu, MF_SEPARATOR,0,NULL);
            AppendMenuW(menu, MF_STRING, 4, L"終了");
            POINT pt; GetCursorPos(&pt);
            SetForegroundWindow(hWnd);
            int cmd = TrackPopupMenu(menu, TPM_RETURNCMD|TPM_RIGHTBUTTON, pt.x,pt.y,0,hWnd,NULL);
            DestroyMenu(menu);
            switch(cmd){
            case 1: ShowWindow(hWnd,SW_SHOWNORMAL);SetForegroundWindow(hWnd);break;
            case 2: DoProtectOn();break;
            case 3: DoProtectOff();break;
            case 4: PostMessageW(hWnd,WM_CLOSE,0,0);break;
            }
        }
        return 0;
    }
    case WM_CLOSE:
        // ×ボタン押しても終了せずトレイに隠れる
        ShowWindow(hWnd, SW_HIDE);
        return 0;
    case WM_DESTROY: {
        // 終了
        g_running.store(false);
        if (g_detectThread.joinable()) g_detectThread.join();
        TrayDestroy();
        if(g_fontBold){ DeleteObject(g_fontBold); g_fontBold=nullptr; }
        if(g_bgBrush){  DeleteObject(g_bgBrush);  g_bgBrush=nullptr;  }
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// エントリポイント
int APIENTRY wWinMain(HINSTANCE hInst,HINSTANCE,LPWSTR cmdLine,int) {
    // 昇格専用コマンド
    if (cmdLine && cmdLine[0]) {
        std::wstring arg(cmdLine);
        if(arg.rfind(L"--do=", 0)==0){
            return ElevatedDo(arg);
        }
    }
    // Mutexで多重起動防止
    HANDLE hMutex = CreateMutexW(NULL,FALSE,L"Invisible_SingleInstance_Mutex");
    if (!hMutex || GetLastError()==ERROR_ALREADY_EXISTS){
        if(hMutex)CloseHandle(hMutex);
        return 0;
    }

    // ウィンドウクラス
    WNDCLASSEXW wc{};
    wc.cbSize     = sizeof(wc);
    wc.lpfnWndProc= WndProc;
    wc.hInstance  = hInst;
    wc.hCursor    = LoadCursorW(NULL, IDC_ARROW);
    wc.hIcon      = LoadIconW(NULL, IDI_SHIELD);
    wc.hIconSm    = wc.hIcon;
    wc.lpszClassName = L"InvisibleMainWnd";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);

    if(!RegisterClassExW(&wc)){
        CloseHandle(hMutex);
        return 1;
    }

    // メインウィンドウ
    g_hWnd = CreateWindowExW(
        0, wc.lpszClassName, kAppTitle,
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX|WS_SIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,700,480,
        NULL,NULL,hInst,nullptr
    );
    if(!g_hWnd){
        CloseHandle(hMutex);
        return 1;
    }

    ShowWindow(g_hWnd,SW_SHOWNORMAL);
    UpdateWindow(g_hWnd);

    // メッセージループ
    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)>0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CloseHandle(hMutex);
    return (int)msg.wParam;
}