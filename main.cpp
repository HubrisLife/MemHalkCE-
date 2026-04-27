/*
    MemHawk CE — Cheat Engine-style Memory Scanner
    C++17 / Win32 API — no external dependencies
    Compile: g++ -std=c++17 -O2 -mwindows -o MemHawkCE.exe main.cpp scanner.cpp
             -lcomctl32 -lcomdlg32 -lshlwapi
    Or:  cl /std:c++17 /O2 main.cpp scanner.cpp /link comctl32.lib comdlg32.lib shlwapi.lib /SUBSYSTEM:WINDOWS
*/

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <windowsx.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <format>
#include "scanner.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' \
    version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ─────────────────── Control IDs ────────────────────────────────────────────

enum {
    IDC_PROC_LIST      = 101, IDC_ATTACH_BTN   = 102, IDC_REFRESH_BTN  = 103,
    IDC_VTYPE          = 104, IDC_SCANTYPE      = 105, IDC_VALUE1       = 106,
    IDC_VALUE2         = 107, IDC_FIRSTSCAN     = 108, IDC_NEXTSCAN     = 109,
    IDC_UNDO           = 110, IDC_RESETSCAN     = 111,
    IDC_PROGRESS       = 112, IDC_RESULTCOUNT   = 113,
    IDC_RESULTS        = 114,  // virtual listview
    IDC_WATCHLIST      = 115,
    IDC_ADD_ADDR       = 116, IDC_REMOVE_ADDR  = 117, IDC_FREEZE_BTN   = 118,
    IDC_EDIT_VAL       = 119, IDC_SAVE_BTN     = 120, IDC_LOAD_BTN     = 121,
    IDC_STATUSBAR      = 122, IDC_MANUAL_ADD   = 123,
    IDC_AOB_SCAN       = 124, IDC_MODULES      = 125, IDC_HEX_VIEW     = 126,
    IDC_PROC_SEARCH    = 127, IDC_UNDO_WRITE   = 128, IDC_PIN_TOP      = 129,
    TIMER_REFRESH      = 1,
};

// ─────────────────── Layout constants ───────────────────────────────────────

constexpr int LEFT_W   = 280;   // left panel width
constexpr int WATCH_H  = 200;   // watch list height
constexpr int SB_H     = 22;    // status bar height
constexpr int PAD       = 6;

// ─────────────────── Global state ───────────────────────────────────────────

static HINSTANCE  g_hInst    = nullptr;
static HWND       g_hWnd     = nullptr;
static MemScanner g_scanner;
static bool       g_scanning = false;
static std::mutex g_mutex;
static HIMAGELIST g_hProcImg = nullptr;   // Process list icon cache

// Recently attached process names (most-recent first, deduped, capped at MAX_RECENT)
static std::vector<std::wstring> g_recentProcesses;
constexpr size_t MAX_RECENT = 5;
static void SaveRecents();   // forward declaration — defined later

// Parallel to g_procList — image-list index per process (so reordering is cheap)
static std::vector<int> g_procIconIdx;

// Write history for one-click revert
struct WriteRecord {
    uintptr_t    address;
    VType        vtype;
    double       oldValue;
    double       newValue;
    std::wstring source;        // e.g. "Edit Value", "Hex Edit"
    SYSTEMTIME   timestamp;
};
static std::vector<WriteRecord> g_writeHistory;
constexpr size_t MAX_WRITE_HISTORY = 200;

static void RecordWrite(uintptr_t addr, VType vt, double oldVal, double newVal,
                         const wchar_t* source) {
    WriteRecord r;
    r.address  = addr;
    r.vtype    = vt;
    r.oldValue = oldVal;
    r.newValue = newVal;
    r.source   = source;
    GetLocalTime(&r.timestamp);
    g_writeHistory.push_back(r);
    if (g_writeHistory.size() > MAX_WRITE_HISTORY)
        g_writeHistory.erase(g_writeHistory.begin());
}

static void AddToRecent(const std::wstring& name) {
    auto it = std::find_if(g_recentProcesses.begin(), g_recentProcesses.end(),
        [&](const std::wstring& s) { return _wcsicmp(s.c_str(), name.c_str()) == 0; });
    if (it != g_recentProcesses.end())
        g_recentProcesses.erase(it);
    g_recentProcesses.insert(g_recentProcesses.begin(), name);
    if (g_recentProcesses.size() > MAX_RECENT)
        g_recentProcesses.pop_back();
    SaveRecents();   // persist immediately so a crash doesn't lose it
}

// Extract small (16x16) icon from an executable file
static HICON GetSmallExeIcon(const std::wstring& path) {
    if (path.empty()) return nullptr;
    SHFILEINFOW sfi = {};
    if (SHGetFileInfoW(path.c_str(), 0, &sfi, sizeof(sfi),
                       SHGFI_ICON | SHGFI_SMALLICON))
        return sfi.hIcon;
    return nullptr;
}

// Scan thread results back to UI
static volatile size_t g_lastCount = 0;
static volatile int    g_lastPct   = 0;
static volatile bool   g_scanDone  = false;

// ─────────────────── Utility functions ──────────────────────────────────────

static void SetStatus(const wchar_t* msg) {
    SendMessage(GetDlgItem(g_hWnd, IDC_STATUSBAR), SB_SETTEXT, 0, (LPARAM)msg);
}

static void Err(const wchar_t* msg) {
    MessageBoxW(g_hWnd, msg, L"MemHawk Error", MB_ICONERROR | MB_OK);
}

// Format a Win32 error code into a readable message via FormatMessage
static std::wstring GetWin32ErrorMsg(DWORD err) {
    LPWSTR buf = nullptr;
    DWORD len = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buf, 0, nullptr);
    std::wstring out;
    if (len > 0 && buf) {
        out = buf;
        while (!out.empty() && (out.back() == L'\n' || out.back() == L'\r' ||
                                 out.back() == L' '  || out.back() == L'.'))
            out.pop_back();
    } else {
        out = L"(no description)";
    }
    if (buf) LocalFree(buf);
    return out;
}

// Show error with Win32 system message appended
static void ErrWithCode(const wchar_t* prefix, DWORD err) {
    wchar_t msg[600];
    swprintf_s(msg, L"%s\n\n%s\n\nError code: %u (0x%08X)",
               prefix, GetWin32ErrorMsg(err).c_str(), err, err);
    Err(msg);
}

// Path to %LOCALAPPDATA%\MemHawkCE\recents.txt — created on first save
static std::wstring GetRecentsFilePath() {
    wchar_t path[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA,
                                    nullptr, 0, path))) {
        wcscat_s(path, L"\\MemHawkCE");
        CreateDirectoryW(path, nullptr);     // OK if it already exists
        wcscat_s(path, L"\\recents.txt");
        return path;
    }
    return L"recents.txt";   // fallback to working dir
}

static void SaveRecents() {
    std::wofstream f(GetRecentsFilePath().c_str());
    if (!f) return;
    for (const auto& r : g_recentProcesses) f << r << L"\n";
}

static void LoadRecents() {
    std::wifstream f(GetRecentsFilePath().c_str());
    if (!f) return;
    std::wstring line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (!line.empty()) g_recentProcesses.push_back(line);
    }
    if (g_recentProcesses.size() > MAX_RECENT)
        g_recentProcesses.resize(MAX_RECENT);
}

static std::wstring FmtAddr(uintptr_t a) {
    wchar_t buf[20];
    swprintf_s(buf, L"0x%0*llX", (int)(sizeof(uintptr_t)*2), (unsigned long long)a);
    return buf;
}

// ─────────────────── Simple modal input box (no .rc needed) ─────────────────

struct InputDlgData { std::wstring prompt, value; };
static INT_PTR CALLBACK InputDlgProc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp) {
    static InputDlgData* data = nullptr;
    switch (msg) {
    case WM_INITDIALOG: {
        data = (InputDlgData*)lp;
        SetDlgItemTextW(hDlg, 1, data->prompt.c_str());
        SetDlgItemTextW(hDlg, 2, data->value.c_str());
        SendDlgItemMessage(hDlg, 2, EM_SETSEL, 0, -1);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            wchar_t buf[512] = {};
            GetDlgItemTextW(hDlg, 2, buf, 512);
            if (data) data->value = buf;
            EndDialog(hDlg, IDOK);
        } else if (LOWORD(wp) == IDCANCEL)
            EndDialog(hDlg, IDCANCEL);
        return TRUE;
    }
    return FALSE;
}

// Build in-memory DLGTEMPLATE for InputBox (label + edit + OK + Cancel)
static std::wstring ShowInputBox(HWND parent, const wchar_t* title,
                                 const wchar_t* prompt, const wchar_t* def = L"") {
    // We build the dialog template entirely in memory.
    struct Align4 { static size_t up(size_t n) { return (n+3)&~3; } };
    std::vector<uint8_t> tmpl;
    auto append = [&](const void* p, size_t n) {
        for (size_t i = 0; i < n; i++) tmpl.push_back(((const uint8_t*)p)[i]);
    };
    auto wz = [&](const wchar_t* s) {
        append(s, (wcslen(s)+1)*sizeof(wchar_t));
    };
    auto pad4 = [&]() {
        while (tmpl.size() & 3) tmpl.push_back(0);
    };
    auto w16 = [&](uint16_t v) { append(&v, 2); };
    auto w32 = [&](uint32_t v) { append(&v, 4); };

    // DLGTEMPLATE
    DLGTEMPLATE dt = {};
    dt.style     = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_SETFONT | DS_CENTER;
    dt.dwExtendedStyle = 0;
    dt.cdit      = 4;   // label + edit + OK + Cancel
    dt.x = 0; dt.y = 0; dt.cx = 200; dt.cy = 80;
    append(&dt, sizeof(dt));
    w16(0); w16(0);  // menu=none, class=default
    wz(title);       // dialog title
    // Font
    w16(9); wz(L"Segoe UI");
    pad4();

    auto addCtrl = [&](uint32_t style, uint32_t exStyle,
                        short x, short y, short cx, short cy,
                        uint16_t id, const wchar_t* cls, const wchar_t* text) {
        pad4();
        DLGITEMTEMPLATE it = {};
        it.style          = style | WS_CHILD | WS_VISIBLE;
        it.dwExtendedStyle = exStyle;
        it.x = x; it.y = y; it.cx = cx; it.cy = cy;
        it.id = id;
        append(&it, sizeof(it));
        // class
        w16(0xFFFF); // not an ordinal form? — use atom
        // Actually for predefined classes use the atom approach:
        // We'll use string form for clarity
        pad4(); // re-align after item header (sizeof DLGITEMTEMPLATE = 18, not aligned)
        // Let's do it properly:
        // class is a string
        wz(cls);
        wz(text);
        w16(0); // no creation data
    };

    // Because building DLGITEMTEMPLATE in-memory is tricky with alignment,
    // let's use a cleaner manual approach:
    tmpl.clear();

    // Re-do with correct DLGTEMPLATE approach
    // Extended dialog template (DLGTEMPLATEEX) for DS_SETFONT
    // We'll use DLGTEMPLATE with DS_SETFONT which embeds point+facename after title

    struct {
        WORD  dlgVer;
        WORD  signature;
        DWORD helpID;
        DWORD exStyle;
        DWORD style;
        WORD  cDlgItems;
        short x, y, cx, cy;
    } hdr = { 1, 0xFFFF, 0, 0,
              WS_POPUP|WS_CAPTION|WS_SYSMENU|DS_MODALFRAME|DS_SETFONT|DS_CENTER|DS_FIXEDSYS,
              4, 0, 0, 210, 85 };
    append(&hdr, sizeof(hdr));
    w16(0); w16(0);   // no menu, default class
    wz(title);        // caption
    w16(8);           // font point size
    w16(400);         // font weight (FW_NORMAL)
    w16(0);           // italic/charset: 0,DEFAULT_CHARSET
    wz(L"Segoe UI");
    pad4();

    // Helper to add a control for DLGTEMPLATEEX
    auto addItem = [&](DWORD exStyle, DWORD style,
                       short x, short y, short cx, short cy,
                       WORD id, const wchar_t* clsName, const wchar_t* txt) {
        pad4();
        struct {
            DWORD helpID; DWORD exStyle; DWORD style;
            short x, y, cx, cy; DWORD id;
        } ih = { 0, exStyle, WS_CHILD|WS_VISIBLE|style,
                 x, y, cx, cy, id };
        append(&ih, sizeof(ih));
        wz(clsName);   // window class
        wz(txt);       // title
        w16(0);        // extra data size
    };

    // Prompt label
    addItem(0, SS_LEFT, 7, 7, 196, 10, 1, L"STATIC", prompt);
    // Edit box
    addItem(WS_EX_CLIENTEDGE, ES_AUTOHSCROLL | WS_TABSTOP,
            7, 20, 196, 14, 2, L"EDIT", def);
    // OK button
    addItem(0, BS_DEFPUSHBUTTON | WS_TABSTOP,
            60, 60, 60, 14, IDOK, L"BUTTON", L"OK");
    // Cancel button
    addItem(0, WS_TABSTOP,
            130, 60, 60, 14, IDCANCEL, L"BUTTON", L"Cancel");

    InputDlgData d { prompt, def };
    INT_PTR res = DialogBoxIndirectParamW(g_hInst,
        (LPCDLGTEMPLATE)tmpl.data(), parent, InputDlgProc, (LPARAM)&d);
    return (res == IDOK) ? d.value : L"";
}

// ─────────────────── ListView helper (virtual/non-virtual) ──────────────────

static void LvSetCol(HWND lv, int i, const wchar_t* hdr, int w, int fmt = LVCFMT_LEFT) {
    LVCOLUMNW c = {};
    c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    c.pszText = (LPWSTR)hdr;
    c.cx   = w;
    c.fmt  = fmt;
    ListView_InsertColumn(lv, i, &c);
}

static void LvSetItem(HWND lv, int row, int col, const wchar_t* txt) {
    LVITEMW item = {};
    item.mask    = LVIF_TEXT;
    item.iItem   = row;
    item.iSubItem = col;
    item.pszText = (LPWSTR)txt;
    if (col == 0) ListView_InsertItem(lv, &item);
    else          ListView_SetItem(lv, &item);
}

// ─────────────────── UI: refresh process list ────────────────────────────────

static std::vector<ProcessInfo> g_procList;

// Populate the listview from g_procList with current search filter and recents pinned to top.
// Each row's lParam stores the original index into g_procList.
static void PopulateProcessList() {
    HWND lv = GetDlgItem(g_hWnd, IDC_PROC_LIST);
    SendMessage(lv, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv);

    // Read filter
    wchar_t searchBuf[128] = {};
    GetDlgItemTextW(g_hWnd, IDC_PROC_SEARCH, searchBuf, 128);
    std::wstring filter = searchBuf;
    std::transform(filter.begin(), filter.end(), filter.begin(), towlower);

    auto matchesFilter = [&](const ProcessInfo& p) -> bool {
        if (filter.empty()) return true;
        std::wstring lname = p.name;
        std::transform(lname.begin(), lname.end(), lname.begin(), towlower);
        if (lname.find(filter) != std::wstring::npos) return true;
        // Also match PID
        wchar_t pidStr[16];
        swprintf_s(pidStr, L"%u", p.pid);
        return wcsstr(pidStr, filter.c_str()) != nullptr;
    };

    // Build display order: recents (in recency order) first, then everyone else.
    std::vector<size_t> order;
    std::vector<bool>   added(g_procList.size(), false);

    for (auto& recent : g_recentProcesses) {
        for (size_t i = 0; i < g_procList.size(); ++i) {
            if (added[i]) continue;
            if (_wcsicmp(g_procList[i].name.c_str(), recent.c_str()) == 0
                && matchesFilter(g_procList[i])) {
                order.push_back(i);
                added[i] = true;
                break;
            }
        }
    }
    size_t recentCount = order.size();

    for (size_t i = 0; i < g_procList.size(); ++i) {
        if (!added[i] && matchesFilter(g_procList[i]))
            order.push_back(i);
    }

    // Insert into ListView
    for (size_t row = 0; row < order.size(); ++row) {
        size_t i = order[row];
        const auto& p = g_procList[i];
        bool isRecent = (row < recentCount);

        // Star prefix for recently-attached processes
        std::wstring displayName = isRecent ? (L"\u2605 " + p.name) : p.name;

        LVITEMW item = {};
        item.mask     = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
        item.iItem    = (int)row;
        item.iSubItem = 0;
        item.pszText  = (LPWSTR)displayName.c_str();
        item.iImage   = (i < g_procIconIdx.size()) ? g_procIconIdx[i] : 0;
        item.lParam   = (LPARAM)i;
        ListView_InsertItem(lv, &item);

        wchar_t pidBuf[16];
        swprintf_s(pidBuf, L"%u", p.pid);
        LVITEMW sub = {};
        sub.mask     = LVIF_TEXT;
        sub.iItem    = (int)row;
        sub.iSubItem = 1;
        sub.pszText  = pidBuf;
        ListView_SetItem(lv, &sub);
    }

    SendMessage(lv, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(lv, nullptr, TRUE);
}

// Reload process list and refresh icon cache, then populate the view
static void RefreshProcessList() {
    HWND lv = GetDlgItem(g_hWnd, IDC_PROC_LIST);
    ListView_DeleteAllItems(lv);
    ImageList_RemoveAll(g_hProcImg);
    g_procIconIdx.clear();

    // Index 0 = default app icon
    HICON defIcon = LoadIconW(nullptr, IDI_APPLICATION);
    ImageList_AddIcon(g_hProcImg, defIcon);

    g_procList = MemScanner::listProcesses();
    g_procIconIdx.resize(g_procList.size(), 0);

    for (size_t i = 0; i < g_procList.size(); i++) {
        const auto& p = g_procList[i];
        if (!p.exePath.empty()) {
            HICON h = GetSmallExeIcon(p.exePath);
            if (h) {
                g_procIconIdx[i] = ImageList_AddIcon(g_hProcImg, h);
                DestroyIcon(h);
            }
        }
    }

    PopulateProcessList();

    wchar_t status[64];
    swprintf_s(status, L"Process list refreshed (%zu processes)", g_procList.size());
    SetStatus(status);
}

// ─────────────────── UI: attach to selected process ─────────────────────────

static void AttachSelected() {
    HWND lv  = GetDlgItem(g_hWnd, IDC_PROC_LIST);
    int  sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    if (sel < 0) { Err(L"Select a process first."); return; }

    // Look up the original g_procList index from the row's lParam
    LVITEMW it = {};
    it.iItem = sel;
    it.mask  = LVIF_PARAM;
    if (!ListView_GetItem(lv, &it)) { Err(L"Invalid selection."); return; }
    size_t idx = (size_t)it.lParam;
    if (idx >= g_procList.size()) { Err(L"Invalid selection."); return; }

    auto& pi = g_procList[idx];
    if (g_scanner.attach(pi.pid, pi.name)) {
        wchar_t msg[200];
        swprintf_s(msg, L"Attached: %s (PID %u)", pi.name.c_str(), pi.pid);
        SetStatus(msg);
        SetWindowTextW(GetDlgItem(g_hWnd, IDC_RESULTCOUNT), L"Results: 0");
        ListView_DeleteAllItems(GetDlgItem(g_hWnd, IDC_RESULTS));
        ListView_SetItemCountEx(GetDlgItem(g_hWnd, IDC_RESULTS), 0, LVSICF_NOINVALIDATEALL);

        AddToRecent(pi.name);
        PopulateProcessList();    // re-sort so this process pins to the top
    } else {
        DWORD err = GetLastError();
        wchar_t prefix[400];
        swprintf_s(prefix,
            L"Could not open process: %s (PID %u)\n\n"
            L"Possible causes:\n"
            L"  \u2022 MemHawk not running as Administrator\n"
            L"  \u2022 Process is protected (anti-cheat, system process)\n"
            L"  \u2022 Process exited between refresh and attach",
            pi.name.c_str(), pi.pid);
        ErrWithCode(prefix, err);
    }
}

// ─────────────────── UI: toggle scan-type value fields visibility ─────────────

static void UpdateValueFields() {
    HWND cb  = GetDlgItem(g_hWnd, IDC_SCANTYPE);
    int  sel = (int)SendMessage(cb, CB_GETCURSEL, 0, 0);
    ScanType st = (ScanType)sel;
    bool needVal  = (st != ScanType::UNKNOWN && st != ScanType::CHANGED &&
                     st != ScanType::UNCHANGED && st != ScanType::INCREASED &&
                     st != ScanType::DECREASED);
    bool needVal2 = (st == ScanType::BETWEEN);
    ShowWindow(GetDlgItem(g_hWnd, IDC_VALUE1), needVal  ? SW_SHOW : SW_HIDE);
    ShowWindow(GetDlgItem(g_hWnd, IDC_VALUE2), needVal2 ? SW_SHOW : SW_HIDE);
}

// ─────────────────── Scan worker thread ─────────────────────────────────────

struct ScanParams {
    bool      first;
    ScanType  st;
    VType     vt;
    double    val, val2;
};

static DWORD WINAPI ScanThread(LPVOID param) {
    auto* p = (ScanParams*)param;
    g_lastPct  = 0;
    g_scanDone = false;

    auto cb = [](int pct){ g_lastPct = pct; };
    if (p->first)
        g_lastCount = g_scanner.firstScan(p->st, p->vt, p->val, p->val2, cb);
    else
        g_lastCount = g_scanner.nextScan(p->st, p->vt, p->val, p->val2, cb);

    delete p;
    g_scanDone = true;
    PostMessage(g_hWnd, WM_USER + 1, 0, 0);   // WM_SCAN_DONE
    return 0;
}

static bool ParseValue(const wchar_t* s, VType vt, double& out) {
    wchar_t* end = nullptr;
    if (vt == VType::FLOAT || vt == VType::DOUBLE)
        out = wcstod(s, &end);
    else {
        long long v = wcstoll(s, &end, 0);
        out = (double)v;
    }
    return end && end != s && *end == L'\0';
}

static void DoScan(bool first) {
    if (!g_scanner.attached()) { Err(L"Attach a process first."); return; }
    if (g_scanning) return;

    HWND cbVT = GetDlgItem(g_hWnd, IDC_VTYPE);
    HWND cbST = GetDlgItem(g_hWnd, IDC_SCANTYPE);
    HWND eV1  = GetDlgItem(g_hWnd, IDC_VALUE1);
    HWND eV2  = GetDlgItem(g_hWnd, IDC_VALUE2);

    auto vt = (VType)SendMessage(cbVT, CB_GETCURSEL, 0, 0);
    auto st = (ScanType)SendMessage(cbST, CB_GETCURSEL, 0, 0);

    bool needVal = (st != ScanType::UNKNOWN && st != ScanType::CHANGED &&
                    st != ScanType::UNCHANGED && st != ScanType::INCREASED &&
                    st != ScanType::DECREASED);

    double val = 0, val2 = 0;
    if (needVal) {
        wchar_t buf[64] = {};
        GetWindowTextW(eV1, buf, 64);
        if (!ParseValue(buf, vt, val)) { Err(L"Invalid value."); return; }
        if (st == ScanType::BETWEEN) {
            wchar_t buf2[64] = {};
            GetWindowTextW(eV2, buf2, 64);
            if (!ParseValue(buf2, vt, val2)) { Err(L"Invalid max value."); return; }
        }
    }

    g_scanning = true;
    SendMessage(GetDlgItem(g_hWnd, IDC_PROGRESS), PBM_SETPOS, 0, 0);
    SetStatus(L"Scanning...");

    auto* p  = new ScanParams { first, st, vt, val, val2 };
    HANDLE th = CreateThread(nullptr, 0, ScanThread, p, 0, nullptr);
    CloseHandle(th);
}

// ─────────────────── Update result listview (virtual) ───────────────────────

static void UpdateResultsView() {
    HWND lv    = GetDlgItem(g_hWnd, IDC_RESULTS);
    size_t cnt = g_scanner.resultCount();
    ListView_SetItemCountEx(lv, (int)(std::min)(cnt, (size_t)200000), LVSICF_NOINVALIDATEALL);
    wchar_t buf[64];
    swprintf_s(buf, L"Results: %zu%s", cnt, cnt > 200000 ? L" (showing first 200,000)" : L"");
    SetWindowTextW(GetDlgItem(g_hWnd, IDC_RESULTCOUNT), buf);
}

// ─────────────────── Watch list (full update) ───────────────────────────────

static void RefreshWatchList() {
    HWND lv = GetDlgItem(g_hWnd, IDC_WATCHLIST);
    ListView_DeleteAllItems(lv);
    int row = 0;
    for (auto& e : g_scanner.watchList) {
        double cur = g_scanner.readValue(e.address, e.vtype);
        wchar_t buf[64];

        // col 0: frozen indicator
        LvSetItem(lv, row, 0, e.frozen ? L"❄" : L"");
        // col 1: description
        LvSetItem(lv, row, 1, e.description.c_str());
        // col 2: address
        LvSetItem(lv, row, 2, FmtAddr(e.address).c_str());
        // col 3: type
        LvSetItem(lv, row, 3, VTYPE_NAMES[(int)e.vtype]);
        // col 4: value
        if (e.vtype == VType::FLOAT || e.vtype == VType::DOUBLE)
            swprintf_s(buf, L"%.4f", cur);
        else
            swprintf_s(buf, L"%lld", (long long)cur);
        LvSetItem(lv, row, 4, buf);
        ++row;
    }
}

// ─────────────────── Add selected scan result to watch list ─────────────────

static void AddSelectedToWatch() {
    HWND lv  = GetDlgItem(g_hWnd, IDC_RESULTS);
    int  sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_scanner.resultCount()) return;
    auto& r = g_scanner.results()[sel];
    VType vt = (VType)SendMessage(GetDlgItem(g_hWnd, IDC_VTYPE), CB_GETCURSEL, 0, 0);
    // Check duplicate
    for (auto& e : g_scanner.watchList)
        if (e.address == r.address && e.vtype == vt) return;
    g_scanner.watchList.push_back({ r.address, vt, L"", false, r.value, true });
    RefreshWatchList();
}

// ─────────────────── Edit selected watch entry value ────────────────────────

static void EditWatchValue() {
    HWND lv  = GetDlgItem(g_hWnd, IDC_WATCHLIST);
    int  sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_scanner.watchList.size()) return;
    auto& e = g_scanner.watchList[sel];
    double cur = g_scanner.readValue(e.address, e.vtype);
    wchar_t def[64];
    if (e.vtype == VType::FLOAT || e.vtype == VType::DOUBLE)
        swprintf_s(def, L"%.4f", cur);
    else
        swprintf_s(def, L"%lld", (long long)cur);

    std::wstring newStr = ShowInputBox(g_hWnd,
        L"Edit Value",
        (std::wstring(L"New value for ") + FmtAddr(e.address)).c_str(),
        def);
    if (newStr.empty()) return;
    double newVal = 0;
    if (!ParseValue(newStr.c_str(), e.vtype, newVal)) { Err(L"Invalid value."); return; }
    if (!g_scanner.writeValue(e.address, newVal, e.vtype)) {
        DWORD err = GetLastError();
        wchar_t prefix[200];
        swprintf_s(prefix, L"Failed to write %s to address 0x%llX",
                   newStr.c_str(), (unsigned long long)e.address);
        ErrWithCode(prefix, err);
        return;
    }
    RecordWrite(e.address, e.vtype, cur, newVal, L"Edit Value");
    RefreshWatchList();
}

// ─────────────────── Toggle freeze on selected watch entry ──────────────────

static void ToggleFreeze() {
    HWND lv  = GetDlgItem(g_hWnd, IDC_WATCHLIST);
    int  sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_scanner.watchList.size()) return;
    auto& e = g_scanner.watchList[sel];
    e.frozen = !e.frozen;
    if (e.frozen)
        e.freezeValue = g_scanner.readValue(e.address, e.vtype);
    RefreshWatchList();
}

// ─────────────────── Remove selected watch entry ─────────────────────────────

static void RemoveWatchEntry() {
    HWND lv  = GetDlgItem(g_hWnd, IDC_WATCHLIST);
    int  sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    if (sel < 0 || sel >= (int)g_scanner.watchList.size()) return;
    g_scanner.watchList.erase(g_scanner.watchList.begin() + sel);
    RefreshWatchList();
}

// ─────────────────── Manual "add address" dialog ────────────────────────────

static void ManualAddAddress() {
    std::wstring addrStr = ShowInputBox(g_hWnd,
        L"Add Address Manually", L"Address (hex, e.g. 0x1234ABCD):", L"0x");
    if (addrStr.empty()) return;
    wchar_t* end = nullptr;
    uintptr_t addr = (uintptr_t)wcstoull(addrStr.c_str(), &end, 16);
    if (!end || end == addrStr.c_str()) { Err(L"Invalid address."); return; }

    std::wstring descStr = ShowInputBox(g_hWnd, L"Add Address Manually",
        L"Description:", L"Player HP");

    VType vt = (VType)SendMessage(GetDlgItem(g_hWnd, IDC_VTYPE), CB_GETCURSEL, 0, 0);
    g_scanner.watchList.push_back({ addr, vt, descStr, false, 0, true });
    RefreshWatchList();
}

// ─────────────────── Session save / load (simple JSON) ──────────────────────

static std::wstring EscJson(const std::wstring& s) {
    std::wstring out;
    for (wchar_t c : s) {
        if (c == L'"') out += L"\\\"";
        else if (c == L'\\') out += L"\\\\";
        else out += c;
    }
    return out;
}

static void SaveSession() {
    OPENFILENAMEW ofn = {};
    wchar_t path[MAX_PATH] = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hWnd;
    ofn.lpstrFilter = L"MemHawk Session (*.mhk)\0*.mhk\0All Files\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = L"mhk";
    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream f(path);
    if (!f) { Err(L"Could not open file for writing."); return; }
    f << L"{\n  \"process\": \"" << EscJson(g_scanner.processName()) << L"\",\n";
    f << L"  \"pid\": " << g_scanner.pid() << L",\n";
    f << L"  \"entries\": [\n";
    for (size_t i = 0; i < g_scanner.watchList.size(); ++i) {
        auto& e = g_scanner.watchList[i];
        f << L"    {\n";
        f << L"      \"address\": " << e.address << L",\n";
        f << L"      \"vtype\": " << (int)e.vtype << L",\n";
        f << L"      \"description\": \"" << EscJson(e.description) << L"\",\n";
        f << L"      \"frozen\": " << (e.frozen ? L"true" : L"false") << L",\n";
        f << L"      \"freezeValue\": " << e.freezeValue << L"\n";
        f << L"    }" << (i + 1 < g_scanner.watchList.size() ? L"," : L"") << L"\n";
    }
    f << L"  ]\n}\n";
    SetStatus(L"Session saved.");
}

static void LoadSession() {
    if (!g_scanner.attached()) { Err(L"Attach a process before loading a session."); return; }
    OPENFILENAMEW ofn = {};
    wchar_t path[MAX_PATH] = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hWnd;
    ofn.lpstrFilter = L"MemHawk Session (*.mhk)\0*.mhk\0All Files\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;

    std::wifstream f(path);
    if (!f) { Err(L"Could not open file."); return; }
    std::wstring content((std::istreambuf_iterator<wchar_t>(f)),
                          std::istreambuf_iterator<wchar_t>());

    // Simple manual JSON parse (avoids external libs)
    auto findField = [&](const std::wstring& key, size_t from) -> size_t {
        std::wstring needle = L"\"" + key + L"\"";
        return content.find(needle, from);
    };
    auto parseInt = [&](const std::wstring& key, size_t from) -> long long {
        size_t p = findField(key, from);
        if (p == std::wstring::npos) return 0;
        p = content.find_first_of(L"-0123456789", p + key.size() + 2);
        if (p == std::wstring::npos) return 0;
        return std::stoll(content.substr(p));
    };
    auto parseBool = [&](const std::wstring& key, size_t from) -> bool {
        size_t p = findField(key, from);
        if (p == std::wstring::npos) return false;
        size_t v = content.find_first_not_of(L": \t\n\r", p + key.size() + 2);
        return v != std::wstring::npos && content[v] == L't';
    };
    auto parseStr = [&](const std::wstring& key, size_t from) -> std::wstring {
        size_t p = findField(key, from);
        if (p == std::wstring::npos) return L"";
        size_t q = content.find(L'"', p + key.size() + 3);
        if (q == std::wstring::npos) return L"";
        size_t e = content.find(L'"', q + 1);
        return (e != std::wstring::npos) ? content.substr(q + 1, e - q - 1) : L"";
    };

    g_scanner.watchList.clear();
    size_t pos = 0;
    while ((pos = content.find(L"\"address\"", pos)) != std::wstring::npos) {
        WatchEntry e = {};
        e.address     = (uintptr_t)parseInt(L"address",     pos);
        e.vtype       = (VType)    parseInt(L"vtype",       pos);
        e.description =            parseStr(L"description", pos);
        e.frozen      =            parseBool(L"frozen",     pos);
        e.freezeValue =     (double)parseInt(L"freezeValue",pos);
        e.active      = true;
        g_scanner.watchList.push_back(e);
        pos++;
    }
    RefreshWatchList();
    SetStatus(L"Session loaded.");
}

// ─────────────────── Hex Viewer Window ──────────────────────────────────────

static HWND       g_hexWnd  = nullptr;
static uintptr_t  g_hexAddr = 0;
constexpr int     HEX_BYTES = 256;          // bytes shown
constexpr int     HEX_PER_ROW = 16;
constexpr UINT    IDC_HEX_ADDR = 401;
constexpr UINT    IDC_HEX_GO   = 402;
constexpr UINT    IDC_HEX_REF  = 403;
constexpr UINT    IDC_HEX_EDIT = 404;
constexpr UINT    IDC_HEX_DISP = 405;
constexpr UINT    HEX_TIMER    = 91;

static void RefreshHexView() {
    if (!g_hexWnd || !g_scanner.attached()) return;
    HWND disp = GetDlgItem(g_hexWnd, IDC_HEX_DISP);

    uint8_t buf[HEX_BYTES] = {};
    bool ok = g_scanner.readRaw(g_hexAddr, buf, HEX_BYTES);

    if (!ok) {
        SetWindowTextW(disp, L"<unable to read memory at this address>");
        return;
    }

    std::wstring out;
    out.reserve(HEX_BYTES * 6);
    wchar_t line[160];
    for (int row = 0; row < HEX_BYTES / HEX_PER_ROW; row++) {
        swprintf_s(line, L"%016llX  ",
                   (unsigned long long)(g_hexAddr + row * HEX_PER_ROW));
        out += line;
        for (int col = 0; col < HEX_PER_ROW; col++) {
            swprintf_s(line, L"%02X ", buf[row * HEX_PER_ROW + col]);
            out += line;
            if (col == 7) out += L" ";
        }
        out += L" |";
        for (int col = 0; col < HEX_PER_ROW; col++) {
            uint8_t b = buf[row * HEX_PER_ROW + col];
            out += (b >= 32 && b < 127) ? (wchar_t)b : L'.';
        }
        out += L"|\r\n";
    }
    SetWindowTextW(disp, out.c_str());
}

static LRESULT CALLBACK HexViewProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HFONT defFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        HFONT monoFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        auto mk = [&](const wchar_t* cls, const wchar_t* txt, DWORD style,
                       int x, int y, int w, int h, int id, HFONT f) -> HWND {
            HWND hw = CreateWindowExW(0, cls, txt, WS_CHILD | WS_VISIBLE | style,
                x, y, w, h, hWnd, (HMENU)(INT_PTR)id, g_hInst, nullptr);
            SendMessage(hw, WM_SETFONT, (WPARAM)f, TRUE);
            return hw;
        };
        mk(L"STATIC", L"Address:", 0, 10, 14, 60, 18, 0, defFont);
        mk(L"EDIT",   L"", WS_BORDER | ES_AUTOHSCROLL, 70, 12, 200, 22, IDC_HEX_ADDR, defFont);
        mk(L"BUTTON", L"Go",          BS_PUSHBUTTON, 280, 12, 50, 22, IDC_HEX_GO,   defFont);
        mk(L"BUTTON", L"Refresh",     BS_PUSHBUTTON, 340, 12, 70, 22, IDC_HEX_REF,  defFont);
        mk(L"BUTTON", L"Edit Byte...", BS_PUSHBUTTON, 420, 12, 100, 22, IDC_HEX_EDIT, defFont);
        mk(L"EDIT", L"",
           WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
           10, 44, 660, 380, IDC_HEX_DISP, monoFont);

        wchar_t buf[32];
        swprintf_s(buf, L"0x%llX", (unsigned long long)g_hexAddr);
        SetDlgItemTextW(hWnd, IDC_HEX_ADDR, buf);

        RefreshHexView();
        SetTimer(hWnd, HEX_TIMER, 750, nullptr);
        return 0;
    }

    case WM_TIMER:
        if (wp == HEX_TIMER) RefreshHexView();
        return 0;

    case WM_SIZE: {
        int w = LOWORD(lp), h = HIWORD(lp);
        HWND disp = GetDlgItem(hWnd, IDC_HEX_DISP);
        if (disp) MoveWindow(disp, 10, 44, w - 20, h - 54, TRUE);
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_HEX_GO || id == IDC_HEX_REF) {
            if (id == IDC_HEX_GO) {
                wchar_t buf[64] = {};
                GetDlgItemTextW(hWnd, IDC_HEX_ADDR, buf, 64);
                wchar_t* end = nullptr;
                uintptr_t a = (uintptr_t)wcstoull(buf, &end, 0);
                if (end && end != buf) g_hexAddr = a;
            }
            RefreshHexView();
        } else if (id == IDC_HEX_EDIT) {
            std::wstring offS = ShowInputBox(hWnd, L"Edit Byte",
                L"Offset within view (hex):", L"0x0");
            if (offS.empty()) return 0;
            wchar_t* end = nullptr;
            unsigned long off = wcstoul(offS.c_str(), &end, 0);
            if (!end || end == offS.c_str() || off >= HEX_BYTES) {
                Err(L"Invalid offset (must be < 0x100).");
                return 0;
            }
            std::wstring valS = ShowInputBox(hWnd, L"Edit Byte",
                L"New byte value (hex 00-FF):", L"00");
            if (valS.empty()) return 0;
            unsigned long v = wcstoul(valS.c_str(), &end, 16);
            if (!end || end == valS.c_str() || v > 0xFF) {
                Err(L"Invalid byte value.");
                return 0;
            }
            uint8_t b = (uint8_t)v;
            uint8_t oldByte = 0;
            g_scanner.readRaw(g_hexAddr + off, &oldByte, 1);
            if (!g_scanner.writeRaw(g_hexAddr + off, &b, 1)) {
                DWORD e = GetLastError();
                wchar_t prefix[160];
                swprintf_s(prefix, L"Failed to write byte 0x%02X to 0x%llX",
                           (unsigned)b, (unsigned long long)(g_hexAddr + off));
                ErrWithCode(prefix, e);
            } else {
                RecordWrite(g_hexAddr + off, VType::UBYTE1,
                            (double)oldByte, (double)b, L"Hex Edit");
            }
            RefreshHexView();
        }
        return 0;
    }

    case WM_CLOSE:
        KillTimer(hWnd, HEX_TIMER);
        DestroyWindow(hWnd);
        g_hexWnd = nullptr;
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wp, lp);
}

static void OpenHexViewer(uintptr_t address) {
    if (!g_scanner.attached()) { Err(L"Attach a process first."); return; }

    static bool registered = false;
    if (!registered) {
        registered = true;
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = HexViewProc;
        wc.hInstance     = g_hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"MemHawkHex";
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
    }

    g_hexAddr = address;
    if (g_hexWnd && IsWindow(g_hexWnd)) {
        wchar_t buf[32];
        swprintf_s(buf, L"0x%llX", (unsigned long long)g_hexAddr);
        SetDlgItemTextW(g_hexWnd, IDC_HEX_ADDR, buf);
        RefreshHexView();
        SetForegroundWindow(g_hexWnd);
        return;
    }

    g_hexWnd = CreateWindowExW(0, L"MemHawkHex",
        L"Hex Viewer", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 700, 500,
        g_hWnd, nullptr, g_hInst, nullptr);
    ShowWindow(g_hexWnd, SW_SHOW);
}

static void OpenHexViewerSelected() {
    HWND lv  = GetDlgItem(g_hWnd, IDC_WATCHLIST);
    int  sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
    if (sel >= 0 && sel < (int)g_scanner.watchList.size()) {
        OpenHexViewer(g_scanner.watchList[sel].address);
        return;
    }
    // Fall back to selected scan result
    HWND rv = GetDlgItem(g_hWnd, IDC_RESULTS);
    int  rs = ListView_GetNextItem(rv, -1, LVNI_SELECTED);
    if (rs >= 0 && rs < (int)g_scanner.resultCount()) {
        OpenHexViewer(g_scanner.results()[rs].address);
        return;
    }
    Err(L"Select an address from the watch list or scan results first.");
}

// ─────────────────── Modules Dialog ─────────────────────────────────────────

static HWND g_modWnd = nullptr;
constexpr UINT IDC_MOD_LIST  = 501;
constexpr UINT IDC_MOD_COPY  = 502;
constexpr UINT IDC_MOD_CLOSE = 503;

static void CopyToClipboard(HWND owner, const wchar_t* text) {
    if (!OpenClipboard(owner)) return;
    EmptyClipboard();
    size_t  bytes = (wcslen(text) + 1) * sizeof(wchar_t);
    HGLOBAL hg    = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hg) {
        memcpy(GlobalLock(hg), text, bytes);
        GlobalUnlock(hg);
        SetClipboardData(CF_UNICODETEXT, hg);
    }
    CloseClipboard();
}

static LRESULT CALLBACK ModulesProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HFONT defFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        HWND lv = CreateWindowExW(WS_EX_CLIENTEDGE, L"SysListView32", L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            10, 10, 580, 380, hWnd, (HMENU)(INT_PTR)IDC_MOD_LIST, g_hInst, nullptr);
        SendMessage(lv, WM_SETFONT, (WPARAM)defFont, TRUE);
        ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT |
                                              LVS_EX_GRIDLINES |
                                              LVS_EX_DOUBLEBUFFER);

        auto col = [&](int i, const wchar_t* t, int w, int fmt = LVCFMT_LEFT) {
            LVCOLUMNW c = {};
            c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            c.pszText = (LPWSTR)t; c.cx = w; c.fmt = fmt;
            ListView_InsertColumn(lv, i, &c);
        };
        col(0, L"Module Name",  170);
        col(1, L"Base Address", 170);
        col(2, L"Size",         100, LVCFMT_RIGHT);
        col(3, L"End Address",  170);

        // Populate
        auto modules = g_scanner.listModules();
        int row = 0;
        for (auto& m : modules) {
            wchar_t buf1[32], buf2[32], buf3[32];
            swprintf_s(buf1, L"0x%016llX", (unsigned long long)m.base);
            swprintf_s(buf2, L"%zu KB",     m.size / 1024);
            swprintf_s(buf3, L"0x%016llX", (unsigned long long)(m.base + m.size));

            LVITEMW it = {};
            it.mask = LVIF_TEXT;
            it.iItem = row;
            it.pszText = (LPWSTR)m.name.c_str();
            ListView_InsertItem(lv, &it);

            it.iSubItem = 1; it.pszText = buf1; ListView_SetItem(lv, &it);
            it.iSubItem = 2; it.pszText = buf2; ListView_SetItem(lv, &it);
            it.iSubItem = 3; it.pszText = buf3; ListView_SetItem(lv, &it);
            row++;
        }

        HWND b1 = CreateWindowW(L"BUTTON", L"📋 Copy Base Address",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            10, 400, 180, 26, hWnd, (HMENU)IDC_MOD_COPY, g_hInst, nullptr);
        HWND b2 = CreateWindowW(L"BUTTON", L"Close",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            500, 400, 90, 26, hWnd, (HMENU)IDC_MOD_CLOSE, g_hInst, nullptr);
        SendMessage(b1, WM_SETFONT, (WPARAM)defFont, TRUE);
        SendMessage(b2, WM_SETFONT, (WPARAM)defFont, TRUE);

        wchar_t title[256];
        swprintf_s(title, L"Loaded Modules — %zu modules in %s",
                   modules.size(), g_scanner.processName().c_str());
        SetWindowTextW(hWnd, title);
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lp), h = HIWORD(lp);
        HWND lv = GetDlgItem(hWnd, IDC_MOD_LIST);
        if (lv) MoveWindow(lv, 10, 10, w - 20, h - 50, TRUE);
        HWND b1 = GetDlgItem(hWnd, IDC_MOD_COPY);
        HWND b2 = GetDlgItem(hWnd, IDC_MOD_CLOSE);
        if (b1) MoveWindow(b1, 10, h - 36, 180, 26, TRUE);
        if (b2) MoveWindow(b2, w - 100, h - 36, 90, 26, TRUE);
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_MOD_COPY) {
            HWND lv = GetDlgItem(hWnd, IDC_MOD_LIST);
            int  sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
            if (sel >= 0) {
                wchar_t buf[64] = {};
                ListView_GetItemText(lv, sel, 1, buf, 64);
                CopyToClipboard(hWnd, buf);
                MessageBoxW(hWnd, L"Base address copied to clipboard.",
                            L"Copied", MB_ICONINFORMATION | MB_OK);
            }
        } else if (id == IDC_MOD_CLOSE) {
            DestroyWindow(hWnd);
            g_modWnd = nullptr;
        }
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hWnd);
        g_modWnd = nullptr;
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wp, lp);
}

static void OpenModulesDialog() {
    if (!g_scanner.attached()) { Err(L"Attach a process first."); return; }

    static bool registered = false;
    if (!registered) {
        registered = true;
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = ModulesProc;
        wc.hInstance     = g_hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"MemHawkModules";
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
    }

    if (g_modWnd && IsWindow(g_modWnd)) {
        SetForegroundWindow(g_modWnd);
        return;
    }

    g_modWnd = CreateWindowExW(0, L"MemHawkModules",
        L"Loaded Modules", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 620, 470,
        g_hWnd, nullptr, g_hInst, nullptr);
    ShowWindow(g_modWnd, SW_SHOW);
}

// ─────────────────── AOB Scan dialog & worker ───────────────────────────────

struct AobParams {
    std::vector<uint8_t> bytes;
    std::vector<bool>    mask;
};

static DWORD WINAPI AobScanThread(LPVOID p) {
    auto* params = (AobParams*)p;
    g_lastPct  = 0;
    g_scanDone = false;
    g_lastCount = g_scanner.aobScan(params->bytes, params->mask,
        [](int pct){ g_lastPct = pct; });
    delete params;
    g_scanDone = true;
    PostMessage(g_hWnd, WM_USER + 1, 0, 0);
    return 0;
}

static void DoAobScan() {
    if (!g_scanner.attached()) { Err(L"Attach a process first."); return; }
    if (g_scanning) return;

    std::wstring pattern = ShowInputBox(g_hWnd, L"AOB Scan",
        L"Hex pattern (?? = wildcard):",
        L"48 8B 05 ?? ?? ?? ?? 89 41");
    if (pattern.empty()) return;

    auto* p = new AobParams;
    if (!MemScanner::parseAobPattern(pattern, p->bytes, p->mask)) {
        delete p;
        Err(L"Invalid pattern.\nUse hex bytes separated by spaces, ?? for wildcards.\n"
            L"Example: 48 8B 05 ?? ?? ?? ?? 89 41");
        return;
    }

    g_scanning = true;
    SendMessage(GetDlgItem(g_hWnd, IDC_PROGRESS), PBM_SETPOS, 0, 0);
    wchar_t status[80];
    swprintf_s(status, L"AOB scanning (%zu bytes)...", p->bytes.size());
    SetStatus(status);

    HANDLE th = CreateThread(nullptr, 0, AobScanThread, p, 0, nullptr);
    CloseHandle(th);
}

// ─────────────────── Write History dialog ──────────────────────────────────

static HWND g_writesWnd = nullptr;
constexpr UINT IDC_WR_LIST   = 601;
constexpr UINT IDC_WR_REVERT = 602;
constexpr UINT IDC_WR_REVALL = 603;
constexpr UINT IDC_WR_CLEAR  = 604;
constexpr UINT IDC_WR_CLOSE  = 605;

static void PopulateWriteHistory(HWND lv) {
    ListView_DeleteAllItems(lv);
    // Show most-recent first
    for (size_t i = 0; i < g_writeHistory.size(); ++i) {
        size_t idx = g_writeHistory.size() - 1 - i;
        const auto& w = g_writeHistory[idx];

        wchar_t timeStr[32], addrStr[32], changeStr[80];
        swprintf_s(timeStr, L"%02d:%02d:%02d",
                   w.timestamp.wHour, w.timestamp.wMinute, w.timestamp.wSecond);
        swprintf_s(addrStr, L"0x%016llX", (unsigned long long)w.address);

        if (w.vtype == VType::FLOAT || w.vtype == VType::DOUBLE)
            swprintf_s(changeStr, L"%.4f \u2192 %.4f", w.oldValue, w.newValue);
        else if (w.vtype == VType::UBYTE1 || w.vtype == VType::BYTE1)
            swprintf_s(changeStr, L"0x%02X \u2192 0x%02X",
                       (unsigned)(uint8_t)w.oldValue, (unsigned)(uint8_t)w.newValue);
        else
            swprintf_s(changeStr, L"%lld \u2192 %lld",
                       (long long)w.oldValue, (long long)w.newValue);

        LVITEMW it = {};
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = (int)i;
        it.pszText = timeStr;
        it.lParam  = (LPARAM)idx;   // remember original index
        ListView_InsertItem(lv, &it);

        LVITEMW sub = {};
        sub.mask = LVIF_TEXT;
        sub.iItem = (int)i;
        sub.iSubItem = 1; sub.pszText = addrStr;                ListView_SetItem(lv, &sub);
        sub.iSubItem = 2; sub.pszText = (LPWSTR)VTYPE_NAMES[(int)w.vtype]; ListView_SetItem(lv, &sub);
        sub.iSubItem = 3; sub.pszText = changeStr;              ListView_SetItem(lv, &sub);
        sub.iSubItem = 4; sub.pszText = (LPWSTR)w.source.c_str(); ListView_SetItem(lv, &sub);
    }
}

static LRESULT CALLBACK WritesProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HFONT defFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        HWND lv = CreateWindowExW(WS_EX_CLIENTEDGE, L"SysListView32", L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
            10, 10, 700, 320, hWnd, (HMENU)(INT_PTR)IDC_WR_LIST, g_hInst, nullptr);
        SendMessage(lv, WM_SETFONT, (WPARAM)defFont, TRUE);
        ListView_SetExtendedListViewStyle(lv,
            LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

        auto col = [&](int i, const wchar_t* t, int w, int fmt = LVCFMT_LEFT) {
            LVCOLUMNW c = {};
            c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            c.pszText = (LPWSTR)t; c.cx = w; c.fmt = fmt;
            ListView_InsertColumn(lv, i, &c);
        };
        col(0, L"Time",     80);
        col(1, L"Address", 170);
        col(2, L"Type",     90);
        col(3, L"Change",  220, LVCFMT_RIGHT);
        col(4, L"Source",  120);

        PopulateWriteHistory(lv);

        auto mkBtn = [&](const wchar_t* txt, int x, int w, int id) {
            HWND b = CreateWindowW(L"BUTTON", txt, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                x, 340, w, 26, hWnd, (HMENU)(INT_PTR)id, g_hInst, nullptr);
            SendMessage(b, WM_SETFONT, (WPARAM)defFont, TRUE);
        };
        mkBtn(L"\u21B6 Revert Selected", 10,  150, IDC_WR_REVERT);
        mkBtn(L"\u21B6 Revert All",      170, 110, IDC_WR_REVALL);
        mkBtn(L"Clear History",          290, 110, IDC_WR_CLEAR);
        mkBtn(L"Close",                  620,  90, IDC_WR_CLOSE);

        wchar_t title[64];
        swprintf_s(title, L"Write History — %zu entries", g_writeHistory.size());
        SetWindowTextW(hWnd, title);
        return 0;
    }

    case WM_SIZE: {
        int w = LOWORD(lp), h = HIWORD(lp);
        HWND lv = GetDlgItem(hWnd, IDC_WR_LIST);
        if (lv) MoveWindow(lv, 10, 10, w - 20, h - 50, TRUE);
        // Reposition buttons along bottom
        int by = h - 36;
        if (auto b = GetDlgItem(hWnd, IDC_WR_REVERT))  MoveWindow(b,  10, by, 150, 26, TRUE);
        if (auto b = GetDlgItem(hWnd, IDC_WR_REVALL))  MoveWindow(b, 170, by, 110, 26, TRUE);
        if (auto b = GetDlgItem(hWnd, IDC_WR_CLEAR))   MoveWindow(b, 290, by, 110, 26, TRUE);
        if (auto b = GetDlgItem(hWnd, IDC_WR_CLOSE))   MoveWindow(b, w - 100, by, 90, 26, TRUE);
        return 0;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);
        HWND lv = GetDlgItem(hWnd, IDC_WR_LIST);
        if (id == IDC_WR_REVERT) {
            int sel = ListView_GetNextItem(lv, -1, LVNI_SELECTED);
            if (sel < 0) { SetStatus(L"Nothing selected."); return 0; }
            LVITEMW it = {}; it.iItem = sel; it.mask = LVIF_PARAM;
            ListView_GetItem(lv, &it);
            size_t idx = (size_t)it.lParam;
            if (idx >= g_writeHistory.size()) return 0;
            auto w = g_writeHistory[idx];
            if (g_scanner.writeValue(w.address, w.oldValue, w.vtype)) {
                g_writeHistory.erase(g_writeHistory.begin() + idx);
                PopulateWriteHistory(lv);
                RefreshWatchList();
                wchar_t msg[120];
                swprintf_s(msg, L"Reverted 0x%llX", (unsigned long long)w.address);
                SetStatus(msg);
            } else {
                Err(L"Revert failed.");
            }
        } else if (id == IDC_WR_REVALL) {
            if (g_writeHistory.empty()) return 0;
            if (MessageBoxW(hWnd,
                    L"Revert ALL writes (most-recent first)?",
                    L"Revert All", MB_YESNO | MB_ICONQUESTION) != IDYES)
                return 0;
            int reverted = 0;
            // Replay in reverse so each revert undoes its successor's effect cleanly
            for (auto it = g_writeHistory.rbegin(); it != g_writeHistory.rend(); ++it) {
                if (g_scanner.writeValue(it->address, it->oldValue, it->vtype)) reverted++;
            }
            g_writeHistory.clear();
            PopulateWriteHistory(lv);
            RefreshWatchList();
            wchar_t msg[80];
            swprintf_s(msg, L"Reverted %d writes.", reverted);
            SetStatus(msg);
        } else if (id == IDC_WR_CLEAR) {
            if (MessageBoxW(hWnd,
                    L"Clear the write history without reverting?",
                    L"Clear History", MB_YESNO | MB_ICONQUESTION) != IDYES)
                return 0;
            g_writeHistory.clear();
            PopulateWriteHistory(lv);
        } else if (id == IDC_WR_CLOSE) {
            DestroyWindow(hWnd);
            g_writesWnd = nullptr;
        }
        return 0;
    }

    case WM_CLOSE:
        DestroyWindow(hWnd);
        g_writesWnd = nullptr;
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wp, lp);
}

static void OpenWriteHistory() {
    static bool registered = false;
    if (!registered) {
        registered = true;
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.style         = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc   = WritesProc;
        wc.hInstance     = g_hInst;
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"MemHawkWrites";
        wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
        RegisterClassExW(&wc);
    }
    if (g_writesWnd && IsWindow(g_writesWnd)) {
        // Refresh contents in case new writes happened since opening
        PopulateWriteHistory(GetDlgItem(g_writesWnd, IDC_WR_LIST));
        SetForegroundWindow(g_writesWnd);
        return;
    }
    g_writesWnd = CreateWindowExW(0, L"MemHawkWrites",
        L"Write History", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 740, 410,
        g_hWnd, nullptr, g_hInst, nullptr);
    ShowWindow(g_writesWnd, SW_SHOW);
}

// ─────────────────── Window creation & layout ───────────────────────────────

static void CreateControls(HWND hWnd) {
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    auto make = [&](const wchar_t* cls, const wchar_t* txt, DWORD style, DWORD exStyle,
                    int x, int y, int w, int h, int id) -> HWND {
        HWND hw = CreateWindowExW(exStyle, cls, txt,
            WS_CHILD | WS_VISIBLE | style, x, y, w, h, hWnd,
            (HMENU)(INT_PTR)id, g_hInst, nullptr);
        SendMessage(hw, WM_SETFONT, (WPARAM)hFont, TRUE);
        return hw;
    };

    // ── Left panel ────────────────────────────────────────────────────────────

    // Group: Process
    make(L"BUTTON", L"Process", BS_GROUPBOX, 0,
         PAD, PAD, LEFT_W - PAD*2, 155, 0);

    make(L"STATIC", L"Filter:", 0, 0,
         PAD*2, 24, 36, 14, 0);
    make(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE,
         PAD*2 + 38, 22, LEFT_W - PAD*4 - 38, 18, IDC_PROC_SEARCH);

    // Process listview with icons
    HWND lv = make(L"SysListView32", L"",
                   LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS |
                   LVS_NOCOLUMNHEADER | WS_TABSTOP, WS_EX_CLIENTEDGE,
                   PAD*2, 46, LEFT_W - PAD*4, 80, IDC_PROC_LIST);
    ListView_SetExtendedListViewStyle(lv, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    LvSetCol(lv, 0, L"Process",  170);
    LvSetCol(lv, 1, L"PID",       60, LVCFMT_RIGHT);

    // Image list for process icons (16x16, 32-bit color w/ alpha)
    g_hProcImg = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 100, 100);
    ListView_SetImageList(lv, g_hProcImg, LVSIL_SMALL);

    // Cue banner placeholder text on the search box
    SendDlgItemMessage(hWnd, IDC_PROC_SEARCH, EM_SETCUEBANNER, TRUE,
                       (LPARAM)L"Type to filter (name or PID)...");

    make(L"BUTTON", L"Refresh", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD*2, 132, 85, 20, IDC_REFRESH_BTN);
    make(L"BUTTON", L"Attach", BS_PUSHBUTTON | WS_TABSTOP | BS_DEFPUSHBUTTON, 0,
         LEFT_W - PAD*2 - 90, 132, 90, 20, IDC_ATTACH_BTN);

    // Group: Scan
    make(L"BUTTON", L"Scan Configuration", BS_GROUPBOX, 0,
         PAD, 165, LEFT_W - PAD*2, 200, 0);

    int ly = 183;
    make(L"STATIC", L"Value Type:", 0, 0, PAD*2, ly, LEFT_W - PAD*4, 14, 0); ly += 15;
    HWND cbVT = make(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP, 0,
                     PAD*2, ly, LEFT_W - PAD*4, 120, IDC_VTYPE); ly += 22;
    for (int i = 0; i < VTYPE_COUNT; i++)
        SendMessage(cbVT, CB_ADDSTRING, 0, (LPARAM)VTYPE_NAMES[i]);
    SendMessage(cbVT, CB_SETCURSEL, 2, 0);   // default: 4 Bytes

    make(L"STATIC", L"Scan Type:", 0, 0, PAD*2, ly, LEFT_W - PAD*4, 14, 0); ly += 15;
    HWND cbST = make(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP, 0,
                     PAD*2, ly, LEFT_W - PAD*4, 200, IDC_SCANTYPE); ly += 22;
    for (int i = 0; i < SCANTYPE_COUNT; i++)
        SendMessage(cbST, CB_ADDSTRING, 0, (LPARAM)SCANTYPE_NAMES[i]);
    SendMessage(cbST, CB_SETCURSEL, 0, 0);

    make(L"STATIC", L"Value:", 0, 0, PAD*2, ly, 40, 14, 0);
    make(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE,
         PAD*2 + 44, ly, LEFT_W - PAD*4 - 44, 18, IDC_VALUE1); ly += 22;
    make(L"STATIC", L"Value 2 (max):", 0, 0, PAD*2, ly, 90, 14, 0);
    make(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE,
         PAD*2 + 94, ly, LEFT_W - PAD*4 - 94, 18, IDC_VALUE2); ly += 22;
    ShowWindow(GetDlgItem(hWnd, IDC_VALUE2), SW_HIDE);

    // Group: Actions
    make(L"BUTTON", L"Scan Actions", BS_GROUPBOX, 0,
         PAD, 372, LEFT_W - PAD*2, 118, 0);

    make(L"BUTTON", L"🔍 First Scan", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD*2, 390, (LEFT_W - PAD*4)/2 - 2, 24, IDC_FIRSTSCAN);
    make(L"BUTTON", L"▶ Next Scan", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD*2 + (LEFT_W - PAD*4)/2 + 2, 390, (LEFT_W - PAD*4)/2 - 2, 24, IDC_NEXTSCAN);
    make(L"BUTTON", L"↩ Undo Scan", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD*2, 418, (LEFT_W - PAD*4)/2 - 2, 24, IDC_UNDO);
    make(L"BUTTON", L"✖ Reset", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD*2 + (LEFT_W - PAD*4)/2 + 2, 418, (LEFT_W - PAD*4)/2 - 2, 24, IDC_RESETSCAN);
    make(L"BUTTON", L"🧬 AOB Scan...", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD*2, 446, LEFT_W - PAD*4, 30, IDC_AOB_SCAN);

    // Progress bar + result count
    make(L"msctls_progress32", L"", PBS_SMOOTH, WS_EX_CLIENTEDGE,
         PAD, 498, LEFT_W - PAD*2, 12, IDC_PROGRESS);
    make(L"STATIC", L"Results: 0", SS_LEFT, 0,
         PAD, 514, LEFT_W - PAD*2, 16, IDC_RESULTCOUNT);

    // Session + Modules buttons (3 columns)
    int btnW = (LEFT_W - PAD*2 - 8) / 3;
    make(L"BUTTON", L"💾 Save", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD, 535, btnW, 22, IDC_SAVE_BTN);
    make(L"BUTTON", L"📂 Load", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD + btnW + 4, 535, btnW, 22, IDC_LOAD_BTN);
    make(L"BUTTON", L"📦 Modules", BS_PUSHBUTTON | WS_TABSTOP, 0,
         PAD + (btnW + 4) * 2, 535, btnW, 22, IDC_MODULES);

    // Always-on-top toggle
    make(L"BUTTON", L"📌 Always on top", BS_AUTOCHECKBOX | WS_TABSTOP, 0,
         PAD, 565, LEFT_W - PAD*2, 20, IDC_PIN_TOP);

    // ── Right panel: scan results (virtual ListView) ──────────────────────

    HWND lvR = make(L"SysListView32", L"",
                    LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS |
                    LVS_OWNERDATA | WS_TABSTOP, WS_EX_CLIENTEDGE,
                    LEFT_W + PAD, PAD, 600, 400, IDC_RESULTS);
    ListView_SetExtendedListViewStyle(lvR, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                                          LVS_EX_DOUBLEBUFFER);
    LvSetCol(lvR, 0, L"Address",        160);
    LvSetCol(lvR, 1, L"Value",          140, LVCFMT_RIGHT);
    LvSetCol(lvR, 2, L"Previous Value", 140, LVCFMT_RIGHT);

    // ── Bottom panel: address/watch list ─────────────────────────────────

    // Address list toolbar
    int bx = PAD;
    auto makeBtnW = [&](const wchar_t* txt, int id, int w = 110) {
        HWND hw = make(L"BUTTON", txt, BS_PUSHBUTTON | WS_TABSTOP, 0,
                       bx, 0, w, 22, id);
        bx += w + 4;
        return hw;
    };

    // We'll position these in WM_SIZE

    HWND lvW = make(L"SysListView32", L"",
                    LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS | WS_TABSTOP,
                    WS_EX_CLIENTEDGE,
                    LEFT_W + PAD, 410 + PAD*2, 600, WATCH_H, IDC_WATCHLIST);
    ListView_SetExtendedListViewStyle(lvW, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES |
                                          LVS_EX_DOUBLEBUFFER | LVS_EX_CHECKBOXES);
    LvSetCol(lvW, 0, L"❄",           30,  LVCFMT_CENTER);
    LvSetCol(lvW, 1, L"Description", 200);
    LvSetCol(lvW, 2, L"Address",     160);
    LvSetCol(lvW, 3, L"Type",         80, LVCFMT_CENTER);
    LvSetCol(lvW, 4, L"Value",        100, LVCFMT_RIGHT);

    // Watch toolbar buttons (positioned in WM_SIZE)
    make(L"BUTTON", L"+ Add Selected", BS_PUSHBUTTON | WS_TABSTOP, 0,
         0, 0, 120, 22, IDC_ADD_ADDR);
    make(L"BUTTON", L"+ Manual Add", BS_PUSHBUTTON | WS_TABSTOP, 0,
         0, 0, 110, 22, IDC_MANUAL_ADD);
    make(L"BUTTON", L"Edit Value", BS_PUSHBUTTON | WS_TABSTOP, 0,
         0, 0, 90, 22, IDC_EDIT_VAL);
    make(L"BUTTON", L"❄ Freeze", BS_PUSHBUTTON | WS_TABSTOP, 0,
         0, 0, 80, 22, IDC_FREEZE_BTN);
    make(L"BUTTON", L"🗑 Remove", BS_PUSHBUTTON | WS_TABSTOP, 0,
         0, 0, 80, 22, IDC_REMOVE_ADDR);
    make(L"BUTTON", L"🔍 Hex View", BS_PUSHBUTTON | WS_TABSTOP, 0,
         0, 0, 100, 22, IDC_HEX_VIEW);
    make(L"BUTTON", L"↶ Writes", BS_PUSHBUTTON | WS_TABSTOP, 0,
         0, 0, 90, 22, IDC_UNDO_WRITE);

    // Status bar
    CreateWindowExW(0, STATUSCLASSNAMEW, L"Ready",
                    WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                    0, 0, 0, 0, hWnd, (HMENU)IDC_STATUSBAR, g_hInst, nullptr);
}

// Resize all controls to fit the window
static void ResizeControls(int cw, int ch) {
    // Status bar height
    HWND sb  = GetDlgItem(g_hWnd, IDC_STATUSBAR);
    SendMessage(sb, WM_SIZE, 0, 0);
    RECT sbr = {}; GetWindowRect(sb, &sbr);
    int sbH  = sbr.bottom - sbr.top;
    int usableH = ch - sbH;

    // Watch toolbar row height
    int tbH = 26;
    // Watch list takes WATCH_H, toolbar tbH above it, separator 4px
    int watchBottom = usableH - 4;
    int watchTop    = watchBottom - WATCH_H;
    int tbTop       = watchTop - tbH - 4;

    // Results listview: top=PAD, bottom=tbTop - PAD
    int rTop = PAD, rBottom = tbTop - PAD;
    int rH   = rBottom - rTop;

    int rLeft = LEFT_W + PAD;
    int rW    = cw - LEFT_W - PAD*2;

    MoveWindow(GetDlgItem(g_hWnd, IDC_RESULTS),   rLeft, rTop, rW, rH, TRUE);
    MoveWindow(GetDlgItem(g_hWnd, IDC_WATCHLIST), rLeft, watchTop, rW, WATCH_H, TRUE);

    // Watch toolbar buttons
    int bx = rLeft;
    auto moveBtn = [&](int id, int w) {
        MoveWindow(GetDlgItem(g_hWnd, id), bx, tbTop, w, 22, TRUE);
        bx += w + 4;
    };
    moveBtn(IDC_ADD_ADDR,   120);
    moveBtn(IDC_MANUAL_ADD, 110);
    moveBtn(IDC_EDIT_VAL,    90);
    moveBtn(IDC_FREEZE_BTN,  80);
    moveBtn(IDC_REMOVE_ADDR, 80);
    moveBtn(IDC_HEX_VIEW,   100);
    moveBtn(IDC_UNDO_WRITE,  90);
}

// ─────────────────── WndProc ─────────────────────────────────────────────────

static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE:
        CreateControls(hWnd);
        RefreshProcessList();
        SetTimer(hWnd, TIMER_REFRESH, 500, nullptr);   // 0.5s auto-refresh
        return 0;

    case WM_SIZE: {
        int cw = LOWORD(lParam), ch = HIWORD(lParam);
        if (cw > 0 && ch > 0) ResizeControls(cw, ch);
        return 0;
    }

    case WM_TIMER:
        if (wParam == TIMER_REFRESH && !g_scanning) {
            // Update progress during scan
            SendMessage(GetDlgItem(hWnd, IDC_PROGRESS), PBM_SETPOS, g_lastPct, 0);
            // Freeze entries
            for (auto& e : g_scanner.watchList)
                if (e.frozen)
                    g_scanner.writeValue(e.address, e.freezeValue, e.vtype);
            // Refresh watch list
            if (!g_scanner.watchList.empty())
                RefreshWatchList();
        }
        return 0;

    case WM_USER + 1:   // WM_SCAN_DONE
        g_scanning = false;
        SendMessage(GetDlgItem(hWnd, IDC_PROGRESS), PBM_SETPOS, 100, 0);
        UpdateResultsView();
        {
            wchar_t buf[80];
            swprintf_s(buf, L"Scan complete: %zu results", g_scanner.resultCount());
            SetStatus(buf);
        }
        return 0;

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        switch (id) {
        case IDC_REFRESH_BTN:  RefreshProcessList();   break;
        case IDC_ATTACH_BTN:   AttachSelected();       break;
        case IDC_FIRSTSCAN:    DoScan(true);           break;
        case IDC_NEXTSCAN:     DoScan(false);          break;
        case IDC_UNDO:
            if (g_scanner.canUndo()) {
                g_scanner.undoScan();
                UpdateResultsView();
                SetStatus(L"Scan undone");
            } else SetStatus(L"Nothing to undo");
            break;
        case IDC_RESETSCAN:
            g_scanner.resetScan();
            ListView_SetItemCountEx(GetDlgItem(hWnd, IDC_RESULTS), 0, LVSICF_NOINVALIDATEALL);
            SetWindowTextW(GetDlgItem(hWnd, IDC_RESULTCOUNT), L"Results: 0");
            SetStatus(L"Scan reset");
            break;
        case IDC_SCANTYPE:
            if (HIWORD(wParam) == CBN_SELCHANGE) UpdateValueFields();
            break;
        case IDC_ADD_ADDR:    AddSelectedToWatch(); break;
        case IDC_MANUAL_ADD:  ManualAddAddress();   break;
        case IDC_EDIT_VAL:    EditWatchValue();     break;
        case IDC_FREEZE_BTN:  ToggleFreeze();       break;
        case IDC_REMOVE_ADDR: RemoveWatchEntry();   break;
        case IDC_SAVE_BTN:    SaveSession();        break;
        case IDC_LOAD_BTN:    LoadSession();        break;
        case IDC_AOB_SCAN:    DoAobScan();          break;
        case IDC_MODULES:     OpenModulesDialog();  break;
        case IDC_HEX_VIEW:    OpenHexViewerSelected(); break;
        case IDC_UNDO_WRITE:  OpenWriteHistory();   break;
        case IDC_PIN_TOP: {
            BOOL on = (SendMessage(GetDlgItem(hWnd, IDC_PIN_TOP),
                                    BM_GETCHECK, 0, 0) == BST_CHECKED);
            SetWindowPos(hWnd, on ? HWND_TOPMOST : HWND_NOTOPMOST,
                         0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            SetStatus(on ? L"Always-on-top: ON" : L"Always-on-top: OFF");
            break;
        }
        }

        // Search box: filter as you type
        if (id == IDC_PROC_SEARCH && HIWORD(wParam) == EN_CHANGE)
            PopulateProcessList();
        return 0;
    }

    // Virtual ListView — supply items on demand
    case WM_NOTIFY: {
        auto* hdr = (NMHDR*)lParam;
        if (hdr->idFrom == IDC_RESULTS && hdr->code == LVN_GETDISPINFOW) {
            auto* nmlv = (NMLVDISPINFOW*)lParam;
            int row = nmlv->item.iItem;
            if (row < 0 || row >= (int)g_scanner.resultCount()) break;
            const auto& r = g_scanner.results()[row];
            static wchar_t buf[64];
            if (nmlv->item.mask & LVIF_TEXT) {
                switch (nmlv->item.iSubItem) {
                case 0:
                    swprintf_s(buf, L"0x%0*llX",
                               (int)(sizeof(uintptr_t)*2), (unsigned long long)r.address);
                    break;
                case 1: {
                    VType vt = (VType)SendMessage(GetDlgItem(hWnd, IDC_VTYPE), CB_GETCURSEL, 0, 0);
                    double cur = g_scanner.readValue(r.address, vt);
                    if (vt == VType::FLOAT || vt == VType::DOUBLE)
                        swprintf_s(buf, L"%.4f", cur);
                    else
                        swprintf_s(buf, L"%lld", (long long)cur);
                    break;
                }
                case 2:
                    if (r.prev == 0)
                        wcscpy_s(buf, L"—");
                    else {
                        VType vt = (VType)SendMessage(GetDlgItem(hWnd, IDC_VTYPE), CB_GETCURSEL, 0, 0);
                        if (vt == VType::FLOAT || vt == VType::DOUBLE)
                            swprintf_s(buf, L"%.4f", r.prev);
                        else
                            swprintf_s(buf, L"%lld", (long long)r.prev);
                    }
                    break;
                }
                nmlv->item.pszText = buf;
            }
        }
        // Double-click results → add to watch
        if (hdr->idFrom == IDC_RESULTS && hdr->code == NM_DBLCLK)
            AddSelectedToWatch();
        // Double-click watch value → edit
        if (hdr->idFrom == IDC_WATCHLIST && hdr->code == NM_DBLCLK)
            EditWatchValue();
        // Double-click process → attach
        if (hdr->idFrom == IDC_PROC_LIST && hdr->code == NM_DBLCLK)
            AttachSelected();
        return 0;
    }

    case WM_DESTROY:
        KillTimer(hWnd, TIMER_REFRESH);
        g_scanner.abortScan = true;
        g_scanner.detach();
        if (g_hProcImg) ImageList_Destroy(g_hProcImg);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ─────────────────── WinMain ─────────────────────────────────────────────────

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int nCmdShow) {
    g_hInst = hInst;

    // Enable visual styles
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    // Register window class
    WNDCLASSEXW wc   = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"MemHawkCE";
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    if (!RegisterClassExW(&wc)) return 1;

    // Load persisted recently-attached process names
    LoadRecents();

    // Create main window
    g_hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        L"MemHawkCE",
        L"MemHawk CE — Memory Scanner (run as Administrator)",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1100, 720,
        nullptr, nullptr, hInst, nullptr
    );
    if (!g_hWnd) return 1;

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
