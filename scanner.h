#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>

// ─────────────────── Value types (mirrors Cheat Engine) ────────────────────

enum class VType : int {
    BYTE1  = 0,   // 1-byte signed
    BYTE2  = 1,   // 2-byte signed
    BYTE4  = 2,   // 4-byte signed  ← most common
    BYTE8  = 3,   // 8-byte signed
    FLOAT  = 4,
    DOUBLE = 5,
    UBYTE1 = 6,
    UBYTE2 = 7,
    UBYTE4 = 8,
    UBYTE8 = 9,
};

static const wchar_t* const VTYPE_NAMES[] = {
    L"1 Byte",  L"2 Bytes", L"4 Bytes", L"8 Bytes",
    L"Float",   L"Double",
    L"1 Byte (U)", L"2 Bytes (U)", L"4 Bytes (U)", L"8 Bytes (U)"
};
constexpr int VTYPE_COUNT = 10;

// ─────────────────── Scan types ────────────────────────────────────────────

enum class ScanType : int {
    EXACT     = 0,
    BIGGER    = 1,
    SMALLER   = 2,
    BETWEEN   = 3,
    CHANGED   = 4,
    UNCHANGED = 5,
    INCREASED = 6,
    DECREASED = 7,
    UNKNOWN   = 8,   // "Unknown Initial Value"
};

static const wchar_t* const SCANTYPE_NAMES[] = {
    L"Exact Value",
    L"Bigger Than",
    L"Smaller Than",
    L"Value Between",
    L"Value Changed",
    L"Value Unchanged",
    L"Value Increased",
    L"Value Decreased",
    L"Unknown Initial Value",
};
constexpr int SCANTYPE_COUNT = 9;

// ─────────────────── Result & watch structures ──────────────────────────────

struct ScanResult {
    uintptr_t address;
    double    value;
    double    prev;
};

struct WatchEntry {
    uintptr_t    address;
    VType        vtype;
    std::wstring description;
    bool         frozen;
    double       freezeValue;
    bool         active;        // checkbox in address list
};

struct ProcessInfo {
    DWORD        pid;
    std::wstring name;
    std::wstring exePath;     // Full path for icon extraction
};

struct ModuleInfo {
    std::wstring name;        // e.g. "game.exe", "kernel32.dll"
    uintptr_t    base;
    size_t       size;
};

// ─────────────────── Progress callback ─────────────────────────────────────

using ProgressCb = std::function<void(int pct)>;

// ─────────────────── Core scanner class ────────────────────────────────────

class MemScanner {
public:
    MemScanner()  = default;
    ~MemScanner() { detach(); }

    // Process management
    static std::vector<ProcessInfo> listProcesses();
    bool attach(DWORD pid, const std::wstring& name);
    void detach();
    bool attached()  const { return handle_ != nullptr; }
    DWORD pid()      const { return pid_; }
    const std::wstring& processName() const { return name_; }

    // Raw memory I/O
    bool readRaw(uintptr_t addr, void* buf, size_t sz) const;
    bool writeRaw(uintptr_t addr, const void* buf, size_t sz) const;

    // Typed memory I/O
    double readValue(uintptr_t addr, VType vt) const;
    bool   writeValue(uintptr_t addr, double val, VType vt) const;

    // Scanning
    size_t firstScan(ScanType st, VType vt, double val, double val2, ProgressCb cb = {});
    size_t nextScan (ScanType st, VType vt, double val, double val2, ProgressCb cb = {});
    size_t aobScan  (const std::vector<uint8_t>& bytes,
                     const std::vector<bool>& mask, ProgressCb cb = {});
    void   undoScan();
    void   resetScan();
    bool   canUndo() const { return !history_.empty(); }

    // Module enumeration (loaded DLLs and the main exe)
    std::vector<ModuleInfo> listModules() const;

    // Parse hex pattern with wildcards: "48 8B 05 ?? ?? ?? ?? 89 41"
    static bool parseAobPattern(const std::wstring& s,
                                std::vector<uint8_t>& bytes,
                                std::vector<bool>&    mask);

    const std::vector<ScanResult>& results() const { return results_; }
    size_t resultCount()                    const { return results_.size(); }

    // Watch list (public — GUI manages it directly)
    std::vector<WatchEntry> watchList;

    // Volatile flag for scan abort
    volatile bool abortScan = false;

    // Helpers
    static size_t vtypeSize(VType vt);
    static double unpack(const uint8_t* p, VType vt);
    static bool   pack(double val, uint8_t* p, VType vt);

private:
    HANDLE       handle_ = nullptr;
    DWORD        pid_    = 0;
    std::wstring name_;

    std::vector<ScanResult>              results_;
    std::vector<std::vector<ScanResult>> history_;   // undo stack (max 10)

    struct Region { uintptr_t base; size_t size; };
    std::vector<Region> enumRegions() const;

    bool matchScan(ScanType st, double cur, double prev, double val, double val2) const;
};
