#include "scanner.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <cstring>
#include <cmath>
#include <algorithm>

#pragma comment(lib, "psapi.lib")

// ────────────────────────────────────────────────────────────────────────────
// Static helpers
// ────────────────────────────────────────────────────────────────────────────

size_t MemScanner::vtypeSize(VType vt) {
    switch (vt) {
    case VType::BYTE1: case VType::UBYTE1: return 1;
    case VType::BYTE2: case VType::UBYTE2: return 2;
    case VType::BYTE4: case VType::UBYTE4: case VType::FLOAT:  return 4;
    case VType::BYTE8: case VType::UBYTE8: case VType::DOUBLE: return 8;
    }
    return 4;
}

double MemScanner::unpack(const uint8_t* p, VType vt) {
    switch (vt) {
    case VType::BYTE1:  { int8_t   v; memcpy(&v, p, 1); return v; }
    case VType::BYTE2:  { int16_t  v; memcpy(&v, p, 2); return v; }
    case VType::BYTE4:  { int32_t  v; memcpy(&v, p, 4); return v; }
    case VType::BYTE8:  { int64_t  v; memcpy(&v, p, 8); return (double)v; }
    case VType::UBYTE1: { uint8_t  v; memcpy(&v, p, 1); return v; }
    case VType::UBYTE2: { uint16_t v; memcpy(&v, p, 2); return v; }
    case VType::UBYTE4: { uint32_t v; memcpy(&v, p, 4); return v; }
    case VType::UBYTE8: { uint64_t v; memcpy(&v, p, 8); return (double)v; }
    case VType::FLOAT:  { float    v; memcpy(&v, p, 4); return v; }
    case VType::DOUBLE: { double   v; memcpy(&v, p, 8); return v; }
    }
    return 0;
}

bool MemScanner::pack(double val, uint8_t* p, VType vt) {
    switch (vt) {
    case VType::BYTE1:  { auto v = (int8_t)val;   memcpy(p, &v, 1); return true; }
    case VType::BYTE2:  { auto v = (int16_t)val;  memcpy(p, &v, 2); return true; }
    case VType::BYTE4:  { auto v = (int32_t)val;  memcpy(p, &v, 4); return true; }
    case VType::BYTE8:  { auto v = (int64_t)val;  memcpy(p, &v, 8); return true; }
    case VType::UBYTE1: { auto v = (uint8_t)val;  memcpy(p, &v, 1); return true; }
    case VType::UBYTE2: { auto v = (uint16_t)val; memcpy(p, &v, 2); return true; }
    case VType::UBYTE4: { auto v = (uint32_t)val; memcpy(p, &v, 4); return true; }
    case VType::UBYTE8: { auto v = (uint64_t)val; memcpy(p, &v, 8); return true; }
    case VType::FLOAT:  { auto v = (float)val;    memcpy(p, &v, 4); return true; }
    case VType::DOUBLE: { memcpy(p, &val, 8); return true; }
    }
    return false;
}

// ────────────────────────────────────────────────────────────────────────────
// Process management
// ────────────────────────────────────────────────────────────────────────────

std::vector<ProcessInfo> MemScanner::listProcesses() {
    std::vector<ProcessInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo pi { pe.th32ProcessID, pe.szExeFile, L"" };
            // Get full executable path (works on most processes without admin)
            HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (ph) {
                wchar_t pathBuf[MAX_PATH] = {};
                DWORD sz = MAX_PATH;
                if (QueryFullProcessImageNameW(ph, 0, pathBuf, &sz))
                    pi.exePath = pathBuf;
                CloseHandle(ph);
            }
            out.push_back(pi);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    std::sort(out.begin(), out.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
        return _wcsicmp(a.name.c_str(), b.name.c_str()) < 0;
    });
    return out;
}

bool MemScanner::attach(DWORD pid, const std::wstring& name) {
    detach();
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) return false;
    handle_ = h;
    pid_    = pid;
    name_   = name;
    results_.clear();
    history_.clear();
    watchList.clear();
    return true;
}

void MemScanner::detach() {
    if (handle_) {
        CloseHandle(handle_);
        handle_ = nullptr;
    }
    pid_  = 0;
    name_.clear();
    results_.clear();
    history_.clear();
}

// ────────────────────────────────────────────────────────────────────────────
// Raw memory I/O
// ────────────────────────────────────────────────────────────────────────────

bool MemScanner::readRaw(uintptr_t addr, void* buf, size_t sz) const {
    if (!handle_) return false;
    SIZE_T rd = 0;
    return ReadProcessMemory(handle_, (LPCVOID)addr, buf, sz, &rd) && rd == sz;
}

bool MemScanner::writeRaw(uintptr_t addr, const void* buf, size_t sz) const {
    if (!handle_) return false;
    SIZE_T wr = 0;
    return WriteProcessMemory(handle_, (LPVOID)addr, buf, sz, &wr) && wr == sz;
}

double MemScanner::readValue(uintptr_t addr, VType vt) const {
    uint8_t buf[8] = {};
    if (!readRaw(addr, buf, vtypeSize(vt))) return 0;
    return unpack(buf, vt);
}

bool MemScanner::writeValue(uintptr_t addr, double val, VType vt) const {
    uint8_t buf[8] = {};
    if (!pack(val, buf, vt)) return false;
    return writeRaw(addr, buf, vtypeSize(vt));
}

// ────────────────────────────────────────────────────────────────────────────
// Region enumeration
// ────────────────────────────────────────────────────────────────────────────

std::vector<MemScanner::Region> MemScanner::enumRegions() const {
    std::vector<Region> regions;
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi = {};
    while (VirtualQueryEx(handle_, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT
            && !(mbi.Protect & PAGE_NOACCESS)
            && !(mbi.Protect & PAGE_GUARD)
            && mbi.Protect != 0)
        {
            regions.push_back({ (uintptr_t)mbi.BaseAddress, mbi.RegionSize });
        }
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    return regions;
}

// ────────────────────────────────────────────────────────────────────────────
// Match helper
// ────────────────────────────────────────────────────────────────────────────

bool MemScanner::matchScan(ScanType st, double cur, double prev,
                           double val, double val2) const {
    constexpr double EPS = 1e-6;
    switch (st) {
    case ScanType::EXACT:     return std::fabs(cur - val) < EPS;
    case ScanType::BIGGER:    return cur > val;
    case ScanType::SMALLER:   return cur < val;
    case ScanType::BETWEEN:   return cur >= val && cur <= val2;
    case ScanType::CHANGED:   return std::fabs(cur - prev) > EPS;
    case ScanType::UNCHANGED: return std::fabs(cur - prev) < EPS;
    case ScanType::INCREASED: return cur > prev;
    case ScanType::DECREASED: return cur < prev;
    case ScanType::UNKNOWN:   return true;
    }
    return false;
}

// ────────────────────────────────────────────────────────────────────────────
// First scan — full memory sweep
// ────────────────────────────────────────────────────────────────────────────

size_t MemScanner::firstScan(ScanType st, VType vt,
                             double val, double val2, ProgressCb cb) {
    if (!handle_) return 0;

    // Push old results to undo history
    if (!results_.empty()) {
        history_.push_back(std::move(results_));
        if (history_.size() > 10) history_.erase(history_.begin());
    }
    results_.clear();
    abortScan = false;

    const size_t  vsz     = vtypeSize(vt);
    const size_t  CHUNKSZ = 4 * 1024 * 1024;  // 4 MB read chunks
    auto          regions = enumRegions();
    const size_t  total   = regions.size();

    // Build target bytes for exact byte-compare fast path
    uint8_t targetBytes[8] = {};
    bool    useByteCompare  = (st == ScanType::EXACT) && pack(val, targetBytes, vt);

    std::vector<uint8_t> buf;

    for (size_t ri = 0; ri < total && !abortScan; ++ri) {
        if (cb && ri % 64 == 0)
            cb((int)(ri * 100 / total));

        auto& reg = regions[ri];
        size_t remaining = reg.size;
        uintptr_t base   = reg.base;

        while (remaining > 0 && !abortScan) {
            size_t toRead = (std::min)(remaining, CHUNKSZ);
            buf.resize(toRead);

            SIZE_T rd = 0;
            if (!ReadProcessMemory(handle_, (LPCVOID)base, buf.data(), toRead, &rd) || rd < vsz) {
                base      += toRead;
                remaining -= toRead;
                continue;
            }

            for (size_t off = 0; off + vsz <= rd; off++) {
                const uint8_t* p = buf.data() + off;

                if (st == ScanType::UNKNOWN) {
                    results_.push_back({ base + off, unpack(p, vt), 0.0 });
                } else if (useByteCompare) {
                    if (memcmp(p, targetBytes, vsz) == 0)
                        results_.push_back({ base + off, val, 0.0 });
                } else {
                    double cur = unpack(p, vt);
                    if (matchScan(st, cur, 0.0, val, val2))
                        results_.push_back({ base + off, cur, 0.0 });
                }
            }

            base      += rd;
            remaining -= rd;
        }
    }

    if (cb) cb(100);
    return results_.size();
}

// ────────────────────────────────────────────────────────────────────────────
// Next scan — filter existing results
// ────────────────────────────────────────────────────────────────────────────

size_t MemScanner::nextScan(ScanType st, VType vt,
                            double val, double val2, ProgressCb cb) {
    if (!handle_ || results_.empty()) return 0;

    history_.push_back(results_);
    if (history_.size() > 10) history_.erase(history_.begin());

    abortScan = false;
    const size_t vsz   = vtypeSize(vt);
    const size_t total = results_.size();

    std::vector<ScanResult> kept;
    kept.reserve(results_.size() / 4);

    uint8_t buf[8];

    for (size_t i = 0; i < total && !abortScan; ++i) {
        if (cb && i % 100000 == 0)
            cb((int)(i * 100 / total));

        auto& r = results_[i];
        if (!readRaw(r.address, buf, vsz)) continue;
        double cur = unpack(buf, vt);
        if (matchScan(st, cur, r.value, val, val2)) {
            kept.push_back({ r.address, cur, r.value });
        }
    }

    results_ = std::move(kept);
    if (cb) cb(100);
    return results_.size();
}

// ────────────────────────────────────────────────────────────────────────────
// Undo / reset
// ────────────────────────────────────────────────────────────────────────────

void MemScanner::undoScan() {
    if (history_.empty()) return;
    results_ = std::move(history_.back());
    history_.pop_back();
}

void MemScanner::resetScan() {
    if (!results_.empty()) {
        history_.push_back(std::move(results_));
        if (history_.size() > 10) history_.erase(history_.begin());
    }
    results_.clear();
}

// ────────────────────────────────────────────────────────────────────────────
// AOB pattern parser  ("48 8B 05 ?? ?? ?? ?? 89 41" → bytes + wildcard mask)
// ────────────────────────────────────────────────────────────────────────────

bool MemScanner::parseAobPattern(const std::wstring& s,
                                  std::vector<uint8_t>& bytes,
                                  std::vector<bool>& mask) {
    bytes.clear();
    mask.clear();
    std::wstring tok;

    auto flush = [&]() -> bool {
        if (tok.empty()) return true;
        if (tok == L"??" || tok == L"?") {
            bytes.push_back(0);
            mask.push_back(true);   // wildcard
        } else if (tok.size() <= 2) {
            wchar_t* end = nullptr;
            unsigned long v = wcstoul(tok.c_str(), &end, 16);
            if (!end || end == tok.c_str() || *end != L'\0' || v > 0xFF)
                return false;
            bytes.push_back((uint8_t)v);
            mask.push_back(false);
        } else {
            return false;
        }
        tok.clear();
        return true;
    };

    for (wchar_t c : s) {
        if (c == L' ' || c == L'\t' || c == L',') {
            if (!flush()) return false;
        } else if (iswxdigit(c) || c == L'?') {
            tok += c;
        } else {
            return false;   // invalid character
        }
    }
    if (!flush()) return false;
    return !bytes.empty();
}

// ────────────────────────────────────────────────────────────────────────────
// AOB scan — find pattern in process memory
// ────────────────────────────────────────────────────────────────────────────

size_t MemScanner::aobScan(const std::vector<uint8_t>& bytes,
                            const std::vector<bool>& mask, ProgressCb cb) {
    if (!handle_ || bytes.empty() || bytes.size() != mask.size()) return 0;

    if (!results_.empty()) {
        history_.push_back(std::move(results_));
        if (history_.size() > 10) history_.erase(history_.begin());
    }
    results_.clear();
    abortScan = false;

    const size_t patLen   = bytes.size();
    const size_t CHUNKSZ  = 4 * 1024 * 1024;
    const size_t OVERLAP  = patLen - 1;        // ensure pattern not split across chunks
    auto         regions  = enumRegions();
    const size_t total    = regions.size();

    std::vector<uint8_t> buf;

    for (size_t ri = 0; ri < total && !abortScan; ++ri) {
        if (cb && ri % 64 == 0) cb((int)(ri * 100 / total));

        auto&     reg       = regions[ri];
        size_t    remaining = reg.size;
        uintptr_t base      = reg.base;

        while (remaining > 0 && !abortScan) {
            size_t toRead = (std::min)(remaining, CHUNKSZ);
            buf.resize(toRead);

            SIZE_T rd = 0;
            if (!ReadProcessMemory(handle_, (LPCVOID)base, buf.data(), toRead, &rd) || rd < patLen) {
                base      += toRead;
                remaining -= toRead;
                continue;
            }

            for (size_t off = 0; off + patLen <= rd; off++) {
                bool ok = true;
                for (size_t i = 0; i < patLen; i++) {
                    if (!mask[i] && buf[off + i] != bytes[i]) { ok = false; break; }
                }
                if (ok)
                    results_.push_back({ base + off, 0.0, 0.0 });
            }

            // Advance with overlap so a pattern straddling chunk boundary still matches
            if (rd <= OVERLAP || rd == toRead) {
                base      += rd;
                remaining -= rd;
            } else {
                base      += rd - OVERLAP;
                remaining -= rd - OVERLAP;
            }
        }
    }

    if (cb) cb(100);
    return results_.size();
}

// ────────────────────────────────────────────────────────────────────────────
// Module enumeration — loaded DLLs and main exe
// ────────────────────────────────────────────────────────────────────────────

std::vector<ModuleInfo> MemScanner::listModules() const {
    std::vector<ModuleInfo> out;
    if (!handle_) return out;

    HMODULE mods[1024];
    DWORD   cbNeeded = 0;
    if (!EnumProcessModulesEx(handle_, mods, sizeof(mods), &cbNeeded, LIST_MODULES_ALL))
        return out;

    int count = (int)(cbNeeded / sizeof(HMODULE));
    for (int i = 0; i < count; i++) {
        wchar_t name[MAX_PATH] = {};
        if (!GetModuleBaseNameW(handle_, mods[i], name, MAX_PATH))
            continue;

        MODULEINFO mi = {};
        if (!GetModuleInformation(handle_, mods[i], &mi, sizeof(mi)))
            continue;

        out.push_back({ name, (uintptr_t)mi.lpBaseOfDll, (size_t)mi.SizeOfImage });
    }

    std::sort(out.begin(), out.end(), [](const ModuleInfo& a, const ModuleInfo& b) {
        return a.base < b.base;
    });
    return out;
}
