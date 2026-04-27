# MemHawk CE

> A lightweight, native Cheat Engine alternative written in C++17 — no external dependencies beyond Win32.

![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)
![Language](https://img.shields.io/badge/language-C%2B%2B17-orange)
![License](https://img.shields.io/badge/license-MIT-green)

---

## What it is

MemHawk CE is a memory scanner and editor for Windows — the same category of tool as Cheat Engine. You attach it to an offline, single-player game, scan for values (health, gold, ammo), narrow the results down to the right address, then freeze or modify the value.

Written entirely in C++17 using the Win32 API. No Qt, no MFC, no external libraries — just `comctl32`, `shell32`, `psapi`, and standard C++. The compiled binary is a single self-contained `.exe`.

> ⚠️ **For offline / single-player games only.** Anti-cheat systems (EAC, BattlEye, VAC) actively detect memory scanning and will ban your account in online games.

---

## Features

### Scanning
| Feature | Description |
|---|---|
| **All standard scan types** | Exact Value, Bigger Than, Smaller Than, Between, Changed / Unchanged / Increased / Decreased, Unknown Initial Value |
| **10 value types** | 1/2/4/8-byte signed & unsigned integers, Float, Double |
| **AOB scan** | Byte-pattern search with `??` wildcards — e.g. `48 8B 05 ?? ?? ?? ?? 89 41` |
| **Virtual ListView** | Handles millions of results without freezing the UI |
| **Up to 10 undo steps** | Step back through your scan filter history |
| **Background scan thread** | UI stays responsive during scans |

### Watch List
| Feature | Description |
|---|---|
| **Live auto-refresh** | Values update every 500 ms in the background |
| **Freeze** | Continuously re-write a value to lock it |
| **Edit Value** | Write a new value directly — supports all value types |
| **Manual add** | Type any hex address directly |
| **Notes / descriptions** | Label each address |
| **Session save/load** | Export watch list to `.mhk` (human-readable JSON) and reload next time |

### Write History
| Feature | Description |
|---|---|
| **Full audit trail** | Every Edit Value and Hex Edit write is logged with timestamp |
| **Revert Selected** | Undo one specific write |
| **Revert All** | Roll back all writes in reverse order |

### Hex Viewer
| Feature | Description |
|---|---|
| **Live memory view** | 256 bytes around any address, auto-refreshing every 750 ms |
| **Navigate** | Jump to any address using the address bar |
| **Edit Byte** | Patch individual bytes — useful for NOP-ing instructions (`0x90`) |

### Module List
| Feature | Description |
|---|---|
| **All loaded DLLs** | Shows every module with base address, size, and end address |
| **Copy base address** | One-click copy for offset arithmetic |

### Process List
| Feature | Description |
|---|---|
| **Process icons** | Each process shows its actual `.exe` icon |
| **Filter as you type** | Search by name or PID — updates instantly |
| **Recently attached (★)** | Last 5 attached games pinned to top, persisted across sessions |

### Quality of Life
| Feature | Description |
|---|---|
| **Always-on-top** | Checkbox to float MemHawk above your game window |
| **Detailed error messages** | Failed operations show the real Win32 reason + error code |
| **Write History & Revert** | Never lose track of what you changed |

---

## Requirements

- **Windows 10 or 11** (64-bit)
- **Run as Administrator** — required to open most game processes
- No runtime dependencies — libgcc and libstdc++ are statically linked in the release build

---

## Building from Source

### Option A — MinGW-w64 via MSYS2 (recommended, free)

1. Install [MSYS2](https://www.msys2.org/)
2. Open the **MSYS2 MinGW 64-bit** shell:
   ```bash
   pacman -S mingw-w64-x86_64-gcc
   ```
3. In the project directory:
   ```bash
   g++ -std=c++17 -O2 -mwindows -o MemHawkCE.exe main.cpp scanner.cpp \
       -lcomctl32 -lcomdlg32 -lshlwapi -lshell32 -lpsapi -lole32 \
       -static-libgcc -static-libstdc++
   ```

Or just run **`build.bat`** if MinGW is already on your PATH.

### Option B — MSVC (Visual Studio 2019 / 2022)

Open a **Developer Command Prompt**, navigate to the project folder:
```bat
cl /std:c++17 /O2 /DUNICODE /D_UNICODE main.cpp scanner.cpp ^
   /link comctl32.lib comdlg32.lib shlwapi.lib shell32.lib psapi.lib ole32.lib ^
   /SUBSYSTEM:WINDOWS /OUT:MemHawkCE.exe
```

### Option C — CMake

```bat
cmake -B build -G "MinGW Makefiles"
cmake --build build --config Release
```

---

## Usage

### Finding a known value (e.g. HP = 100)

1. Launch your game, get to a screen where you can see the value
2. Open MemHawk as Administrator → attach to your game
3. Set **Value Type** = `4 Bytes`, **Scan Type** = `Exact Value`
4. Enter `100` → **First Scan**
5. In-game: change the value (take damage, spend gold...)
6. Enter the new value → **Next Scan**
7. Repeat until you have a handful of addresses
8. Double-click a result to add it to the **Watch List**
9. Double-click the watch entry to **Edit Value**, or click **❄ Freeze**

### Finding an unknown value

1. Attach to process → `Unknown Initial Value` → **First Scan** (snapshots all memory)
2. Trigger a change in the game
3. `Value Decreased` (or `Value Changed`) → **Next Scan**
4. Repeat until you isolate the address

### AOB scan — patching code

1. Click **🧬 AOB Scan...**
2. Enter a byte pattern with `??` wildcards:
   ```
   48 8B 05 ?? ?? ?? ?? 89 41 08
   ```
3. Results are code addresses — open one in **🔍 Hex View** and patch bytes to `90` (NOP) to disable the instruction

### Module list — stable offsets across restarts

Games use ASLR so raw addresses change every launch. Use **📦 Modules** to find where `game.exe` is loaded, then record:
```
offset = found_address - game_base_address
```
Next session, the offset stays constant even though the base changes.

### Reverting writes

Click **↶ Writes** in the watch toolbar to open the Write History dialog. Every value you've written is listed with timestamp, old value, and new value. Select an entry and click **Revert Selected** to restore the original — or **Revert All** to roll everything back in reverse order.

---

## Project structure

```
MemHawkCE/
├── main.cpp        Win32 GUI — process list, scan controls, watch list,
│                   hex viewer, modules dialog, write history, AOB dialog
├── scanner.h       Core types, enums, and MemScanner class declaration
├── scanner.cpp     Memory engine — process/region/module enumeration,
│                   first scan, next scan, AOB scan, undo stack
├── CMakeLists.txt  CMake build configuration
├── build.bat       One-click MinGW build script
├── LICENSE         MIT
└── README.md       This file
```

---

## Comparison with Cheat Engine

| Feature | Cheat Engine | MemHawk CE |
|---|---|---|
| All standard scan types | ✅ | ✅ |
| AOB scan | ✅ | ✅ |
| Virtual list (millions of results) | ✅ | ✅ |
| Scan undo | ✅ | ✅ (10 steps) |
| Hex editor | ✅ Full | ✅ Basic |
| Module list | ✅ | ✅ |
| Process icons | ✅ | ✅ |
| Auto-refresh watch list | Manual | ✅ Every 500ms |
| Write history + revert | ❌ | ✅ |
| Persisted recent processes | ❌ | ✅ |
| Always-on-top | ❌ | ✅ |
| Session save format | Binary `.CT` | ✅ Human-readable `.mhk` |
| Pointer scanner | ✅ | ❌ (roadmap) |
| Disassembler | ✅ | ❌ (roadmap) |
| "What writes to address" | ✅ | ❌ (roadmap) |
| Lua scripting | ✅ | ❌ (roadmap) |
| External dependencies | None | None |
| Source lines of code | ~200k (Delphi) | ~2,400 (C++) |

---

## Roadmap

- [ ] Pointer scanner — find stable pointer chains across restarts
- [ ] What writes/reads to address — hardware breakpoints + instruction logging
- [ ] Disassembler view — x86/x64 assembly at any address
- [ ] Auto-detach detection — detect when target process exits
- [ ] Hotkeys — keyboard shortcuts for freeze/unfreeze/toggle
- [ ] Trainer generator — export a standalone cheat `.exe`
- [ ] Multi-threaded scan — parallel region scanning for speed
- [ ] Dark theme

---

## Data files created

| File | Location | Contents |
|---|---|---|
| `recents.txt` | `%LOCALAPPDATA%\MemHawkCE\recents.txt` | Last 5 attached process names |

Session files (`.mhk`) are saved wherever you choose via the Save dialog. Everything else is in-memory only.

---

## Antivirus false positives

Memory scanners are flagged by antivirus software as `HackTool` — this applies to Cheat Engine too. It is a false positive. To use MemHawk CE, add the executable to your AV exclusions:

**Windows Defender:** Settings → Virus & threat protection → Manage settings → Exclusions → Add or remove exclusions → Add the `.exe`

Or via PowerShell (admin):
```powershell
Add-MpPreference -ExclusionPath "C:\path\to\MemHawkCE.exe"
```

---

## License

MIT — see [LICENSE](LICENSE).

For educational purposes and personal use with games you own, on your own machine. Not responsible for misuse.
