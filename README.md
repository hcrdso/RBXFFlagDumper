# RBXFFlagDumper

**RBXFFlagDumper** is a small Windows/x64 research utility that inspects a running Roblox client and generates a C++ header containing the discovered FFlag value offsets.

The dumper is read-only: it opens the Roblox process with memory-query/read permissions, discovers candidate list layouts at runtime, validates the resulting chain, and writes `FFlags.hpp`.

## What changed in this version

The project was hardened substantially without changing its basic purpose:

- Runtime memory regions are discovered with `VirtualQueryEx` instead of blindly reading every address in a fixed range.
- All `ReadProcessMemory` operations now report success/failure instead of silently returning zero-filled data.
- Process handles use RAII and are closed reliably.
- `PROCESS_ALL_ACCESS` and the unused write path were removed; the tool is read-only.
- Pointer arithmetic is checked for overflow.
- List traversal has bounded iteration and cycle detection.
- FTV detection validates readable string values, reducing false positives.
- Candidate layouts are deduplicated and ranked deterministically.
- Generated C++ identifiers are sanitized, prefixed, and deduplicated.
- The generated header uses `std::uintptr_t` and C++17 `inline constexpr` declarations.
- The project is explicitly **x64-only**, matching the 64-bit Roblox client and preventing broken x86 builds.
- Failure messages now explain which stage failed and include the Windows error code where useful.

## Requirements

- Windows 10/11
- Visual Studio 2022 with the **Desktop development with C++** workload
- Windows SDK
- An x64 Roblox client process

The project uses the Visual Studio `v143` toolset and C++17.

## Build

1. Open `fflag dumper.sln` in Visual Studio.
2. Select `Release | x64` (recommended).
3. Build with **Build → Build Solution**.
4. Run the generated executable while the Roblox client is open.

Only x64 configurations are included because the dumper stores and follows 64-bit process pointers.

## Usage

Start the Roblox client and wait until it is fully loaded. Then run the dumper.

A successful run prints the discovered layout and creates:

```text
FFlags.hpp
```

in the program's current working directory.

The generated file has the following general form:

```cpp
#pragma once
#include <cstdint>

namespace FFlagOffsets {
    inline constexpr std::uintptr_t FFlagList = 0x...ULL;
    inline constexpr std::uintptr_t HeadPointer = 0x...ULL;
    inline constexpr std::uintptr_t ValueGetSet = 0x...ULL;
    inline constexpr std::uintptr_t FlagToValue = 0x...ULL;
}

namespace FFlags {
    inline constexpr std::uintptr_t FFlag_Example = 0x...ULL;
}
```

Roblox's internal memory layout is not stable. A build can legitimately produce no compatible layout, and that is preferable to silently emitting incorrect offsets.

## Troubleshooting

**`RobloxPlayerBeta.exe was not found`**

Start Roblox before launching the dumper.

**`Failed to open Roblox process`**

Check Windows permissions and security software. The program only requests process query/read access; it does not request write access.

**`No compatible FFlag layout was found`**

The client's internal structures may have changed. This version intentionally fails closed instead of trusting weak pointer patterns.

**`Failed to identify the flag-to-value field`**

The list was found, but the value representation did not match the expected string-based layout. This can also happen after an internal Roblox update.

## Development notes

The source intentionally keeps the runtime layout discovery logic in `main.cxx` and generic Windows process/memory helpers in:

```text
fflag dumper/process access/memory/memory.h
```

There are no third-party dependencies.

## License

This project is licensed under the MIT License. See `LICENSE`.

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by Roblox Corporation. It is provided as-is for educational and research purposes. Users are responsible for complying with applicable software terms and platform rules.
