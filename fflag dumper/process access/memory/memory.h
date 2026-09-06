#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <algorithm>

class Driver final {
public:
    struct MemoryRegion {
        uintptr_t base = 0;
        size_t size = 0;
    };

    DWORD vm_procid = 0;
    HANDLE vm_hprocid = nullptr;

    Driver() = default;
    Driver(const Driver&) = delete;
    Driver& operator=(const Driver&) = delete;

    ~Driver() {
        detach();
    }

    bool vm_attach(DWORD pid) {
        detach();

        if (pid == 0)
            return false;

        constexpr DWORD access =
            PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_READ;

        HANDLE handle = OpenProcess(access, FALSE, pid);
        if (!handle)
            return false;

        vm_hprocid = handle;
        vm_procid = pid;
        return true;
    }

    void detach() noexcept {
        if (vm_hprocid) {
            CloseHandle(vm_hprocid);
            vm_hprocid = nullptr;
        }
        vm_procid = 0;
    }

    DWORD vm_getpid(const std::wstring& name) const {
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        DWORD result = 0;
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(name.c_str(), pe.szExeFile) == 0) {
                    result = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }

        CloseHandle(snap);
        return result;
    }

    uintptr_t vm_getmodulebase(const std::wstring& name) const {
        if (vm_procid == 0)
            return 0;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        HANDLE snap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            vm_procid);

        if (snap == INVALID_HANDLE_VALUE)
            return 0;

        uintptr_t result = 0;
        if (Module32FirstW(snap, &me)) {
            do {
                if (_wcsicmp(name.c_str(), me.szModule) == 0) {
                    result = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                    break;
                }
            } while (Module32NextW(snap, &me));
        }

        CloseHandle(snap);
        return result;
    }

    bool vmread_raw(uintptr_t addr, void* buffer, size_t size) const {
        if (!vm_hprocid || !buffer || size == 0)
            return false;

        if (!is_plausible_user_address(addr) ||
            size > (std::numeric_limits<SIZE_T>::max)() - addr)
            return false;

        SIZE_T bytesRead = 0;
        return ReadProcessMemory(
                   vm_hprocid,
                   reinterpret_cast<LPCVOID>(addr),
                   buffer,
                   size,
                   &bytesRead) != FALSE &&
               bytesRead == size;
    }

    template <typename T>
    std::optional<T> vm_read(uintptr_t addr) const {
        static_assert(std::is_trivially_copyable_v<T>,
                      "vm_read requires a trivially copyable type");

        T value{};
        if (!vmread_raw(addr, &value, sizeof(T)))
            return std::nullopt;
        return value;
    }

    bool vm_is_readable(uintptr_t addr, size_t size = 1) const {
        if (!vm_hprocid || size == 0 || !is_plausible_user_address(addr))
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(
                vm_hprocid,
                reinterpret_cast<LPCVOID>(addr),
                &mbi,
                sizeof(mbi)) == 0) {
            return false;
        }

        if (mbi.State != MEM_COMMIT)
            return false;

        if (is_guard_or_noaccess(mbi.Protect))
            return false;

        const uintptr_t regionBase =
            reinterpret_cast<uintptr_t>(mbi.BaseAddress);

        if (regionBase > (std::numeric_limits<uintptr_t>::max)() - mbi.RegionSize)
            return false;

        const uintptr_t regionEnd =
            regionBase + static_cast<uintptr_t>(mbi.RegionSize);

        if (addr > (std::numeric_limits<uintptr_t>::max)() - size)
            return false;

        return addr >= regionBase &&
               addr + size <= regionEnd;
    }

    std::vector<MemoryRegion> vm_readable_regions(
        uintptr_t start,
        uintptr_t end) const {

        std::vector<MemoryRegion> result;
        if (!vm_hprocid || start >= end)
            return result;

        uintptr_t current = start;

        while (current < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(
                    vm_hprocid,
                    reinterpret_cast<LPCVOID>(current),
                    &mbi,
                    sizeof(mbi)) == 0) {
                break;
            }

            const uintptr_t regionBase =
                reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t regionSize =
                static_cast<uintptr_t>(mbi.RegionSize);

            if (regionSize == 0 ||
                regionBase > (std::numeric_limits<uintptr_t>::max)() - regionSize)
                break;

            const uintptr_t regionEnd = regionBase + regionSize;

            if (mbi.State == MEM_COMMIT &&
                !is_guard_or_noaccess(mbi.Protect)) {

                const uintptr_t clippedStart = (std::max)(current, regionBase);
                const uintptr_t clippedEnd = (std::min)(end, regionEnd);

                if (clippedStart < clippedEnd) {
                    result.push_back({
                        clippedStart,
                        static_cast<size_t>(clippedEnd - clippedStart)
                    });
                }
            }

            if (regionEnd <= current)
                break;

            current = regionEnd;
        }

        return result;
    }

    std::string readstring(uintptr_t addr, size_t maxLength = 4096) const {
        if (addr > (std::numeric_limits<uintptr_t>::max)() - 0x18)
            return {};

        const auto lenOpt = vm_read<int32_t>(addr + 0x18);
        if (!lenOpt)
            return {};

        const int32_t rawLength = *lenOpt;
        if (rawLength <= 0 || static_cast<size_t>(rawLength) > maxLength)
            return {};

        uintptr_t data = addr;
        if (rawLength >= 16) {
            const auto dataOpt = vm_read<uintptr_t>(addr);
            if (!dataOpt || !is_plausible_user_address(*dataOpt))
                return {};
            data = *dataOpt;
        }

        std::string value(static_cast<size_t>(rawLength), '\0');
        if (!vmread_raw(data, value.data(), value.size()))
            return {};

        const auto nul = value.find('\0');
        if (nul != std::string::npos)
            value.resize(nul);

        return value;
    }

    static bool is_plausible_user_address(uintptr_t p) noexcept {
        return p >= 0x10000ULL && p <= 0x00007FFFFFFFFFFFULL;
    }

    static bool vm_isvalid(uintptr_t p) noexcept {
        return is_plausible_user_address(p);
    }

    static bool vm_isvalidname(const std::string& s) {
        if (s.size() < 3 || s.size() > 200)
            return false;

        if (!std::isalpha(static_cast<unsigned char>(s.front())))
            return false;

        for (unsigned char c : s) {
            if (!std::isalnum(c) && c != '_')
                return false;
        }

        return true;
    }

private:
    static bool is_guard_or_noaccess(DWORD protect) noexcept {
        return protect == PAGE_NOACCESS ||
               (protect & PAGE_GUARD) != 0;
    }
};

inline Driver driver;
