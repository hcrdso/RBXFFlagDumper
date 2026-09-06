#include "main.h"
#include <cstring>
#include <tuple>

namespace {

constexpr wchar_t kRobloxProcessName[] = L"RobloxPlayerBeta.exe";

constexpr uintptr_t kScanStartRva = 0x04000000ULL;
constexpr uintptr_t kScanEndRva   = 0x40000000ULL;
constexpr uintptr_t kMaxListNodes = 3000;
constexpr uintptr_t kMaxFtvOffset = 0x400;
constexpr uintptr_t kMaxGeneratedRva = 0x40000000ULL;

struct Candidate {
    uintptr_t rva = 0;
    uintptr_t headOffset = 0;
    uintptr_t valueGetSetOffset = 0;
    int score = 0;
};

bool checked_add(uintptr_t lhs, uintptr_t rhs, uintptr_t& result) {
    if (lhs > (std::numeric_limits<uintptr_t>::max)() - rhs)
        return false;
    result = lhs + rhs;
    return true;
}

std::optional<uintptr_t> read_ptr(uintptr_t address) {
    return driver.vm_read<uintptr_t>(address);
}

bool is_bool_string(const std::string& value) {
    return value == "True" || value == "False";
}

bool is_reasonable_value(const std::string& value) {
    if (value.empty() || value.size() > 4096)
        return false;

    for (unsigned char c : value) {
        if (c == '\0')
            break;

        // Accept normal printable ASCII plus common UTF-8 bytes.
        if (c < 0x20 && c != '\t')
            return false;
    }

    return true;
}

int count_valid_nodes(uintptr_t start, uintptr_t valueGetSetOffset) {
    std::unordered_set<uintptr_t> seen;
    seen.reserve(512);

    uintptr_t node = start;
    int hits = 0;

    for (uintptr_t i = 0;
         i < kMaxListNodes && driver.vm_isvalid(node);
         ++i) {

        if (!seen.insert(node).second)
            break;

        uintptr_t nameAddress = 0;
        if (!checked_add(node, 0x10, nameAddress))
            break;

        const std::string name = driver.readstring(nameAddress, 256);
        if (driver.vm_isvalidname(name)) {
            uintptr_t valueAddress = 0;
            if (checked_add(node, valueGetSetOffset, valueAddress)) {
                const auto valueGetSet = read_ptr(valueAddress);
                if (valueGetSet && driver.vm_is_readable(*valueGetSet, sizeof(uintptr_t)))
                    ++hits;
            }
        }

        const auto next = read_ptr(node);
        if (!next || *next == node)
            break;

        node = *next;
    }

    return hits;
}

int sniff_ftv(uintptr_t start, uintptr_t valueGetSetOffset, uintptr_t moduleBase) {
    int bestOffset = -1;
    size_t bestUniquePointers = 0;
    int bestValidValues = 0;

    uintptr_t generatedRangeEnd = 0;
    if (!checked_add(moduleBase, kMaxGeneratedRva, generatedRangeEnd))
        return -1;

    std::unordered_set<uintptr_t> seenNodes;
    seenNodes.reserve(512);

    // The offset is generally small, so checking 8-byte aligned candidates
    // is cheap compared with scanning the process for the list itself.
    for (uintptr_t offset = 0; offset < kMaxFtvOffset; offset += sizeof(uintptr_t)) {
        seenNodes.clear();

        std::unordered_set<uintptr_t> uniquePointers;
        uniquePointers.reserve(512);

        int validValues = 0;
        uintptr_t node = start;

        for (int i = 0; i < 800 && driver.vm_isvalid(node); ++i) {
            if (!seenNodes.insert(node).second)
                break;

            uintptr_t valueGetSetAddress = 0;
            if (!checked_add(node, valueGetSetOffset, valueGetSetAddress)) {
                break;
            }

            const auto valueGetSet = read_ptr(valueGetSetAddress);
            if (valueGetSet) {
                uintptr_t candidateValueAddress = 0;
                if (checked_add(*valueGetSet, offset, candidateValueAddress)) {
                    const auto candidateValue = read_ptr(candidateValueAddress);

                    if (candidateValue &&
                        driver.vm_isvalid(*candidateValue) &&
                        *candidateValue >= moduleBase &&
                        *candidateValue < generatedRangeEnd) {

                        const std::string text =
                            driver.readstring(*candidateValue, 256);

                        if (is_reasonable_value(text)) {
                            uniquePointers.insert(*candidateValue);
                            ++validValues;
                        }
                    }
                }
            }

            const auto next = read_ptr(node);
            if (!next || *next == node)
                break;

            node = *next;
        }

        const size_t minUnique =
            validValues > 0 ? static_cast<size_t>(validValues * 3 / 4) : 0;

        if (validValues >= 30 &&
            uniquePointers.size() >= minUnique &&
            uniquePointers.size() > bestUniquePointers) {

            bestUniquePointers = uniquePointers.size();
            bestValidValues = validValues;
            bestOffset = static_cast<int>(offset);
        }
    }

    if (bestOffset >= 0) {
        std::cout << "[+] FTV candidate: 0x" << std::hex
                  << bestOffset << " (" << std::dec
                  << bestValidValues << " readable values)\n";
    }

    return bestOffset;
}

std::string sanitize_identifier(std::string name) {
    for (char& c : name) {
        const auto uc = static_cast<unsigned char>(c);
        if (!std::isalnum(uc) && c != '_')
            c = '_';
    }

    if (name.empty())
        name = "Unknown";

    // Prefixing every generated identifier also avoids collisions with
    // C++ keywords and names such as "__..." that are reserved to the
    // implementation.
    return "FFlag_" + name;
}

std::string make_unique_identifier(
    std::string name,
    std::unordered_set<std::string>& used) {

    name = sanitize_identifier(std::move(name));

    if (used.insert(name).second)
        return name;

    for (unsigned int i = 2; i != 0; ++i) {
        std::string candidate = name + "_" + std::to_string(i);
        if (used.insert(candidate).second)
            return candidate;
    }

    // Practically unreachable, but keeps the function total.
    return name + "_duplicate";
}

bool wait_for_enter() {
    std::cout << "\nPress Enter to exit...";
    std::string ignored;
    std::getline(std::cin, ignored);
    return true;
}

} // namespace

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleTitleW(L"FFlags Dumper");

    const auto startTime = std::chrono::steady_clock::now();

    const DWORD pid = driver.vm_getpid(kRobloxProcessName);
    if (pid == 0) {
        std::cerr << "[-] RobloxPlayerBeta.exe was not found.\n";
        wait_for_enter();
        return 1;
    }

    if (!driver.vm_attach(pid)) {
        std::cerr << "[-] Failed to open Roblox process (PID " << pid
                  << "). Try running the dumper with sufficient permissions.\n"
                  << "    Windows error: " << GetLastError() << "\n";
        wait_for_enter();
        return 1;
    }

    const uintptr_t base = driver.vm_getmodulebase(kRobloxProcessName);
    if (!Driver::is_plausible_user_address(base)) {
        std::cerr << "[-] Failed to locate RobloxPlayerBeta.exe module base.\n";
        wait_for_enter();
        return 1;
    }

    uintptr_t scanStart = 0;
    uintptr_t scanEnd = 0;
    uintptr_t generatedRangeEnd = 0;

    if (!checked_add(base, kScanStartRva, scanStart) ||
        !checked_add(base, kScanEndRva, scanEnd) ||
        !checked_add(base, kMaxGeneratedRva, generatedRangeEnd) ||
        scanStart >= scanEnd) {
        std::cerr << "[-] Invalid scan range.\n";
        wait_for_enter();
        return 1;
    }

    std::cout << "[+] pid  " << std::dec << pid << "\n"
              << "[+] base 0x" << std::hex << base << "\n\n"
              << "[+] discovering readable memory regions...\n";

    const auto regions = driver.vm_readable_regions(scanStart, scanEnd);
    if (regions.empty()) {
        std::cerr << "[-] No readable memory regions were found in the scan range.\n";
        wait_for_enter();
        return 1;
    }

    // These are intentionally small candidate sets. The actual list/field
    // layout is discovered at runtime instead of being hard-coded to one build.
    constexpr uintptr_t kHeadOffsets[] = {
        0x8, 0x10, 0x18, 0x20
    };

    constexpr uintptr_t kValueGetSetOffsets[] = {
        0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58
    };

    std::vector<Candidate> candidates;
    candidates.reserve(64);

    std::set<std::tuple<uintptr_t, uintptr_t, uintptr_t>> uniqueCandidates;

    size_t regionsScanned = 0;
    size_t pointerSlotsScanned = 0;
    size_t objectMarkersFound = 0;

    std::cout << "[+] scanning " << std::dec << regions.size()
              << " readable regions...\n";

    for (const auto& region : regions) {
        ++regionsScanned;

        uintptr_t regionEnd = 0;
        if (!checked_add(region.base, static_cast<uintptr_t>(region.size), regionEnd))
            continue;

        constexpr size_t kChunkSize = 1ULL << 20; // 1 MiB
        for (uintptr_t cursor = region.base; cursor < regionEnd;) {
            const uintptr_t remaining = regionEnd - cursor;
            const size_t toRead =
                static_cast<size_t>((std::min)(
                    remaining, static_cast<uintptr_t>(kChunkSize)));

            if (toRead < sizeof(uintptr_t))
                break;

            std::vector<std::uint8_t> buffer(toRead);
            if (!driver.vmread_raw(cursor, buffer.data(), buffer.size())) {
                cursor += toRead;
                continue;
            }

            size_t offset = 0;
            if ((cursor & (sizeof(uintptr_t) - 1)) != 0)
                offset = sizeof(uintptr_t) - (cursor & (sizeof(uintptr_t) - 1));

            for (; offset + sizeof(uintptr_t) <= buffer.size();
                 offset += sizeof(uintptr_t)) {

                ++pointerSlotsScanned;

                uintptr_t markerAddress = cursor + offset;
                uintptr_t object = 0;
                std::memcpy(&object, buffer.data() + offset, sizeof(object));

                if (!Driver::is_plausible_user_address(object))
                    continue;

                const auto marker = driver.vm_read<std::uint32_t>(object);
                if (!marker || *marker != 0x3F800000U)
                    continue;

                ++objectMarkersFound;

                for (const uintptr_t headOffset : kHeadOffsets) {
                    uintptr_t headField = 0;
                    if (!checked_add(object, headOffset, headField))
                        continue;

                    const auto listManager = read_ptr(headField);
                    if (!listManager)
                        continue;

                    const auto head = read_ptr(*listManager);
                    if (!head || !Driver::is_plausible_user_address(*head))
                        continue;

                    for (const uintptr_t valueGetSetOffset :
                         kValueGetSetOffsets) {

                        const int score =
                            count_valid_nodes(*head, valueGetSetOffset);

                        if (score < 30)
                            continue;

                        const auto key = std::make_tuple(
                            markerAddress - base,
                            headOffset,
                            valueGetSetOffset);

                        if (uniqueCandidates.insert(key).second) {
                            candidates.push_back({
                                markerAddress - base,
                                headOffset,
                                valueGetSetOffset,
                                score
                            });
                        }
                    }
                }
            }

            if (regionEnd - cursor <= toRead)
                break;

            cursor += toRead;
        }
    }

    std::cout << "[+] regions scanned: " << std::dec << regionsScanned << "\n"
              << "[+] pointer slots:  " << pointerSlotsScanned << "\n"
              << "[+] object markers: " << objectMarkersFound << "\n"
              << "[+] viable layouts: " << candidates.size() << "\n";

    if (candidates.empty()) {
        std::cerr << "[-] No compatible FFlag layout was found.\n"
                  << "    The target's internal layout may have changed.\n";
        wait_for_enter();
        return 1;
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const Candidate& a, const Candidate& b) {
            if (a.score != b.score)
                return a.score > b.score;
            if (a.rva != b.rva)
                return a.rva < b.rva;
            return a.valueGetSetOffset < b.valueGetSetOffset;
        });

    std::cout << "\nTOP candidates:\n";
    for (size_t i = 0; i < (std::min)(size_t{5}, candidates.size()); ++i) {
        const auto& c = candidates[i];
        std::cout << "  " << std::dec << i
                  << ". RVA=0x" << std::hex << c.rva
                  << " H=0x" << c.headOffset
                  << " V=0x" << c.valueGetSetOffset
                  << " SCORE=" << std::dec << c.score << "\n";
    }

    const Candidate& picked = candidates.front();

    uintptr_t listAddress = 0;
    if (!checked_add(base, picked.rva, listAddress)) {
        std::cerr << "[-] Selected list address overflowed.\n";
        wait_for_enter();
        return 1;
    }

    const auto listObject = read_ptr(listAddress);
    if (!listObject) {
        std::cerr << "[-] Selected list pointer could not be read.\n";
        wait_for_enter();
        return 1;
    }

    uintptr_t headField = 0;
    if (!checked_add(*listObject, picked.headOffset, headField)) {
        std::cerr << "[-] Selected head field address overflowed.\n";
        wait_for_enter();
        return 1;
    }

    const auto manager = read_ptr(headField);
    if (!manager) {
        std::cerr << "[-] Selected list manager could not be read.\n";
        wait_for_enter();
        return 1;
    }

    const auto head = read_ptr(*manager);
    if (!head) {
        std::cerr << "[-] Selected list head could not be read.\n";
        wait_for_enter();
        return 1;
    }

    const int flagToValue = sniff_ftv(
        *head, picked.valueGetSetOffset, base);

    if (flagToValue < 0) {
        std::cerr << "[-] Failed to identify the flag-to-value field.\n";
        wait_for_enter();
        return 1;
    }

    std::cout << "\n[+] layout\n"
              << "    list  = 0x" << std::hex << picked.rva << "\n"
              << "    head  = 0x" << picked.headOffset << "\n"
              << "    vgs   = 0x" << picked.valueGetSetOffset << "\n"
              << "    ftv   = 0x" << flagToValue << "\n\n";

    std::ofstream output("FFlags.hpp", std::ios::binary | std::ios::trunc);
    if (!output) {
        std::cerr << "[-] Failed to create FFlags.hpp in the current directory.\n";
        wait_for_enter();
        return 1;
    }

    output << "// Generated by RBXFFlagDumper.\n"
           << "// This file contains offsets observed in the current client.\n"
           << "//\n"
           << "// NOTE: Roblox internals can change without notice.\n\n"
           << "#pragma once\n"
           << "#include <cstdint>\n\n"
           << "namespace FFlagOffsets {\n"
           << "    inline constexpr std::uintptr_t FFlagList = 0x"
           << std::uppercase << std::hex << picked.rva << "ULL;\n"
           << "    inline constexpr std::uintptr_t HeadPointer = 0x"
           << picked.headOffset << "ULL;\n"
           << "    inline constexpr std::uintptr_t ValueGetSet = 0x"
           << picked.valueGetSetOffset << "ULL;\n"
           << "    inline constexpr std::uintptr_t FlagToValue = 0x"
           << flagToValue << "ULL;\n"
           << "}\n\n"
           << "namespace FFlags {\n";

    std::unordered_set<uintptr_t> seenNodes;
    seenNodes.reserve(1024);

    std::unordered_set<std::string> usedNames;
    usedNames.reserve(1024);

    uintptr_t node = *head;
    size_t dumped = 0;
    size_t skipped = 0;

    for (size_t i = 0;
         i < kMaxListNodes && Driver::is_plausible_user_address(node);
         ++i) {

        if (!seenNodes.insert(node).second)
            break;

        uintptr_t nameAddress = 0;
        if (!checked_add(node, 0x10, nameAddress)) {
            ++skipped;
            break;
        }

        const std::string rawName = driver.readstring(nameAddress, 256);

        uintptr_t valueGetSetAddress = 0;
        uintptr_t valuePointerAddress = 0;

        const auto valueGetSetFieldOk =
            checked_add(node, picked.valueGetSetOffset, valueGetSetAddress);

        bool emitted = false;

        if (valueGetSetFieldOk) {
            const auto valueGetSet = read_ptr(valueGetSetAddress);

            if (valueGetSet &&
                checked_add(*valueGetSet,
                            static_cast<uintptr_t>(flagToValue),
                            valuePointerAddress)) {

                const auto valuePointer = read_ptr(valuePointerAddress);

                if (valuePointer &&
                    Driver::is_plausible_user_address(*valuePointer) &&
                    *valuePointer >= base &&
                    *valuePointer < generatedRangeEnd) {

                    const std::string value =
                        driver.readstring(*valuePointer, 4096);

                    if (Driver::vm_isvalidname(rawName) &&
                        !is_bool_string(value) &&
                        is_reasonable_value(value)) {

                        const uintptr_t rva = *valuePointer - base;
                        if (rva > 0x10000ULL &&
                            rva < kMaxGeneratedRva) {

                            const std::string identifier =
                                make_unique_identifier(rawName, usedNames);

                            output << "    inline constexpr std::uintptr_t "
                                   << identifier
                                   << " = 0x"
                                   << std::uppercase << std::hex
                                   << rva << "ULL;\n";

                            ++dumped;
                            emitted = true;
                        }
                    }
                }
            }
        }

        if (!emitted)
            ++skipped;

        const auto next = read_ptr(node);
        if (!next || *next == node)
            break;

        node = *next;
    }

    output << "}\n";
    output.close();

    const auto endTime = std::chrono::steady_clock::now();
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);

    std::cout << "\n[+] dumped " << std::dec << dumped
              << " flags (" << skipped << " skipped)\n"
              << "[+] wrote FFlags.hpp\n"
              << "[+] completed in " << elapsed.count() << " ms\n"
              << "\nDone.\n";

    wait_for_enter();
    return 0;
}
