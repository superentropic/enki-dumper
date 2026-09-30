#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <cstring>

#include "Settings.h"

struct SectionInfo {
    uintptr_t Start = 0;
    uint32_t Size = 0;

    bool IsValid() const { return Start != 0 && Size != 0; }
};

struct GObjectsInfo {
    uintptr_t address = 0;
    bool chunked = true;
    int32_t elementsPerChunk = 0x10000;
    int32_t objectsOffset = 0;
    int32_t maxElementsOffset = 0x10;
    int32_t numElementsOffset = 0x14;
    int32_t maxChunksOffset = 0x18;
    int32_t numChunksOffset = 0x1C;
    int32_t itemSize = 0x18;
    int32_t itemInitialOffset = 0;
};
struct GNamesInfo { uintptr_t address = 0; int32_t chunksStart = 0x10; int32_t stride = 2; };

namespace PlatformLinux {

bool Initialize(int pid, const std::string& moduleName);
const std::string& GetInitializationError();
int GetProcessId();
bool ReadMemory(uintptr_t address, void* buffer, size_t size);
bool ReadCachedMemory(uintptr_t address, void* buffer, size_t size);
bool IsAddressInProcessRange(uintptr_t address);
std::vector<SectionInfo> GetRemoteSections();
GObjectsInfo FindGObjects(uintptr_t namePool = 0);
// The Linux entry point validates the object array before SDK initialization.
// Keep the complete result (including the dynamically detected FUObjectItem
// layout) available to ObjectArray::Init instead of reconstructing it from a
// global address and silently assuming a stride.
const GObjectsInfo& GetLastGObjectsInfo();
GNamesInfo FindGNames(uintptr_t overrideOffset = 0);

template <typename T>
bool Read(uintptr_t address, T& value) { return ReadMemory(address, &value, sizeof(T)); }

template <typename T>
T ReadOr(uintptr_t address, T fallback = {}) { T value{}; return Read(address, value) ? value : fallback; }

template <typename T>
const std::vector<T>& ReadRemoteArray(uintptr_t address)
{
    static thread_local std::unordered_map<uintptr_t, std::vector<T>> cache;
    auto& result = cache[address];
    uintptr_t data{};
    int32_t count{}, capacity{};
    if (!Read(address, data) || !Read(address + sizeof(uintptr_t), count) ||
        !Read(address + sizeof(uintptr_t) + sizeof(int32_t), capacity) ||
        count < 0 || count > 0x1000000 || capacity < count || (count && !IsAddressInProcessRange(data))) {
        result.clear();
        return result;
    }
    result.resize(static_cast<size_t>(count));
    if (count && !ReadMemory(data, result.data(), sizeof(T) * static_cast<size_t>(count)))
        result.clear();
    return result;
}

inline void Sleep(unsigned long milliseconds)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

consteval bool Is32Bit() { return false; }

uintptr_t GetModuleBase(const char* ModuleName = Settings::General::DefaultModuleName);
uintptr_t GetOffset(uintptr_t Address, const char* ModuleName = Settings::General::DefaultModuleName);
uintptr_t GetOffset(const void* Address, const char* ModuleName = Settings::General::DefaultModuleName);

SectionInfo GetSectionInfo(const std::string& SectionName,
                           const char* ModuleName = Settings::General::DefaultModuleName);
void* IterateSectionWithCallback(const SectionInfo& Info,
    const std::function<bool(void* Address)>& Callback,
    uint32_t Granularity = 0x4, uint32_t OffsetFromEnd = 0x0);
void* IterateAllSectionsWithCallback(const std::function<bool(void* Address)>& Callback,
    uint32_t Granularity = 0x4, uint32_t OffsetFromEnd = 0x0,
    const char* ModuleName = Settings::General::DefaultModuleName);

bool IsAddressInAnyModule(uintptr_t Address);
bool IsAddressInAnyModule(const void* Address);
bool IsAddressInProcessRange(uintptr_t Address);
bool IsAddressInProcessRange(const void* Address);
bool IsBadReadPtr(uintptr_t Address);
bool IsBadReadPtr(const void* Address);

const void* GetAddressOfImportedFunction(const char*, const char*, const char*);
const void* GetAddressOfImportedFunctionFromAnyModule(const char*, const char*);
const void* GetAddressOfExportedFunction(const char*, const char*);

void* FindPattern(const char* Signature, uint32_t Offset = 0,
    bool SearchAllSections = false, uintptr_t StartAddress = 0,
    const char* ModuleName = Settings::General::DefaultModuleName);
void* FindPatternInRange(const char* Signature, const void* Start, uintptr_t Range,
    bool Relative = false, uint32_t Offset = 0);
void* FindPatternInRange(const char* Signature, uintptr_t Start, uintptr_t Range,
    bool Relative = false, uint32_t Offset = 0);
void* FindPatternInRange(std::vector<int>&& Signature, const void* Start, uintptr_t Range,
    bool Relative = false, uint32_t Offset = 0, uint32_t SkipCount = 0);

template<bool = true, typename CharType = char>
void* FindByStringInAllSections(const CharType*, uintptr_t = 0, int32_t = 0,
    bool = true, const char* = Settings::General::DefaultModuleName) { return nullptr; }

template<bool, typename CharType>
void* FindStringInRange(const CharType*, uintptr_t, int32_t) { return nullptr; }

template<typename T>
T* FindAlignedValueInAllSections(const T value, int32_t alignment = alignof(T), uintptr_t start = 0,
    int32_t range = 0, const char* = Settings::General::DefaultModuleName) {
    if (alignment <= 0) return nullptr;
    for (const auto& section : GetRemoteSections()) {
        if (start >= section.Start + section.Size) continue;
        std::vector<uint8_t> bytes(section.Size);
        if (!ReadMemory(section.Start, bytes.data(), bytes.size())) continue;
        auto offset = start > section.Start ? start - section.Start : 0;
        offset = (offset + alignment - 1) / alignment * alignment;
        for (; offset + sizeof(T) <= bytes.size(); offset += alignment) {
            if (range > 0 && start && section.Start + offset - start >= static_cast<uintptr_t>(range)) break;
            T candidate{};
            std::memcpy(&candidate, bytes.data() + offset, sizeof(T));
            if (candidate == value) return reinterpret_cast<T*>(section.Start + offset);
        }
    }
    return nullptr;
}

template<typename T>
std::vector<T*> FindAllAlignedValuesInProcess(const T Value, int32_t Alignment = alignof(T),
    uintptr_t StartAddress = 0, int32_t Range = 0,
    const char* ModuleName = Settings::General::DefaultModuleName) {
    std::vector<T*> result;
    uintptr_t cursor = StartAddress;
    while (auto* found = FindAlignedValueInAllSections(Value, Alignment, cursor, Range, ModuleName)) {
        result.push_back(found);
        cursor = reinterpret_cast<uintptr_t>(found) + sizeof(T);
    }
    return result;
}

template<bool = true>
std::pair<const void*, int32_t> IterateVTableFunctions(void**,
    const std::function<bool(const uint8_t*, int32_t)>&, int32_t = 0x150,
    int32_t = 0) { return {nullptr, -1}; }

} // namespace PlatformLinux
