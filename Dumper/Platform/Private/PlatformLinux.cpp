#include "PlatformLinux.h"
#include "LinuxProcess.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <cctype>
#include <limits>
#include <iostream>
#include <array>

namespace {
struct RemoteSection { uintptr_t address{}; uint32_t size{}; bool executable{}; std::string name; };
LinuxInspection::Process g_process;
const auto& g_maps = g_process.Maps();
std::string g_initializationError;
std::string g_module;
uintptr_t g_moduleBase = 0;
std::vector<RemoteSection> g_sections;
GObjectsInfo g_lastGObjects;
std::unordered_map<uintptr_t, std::array<uint8_t, 4096>> g_readPages;

bool read_remote(uintptr_t address, void* buffer, size_t size)
{
    return g_process.Read(address, buffer, size);
}
bool module_match(const LinuxInspection::Mapping& map)
{
    return LinuxInspection::ModuleMatches(map.path, g_module);
}
struct DosHeader { uint16_t magic; uint8_t pad[58]; int32_t peOffset; };
struct FileHeader { uint16_t machine, sections; uint32_t time, symbols, symbolsCount; uint16_t optionalSize, characteristics; };
struct NtPrefix { uint32_t signature; FileHeader file; };
#pragma pack(push, 1)
struct SectionHeader {
    char name[8];
    uint32_t virtualSize, virtualAddress, rawSize, rawAddress, reloc, line;
    uint16_t relocCount, lineCount;
    uint32_t characteristics;
};
#pragma pack(pop)
static_assert(sizeof(DosHeader) == 64 && sizeof(NtPrefix) == 24 && sizeof(SectionHeader) == 40);
std::vector<int> parse_signature(const char* signature)
{
    std::vector<int> result; std::stringstream stream(signature ? signature : ""); std::string token;
    while (stream >> token) result.push_back(token == "?" || token == "??" ? -1 : std::strtol(token.c_str(), nullptr, 16));
    return result;
}

bool read_fname_pool(uintptr_t namePool, int32_t comparisonIndex, std::string& value)
{
    value.clear();
    if (!namePool || comparisonIndex < 0 || comparisonIndex >= 0x2000000) return false;
    const uint32_t index = static_cast<uint32_t>(comparisonIndex);
    uintptr_t block{};
    if (!read_remote(namePool + 0x10 + static_cast<uintptr_t>(index >> 16) * sizeof(uintptr_t), &block, sizeof(block)) || !block)
        return false;
    const uintptr_t entry = block + static_cast<uintptr_t>(index & 0xffff) * 2;
    uint16_t header{};
    if (!read_remote(entry, &header, sizeof(header))) return false;
    const uint16_t length = header >> 6;
    if (!length || length > 256 || (header & 1)) return false;
    value.resize(length);
    if (!read_remote(entry + 2, value.data(), value.size())) { value.clear(); return false; }
    return std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= 0x20 && c < 0x7f; });
}

bool has_unreal_class_chain(uintptr_t object, uintptr_t namePool)
{
    uintptr_t klass{};
    if (!read_remote(object + 0x10, &klass, sizeof(klass)) || !klass) return false;
    for (int depth = 0; depth != 4; ++depth) {
        int32_t nameIndex{};
        std::string name;
        if (!read_remote(klass + 0x18, &nameIndex, sizeof(nameIndex)) || !read_fname_pool(namePool, nameIndex, name))
            return false;
        if (name == "Class") return true;
        uintptr_t next{};
        if (!read_remote(klass + 0x10, &next, sizeof(next)) || !next || next == klass) return false;
        klass = next;
    }
    return false;
}
}

namespace PlatformLinux {
bool Initialize(int pid, const std::string& moduleName)
{
    g_module = moduleName; g_moduleBase = 0; g_sections.clear(); g_lastGObjects = {}; g_readPages.clear(); g_initializationError.clear();
    const auto fail = [](const std::string& message) {
        g_initializationError = message;
        g_moduleBase = 0;
        g_sections.clear();
        g_process.Detach();
        return false;
    };
    if (!g_process.Attach(pid)) return fail("process inspection: " + std::string(std::strerror(g_process.LastFailure().error)));
    for (const auto& map : g_maps) if (map.read && module_match(map) && map.offset == 0) { g_moduleBase = map.start; break; }
    if (!g_moduleBase) return fail("no readable offset-zero mapping matches the module basename");
    DosHeader dos{};
    if (!read_remote(g_moduleBase, &dos, sizeof(dos))) return fail("DOS header read: " + std::string(std::strerror(g_process.LastFailure().error)));
    if (dos.magic != 0x5A4D || dos.peOffset < 64 || dos.peOffset > 0x100000)
        return fail("invalid DOS header or PE header offset");
    if (g_moduleBase > std::numeric_limits<uintptr_t>::max() - 0x200000)
        return fail("PE header address overflow");
    NtPrefix nt{};
    if (!read_remote(g_moduleBase + dos.peOffset, &nt, sizeof(nt))) return fail("NT header read: " + std::string(std::strerror(g_process.LastFailure().error)));
    if (nt.signature != 0x4550 || nt.file.machine != 0x8664 || nt.file.sections == 0 ||
        nt.file.sections > 96 || nt.file.optionalSize < 112 || nt.file.optionalSize > 4096)
        return fail("invalid or unsupported PE header (requires x86-64 PE32+)");
    const uintptr_t optional = g_moduleBase + dos.peOffset + sizeof(NtPrefix);
    uint16_t magic{};
    uint32_t imageSize{}, headersSize{};
    if (!Read(optional, magic) || !Read(optional + 56, imageSize) || !Read(optional + 60, headersSize))
        return fail("optional header read: " + std::string(std::strerror(g_process.LastFailure().error)));
    const uintptr_t table = g_moduleBase + dos.peOffset + sizeof(NtPrefix) + nt.file.optionalSize;
    if (magic != 0x20B || !headersSize || headersSize > imageSize ||
        imageSize > std::numeric_limits<uintptr_t>::max() - g_moduleBase ||
        table - g_moduleBase + nt.file.sections * sizeof(SectionHeader) > headersSize)
        return fail("invalid PE image/header bounds");
    for (uint16_t i = 0; i < nt.file.sections; ++i) {
        SectionHeader section{};
        if (!read_remote(table + i * sizeof(section), &section, sizeof(section)))
            return fail("section header read: " + std::string(std::strerror(g_process.LastFailure().error)));
        const uint32_t size = std::max(section.virtualSize, section.rawSize);
        if (section.virtualAddress > imageSize || size > imageSize - section.virtualAddress)
            return fail("PE section extends outside SizeOfImage");
        if (size) g_sections.push_back({g_moduleBase + section.virtualAddress, size, (section.characteristics & 0x20000000u) != 0,
            std::string(section.name, strnlen(section.name, sizeof(section.name)))});
    }
    return !g_sections.empty() || fail("PE image has no nonempty sections");
}
const std::string& GetInitializationError() { return g_initializationError; }
int GetProcessId() { return g_process.Pid(); }
bool ReadMemory(uintptr_t address, void* buffer, size_t size) { return read_remote(address, buffer, size); }
bool ReadCachedMemory(uintptr_t address, void* buffer, size_t size)
{
    if (!buffer || !size || !address || size - 1 > UINTPTR_MAX - address) return false;
    size_t copied = 0;
    while (copied < size) {
        const auto current = address + copied;
        const auto page = current & ~uintptr_t(4095);
        const auto offset = current - page;
        const auto length = std::min(size - copied, size_t(4096 - offset));
        auto it = g_readPages.find(page);
        if (it == g_readPages.end()) {
            std::array<uint8_t, 4096> bytes{};
            if (!read_remote(page, bytes.data(), bytes.size())) {
                // Boundary pages may be partially readable; preserve exact
                // read failure handling instead of caching incomplete data.
                return read_remote(address, buffer, size);
            }
            // Bound cache memory to 512 MiB. Values are copied out, so eviction
            // cannot invalidate references retained by the generator.
            if (g_readPages.size() >= 131072) g_readPages.clear();
            it = g_readPages.emplace(page, bytes).first;
        }
        std::memcpy(static_cast<uint8_t*>(buffer) + copied, it->second.data() + offset, length);
        copied += length;
    }
    return true;
}
std::vector<SectionInfo> GetRemoteSections()
{
    std::vector<SectionInfo> result;
    for (const auto& section : g_sections) result.push_back({section.address, section.size});
    return result;
}

GObjectsInfo FindGObjects(uintptr_t namePool)
{
    if (g_lastGObjects.address)
        return g_lastGObjects;
    const GObjectsInfo layouts[] = {
        {0, true, 0x10000, 0x00, 0x10, 0x14, 0x18, 0x1C},
        {0, true, 0x10000, 0x00, 0x0C, 0x08, 0x14, 0x10},
        {0, true, 0x10000, 0x10, 0x00, 0x04, 0x08, 0x0C},
        {0, true, 0x10000, 0x18, 0x10, 0x00, 0x14, 0x20},
        {0, true, 0x10000, 0x18, 0x00, 0x14, 0x10, 0x04},
    };
    auto valid = [](uintptr_t address) { return address >= 0x10000 && IsAddressInProcessRange(address); };
    auto scanSections = g_sections;
    std::stable_sort(scanSections.begin(), scanSections.end(), [](const auto& a, const auto& b) {
        return (a.name == ".data") > (b.name == ".data");
    });
    for (const auto& section : scanSections) {
        std::cerr << "[scan] " << section.name << " @ 0x" << std::hex << section.address << std::dec << '\n';
        std::vector<uint8_t> bytes(section.size);
        if (!ReadMemory(section.address, bytes.data(), bytes.size())) continue;
        // Match Dumper-7's 4-byte global scan. Some valid UE globals are
        // aligned to four bytes even in a 64-bit PE image.
        for (uint32_t cursor = 0; cursor + 0x50 <= section.size; cursor += 4) {
            const uintptr_t address = section.address + cursor;
            uintptr_t fixedObjects{};
            int32_t fixedMax{}, fixedNum{};
            std::memcpy(&fixedObjects, bytes.data() + cursor, sizeof(fixedObjects));
            std::memcpy(&fixedMax, bytes.data() + cursor + sizeof(uintptr_t), sizeof(fixedMax));
            std::memcpy(&fixedNum, bytes.data() + cursor + sizeof(uintptr_t) + sizeof(int32_t), sizeof(fixedNum));
            if (fixedNum >= 0x1000 && fixedNum <= fixedMax && fixedMax <= 0x400000 && valid(fixedObjects)) {
                uintptr_t fifth{};
                int32_t index{};
                if (Read(fixedObjects + 5 * 0x18, fifth) && valid(fifth) &&
                    Read(fifth + sizeof(uintptr_t) + sizeof(int32_t), index) && index == 5)
                    return g_lastGObjects = {address, false, 0, 0, sizeof(uintptr_t), sizeof(uintptr_t) + sizeof(int32_t), 0, 0};
            }
            for (const auto& layout : layouts) {
                const auto i32 = [&](int32_t offset) { int32_t value{}; std::memcpy(&value, bytes.data() + cursor + offset, sizeof(value)); return value; };
                uintptr_t objects{}; std::memcpy(&objects, bytes.data() + cursor + layout.objectsOffset, sizeof(objects));
                const int32_t maxElements = i32(layout.maxElementsOffset);
                const int32_t numElements = i32(layout.numElementsOffset);
                const int32_t maxChunks = i32(layout.maxChunksOffset);
                const int32_t numChunks = i32(layout.numChunksOffset);
                if (numChunks < 1 || numChunks > 0x14 || maxChunks < 6 || maxChunks > 0x5FF ||
                    numElements <= 0x800 || maxElements <= 0x10000 || numElements > maxElements ||
                    numChunks > maxChunks || maxElements % 0x10) continue;
                const int32_t perChunk = maxElements / maxChunks;
                if (perChunk % 0x10 || perChunk < 0x8000 || perChunk > 0x80000 ||
                    (numElements / perChunk) + 1 != numChunks || maxElements / perChunk != maxChunks || !valid(objects))
                    continue;
                bool chunksValid = true;
                for (int i = 0; i < numChunks; ++i) {
                    uintptr_t chunk{};
                    if (!Read(objects + i * sizeof(uintptr_t), chunk) || !valid(chunk)) { chunksValid = false; break; }
                }
                if (chunksValid) {
                    // This is the remote equivalent of Dumper-7's
                    // ObjectArray::InitializeFUObjectItem().  Do not assume
                    // the common UE5 0x18 FUObjectItem layout.
                    uintptr_t firstChunk{};
                    if (!Read(objects, firstChunk) || !valid(firstChunk)) continue;
                    int32_t itemInitialOffset = -1;
                    for (int32_t offset = 0; offset < 0x20; offset += 4) {
                        uintptr_t firstObject{};
                        if (Read(firstChunk + offset, firstObject) && valid(firstObject)) {
                            itemInitialOffset = offset;
                            break;
                        }
                    }
                    if (itemInitialOffset < 0) continue;
                    int32_t itemSize = 0;
                    for (int32_t offset = itemInitialOffset + static_cast<int32_t>(sizeof(uintptr_t)); offset <= 0x38; offset += 4) {
                        uintptr_t secondObject{}, thirdObject{}, secondVft{}, thirdVft{};
                        if (Read(firstChunk + offset, secondObject) &&
                            Read(firstChunk + (offset * 2) - itemInitialOffset, thirdObject) &&
                            valid(secondObject) && valid(thirdObject) &&
                            Read(secondObject, secondVft) && valid(secondVft) &&
                            Read(thirdObject, thirdVft) && valid(thirdVft)) {
                            itemSize = offset - itemInitialOffset;
                            break;
                        }
                    }
                    if (!itemSize) continue;
                    std::cerr << "[scan] GObjects RVA=0x" << std::hex << (address-g_moduleBase)
                              << " item_size=0x" << itemSize << " item_offset=0x" << itemInitialOffset
                              << std::dec << " count=" << numElements << " chunks=" << numChunks << '\n';
                    GObjectsInfo result = layout;
                    result.address = address;
                    result.elementsPerChunk = perChunk;
                    result.itemSize = itemSize;
                    result.itemInitialOffset = itemInitialOffset;
                    return g_lastGObjects = result;
                }
            }
        }
    }
    return {};
}

const GObjectsInfo& GetLastGObjectsInfo()
{
    return g_lastGObjects;
}

GNamesInfo FindGNames(uintptr_t overrideOffset)
{
    // External candidate search; NameArray::InitializeNamePool performs the
    // original full header/chunk validation before these candidates are used.
    const auto candidate = [](uintptr_t address) -> GNamesInfo {
        int32_t current{}, cursor{};
        uintptr_t first{};
        if (!Read(address + 8, current) || current <= 0 || current > 0x10000 ||
            !Read(address + 12, cursor) || cursor < 0 || cursor > 0x40000 ||
            !Read(address + 16, first) || !IsAddressInProcessRange(first)) return {};
        std::array<uint8_t, 0x1008> probe{};
        if (!ReadMemory(first, probe.data(), probe.size())) return {};
        int header = 0;
        for (int offset : {2, 6})
            if (std::memcmp(probe.data() + offset, "None", 4) == 0) header = offset;
        if (!header) return {};
        const char core[] = "CoreUObj";
        if (std::search(probe.begin(), probe.end(), core, core + 8) == probe.end()) return {};
        return {address, 0x10, header == 2 ? 2 : 4};
    };
    if (overrideOffset) return candidate(g_moduleBase + overrideOffset);
    auto sections = g_sections;
    std::stable_sort(sections.begin(), sections.end(), [](const auto& a, const auto& b) {
        return a.name == ".data" && b.name != ".data";
    });
    for (const auto& section : sections) {
        std::vector<uint8_t> bytes(section.size);
        if (!ReadMemory(section.address, bytes.data(), bytes.size())) continue;
        for (uint32_t cursor = 0; cursor + 0x20 <= section.size; cursor += 8) {
            int32_t current{}, used{};
            std::memcpy(&current, bytes.data() + cursor + 8, 4);
            std::memcpy(&used, bytes.data() + cursor + 12, 4);
            if (current <= 0 || current > 0x10000 || used < 0 || used > 0x40000) continue;
            if (auto found = candidate(section.address + cursor); found.address) return found;
        }
    }
    return {};
}
uintptr_t GetModuleBase(const char*) { return g_moduleBase; }
uintptr_t GetOffset(uintptr_t address, const char*) { return address >= g_moduleBase ? address - g_moduleBase : 0; }
uintptr_t GetOffset(const void* address, const char* module) { return GetOffset(reinterpret_cast<uintptr_t>(address), module); }
SectionInfo GetSectionInfo(const std::string& name, const char*)
{
    for (const auto& section : g_sections)
        if (section.name == name) return {section.address, section.size};
    return {};
}
void* IterateSectionWithCallback(const SectionInfo& info, const std::function<bool(void*)>& callback, uint32_t granularity, uint32_t offsetFromEnd)
{
    if (!info.IsValid()) return nullptr;
    for (uintptr_t p = info.Start; p + offsetFromEnd < info.Start + info.Size; p += std::max(1u, granularity))
        if (callback(reinterpret_cast<void*>(p))) return reinterpret_cast<void*>(p);
    return nullptr;
}
void* IterateAllSectionsWithCallback(const std::function<bool(void*)>& callback, uint32_t granularity, uint32_t offsetFromEnd, const char*)
{
    for (const auto& section : g_sections)
        if (auto* found = IterateSectionWithCallback({section.address, section.size}, callback, granularity, offsetFromEnd)) return found;
    return nullptr;
}
bool IsAddressInAnyModule(uintptr_t address) {
    for (const auto& section : g_sections)
        if (address >= section.address && address - section.address < section.size) return true;
    auto it = std::upper_bound(g_maps.begin(), g_maps.end(), address,
        [](uintptr_t value, const LinuxInspection::Mapping& map) { return value < map.start; });
    if (it == g_maps.begin()) return false;
    --it;
    if (!it->read || address >= it->end) return false;
    auto path = LinuxInspection::BaseName(it->path);
    std::transform(path.begin(), path.end(), path.begin(), [](unsigned char c) { return std::tolower(c); });
    return path.ends_with(".dll") || path.ends_with(".exe");
}
bool IsAddressInAnyModule(const void* address) { return IsAddressInAnyModule(reinterpret_cast<uintptr_t>(address)); }
bool IsAddressInProcessRange(uintptr_t address)
{
    // /proc maps are sorted. This is a metadata check, not a read guarantee;
    // ReadMemory separately pins/checks process lifetime and rejects faults.
    auto it = std::upper_bound(g_maps.begin(), g_maps.end(), address,
        [](uintptr_t value, const LinuxInspection::Mapping& map) { return value < map.start; });
    if (it == g_maps.begin()) return false;
    --it;
    return it->read && address < it->end;
}
bool IsAddressInProcessRange(const void* address) { return IsAddressInProcessRange(reinterpret_cast<uintptr_t>(address)); }
bool IsBadReadPtr(uintptr_t address) { return !IsAddressInProcessRange(address); }
bool IsBadReadPtr(const void* address) { return IsBadReadPtr(reinterpret_cast<uintptr_t>(address)); }
const void* GetAddressOfImportedFunction(const char*, const char*, const char*) { return nullptr; }
const void* GetAddressOfImportedFunctionFromAnyModule(const char*, const char*) { return nullptr; }
const void* GetAddressOfExportedFunction(const char*, const char*) { return nullptr; }
void* FindPatternInRange(std::vector<int>&& pattern, const void* start, uintptr_t range, bool relative, uint32_t offset, uint32_t skipCount)
{
    const uintptr_t address = reinterpret_cast<uintptr_t>(start);
    if (pattern.empty() || range < pattern.size()) return nullptr;
    std::vector<uint8_t> bytes(range);
    if (!read_remote(address, bytes.data(), bytes.size())) return nullptr;
    for (uintptr_t i = 0; i + pattern.size() <= range; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j)
            if (pattern[j] >= 0 && bytes[i + j] != static_cast<uint8_t>(pattern[j])) { match = false; break; }
        if (!match) continue;
        if (skipCount && skipCount--) continue;
        uintptr_t found = address + i + offset;
        if (relative) { int32_t displacement{}; if (!read_remote(found, &displacement, sizeof(displacement))) return nullptr; found += sizeof(displacement) + displacement; }
        return reinterpret_cast<void*>(found);
    }
    return nullptr;
}
void* FindPatternInRange(const char* signature, const void* start, uintptr_t range, bool relative, uint32_t offset)
{ return FindPatternInRange(parse_signature(signature), start, range, relative, offset); }
void* FindPatternInRange(const char* signature, uintptr_t start, uintptr_t range, bool relative, uint32_t offset)
{ return FindPatternInRange(signature, reinterpret_cast<void*>(start), range, relative, offset); }
void* FindPattern(const char* signature, uint32_t offset, bool searchAll, uintptr_t start, const char*)
{
    const auto pattern = parse_signature(signature);
    for (const auto& section : g_sections) {
        if (!searchAll && !section.executable) continue;
        const uintptr_t begin = start ? start : section.address;
        if (begin < section.address || begin >= section.address + section.size) continue;
        if (auto* found = FindPatternInRange(std::vector<int>(pattern), reinterpret_cast<void*>(begin), section.address + section.size - begin, false, offset)) return found;
    }
    return nullptr;
}
}
