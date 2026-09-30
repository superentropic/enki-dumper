#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#include "PlatformLinux.h"
#include "Unreal/NameArray.h"

namespace OriginalNames {
struct FNameEntry {
    static inline int64 headerSize = 0;
    static void Init(uint8*, int64 size) { headerSize = size; }
};
struct NameArray {
    static inline int64 NameEntryStride = 0;
    static inline void* (*ByIndex)(void*, int32, int32) = nullptr;
    static bool InitializeNamePool(uint8*);
    static int32 GetNumChunks() { return 1; }
    static int32 GetByteCursor() { return 100; }
};
// Unmodified original code, not another rewrite of our Linux initializer.
#include "upstream-name-pool.inc"
}

template<class T> void put(void* base, size_t offset, T value) {
    std::memcpy(static_cast<uint8*>(base) + offset, &value, sizeof(value));
}
void require(bool value, const char* what) { if (!value) throw std::runtime_error(what); }

int main() try {
    constexpr size_t page = 4096, size = 20 * page;
    const int fd = memfd_create("NameOracle.exe", 0);
    require(fd >= 0 && ftruncate(fd, size) == 0, "allocation");
    auto* image = static_cast<uint8*>(mmap(nullptr, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0));
    require(image != MAP_FAILED, "mapping");
    std::vector<uint8> first(0x2000), second(0x2000);
    put<uint16>(image, 0, 0x5a4d); put<int32>(image, 60, 0x80);
    put<uint32>(image, 0x80, 0x4550); put<uint16>(image, 0x84, 0x8664);
    put<uint16>(image, 0x86, 1); put<uint16>(image, 0x94, 0xf0);
    put<uint16>(image, 0x98, 0x20b); put<uint32>(image, 0xd0, size);
    put<uint32>(image, 0xd4, page); std::memcpy(image+0x188, ".data", 5);
    put<uint32>(image, 0x190, size-page); put<uint32>(image, 0x194, page);
    auto* pool = image + page + 0x100;
    for (const int headerSize : {2, 6}) {
        std::fill(first.begin(), first.end(), 0);
        std::memset(pool, 0, size-page-0x100);
        const int stride = headerSize == 2 ? 2 : 4;
        const int headerOffset = headerSize == 2 ? 0 : 4;
        const int byteEntry = (headerSize + 4 + stride - 1) / stride * stride;
        put<uint16>(first.data(), headerOffset, 4 << 6);
        std::memcpy(first.data()+headerSize, "None", 4);
        put<uint16>(first.data(), byteEntry+headerOffset, 12 << 6);
        std::memcpy(first.data()+byteEntry+headerSize, "ByteProperty", 12);
        std::memcpy(first.data()+100, "/Script/CoreUObject", 19);
        put<int32>(pool, 8, 1); put<int32>(pool, 12, 100);
        put<uintptr_t>(pool, 16, reinterpret_cast<uintptr_t>(first.data()));
        put<uintptr_t>(pool, 24, reinterpret_cast<uintptr_t>(second.data()));
        require(PlatformLinux::Initialize(getpid(), "memfd:NameOracle.exe"), "PE inspection");
        require(OriginalNames::NameArray::InitializeNamePool(pool), "original name pool validation");
        const auto originalMax = Off::NameArray::MaxChunkIndex;
        const auto originalCursor = Off::NameArray::ByteCursor;
        const auto originalStart = Off::NameArray::ChunksStart;
        require(OriginalNames::FNameEntry::headerSize == headerSize, "original header size");
        require(PlatformLinux::FindGNames().address == reinterpret_cast<uintptr_t>(pool), "offset-free discovery");
        require(NameArray::InitLinux(reinterpret_cast<uintptr_t>(pool)), "external original initializer");
        require(Off::NameArray::MaxChunkIndex == originalMax && Off::NameArray::ByteCursor == originalCursor &&
                Off::NameArray::ChunksStart == originalStart, "header layout equality");
        require(Off::InSDK::NameArray::FNameEntryStride == OriginalNames::NameArray::NameEntryStride, "stride equality");
        require(NameArray::GetNameEntry(0).GetString() == "None", "None decoding");
        require(NameArray::GetNameEntry(byteEntry/stride).GetString() == "ByteProperty", "ByteProperty decoding");
        put<int32>(pool, 8, 3);
        require(PlatformLinux::Initialize(getpid(), "memfd:NameOracle.exe"), "refresh fixture");
        require(!OriginalNames::NameArray::InitializeNamePool(pool) && !NameArray::InitLinux(reinterpret_cast<uintptr_t>(pool)), "mismatched chunk count rejected by both");
    }
    munmap(image, size); close(fd);
    std::cout << "PASS: original and external FNamePool initializers agree for 2/6-byte headers, stride, strings, and invalid count rejection\n";
} catch(const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
