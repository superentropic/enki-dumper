#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>
#include "PlatformLinux.h"
#include "OffsetFinder/Offsets.h"

namespace Platform {
bool IsBadReadPtr(const void* p) { unsigned char b{}; return !PlatformLinux::ReadMemory(reinterpret_cast<uintptr_t>(p), &b, 1); }
}
class ObjectArray {
public:
    static inline uint32 SizeOfFUObjectItem = 16;
    static inline uint32 FUObjectItemInitialOffset = 0;
    static uint8* DecryptPtr(void* ptr) { return static_cast<uint8*>(ptr); }
    static void InitializeFUObjectItem(uint8_t* ptr);
};

// Generated verbatim from git HEAD, NOT a reimplementation of the oracle.
#include "upstream-object-array.inc"

template<class T> void put(void* base, size_t offset, T value) {
    std::memcpy(static_cast<uint8_t*>(base) + offset, &value, sizeof(value));
}
void require(bool ok, const char* what) { if (!ok) throw std::runtime_error(what); }

int main() try {
    constexpr size_t page = 4096;
    int fd = memfd_create("UpstreamOracle.exe", 0);
    require(fd >= 0 && ftruncate(fd, page * 2) == 0, "fixture allocation");
    auto* image = static_cast<uint8_t*>(mmap(nullptr, page * 2, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0));
    require(image != MAP_FAILED, "fixture mapping");
    put<uint16_t>(image, 0, 0x5a4d); put<int32_t>(image, 60, 0x80);
    put<uint32_t>(image, 0x80, 0x4550); put<uint16_t>(image, 0x84, 0x8664);
    put<uint16_t>(image, 0x86, 1); put<uint16_t>(image, 0x94, 0xf0);
    put<uint16_t>(image, 0x98, 0x20b); put<uint32_t>(image, 0xd0, page*2);
    put<uint32_t>(image, 0xd4, page); std::memcpy(image+0x188, ".data", 5);
    put<uint32_t>(image, 0x190, page); put<uint32_t>(image, 0x194, page);
    auto* global = image + page + 0x100;
    auto* items = image + page + 0x300;
    auto* chunks = image + page + 0x280;
    auto* vft = image + page + 0x600;
    auto* objects = image + page + 0x700;
    for (const auto& layout : FChunkedFixedUObjectArrayLayouts) {
        for (uint32 initial : {0u, 8u}) {
            std::memset(image+page, 0, page);
            put<uintptr_t>(global, layout.ObjectsOffset, reinterpret_cast<uintptr_t>(chunks));
            put<int32>(global, layout.MaxElementsOffset, 6*0x10000);
            put<int32>(global, layout.NumElementsOffset, 0x900);
            put<int32>(global, layout.MaxChunksOffset, 6);
            put<int32>(global, layout.NumChunksOffset, 1);
            put<uintptr_t>(chunks, 0, reinterpret_cast<uintptr_t>(items));
            for (int i=0; i<3; ++i) {
                put<uintptr_t>(items, i*0x18 + initial, reinterpret_cast<uintptr_t>(objects+i*0x40));
                put<uintptr_t>(objects, i*0x40, reinterpret_cast<uintptr_t>(vft));
            }
            if (initial == 0) {
                // Readable pointers are insufficient: these deliberately
                // wrong stride candidates point at data without a vtable.
                put<uintptr_t>(items, 8, reinterpret_cast<uintptr_t>(vft));
                put<uintptr_t>(items, 16, reinterpret_cast<uintptr_t>(vft));
            }
            require(PlatformLinux::Initialize(getpid(), "memfd:UpstreamOracle.exe"), "fixture PE inspection");
            require(IsAddressValidGObjects(reinterpret_cast<uintptr_t>(global), layout), "original structural validator");
            ObjectArray::SizeOfFUObjectItem = 16; ObjectArray::FUObjectItemInitialOffset = 0;
            ObjectArray::InitializeFUObjectItem(items);
            const auto external = PlatformLinux::FindGObjects();
            require(external.address == reinterpret_cast<uintptr_t>(global), "global address equality");
            require(external.itemSize == ObjectArray::SizeOfFUObjectItem, "stride equality to original");
            require(external.itemInitialOffset == ObjectArray::FUObjectItemInitialOffset, "pointer offset equality to original");
            require(external.objectsOffset == layout.ObjectsOffset && external.numElementsOffset == layout.NumElementsOffset, "layout equality to original");
            require(PlatformLinux::GetLastGObjectsInfo().itemInitialOffset == initial, "generator handoff retains layout");
        }
    }
    std::cout << "PASS: 5 upstream chunk layouts x 2 item pointer offsets; original validators and InitializeFUObjectItem agree\n";
    munmap(image, page*2); close(fd);
} catch(const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 1; }
