#pragma once

#ifndef _WIN32
#include <cstddef>
#include <cstdint>
#include <thread>
#include <chrono>

using BYTE = uint8_t;
using WORD = uint16_t;
using DWORD = uint32_t;
using LONG = int32_t;
using ULONG = uint32_t;
using uint8 = uint8_t;
using uint16 = uint16_t;
using uint32 = uint32_t;
using int8 = int8_t;
using int16 = int16_t;
using int32 = int32_t;
using int64 = int64_t;
using uint64 = uint64_t;
using HANDLE = void*;
using HMODULE = void*;
using PVOID = void*;

#pragma pack(push, 1)
struct IMAGE_DOS_HEADER {
    WORD e_magic{};
    BYTE reserved[58]{};
    LONG e_lfanew{};
};
struct IMAGE_FILE_HEADER {
    WORD Machine{};
    WORD NumberOfSections{};
    DWORD TimeDateStamp{};
    DWORD PointerToSymbolTable{};
    DWORD NumberOfSymbols{};
    WORD SizeOfOptionalHeader{};
    WORD Characteristics{};
};
struct IMAGE_OPTIONAL_HEADER64 {
    WORD Magic{};
    BYTE reserved[54]{};
    DWORD SizeOfImage{};
};
struct IMAGE_NT_HEADERS64 {
    DWORD Signature{};
    IMAGE_FILE_HEADER FileHeader{};
    IMAGE_OPTIONAL_HEADER64 OptionalHeader{};
};
struct IMAGE_SECTION_HEADER {
    BYTE Name[8]{};
    union { DWORD PhysicalAddress; DWORD VirtualSize; } Misc{};
    DWORD VirtualAddress{};
    DWORD SizeOfRawData{};
    DWORD PointerToRawData{};
    DWORD PointerToRelocations{};
    DWORD PointerToLinenumbers{};
    WORD NumberOfRelocations{};
    WORD NumberOfLinenumbers{};
    DWORD Characteristics{};
};
#pragma pack(pop)

using PIMAGE_DOS_HEADER = IMAGE_DOS_HEADER*;
using PIMAGE_NT_HEADERS = IMAGE_NT_HEADERS64*;
using PIMAGE_SECTION_HEADER = IMAGE_SECTION_HEADER*;
using PIMAGE_FILE_HEADER = IMAGE_FILE_HEADER*;

inline void Sleep(unsigned long milliseconds)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

constexpr WORD IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr DWORD IMAGE_NT_SIGNATURE = 0x00004550;
constexpr DWORD IMAGE_SCN_MEM_READ = 0x40000000;

#endif
