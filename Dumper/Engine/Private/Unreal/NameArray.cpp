
#include <format>
#include "TargetMemory.h"

#include "Unreal/ObjectArray.h"
#include "Unreal/NameArray.h"

#include "Platform.h"
#include "Architecture.h"

uint8* NameArray::GNames = nullptr;

FNameEntry::FNameEntry(void* Ptr)
	: Address((uint8*)Ptr)
{
}

std::wstring FNameEntry::GetWString()
{
	if (!Address)
		return L"";

	return GetStr(Address);
}

std::string FNameEntry::GetString()
{
	if (!Address)
		return "";

	return UtfN::WStringToString(GetWString());
}

void* FNameEntry::GetAddress()
{
	return Address;
}

void FNameEntry::Init(const uint8_t* FirstChunkPtr, int64 NameEntryStringOffset)
{
#if defined(__linux__)
    Off::FNameEntry::NamePool::StringOffset = NameEntryStringOffset;
    Off::FNameEntry::NamePool::HeaderOffset = NameEntryStringOffset == 6 ? 4 : 0;
    // Same ByteProperty anchor and header-shift derivation as upstream.
    auto entry = TargetMemory::Read<uintptr_t>(FirstChunkPtr) + NameEntryStringOffset + 4;
    for (int padding = 0; padding < 4; ++padding) {
        if (TargetMemory::Read<uint32>(entry + NameEntryStringOffset) == 0x65747942) break;
        ++entry;
    }
    auto header = TargetMemory::Read<uint16>(entry + Off::FNameEntry::NamePool::HeaderOffset);
    FNameEntryLengthShiftCount = 0;
    while (header != 12 && FNameEntryLengthShiftCount < 16) {
        ++FNameEntryLengthShiftCount;
        header >>= 1;
    }
    if (FNameEntryLengthShiftCount == 16) throw std::runtime_error("upstream ByteProperty FName header check failed");
    std::cerr << "FNameEntryLengthShiftCount: " << FNameEntryLengthShiftCount << '\n';
    GetStr = [](uint8* NameEntry) -> std::wstring
    {
        const uintptr_t address = reinterpret_cast<uintptr_t>(NameEntry);
        const uint16 header = TargetMemory::Read<uint16>(address + Off::FNameEntry::NamePool::HeaderOffset);
        const int32 length = header >> FNameEntryLengthShiftCount;
        if (length > 1024) return {};
        if (length == 0) {
            const auto entryIdOffset = Off::FNameEntry::NamePool::StringOffset +
                ((Off::FNameEntry::NamePool::StringOffset == 6) * 2);
            const auto next = TargetMemory::Read<int32>(address + entryIdOffset);
            const auto number = TargetMemory::Read<int32>(address + entryIdOffset + sizeof(int32));
            static thread_local int depth = 0;
            if (depth >= 16) return {};
            ++depth;
            auto result = NameArray::GetNameEntry(next).GetWString();
            --depth;
            if (number > 0) result += L'_' + std::to_wstring(number - 1);
            return result;
        }
        if (header & NameWideMask)
        {
            std::vector<uint16_t> text(static_cast<size_t>(length));
            if (!PlatformLinux::ReadCachedMemory(address + Off::FNameEntry::NamePool::StringOffset, text.data(), text.size() * sizeof(uint16_t))) return {};
            std::wstring result;
            for (uint16_t character : text) result.push_back(static_cast<wchar_t>(character));
            return result;
        }
        std::string text(static_cast<size_t>(length), '\0');
        if (!PlatformLinux::ReadCachedMemory(address + Off::FNameEntry::NamePool::StringOffset, text.data(), text.size())) return {};
        return UtfN::StringToWString(text);
    };
    return;
#endif
	if (Settings::Internal::bUseNamePool)
	{
		constexpr int64 NoneStrLen = 0x4;
		constexpr uint16 BytePropertyStrLen = 0xC;

		constexpr uint32 BytePropertyStartAsUint32 = 'etyB'; // "Byte" part of "ByteProperty"

		Off::FNameEntry::NamePool::StringOffset = NameEntryStringOffset;
		Off::FNameEntry::NamePool::HeaderOffset = NameEntryStringOffset == 6 ? 4 : 0;

		const uint8* AssumedBytePropertyEntry = *reinterpret_cast<uint8* const*>(FirstChunkPtr) + NameEntryStringOffset + NoneStrLen;

		/* Check if there's pading after an FNameEntry. Check if there's up to 0x4 bytes padding. */
		for (int i = 0; i < 0x4; i++)
		{
			const uint32 FirstPartOfByteProperty = *reinterpret_cast<const uint32*>(AssumedBytePropertyEntry + NameEntryStringOffset);

			if (FirstPartOfByteProperty == BytePropertyStartAsUint32)
				break;

			AssumedBytePropertyEntry += 0x1;
		}

		uint16 BytePropertyHeader = *reinterpret_cast<const uint16*>(AssumedBytePropertyEntry + Off::FNameEntry::NamePool::HeaderOffset);

		/* Shifiting past the size of the header is not allowed, so limmit the shiftcount here */
		constexpr int32 MaxAllowedShiftCount = sizeof(BytePropertyHeader) * 0x8;

		while (BytePropertyHeader != BytePropertyStrLen && FNameEntryLengthShiftCount < MaxAllowedShiftCount)
		{			
			FNameEntryLengthShiftCount++;
			BytePropertyHeader >>= 1;
		}

		if (FNameEntryLengthShiftCount == MaxAllowedShiftCount)
		{
			std::cerr << "\nDumper-7: Error, couldn't get FNameEntryLengthShiftCount!\n" << std::endl;
			GetStr = [](uint8* NameEntry) -> std::wstring { return L"Invalid FNameEntryLengthShiftCount!"; };
			return;
		}

		GetStr = [](uint8* NameEntry) -> std::wstring
		{
			const uint16 HeaderWithoutNumber = *reinterpret_cast<uint16*>(NameEntry + Off::FNameEntry::NamePool::HeaderOffset);
			const int32 NameLen = HeaderWithoutNumber >> FNameEntry::FNameEntryLengthShiftCount;

			if (NameLen == 0)
			{
				const int32 EntryIdOffset = Off::FNameEntry::NamePool::StringOffset + ((Off::FNameEntry::NamePool::StringOffset == 6) * 2);

				const int32 NextEntryIndex = *reinterpret_cast<int32*>(NameEntry + EntryIdOffset);
				const int32 Number = *reinterpret_cast<int32*>(NameEntry + EntryIdOffset + sizeof(int32));

				if (Number > 0)
					return NameArray::GetNameEntry(NextEntryIndex).GetWString() + L'_' + std::to_wstring(Number - 1);

				return NameArray::GetNameEntry(NextEntryIndex).GetWString();
			}

			if (HeaderWithoutNumber & NameWideMask)
				return std::wstring(reinterpret_cast<const wchar_t*>(NameEntry + Off::FNameEntry::NamePool::StringOffset), NameLen);

			return UtfN::StringToWString(std::string(reinterpret_cast<const char*>(NameEntry + Off::FNameEntry::NamePool::StringOffset), NameLen));
		};
	}
	else
	{
		const uint8_t* FNameEntryNone =     static_cast<uint8_t*>(NameArray::GetNameEntry(0x0).GetAddress());
		const uint8_t* FNameEntryIdxThree = static_cast<uint8_t*>(NameArray::GetNameEntry(0x3).GetAddress());
		const uint8_t* FNameEntryIdxEight = static_cast<uint8_t*>(NameArray::GetNameEntry(0x8).GetAddress());

		for (int i = 0; i < 0x20; i++)
		{
			if (*reinterpret_cast<const uint32*>(FNameEntryNone + i) == 'enoN') // None
			{
				Off::FNameEntry::NameArray::StringOffset = i;
				break;
			}
		}

		for (int i = 0; i < 0x20; i++)
		{
			// lowest bit is bIsWide mask, shift right by 1 to get the index
			if ((*reinterpret_cast<const uint32*>(FNameEntryIdxThree + i) >> 1) == 0x3 &&
				(*reinterpret_cast<const uint32*>(FNameEntryIdxEight + i) >> 1) == 0x8)
			{
				Off::FNameEntry::NameArray::IndexOffset = i;
				break;
			}
		}

		GetStr = [](uint8* NameEntry) -> std::wstring
		{
			const int32 NameIdx = *reinterpret_cast<int32*>(NameEntry + Off::FNameEntry::NameArray::IndexOffset);
			const void* NameString = reinterpret_cast<void*>(NameEntry + Off::FNameEntry::NameArray::StringOffset);

			if (NameIdx & NameWideMask)
				return std::wstring(reinterpret_cast<const wchar_t*>(NameString));

			return UtfN::StringToWString<std::string>(reinterpret_cast<const char*>(NameString));
		};
	}
}

bool NameArray::InitializeNameArray(uint8_t* NameArray)
{
	int32 ValidPtrCount = 0x0;
	int32 ZeroQWordCount = 0x0;

	int32 PerChunk = 0x0;

	if (!NameArray || Platform::IsBadReadPtr(NameArray))
		return false;

	for (int i = 0; i < 0x800; i += sizeof(void*))
	{
		uint8_t* SomePtr = *reinterpret_cast<uint8_t**>(NameArray + i);

		if (SomePtr == 0)
		{
			ZeroQWordCount++;
		}
		else if (ZeroQWordCount == 0x0 && SomePtr != nullptr)
		{
			ValidPtrCount++;
		}
		else if (ZeroQWordCount > 0 && SomePtr != 0)
		{
			int32 NumElements = *reinterpret_cast<int32_t*>(NameArray + i);
			int32 NumChunks = *reinterpret_cast<int32_t*>(NameArray + i + 4);

			if (NumChunks == ValidPtrCount)
			{
				Off::NameArray::NumElements = i;
				Off::NameArray::MaxChunkIndex = i + 4;

				ByIndex = [](void* NamesArray, int32 ComparisonIndex, int32 NamePoolBlockOffsetBits) -> void*
				{
					const int32 ChunkIdx = ComparisonIndex / 0x4000;
					const int32 InChunk = ComparisonIndex % 0x4000;

					if (ComparisonIndex > NameArray::GetNumElements())
						return nullptr;

					return reinterpret_cast<void***>(NamesArray)[ChunkIdx][InChunk];
				};

				return true;
			}
		}
	}

	return false;
}

bool NameArray::InitializeNamePool(uint8_t* NamePool)
{
	Off::NameArray::MaxChunkIndex = 0x0;
	Off::NameArray::ByteCursor = 0x4;

	Off::NameArray::ChunksStart = 0x10;

	bool bWasMaxChunkIndexFound = false;

	for (int i = 0x0; i < 0x20; i += 4)
	{
		const int32 PossibleMaxChunkIdx = TargetMemory::Read<int32>(NamePool + i);

		if (PossibleMaxChunkIdx <= 0 || PossibleMaxChunkIdx > 0x10000)
			continue;

		int32 NotNullptrCount = 0x0;
		bool bFoundFirstPtr = false;

		/* Number of invalid pointers we can encounter before we assume that there are no valid pointers anymore. */
		constexpr int32 MaxAllowedNumInvalidPtrs = 0x500;
		int32 NumPtrsSinceLastValid = 0x0;

		for (int j = 0x0; j < 0x10000; j += 8)
		{
			const int32 ChunkOffset = i + 8 + j + (i % 8);

			if (TargetMemory::Read<uint8_t*>(NamePool + ChunkOffset) != nullptr)
			{
				NotNullptrCount++;
				NumPtrsSinceLastValid = 0;

				if (!bFoundFirstPtr)
				{
					bFoundFirstPtr = true;
					Off::NameArray::ChunksStart = i + 8 + j + (i % 8);
				}
			}
			else
			{
				NumPtrsSinceLastValid++;

				/* The last time we've seen a non-nullptr value was 0x500 iterations ago. It's safe to say we wont find any more. */
				if (NumPtrsSinceLastValid == MaxAllowedNumInvalidPtrs)
					break;
			}
		}

		if (PossibleMaxChunkIdx == (NotNullptrCount - 1))
		{
			Off::NameArray::MaxChunkIndex = i;
			Off::NameArray::ByteCursor = i + 4;
			bWasMaxChunkIndexFound = true;
			break;
		}
	}

	if (!bWasMaxChunkIndexFound)
		return false;

	constexpr uint64 CoreUObjAsUint64 = 0x6A624F5565726F43; // little endian "jbOUeroC" ["/Script/CoreUObject"]
	constexpr uint32 NoneAsUint32 = 0x656E6F4E; // little endian "None"

	uint8_t** ChunkPtr = reinterpret_cast<uint8_t**>(NamePool + Off::NameArray::ChunksStart);

	// "/Script/CoreUObject"
	bool bFoundCoreUObjectString = false;
	int64 FNameEntryHeaderSize = 0x0;

	constexpr int32 LoopLimit = 0x1000;

	for (int i = 0; i < LoopLimit; i++)
	{
		if (TargetMemory::Read<uint32>(TargetMemory::Read<uint8_t*>(ChunkPtr) + i) == NoneAsUint32 && FNameEntryHeaderSize == 0)
		{
			FNameEntryHeaderSize = i;
		}
		else if (TargetMemory::Read<uint64>(TargetMemory::Read<uint8_t*>(ChunkPtr) + i) == CoreUObjAsUint64)
		{
			bFoundCoreUObjectString = true;
			break;
		}
	}

	if (!bFoundCoreUObjectString)
		return false;

	NameEntryStride = FNameEntryHeaderSize == 2 ? 2 : 4;
	Off::InSDK::NameArray::FNameEntryStride = NameEntryStride;

	ByIndex = [](void* NamesArray, int32 ComparisonIndex, int32 NamePoolBlockOffsetBits) -> void*
	{
		const int32 ChunkIdx = ComparisonIndex >> NamePoolBlockOffsetBits;
		const int32 InChunkOffset = (ComparisonIndex & ((1 << NamePoolBlockOffsetBits) - 1)) * NameEntryStride;

		const bool bIsBeyondLastChunk = ChunkIdx == NameArray::GetNumChunks() && InChunkOffset > NameArray::GetByteCursor();

		if (ChunkIdx < 0 || ChunkIdx > GetNumChunks() || bIsBeyondLastChunk)
			return nullptr;

		uint8_t* ChunkPtr = reinterpret_cast<uint8_t*>(NamesArray) + Off::NameArray::ChunksStart;

		return TargetMemory::Read<uint8_t*>(ChunkPtr + sizeof(void*) * ChunkIdx) + InChunkOffset;
	};

	Settings::Internal::bUseNamePool = true;
	FNameEntry::Init(reinterpret_cast<uint8*>(ChunkPtr), FNameEntryHeaderSize);

	return true;
}


/* 
 * Finds a call to FName::GetNames, OR a reference to GNames directly, if the call has been inlined
 * 
 * returns { GetNames/GNames, bIsGNamesDirectly };
*/
inline std::pair<uintptr_t, bool> FindFNameGetNamesOrGNames_Windows(const uintptr_t EnterCriticalSectionAddress, const uintptr_t StartAddress)
{
#ifdef PLATFORM_WINDOWS

	/* 2 bytes operation + 4 bytes relative offset */
	constexpr int32 ASMRelativeCallSizeBytes = 0x6;

	/* Range from "ByteProperty" which we want to search upwards for "GetNames" call */
	constexpr int32 GetNamesCallSearchRange = 0x150;

	/* Find a reference to the string "ByteProperty" in 'FName::StaticInit' */
	const uint8* BytePropertyStringAddress = static_cast<uint8*>(Platform::FindByStringInAllSections(L"ByteProperty", StartAddress, 0x0, Settings::General::bSearchOnlyExecutableSectionsForStrings));

	/* Important to prevent infinite-recursion */
	if (!BytePropertyStringAddress)
		return { 0x0, false };

	for (int i = 0; i < GetNamesCallSearchRange; i++)
	{
		/* Check upwards (yes negative indexing) for a relative call opcode */
		if (BytePropertyStringAddress[-i] != 0xFF)
			continue;

#if defined(_WIN64)
		const uintptr_t CallTarget = Architecture_x86_64::Resolve32BitSectionRelativeCall(reinterpret_cast<uintptr_t>(BytePropertyStringAddress - i));
#elif defined(_WIN32)
		uintptr_t CallTarget = Architecture_x86_64::Resolve32bitAbsoluteCall(reinterpret_cast<uintptr_t>(BytePropertyStringAddress - i));
#endif

		if (CallTarget != EnterCriticalSectionAddress)
			continue;

		const uintptr_t InstructionAfterCall = reinterpret_cast<uintptr_t>(BytePropertyStringAddress - (i - ASMRelativeCallSizeBytes));
		
		/* Check if we're dealing with a 'call' opcode */
		if (*reinterpret_cast<const uint8*>(InstructionAfterCall) == 0xE8)
			return { Architecture_x86_64::Resolve32BitRelativeCall(InstructionAfterCall), false };

		// Looks like on 32bit like literally everything is absolute???? fuck you
#if defined(_WIN64)
		return { Architecture_x86_64::Resolve32BitRelativeMove(InstructionAfterCall), true };
#elif defined(_WIN32)
		return { Architecture_x86_64::Resolve32bitAbsoluteMove(InstructionAfterCall), true };
#endif
	}

	/* Continue and search for another reference to "ByteProperty", safe because we're checking if another string-ref was found*/
	return FindFNameGetNamesOrGNames_Windows(EnterCriticalSectionAddress, reinterpret_cast<uintptr_t>(BytePropertyStringAddress) + ASMRelativeCallSizeBytes);

#endif // PLATFORM_WINDOWS
};

bool NameArray::TryFindNameArray_Windows()
{
#ifdef PLATFORM_WINDOWS

	/* Type of 'static TNameEntryArray& FName::GetNames()' */
	using GetNameType = void* (*)();

	/* Range from 'FName::GetNames' which we want to search down for 'mov register, GNames' */
	constexpr int32 GetNamesCallSearchRange = 0x100;

	const void* EnterCriticalSectionAddress = Platform::GetAddressOfImportedFunctionFromAnyModule("kernel32.dll", "EnterCriticalSection");

	auto [Address, bIsGNamesDirectly] = FindFNameGetNamesOrGNames_Windows(reinterpret_cast<uintptr_t>(EnterCriticalSectionAddress), Platform::GetModuleBase());

	if (Address == 0x0)
		return false;

	if (bIsGNamesDirectly)
	{
		if (!Platform::IsAddressInProcessRange(Address) || Platform::IsBadReadPtr(*reinterpret_cast<void**>(Address)))
			return false;

		Off::InSDK::NameArray::GNames = Platform::GetOffset(Address);
		return true;
	}

	// TODO (encryqed): Fix below for 32-bit ue shit 

	/* Call GetNames to retreive the pointer to the allocation of the name-table, used for later comparison */
	void* Names = reinterpret_cast<GetNameType>(Address)();

	for (int i = 0; i < GetNamesCallSearchRange; i++)
	{
		/* Check upwards (yes negative indexing) for a relative call opcode */
		if (*reinterpret_cast<const uint16*>(Address + i) != 0x8B48)
			continue;

		const uintptr_t MoveTarget = Architecture_x86_64::Resolve32BitRelativeMove(Address + i);

		if (!Platform::IsAddressInProcessRange(MoveTarget))
			continue;

		const void* ValueOfMoveTargetAsPtr = *reinterpret_cast<void**>(MoveTarget);

		if (Platform::IsBadReadPtr(ValueOfMoveTargetAsPtr) || ValueOfMoveTargetAsPtr != Names)
			continue;

		Off::InSDK::NameArray::GNames = Platform::GetOffset(MoveTarget);
		return true;
	}
	
	return false;

#endif // PLATFORM_WINDOWS
}

bool NameArray::TryFindNamePool_Windows()
{
#ifdef PLATFORM_WINDOWS

	// TODO (encryqed): Fix this below for 32-bit ue games ig?

	/* Number of bytes we want to search for an indirect call to InitializeSRWLock */
	constexpr int32 InitSRWLockSearchRange = 0x50;

	/* Number of bytes we want to search for lea instruction loading the string "ByteProperty" */
	constexpr int32 BytePropertySearchRange = 0x2A0;

	/* FNamePool::FNamePool contains a call to InitializeSRWLock or RtlInitializeSRWLock, we're going to check for that later */
	const uintptr_t InitSRWLockAddress = reinterpret_cast<uintptr_t>(Platform::GetAddressOfImportedFunctionFromAnyModule("kernel32.dll", "InitializeSRWLock"));
	const uintptr_t RtlInitSRWLockAddress = reinterpret_cast<uintptr_t>(Platform::GetAddressOfImportedFunctionFromAnyModule("ntdll.dll", "RtlInitializeSRWLock"));

	/* Singleton instance of FNamePool, which is passed as a parameter to FNamePool::FNamePool */
	void* NamePoolIntance = nullptr;

	uintptr_t SigOccurrence = 0x0;;

	uintptr_t Counter = 0x0;

	while (!NamePoolIntance)
	{
		/* add 0x1 so we don't find the same occurence again and cause an infinite loop (20min. of debugging for that) */
		if (SigOccurrence > 0x0)
			SigOccurrence += 0x1;

		/* Find the next occurence of this signature to see if that may be a call to the FNamePool constructor */
		SigOccurrence = reinterpret_cast<uintptr_t>(Platform::FindPattern("48 8D 0D ? ? ? ? E8", 0x0, true, SigOccurrence));

		if (SigOccurrence == 0x0)
			break;

		constexpr int32 SizeOfMovInstructionBytes = 0x7;

		const uintptr_t PossibleConstructorAddress = Architecture_x86_64::Resolve32BitRelativeCall(SigOccurrence + SizeOfMovInstructionBytes);

		if (!Platform::IsAddressInProcessRange(PossibleConstructorAddress))
			continue;

		for (int i = 0; i < InitSRWLockSearchRange; i++)
		{
			/* Check for a relative call with the opcodes FF 15 00 00 00 00 */
			if (*reinterpret_cast<uint16*>(PossibleConstructorAddress + i) != 0x15FF)
				continue;

			const uintptr_t RelativeCallTarget = Architecture_x86_64::Resolve32BitSectionRelativeCall(PossibleConstructorAddress + i);

			if (!Platform::IsAddressInProcessRange(RelativeCallTarget))
				continue;

			const uintptr_t ValueOfCallTarget = *reinterpret_cast<uintptr_t*>(RelativeCallTarget);

			if (ValueOfCallTarget != InitSRWLockAddress && ValueOfCallTarget != RtlInitSRWLockAddress)
				continue;

			/* Try to find the "ByteProperty" string, as it's always referenced in FNamePool::FNamePool, so we use it to verify that we got the right function */
			const void* StringRef = Platform::FindByStringInAllSections(L"ByteProperty", PossibleConstructorAddress, BytePropertySearchRange, Settings::General::bSearchOnlyExecutableSectionsForStrings);

			/* We couldn't find a wchar_t string L"ByteProperty", now see if we can find a char string "ByteProperty" */
			if (StringRef == nullptr)
				StringRef = Platform::FindByStringInAllSections("ByteProperty", PossibleConstructorAddress, BytePropertySearchRange, Settings::General::bSearchOnlyExecutableSectionsForStrings);

			if (StringRef)
			{
				NamePoolIntance = reinterpret_cast<void*>(Architecture_x86_64::Resolve32BitRelativeMove(SigOccurrence));
				break;
			}
		}
	}

	if (NamePoolIntance)
	{
		Off::InSDK::NameArray::GNames = Platform::GetOffset(NamePoolIntance);
		return true;
	}

	return false;

#endif // PLATFORM_WINDOWS
}

bool NameArray::TryFindNameArray_Linux()
{
	return false;
}

bool NameArray::TryFindNamePool_Linux()
{
	return false;
}

bool NameArray::InitLinux(uintptr_t Address, int32, int32)
{
    if (!Address || !PlatformLinux::IsAddressInProcessRange(Address)) return false;
    GNames = reinterpret_cast<uint8*>(Address);
    FNameBlockOffsetBits = 0x10;
    Off::InSDK::NameArray::FNamePoolBlockOffsetBits = FNameBlockOffsetBits;
    // Run the original initializer, now using external value reads. In
    // particular, do not invent MaxChunkIndex/ByteCursor from ChunksStart.
    return InitializeNamePool(GNames);
}

bool NameArray::TryInit(bool bIsTestOnly)
{
	const uintptr_t ImageBase = Platform::GetModuleBase();

	uint8* GNamesAddress = nullptr;

	bool bFoundNameArray = false;
	bool bFoundnamePool = false;

	if (CALL_PLATFORM_SPECIFIC_FUNCTION(NameArray::TryFindNameArray))
	{
		std::cerr << std::format("Found 'TNameEntryArray GNames' at offset 0x{:X}\n", Off::InSDK::NameArray::GNames) << std::endl;
		GNamesAddress = *reinterpret_cast<uint8**>(ImageBase + Off::InSDK::NameArray::GNames);// Derefernce
		Settings::Internal::bUseNamePool = false;
		bFoundNameArray = true;
	}
	else if (CALL_PLATFORM_SPECIFIC_FUNCTION(NameArray::TryFindNamePool))
	{
		std::cerr << std::format("Found 'FNamePool GNames' at offset 0x{:X}\n", Off::InSDK::NameArray::GNames) << std::endl;
		GNamesAddress = reinterpret_cast<uint8*>(ImageBase + Off::InSDK::NameArray::GNames); // No derefernce
		Settings::Internal::bUseNamePool = true;
		bFoundnamePool = true;
	}

	if (!bFoundNameArray && !bFoundnamePool)
	{
		std::cerr << "\n\nCould not find GNames!\n\n" << std::endl;
		return false;
	}

	if (bIsTestOnly)
		return false;

	if (bFoundNameArray && NameArray::InitializeNameArray(GNamesAddress))
	{
		GNames = GNamesAddress;
		Settings::Internal::bUseNamePool = false;
		FNameEntry::Init();
		return true;
	}
	else if (bFoundnamePool && NameArray::InitializeNamePool(reinterpret_cast<uint8_t*>(GNamesAddress)))
	{
		GNames = GNamesAddress;
		Settings::Internal::bUseNamePool = true;
		/* FNameEntry::Init() was moved into NameArray::InitializeNamePool to avoid duplicated logic */
		return true;
	}

	std::cerr << "The address that was found couldn't be used by the generator, this might be due to GNames-encryption.\n" << std::endl;

	return false;
}


bool NameArray::TryInit(int32 OffsetOverride, bool bIsNamePool, const char* const ModuleName)
{
	const uintptr_t ImageBase = Platform::GetModuleBase(ModuleName);

	uint8* GNamesAddress = nullptr;

	const bool bIsNameArrayOverride = !bIsNamePool;
	const bool bIsNamePoolOverride = bIsNamePool;

	bool bFoundNameArray = false;
	bool bFoundnamePool = false;

	Off::InSDK::NameArray::GNames = OffsetOverride;

	if (bIsNameArrayOverride)
	{
		std::cerr << std::format("Overwrote offset: 'TNameEntryArray GNames' set as offset 0x{:X}\n", Off::InSDK::NameArray::GNames) << std::endl;
		GNamesAddress = *reinterpret_cast<uint8**>(ImageBase + Off::InSDK::NameArray::GNames);// Derefernce
		Settings::Internal::bUseNamePool = false;
		bFoundNameArray = true;
	}
	else if (bIsNamePoolOverride)
	{
		std::cerr << std::format("Overwrote offset: 'FNamePool GNames' set as offset 0x{:X}\n", Off::InSDK::NameArray::GNames) << std::endl;
		GNamesAddress = reinterpret_cast<uint8*>(ImageBase + Off::InSDK::NameArray::GNames); // No derefernce
		Settings::Internal::bUseNamePool = true;
		bFoundnamePool = true;
	}

	if (!bFoundNameArray && !bFoundnamePool)
	{
		std::cerr << "\n\nCould not find GNames!\n\n" << std::endl;
		return false;
	}

	if (bFoundNameArray && NameArray::InitializeNameArray(GNamesAddress))
	{
		GNames = GNamesAddress;
		Settings::Internal::bUseNamePool = false;
		FNameEntry::Init();
		return true;
	}
	else if (bFoundnamePool && NameArray::InitializeNamePool(reinterpret_cast<uint8_t*>(GNamesAddress)))
	{
		GNames = GNamesAddress;
		Settings::Internal::bUseNamePool = true;
		/* FNameEntry::Init() was moved into NameArray::InitializeNamePool to avoid duplicated logic */
		return true;
	}

	std::cerr << "The address was overwritten, but couldn't be used. This might be due to GNames-encryption.\n" << std::endl;

	return false;
}

bool NameArray::SetGNamesWithoutCommitting()
{
	/* GNames is already set */
	if (Off::InSDK::NameArray::GNames != 0x0)
		return false;

	if (CALL_PLATFORM_SPECIFIC_FUNCTION(NameArray::TryFindNameArray))
	{
		std::cerr << std::format("Found 'TNameEntryArray GNames' at offset 0x{:X}\n", Off::InSDK::NameArray::GNames) << std::endl;
		Settings::Internal::bUseNamePool = false;
		return true;
	}
	else if (CALL_PLATFORM_SPECIFIC_FUNCTION(NameArray::TryFindNamePool))
	{
		std::cerr << std::format("Found 'FNamePool GNames' at offset 0x{:X}\n", Off::InSDK::NameArray::GNames) << std::endl;
		Settings::Internal::bUseNamePool = true;
		return true;
	}

	std::cerr << "\n\nCould not find GNames!\n\n" << std::endl;
	return false;
}

void NameArray::PostInit()
{
	if (GNames && Settings::Internal::bUseNamePool)
	{
		// Reverse-order iteration because newer objects are more likely to have a chunk-index equal to NumChunks - 1
		
		NameArray::FNameBlockOffsetBits = 0xE;

		int i = ObjectArray::Num();
		while (i >= 0)
		{
			const int32 CurrentBlock = NameArray::GetNumChunks();

			UEObject Obj = ObjectArray::GetByIndex(i);

			if (!Obj)
			{
				i--;
				continue;
			}

			const int32 ObjNameChunkIdx = Obj.GetFName().GetCompIdx() >> NameArray::FNameBlockOffsetBits;

			if (ObjNameChunkIdx == CurrentBlock)
				break;

			if (ObjNameChunkIdx > CurrentBlock)
			{
				NameArray::FNameBlockOffsetBits++;
				i = ObjectArray::Num();
			}

			i--;
		}
		Off::InSDK::NameArray::FNamePoolBlockOffsetBits = NameArray::FNameBlockOffsetBits;

		std::cerr << "NameArray::FNameBlockOffsetBits: 0x" << std::hex << NameArray::FNameBlockOffsetBits << "\n" << std::endl;
	}
}

int32 NameArray::GetNumChunks()
{
	return TargetMemory::Read<int32>(GNames + Off::NameArray::MaxChunkIndex);
}

int32 NameArray::GetNumElements()
{
	return !Settings::Internal::bUseNamePool ? *reinterpret_cast<int32*>(GNames + Off::NameArray::NumElements) : 0;
}

int32 NameArray::GetByteCursor()
{
	return Settings::Internal::bUseNamePool ? TargetMemory::Read<int32>(GNames + Off::NameArray::ByteCursor) : 0;
}

FNameEntry NameArray::GetNameEntry(const void* Name)
{
	return ByIndex(GNames, FName(Name).GetCompIdx(), FNameBlockOffsetBits);
}

FNameEntry NameArray::GetNameEntry(int32 Idx)
{
	return ByIndex(GNames, Idx, FNameBlockOffsetBits);
}

size_t NameArray::DumpNames(std::ostream& Output)
{
    if (!Settings::Internal::bUseNamePool) throw std::runtime_error("External name dump requires FNamePool");
    const int32 last = GetNumChunks();
    const int32 used = GetByteCursor();
    if (last < 0 || last >= 8192 || FNameBlockOffsetBits > 20 || NameEntryStride <= 0)
        throw std::runtime_error("Invalid name pool bounds");
    const size_t blockSize = size_t(NameEntryStride) << FNameBlockOffsetBits;
    if (used < 0 || size_t(used) > blockSize) throw std::runtime_error("Invalid name pool cursor");
    size_t count = 0;
    for (int32 chunk = 0; chunk <= last; ++chunk) {
        const auto block = TargetMemory::Read<uintptr_t>(GNames + Off::NameArray::ChunksStart + chunk * sizeof(void*));
        const size_t limit = chunk == last ? used : blockSize;
        for (size_t offset = 0; offset + Off::FNameEntry::NamePool::StringOffset <= limit;) {
            const auto address = block + offset;
            const auto header = TargetMemory::Read<uint16>(address + Off::FNameEntry::NamePool::HeaderOffset);
            const size_t length = header >> FNameEntry::FNameEntryLengthShiftCount;
            size_t entrySize = Off::FNameEntry::NamePool::StringOffset + length * ((header & 1) ? 2 : 1);
            if (!length) {
                const size_t idOffset = Off::FNameEntry::NamePool::StringOffset +
                    ((Off::FNameEntry::NamePool::StringOffset == 6) * 2);
                if (offset + idOffset + 8 > limit || TargetMemory::Read<uint64>(address + idOffset) == 0) break;
                entrySize = idOffset + 8;
            }
            if (length > 1024 || offset + entrySize > limit) break;
            const uint32 id = (uint32(chunk) << FNameBlockOffsetBits) | (offset / NameEntryStride);
            Output << id << '\t' << GetNameEntry(static_cast<int32>(id)).GetString() << '\n';
            ++count;
            offset += (entrySize + NameEntryStride - 1) / NameEntryStride * NameEntryStride;
        }
    }
    if (!Output) throw std::runtime_error("Unable to write names dump");
    return count;
}
