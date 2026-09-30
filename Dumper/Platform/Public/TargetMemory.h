#pragma once
#include <cstring>
#include <type_traits>
#include "Platform.h"

// Preserve the upstream value-reading operations while making the address
// space explicit. Values returned here never reference the target directly.
namespace TargetMemory {
template<class T, class Address>
std::remove_cv_t<T> Read(Address address) {
    const auto ptr = const_cast<const void*>(reinterpret_cast<const volatile void*>(address));
#if defined(__linux__)
    std::remove_cv_t<T> value{};
    PlatformLinux::ReadCachedMemory(reinterpret_cast<uintptr_t>(ptr), &value, sizeof(value));
    return value;
#else
    return *reinterpret_cast<const T*>(ptr);
#endif
}
}
