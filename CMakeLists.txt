cmake_minimum_required(VERSION 3.15...4.0)

# Ninja generator does not support platform specification
if(CMAKE_GENERATOR MATCHES "Ninja")
    # Remove all variables related to platform
    unset(CMAKE_GENERATOR_PLATFORM CACHE)
    unset(CMAKE_GENERATOR_PLATFORM)
    unset(CMAKE_VS_PLATFORM_NAME CACHE)
    unset(CMAKE_VS_PLATFORM_NAME)
    message(STATUS "Using Ninja generator - platform specification disabled")
endif()

project(Dumper-7 LANGUAGES CXX C)

include(${CMAKE_SOURCE_DIR}/cmake/Common.cmake)

# Source files - automatic search for all source files
file(GLOB_RECURSE CPP_SOURCES 
    "Dumper/*.cpp"
    "Dumper/*.cxx"
    "Dumper/*.cc"
    "Dumper/*.c"
)

if(NOT WIN32)
    list(FILTER CPP_SOURCES EXCLUDE REGEX "/PlatformWindows\\.cpp$")
    list(FILTER CPP_SOURCES EXCLUDE REGEX "/main\\.cpp$")
    list(APPEND CPP_SOURCES
        "${CMAKE_SOURCE_DIR}/Dumper/Platform/Private/PlatformLinux.cpp"
        "${CMAKE_SOURCE_DIR}/Dumper/SettingsLinux.cpp"
    )
endif()

if(WIN32)
    list(FILTER CPP_SOURCES EXCLUDE REGEX "/(LinuxMain|SettingsLinux|PlatformLinux|LinuxProcess)\\.cpp$")
    add_library(${PROJECT_NAME} SHARED ${CPP_SOURCES})
    set(DUMPER_TARGET ${PROJECT_NAME})
else()
    list(APPEND CPP_SOURCES "${CMAKE_SOURCE_DIR}/Dumper/LinuxMain.cpp")
    add_executable(dumper7-linux ${CPP_SOURCES})
    set(DUMPER_TARGET dumper7-linux)
endif()

target_compile_features(${DUMPER_TARGET} PRIVATE cxx_std_20)

# Include directories
target_include_directories(${DUMPER_TARGET} PRIVATE
# Dumper
    ${CMAKE_SOURCE_DIR}/Dumper

    # Engine
    ${CMAKE_SOURCE_DIR}/Dumper/Engine
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Private
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Private/OffsetFinder
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Private/Unreal

    # Engine Public
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Public
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Public/OffsetFinder
    ${CMAKE_SOURCE_DIR}/Dumper/Engine/Public/Unreal

    # Generator
    ${CMAKE_SOURCE_DIR}/Dumper/Generator
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Private
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Private/Generators
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Private/Managers
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Private/Wrappers

    # Generator Public
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Public
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Public/Generators
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Public/Managers
    ${CMAKE_SOURCE_DIR}/Dumper/Generator/Public/Wrappers

    # Platform
    ${CMAKE_SOURCE_DIR}/Dumper/Platform
    ${CMAKE_SOURCE_DIR}/Dumper/Platform/Private

    # Platform Public
    ${CMAKE_SOURCE_DIR}/Dumper/Platform/Public

    # Utils
    ${CMAKE_SOURCE_DIR}/Dumper/Utils
    ${CMAKE_SOURCE_DIR}/Dumper/Utils/Compression
    ${CMAKE_SOURCE_DIR}/Dumper/Utils/Dumpspace
    ${CMAKE_SOURCE_DIR}/Dumper/Utils/Encoding
    ${CMAKE_SOURCE_DIR}/Dumper/Utils/Json
)

# Compiler definitions
target_compile_definitions(${DUMPER_TARGET} PRIVATE
    $<$<CONFIG:Debug>:_DEBUG>
    $<$<CONFIG:Release>:NDEBUG>
    _CONSOLE
)

# Set Windows subsystem
set_target_properties(${DUMPER_TARGET} PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS ON
    VS_GLOBAL_KEYWORD "Win32Proj"
)

if(NOT WIN32)
    include(CTest)
    if(BUILD_TESTING)
        add_executable(linux-inspection-test
            tests/linux_inspection_test.cpp
            Dumper/Platform/Private/LinuxProcess.cpp
            Dumper/Platform/Private/PlatformLinux.cpp)
        target_compile_features(linux-inspection-test PRIVATE cxx_std_20)
        target_include_directories(linux-inspection-test PRIVATE Dumper Dumper/Engine/Public Dumper/Platform/Private)
        add_test(NAME linux-inspection COMMAND linux-inspection-test)
        set_tests_properties(linux-inspection PROPERTIES TIMEOUT 15)
    endif()
endif()
