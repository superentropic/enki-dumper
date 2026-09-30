#include <cstdint>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstdio>
#include <dirent.h>
#include <string>
#include <vector>

#include "Platform.h"
#include "LinuxProcess.h"
#include "LinuxValidation.h"
#include "Settings.h"
#include "Generators/Generator.h"
#include "Generators/CppGenerator.h"
#include "Generators/MappingGenerator.h"
#include "Generators/IDAMappingGenerator.h"
#include "Generators/DumpspaceGenerator.h"
#include "Unreal/NameArray.h"

namespace fs = std::filesystem;

static uintptr_t scan_gobjects(uintptr_t overrideOffset, uintptr_t namePool)
{
    const auto info = PlatformLinux::FindGObjects(namePool);
    if (overrideOffset && info.address != PlatformLinux::GetModuleBase() + overrideOffset) return 0;
    if (info.address) return info.address;
    return 0;
}

static uintptr_t scan_gnames(uintptr_t overrideOffset)
{
    return PlatformLinux::FindGNames(overrideOffset).address;
}

static size_t dump_names(const fs::path& output)
{
    std::ofstream names(output / "names.txt");
    if (!names) throw std::runtime_error("Could not create names.txt");
    return NameArray::DumpNames(names);
}

static void probe_objects(uintptr_t gobjects)
{
    const auto& layout = PlatformLinux::GetLastGObjectsInfo();
    if (layout.address != gobjects) throw std::runtime_error("Object array has not been validated");
    auto items = PlatformLinux::ReadOr<uintptr_t>(gobjects + layout.objectsOffset);
    if (layout.chunked) items = PlatformLinux::ReadOr<uintptr_t>(items);
    std::cerr << "Validated item stride 0x" << std::hex << layout.itemSize
              << ", object pointer +0x" << layout.itemInitialOffset << std::dec << '\n';
    for (int index = 0; index < 16; ++index) {
        const auto object = PlatformLinux::ReadOr<uintptr_t>(items + index * layout.itemSize + layout.itemInitialOffset);
        std::cerr << '[' << index << "] object=0x" << std::hex << object << std::dec << '\n';
    }
}

static void usage(const char* name)
{
    std::cerr << "Usage: " << name << " [--pid PID | --select-process] [--module Game.exe] [--inspect-only | --output /absolute/path [--names 0xOFFSET] [--objects 0xOFFSET] [--skip-name-dump] [--report-only]]\n";
}

static int select_process(const std::string& module)
{
    std::string command = "zenity --list --title='Select Proton process' --text='Choose the authorized Unreal process' --print-column=1 --column=PID --column=Process";
    const auto quote = [](const std::string& value) {
        std::string result = "'";
        for (char c : value) result += c == '\'' ? "'\\''" : std::string(1, c);
        return result + "'";
    };
    // The UI remains optional; the stable machine-readable process list is used as its input.
    DIR* directory = opendir("/proc");
    if (!directory) return 0;
    while (const dirent* entry = readdir(directory)) {
        if (entry->d_type != DT_DIR || !std::isdigit(entry->d_name[0])) continue;
        const int candidate = std::atoi(entry->d_name);
        const std::string name = LinuxInspection::ProcessImage(candidate, module);
        if (name.empty()) continue;
        command += " " + quote(std::to_string(candidate)) + " " + quote(name);
    }
    closedir(directory);
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return 0;
    char buffer[64]{};
    const bool read = std::fgets(buffer, sizeof(buffer), pipe) != nullptr;
    pclose(pipe);
    return read ? std::atoi(buffer) : 0;
}

int main(int argc, char** argv) try {
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    int pid = 0;
    std::string module;
    fs::path output;
    uintptr_t namesOffset = 0;
    uintptr_t objectsOffset = 0;
    bool chooseProcess = false;
    bool generateSdk = true;
    bool inspectOnly = false;
    bool dumpNames = true;
    bool probeObjects = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help") { usage(argv[0]); return 0; }
        else if (arg == "--pid" && i + 1 < argc) pid = std::stoi(argv[++i]);
        else if (arg == "--select-process") chooseProcess = true;
        else if (arg == "--report-only") generateSdk = false;
        else if (arg == "--inspect-only") inspectOnly = true;
        else if (arg == "--skip-name-dump") dumpNames = false;
        else if (arg == "--probe-objects") probeObjects = true;
        else if (arg == "--module" && i + 1 < argc) module = argv[++i];
        else if (arg == "--output" && i + 1 < argc) output = fs::path(argv[++i]);
        else if (arg == "--names" && i + 1 < argc) namesOffset = std::stoull(argv[++i], nullptr, 0);
        else if (arg == "--objects" && i + 1 < argc) objectsOffset = std::stoull(argv[++i], nullptr, 0);
        else { usage(argv[0]); return 2; }
    }
    if (!pid && chooseProcess) pid = select_process(module);
    if (pid > 0 && module.empty()) module = LinuxInspection::DiscoverExecutable(pid);
    if (module.empty()) {
        std::cerr << "Could not find a mapped Windows .exe. Use --module Game.exe to choose one.\n";
        return 1;
    }
    if (pid <= 0 || (!inspectOnly && (output.empty() || !output.is_absolute()))) { usage(argv[0]); return 2; }
    if (!PlatformLinux::Initialize(pid, module)) {
        std::cerr << "Unable to attach/read " << module << " in PID " << pid << ": " << PlatformLinux::GetInitializationError() << ".\n";
        return 1;
    }
    std::cout << "Attached to PID " << pid << ", " << module << " at 0x" << std::hex << PlatformLinux::GetModuleBase() << std::dec << "\n";
    if (inspectOnly) {
        for (const auto& section : PlatformLinux::GetRemoteSections())
            std::cout << "PE section 0x" << std::hex << section.Start << " + 0x" << section.Size << std::dec << '\n';
        std::cout << "Read-only process/header inspection completed; no scanner or SDK generator was run.\n";
        return 0;
    }
    std::error_code ec;
    fs::create_directories(output, ec);
    if (ec) { std::cerr << "Could not create output directory: " << ec.message() << "\n"; return 1; }
    const uintptr_t gnamesAddress = scan_gnames(namesOffset);
    const uintptr_t gobjectsAddress = scan_gobjects(objectsOffset, gnamesAddress);
    std::ofstream report(output / "dumper7-linux-offsets.json");
    if (!report) throw std::runtime_error("Could not create offsets report");
    report << "{\n  \"module\": \"" << module << "\",\n  \"pid\": " << pid
           << ",\n  \"gobjects\": \"0x" << std::hex << PlatformLinux::GetOffset(gobjectsAddress)
           << "\",\n  \"gnames\": \"0x" << PlatformLinux::GetOffset(gnamesAddress) << "\"\n}\n";
    report.close();
    if (!gobjectsAddress || !gnamesAddress) {
        std::cerr << "Automatic scan did not find both TUObjectArray and a supported FNamePool.\n";
        return 1;
    }
    if (probeObjects) {
        probe_objects(gobjectsAddress);
        return 0;
    }
    Off::InSDK::ObjArray::GObjects = static_cast<int32>(PlatformLinux::GetOffset(gobjectsAddress));
    std::cout << "TUObjectArray found at module offset 0x" << std::hex << PlatformLinux::GetOffset(gobjectsAddress) << std::dec << "\n";
    std::cout << "FNamePool candidate at module offset 0x" << std::hex << PlatformLinux::GetOffset(gnamesAddress) << std::dec << "\n";
    Off::InSDK::NameArray::GNames = static_cast<int32>(PlatformLinux::GetOffset(gnamesAddress));
    Settings::Generator::SDKGenerationPath = output.string();
    Settings::Generator::GameName = module;
    Settings::Generator::GameVersion = "external-linux";
    Generator::InitEngineCore();
    if (dumpNames) std::cout << "Wrote " << dump_names(output) << " decoded name entries\n";
    if (generateSdk) {
        auto validation = ValidateLinuxReflection();
        std::ofstream(output / "reflection-validation.json") << validation.dump(2) << '\n';
        std::cerr << "[validation] 2048 object indices and required reflected properties passed\n";
        std::cerr << "[linux] InitInternal\n";
        Generator::InitInternal();
        std::cerr << "[linux] Generate Cpp\n";
        if (!Generator::Generate<CppGenerator>() || !Generator::Generate<MappingGenerator>() ||
            !Generator::Generate<IDAMappingGenerator>() || !Generator::Generate<DumpspaceGenerator>())
            throw std::runtime_error("Could not create generator output folders");
        for (const auto& folder : {CppGenerator::MainFolder, MappingGenerator::MainFolder,
                                   IDAMappingGenerator::MainFolder, DumpspaceGenerator::MainFolder}) {
            size_t files = 0;
            for (const auto& entry : fs::recursive_directory_iterator(folder)) {
                if (!entry.is_regular_file()) continue;
                if (entry.file_size() == 0) throw std::runtime_error("Empty generated file: " + entry.path().string());
                ++files;
            }
            if (!files) throw std::runtime_error("Empty generator output folder: " + folder.string());
        }
        validation["sdk_generation"] = "completed";
        std::ofstream(output / "reflection-validation.json") << validation.dump(2) << '\n';
    }
    std::cout << "Wrote " << (output / "dumper7-linux-offsets.json") << "\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "Dumper failed: " << error.what() << '\n';
    return 1;
}
