#include "LinuxProcess.h"
#include "PlatformLinux.h"

#include <array>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {
void Check(bool value, const char* description)
{
    if (!value) throw std::runtime_error(description);
}

struct Child {
    int commands[2]{-1, -1};
    int responses[2]{-1, -1};
    pid_t pid{-1};
    ~Child()
    {
        // Closing the parent's command pipe releases the child even after a
        // failing test. Never signal or modify any unrelated process.
        for (int fd : commands) if (fd >= 0) close(fd);
        for (int fd : responses) if (fd >= 0) close(fd);
        if (pid > 0) waitpid(pid, nullptr, 0);
    }
};

template<class T> void Put(unsigned char* image, size_t offset, T value)
{
    std::memcpy(image + offset, &value, sizeof(value));
}
}

int main()
try {
    Check(LinuxInspection::ModuleMatches("s:\\games\\TestUE.EXE", "testue.exe"), "Windows basename/case matching");
    Check(LinuxInspection::ModuleMatches("/games/Test UE.exe (deleted)", "Test UE.exe"), "mapped pathname with spaces");
    Check(!LinuxInspection::ModuleMatches("/games/TestUE.exe.bak", "TestUE.exe"), "reject substring module match");

    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    Child child;
    Check(pipe(child.commands) == 0 && pipe(child.responses) == 0, "pipes");
    child.pid = fork();
    Check(child.pid >= 0, "fork");
    if (child.pid == 0) {
        close(child.commands[1]);
        close(child.responses[0]);
        auto* memory = static_cast<unsigned char*>(mmap(nullptr, page * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        if (memory == MAP_FAILED) _exit(10);
        std::memset(memory, 0x5A, page * 4);
        if (mprotect(memory + page, page, PROT_NONE) != 0 || munmap(memory + page * 3, page) != 0) _exit(11);

        // A synthetic mapped PE tests Proton-style module inspection without
        // accessing a game. memfd naming is visible in /proc/<pid>/maps.
        const int imageFd = memfd_create("TestUE.exe", 0);
        if (imageFd < 0 || ftruncate(imageFd, page * 2) != 0) _exit(12);
        auto* image = static_cast<unsigned char*>(mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_SHARED, imageFd, 0));
        if (image == MAP_FAILED) _exit(13);
        Put<uint16_t>(image, 0, 0x5A4D);
        Put<int32_t>(image, 60, 0x80);
        Put<uint32_t>(image, 0x80, 0x4550);
        Put<uint16_t>(image, 0x84, 0x8664);
        Put<uint16_t>(image, 0x86, 1);
        Put<uint16_t>(image, 0x94, 0xF0);
        Put<uint16_t>(image, 0x98, 0x20B);
        Put<uint32_t>(image, 0x98 + 56, page * 2);
        Put<uint32_t>(image, 0x98 + 60, page);
        std::memcpy(image + 0x188, ".data", 5);
        Put<uint32_t>(image, 0x188 + 8, page);
        Put<uint32_t>(image, 0x188 + 12, page);
        auto* large = static_cast<unsigned char*>(mmap(nullptr, page * 512, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
        if (large == MAP_FAILED) _exit(15);
        std::memset(large, 0xA7, page * 512);
        const std::array<uintptr_t, 3> addresses{reinterpret_cast<uintptr_t>(memory), reinterpret_cast<uintptr_t>(image), reinterpret_cast<uintptr_t>(large)};
        if (write(child.responses[1], addresses.data(), sizeof(addresses)) != sizeof(addresses)) _exit(14);
        char command;
        while (read(child.commands[0], &command, 1) == 1) {
            if (command == 'x') break;
            if (command == 'm') Put<uint32_t>(image, 0x188 + 8, page * 3);
            if (write(child.responses[1], &command, 1) != 1) break;
        }
        _exit(0);
    }
    close(child.commands[0]); child.commands[0] = -1;
    close(child.responses[1]); child.responses[1] = -1;
    std::array<uintptr_t, 3> addresses{};
    Check(read(child.responses[0], addresses.data(), sizeof(addresses)) == sizeof(addresses), "child fixture ready");
    const uintptr_t remote = addresses[0];
    LinuxInspection::Process process;
    Check(process.Attach(child.pid), "attach child");
    Check(process.Alive() && !process.Maps().empty(), "live process/maps");
    Check(LinuxInspection::ProcessImage(child.pid, "memfd:TestUE.exe") == "memfd:TestUE.exe", "process image map fallback");
    Check(LinuxInspection::ProcessImage(child.pid, "memfd:TestUE.exe") == "memfd:TestUE.exe", "process image exact match");
    Check(LinuxInspection::DiscoverExecutable(child.pid) == "memfd:TestUE.exe", "automatic executable discovery");
    Check(LinuxInspection::ProcessImage(child.pid, "Wrapper.exe").empty(), "wrapper without mapped image rejected");
    std::vector<unsigned char> large(page * 512);
    Check(process.Read(addresses[2], large.data(), large.size()), "multi-chunk read across readable pages");
    for (auto byte : large) Check(byte == 0xA7, "multi-chunk exact bytes");
    std::array<unsigned char, 32> bytes{};
    Check(process.Read(remote + 7, bytes.data(), bytes.size()), "valid remote read");
    for (auto byte : bytes) Check(byte == 0x5A, "exact bytes");
    Check(!process.Read(remote + page - 16, bytes.data(), bytes.size()), "crossing inaccessible page fails");
    Check(process.LastFailure().error == EFAULT && process.LastFailure().transferred == 16, "partial read diagnostic");
    for (auto byte : bytes) Check(byte == 0, "failed read clears entire destination");
    Check(!process.Read(remote + page * 3, bytes.data(), bytes.size()), "unmapped page fails");
    Check(!process.Read(std::numeric_limits<uintptr_t>::max() - 3, bytes.data(), bytes.size()) &&
        process.LastFailure().error == EOVERFLOW, "overflow rejected before syscall");
    Check(!process.Read(0, bytes.data(), bytes.size()), "null target rejected");
    Check(!process.Read(remote, nullptr, bytes.size()), "null local buffer rejected");
    Check(process.Read(remote, bytes.data(), bytes.size()), "reader recovers after failure");

    Check(PlatformLinux::Initialize(child.pid, "memfd:TestUE.exe"), "valid PE image accepted");
    Check(PlatformLinux::GetModuleBase() == addresses[1], "correct image base");
    const auto sections = PlatformLinux::GetRemoteSections();
    Check(sections.size() == 1 && sections[0].Start == addresses[1] + page && sections[0].Size == page, "section bounds");
    Check(!PlatformLinux::Initialize(child.pid, "TestUE"), "wrong module does not match substring");
    Check(PlatformLinux::GetModuleBase() == 0 && PlatformLinux::GetRemoteSections().empty(), "failed init clears old module state");
    char command = 'm';
    Check(write(child.commands[1], &command, 1) == 1 && read(child.responses[0], &command, 1) == 1, "mutate own test fixture");
    Check(!PlatformLinux::Initialize(child.pid, "memfd:TestUE.exe"), "out-of-image section rejected");
    Check(PlatformLinux::GetInitializationError().find("outside SizeOfImage") != std::string::npos, "PE diagnostic");

    command = 'x';
    Check(write(child.commands[1], &command, 1) == 1, "release child");
    int status{};
    Check(waitpid(child.pid, &status, 0) == child.pid && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child exits normally");
    child.pid = -1;
    Check(!process.Alive(), "exit detected by pinned process handle");
    Check(!process.Read(remote, bytes.data(), bytes.size()) && process.LastFailure().error == ESRCH, "read after exit rejected");
    for (auto byte : bytes) Check(byte == 0, "exit failure clears data");
    Check(!process.Attach(-1) && process.Maps().empty(), "invalid reattach discards old state");
    std::cout << "PASS: exact/partial/unmapped/overflow/exit reads, module matching, PE validation\n";
    return 0;
} catch (const std::exception& error) {
    std::cerr << "FAIL: " << error.what() << '\n';
    return 1;
}
