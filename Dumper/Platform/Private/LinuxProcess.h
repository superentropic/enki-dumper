#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace LinuxInspection {

struct Mapping {
    uintptr_t start{}, end{}, offset{};
    std::string path;
    bool read{};
};

struct ReadFailure {
    int error{};
    uintptr_t address{};
    size_t transferred{};
};

// Target addresses are integers, never pointers that this process dereferences.
// Single-threaded owner. No write, injection, or remote execution API.
class Process {
public:
    Process() = default;
    ~Process();
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    bool Attach(int pid);
    void Detach();
    bool Alive() const;
    bool RefreshMaps();
    // Exact read. On failure the complete destination is cleared, including any
    // prefix the kernel copied. The caller must supply a valid local buffer.
    bool Read(uintptr_t address, void* destination, size_t size);
    int Pid() const { return pid_; }
    const std::vector<Mapping>& Maps() const { return maps_; }
    const ReadFailure& LastFailure() const { return failure_; }
private:
    int pid_{-1};
    int pidfd_{-1};
    std::vector<Mapping> maps_;
    ReadFailure failure_{};
};

std::string BaseName(std::string path);
bool ModuleMatches(const std::string& path, const std::string& module);
// Proton's comm/exe often names Wine, whereas a later NUL-separated argv entry
// identifies the Windows image. Maps provide a fallback when argv hides it.
std::string ProcessImage(int pid, const std::string& preferredModule);
// Return the first mapped Windows executable when no module was supplied.
std::string DiscoverExecutable(int pid);

} // namespace LinuxInspection
