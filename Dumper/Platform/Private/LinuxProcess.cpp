#include "LinuxProcess.h"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <cstring>
#include <fstream>
#include <limits>
#include <poll.h>
#include <sstream>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

namespace LinuxInspection {
namespace {
bool Hex(const std::string& text, uintptr_t& value)
{
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

bool ParseMap(const std::string& line, Mapping& map)
{
    std::istringstream stream(line);
    std::string range, permissions, offset, device, inode;
    if (!(stream >> range >> permissions >> offset >> device >> inode)) return false;
    const auto dash = range.find('-');
    if (dash == std::string::npos || permissions.size() != 4 ||
        !Hex(range.substr(0, dash), map.start) || !Hex(range.substr(dash + 1), map.end) ||
        !Hex(offset, map.offset) || map.start >= map.end) return false;
    std::getline(stream, map.path);
    map.path.erase(0, map.path.find_first_not_of(' '));
    map.read = permissions[0] == 'r';
    return true;
}

std::string Lower(std::string value)
{
    for (auto& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}
}

Process::~Process() { Detach(); }

void Process::Detach()
{
    if (pidfd_ >= 0) close(pidfd_);
    pidfd_ = -1;
    pid_ = -1;
    maps_.clear();
    failure_ = {};
}

bool Process::Attach(int pid)
{
    Detach();
    if (pid <= 0) { failure_.error = EINVAL; return false; }
    // Pin process identity, not just its recyclable numeric PID. Linux >= 5.3.
    pidfd_ = static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
    if (pidfd_ < 0) { failure_.error = errno; return false; }
    pid_ = pid;
    if (RefreshMaps()) return true;
    const auto failure = failure_;
    Detach();
    failure_ = failure;
    return false;
}

bool Process::Alive() const
{
    if (pidfd_ < 0) return false;
    pollfd descriptor{pidfd_, POLLIN, 0};
    int result;
    do { result = poll(&descriptor, 1, 0); } while (result < 0 && errno == EINTR);
    return result == 0;
}

bool Process::RefreshMaps()
{
    maps_.clear();
    if (!Alive()) { failure_.error = ESRCH; return false; }
    errno = 0;
    std::ifstream input("/proc/" + std::to_string(pid_) + "/maps");
    if (!input) { failure_.error = errno ? errno : EACCES; return false; }
    std::vector<Mapping> pending;
    std::string line;
    while (std::getline(input, line)) {
        Mapping map;
        if (!ParseMap(line, map)) { failure_.error = EINVAL; return false; }
        pending.push_back(std::move(map));
    }
    if (input.bad() || pending.empty() || !Alive()) {
        failure_.error = Alive() ? EIO : ESRCH;
        return false;
    }
    maps_ = std::move(pending);
    failure_ = {};
    return true;
}

bool Process::Read(uintptr_t address, void* destination, size_t size)
{
    failure_ = {};
    const auto fail = [&](int error, size_t copied) {
        failure_ = {error, address + copied, copied};
        if (destination && size) std::memset(destination, 0, size);
        return false;
    };
    if (!destination || !size || !address) return fail(EINVAL, 0);
    if (size - 1 > std::numeric_limits<uintptr_t>::max() - address) return fail(EOVERFLOW, 0);
    if (!Alive()) return fail(ESRCH, 0);
    size_t copied = 0;
    while (copied < size) {
        const size_t length = std::min(size - copied, size_t{1024 * 1024});
        iovec local{static_cast<unsigned char*>(destination) + copied, length};
        iovec remote{reinterpret_cast<void*>(address + copied), length};
        ssize_t count;
        do { count = process_vm_readv(pid_, &local, 1, &remote, 1, 0); }
        while (count < 0 && errno == EINTR);
        if (count <= 0) return fail(count < 0 ? errno : EIO, copied);
        copied += static_cast<size_t>(count);
        // Reject data if the original process exited during a syscall, even if
        // the PID was reused. pidfd itself is never used to alter the target.
        if (!Alive()) return fail(ESRCH, copied);
    }
    return true;
}

std::string BaseName(std::string path)
{
    constexpr char deleted[] = " (deleted)";
    if (path.ends_with(deleted)) path.resize(path.size() - (sizeof(deleted) - 1));
    const auto slash = path.find_last_of("/\\");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

bool ModuleMatches(const std::string& path, const std::string& module)
{
    return !path.empty() && !module.empty() && Lower(BaseName(path)) == Lower(BaseName(module));
}

std::string ProcessImage(int pid, const std::string& preferredModule)
{
    const auto root = "/proc/" + std::to_string(pid);
    // A wrapper's argv can mention the game without mapping its PE image.
    // The mapped image is the authoritative answer for process selection.
    std::ifstream maps(root + "/maps");
    std::string line;
    while (std::getline(maps, line)) {
        Mapping map;
        if (!ParseMap(line, map) || !map.read || map.offset != 0) continue;
        if ((!preferredModule.empty() && ModuleMatches(map.path, preferredModule)) ||
            (preferredModule.empty() && Lower(BaseName(map.path)).ends_with(".exe")))
            return BaseName(map.path);
    }
    return {};
}

std::string DiscoverExecutable(int pid)
{
    return ProcessImage(pid, {});
}
} // namespace LinuxInspection
