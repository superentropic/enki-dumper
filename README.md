# Enki Dumper

Linux external Dumper-7 for Unreal games running with Proton.

It reads the game process without injecting anything. It can find Unreal
objects and names, then create a C++ SDK, mappings, and Dumpspace files.

## Build

```bash
cmake -S . -B build-linux
cmake --build build-linux -j2
```

## Run

```bash
./build-linux/bin/dumper7-linux \
  --select-process \
  --output /absolute/path/to/output
```

The game must be running. The tool finds a mapped Windows `.exe` automatically.
Use `--module Game.exe` if the process has more than one Windows executable.
The output path must be absolute.

This project is for authorized testing only. See [LINUX.md](LINUX.md) for more
information.
