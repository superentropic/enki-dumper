# Dumper-7 external Linux / Proton port

Standalone Linux executable built from this Dumper-7 clone. It reads the Windows
PE and Unreal reflection data of a running Proton process, then runs the original
C++, USMAP, IDA and Dumpspace generators. The research tool and overlay are not
dependencies.

The backend uses `/proc`, `pidfd` and `process_vm_readv`. It has no target-write,
injection, protection-changing or remote-execution interface. Read access must
already be permitted by the kernel; no security settings are changed. Cached
reflection pages are **not an atomic snapshot**. Keep the game running in a
stable scene during a dump; rerun if a level transition invalidates data.

## Build

Requires CMake, C++20 with `<format>` (tested GCC 13), Python 3 for tests, and
optionally Zenity for process selection.

```sh
cd /home/enki/Downloads/dad-research-tool-main/dumper7
cmake -S . -B build-linux -G 'Unix Makefiles'
cmake --build build-linux -j2
```

## Run without known offsets

```sh
/home/enki/Downloads/dad-research-tool-main/dumper7/build-linux/bin/dumper7-linux \
  --select-process \
  --output /home/enki/Downloads/dad-research-tool-main/dumps/my-sdk
```

The picker lists Proton processes with mapped Windows `.exe` images. The tool
automatically uses that executable. Add `--module Game.exe` when a process maps
more than one Windows executable. Attachment verifies that the chosen process
actually maps the selected PE image.
Alternatively use `--pid CURRENT_PID` in place of `--select-process`.

Use a fresh absolute output directory. Existing SDK directories are handled by
the original generator's backup-folder behavior. PIDs change on game restart.

- `--inspect-only`: process/module/PE inspection, no scan or output needed.
- `--report-only`: discover layouts and dump names, without SDK generation.
- `--skip-name-dump`: omit names.txt, not SDK name resolution.
- `--names 0xRVA`, `--objects 0xRVA`: optional diagnostics; not needed for the
  tested target. RVAs are relative to the Windows module base.

## Output and validation

Output includes `dumper7-linux-offsets.json`, `names.txt` (comparison ID and name),
`reflection-validation.json`, and `external-linux-<selected-exe>/` containing
`CppSDK`, `Mappings`, `IDAMappings`, `Dumpspace`, and object/property listings.
The reflection report distinguishes field checks from fresh live camera-chain
checks: an inactive or null world is not silently called a valid camera chain.

```sh
ctest --test-dir build-linux --output-on-failure
python3 tests/compare_upstream.py
python3 tests/validate_sdk.py /absolute/path/to/output
python3 tests/validate_sdk.py /absolute/path/to/output --compile
```

The last command compares twelve selected live-reflection fields with C++ and
Dumpspace, checks output files, JSON, global offsets and USMAP magic, and writes
`sdk-validation.json`. Adding `--compile` also checks the complete SDK.hpp
(classes, structs and parameters) with generated layout assertions enabled,
recording compiler exit status and a log. This can use about 1.5 GiB RAM.
It does not link or runtime-test every property/function.
See `UPSTREAM_COMPARISON.md` for evidence and comparison scope.

## Limitations

- Live-tested on this x86-64 `DungeonCrawler.exe`, not every UE game. Automatic
  name candidates currently require the standard FNamePool chunk table at +0x10;
  the original initializer validates the pool. Legacy TNameEntryArray, encrypted
  pointers, custom pool headers and Windows import/xref fallback paths are not
  fully ported. The current reflection-validation profile checks Engine camera
  classes and will reject a target lacking those fields.
- Helpers that execute target code cannot run externally. `FText` retains its
  reflected size/alignment but has opaque contents; string accessors throw.
  `FFieldClass` exposes the observed Name/CastFlags prefix, not guessed fields.
- Generated C++ describes **Windows target memory**. Function wrappers remain
  upstream in-process helpers, not an external RPC API; do not call them with
  remote addresses. Linux layout checks use C++20 and `-fshort-wchar` for UTF-16.
  This flag does not make the host wide-string library ABI Windows-compatible.
- Out-of-range reflected enum sentinels become separate `_Raw` constants, keeping
  the enum storage width and property offsets intact.
- No Windows Dumper-7 DLL was injected or executed. Comparisons use original
  source on controlled fixtures; full output equality to a Windows run of this
  game has not been established.
