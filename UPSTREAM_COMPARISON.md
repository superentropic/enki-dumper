# Upstream comparison and live validation

Reference: [Encryqed/Dumper-7, pinned commit
dd8fe34df8283378a1055386eee195005a100924](https://github.com/Encryqed/Dumper-7/tree/dd8fe34df8283378a1055386eee195005a100924).
`git HEAD` is the original source; the Linux changes are working-tree changes.
This report does not claim a side-by-side run of the injected Windows DLL.

## Comparisons that execute the original code

`python3 tests/compare_upstream.py` extracts original functions with `git show`
and compiles them as test oracles. It does not compare two copies of the Linux
rewrite. Tests use self-owned synthetic PE mappings and do not modify the game.

| Check | Original source | Result |
| --- | --- | --- |
| Five chunk layouts, object pointer at +0 and +8 | ObjectArray.cpp validators and InitializeFUObjectItem | Agreement on address, layout, stride and pointer offset; readable decoys without vtables do not win |
| FNamePool headers of 2 and 6 bytes | NameArray.cpp InitializeNamePool | Agreement on header fields, chunk table, stride and None/ByteProperty decoding; both reject inconsistent chunk count |
| Dynamic offset initialization | Offsets.cpp Off::Init | Unchanged function body, ignoring whitespace |
| Property size initialization | Offsets.cpp PropertySizes::Init | Unchanged function body, ignoring whitespace |
| Four UE feature/size settings initializers | Settings.cpp | Unchanged function bodies, ignoring whitespace |

These tests cover the specified fixtures, not every possible UE layout or
encrypted/customized engine. The external candidate search is different from
Windows import/constructor discovery. After selection, the original name-pool
initializer runs with remote value reads. The original field finders use the
same semantic objects and tests; target dereferences now use `TargetMemory`.

`ctest --test-dir build-linux --output-on-failure` additionally tests exact and
partial reads, unmapped/overflow ranges, target exit, module matching, and
valid/invalid PE headers against a child process. No kernel permissions change.

## Live read-only evidence

Target PID 4888, `DungeonCrawler.exe` under Proton, image base `0x140000000`.
The latest offset-free run used **no --names, --objects or GWorld input** and
finished with exit 0 in 1 minute 55.56 seconds (759,284 KiB peak RSS).

| Discovery | Observed result |
| --- | --- |
| GObjects RVA | `0xDFE9600` |
| FNamePool RVA | `0xDF1D980` |
| GWorld RVA | `0xE06F918` |
| ProcessEvent RVA / vtable index | `0x1881250` / `0x4A` |
| FUObjectItem stride / object-pointer field | `0x18` / `+0x8` |
| Captured object-array count | 629,637 (includes slots not necessarily populated) |
| Decoded name entries | 471,154 |

The earlier `0x10` item stride was incorrect: mere readable pointers were not
enough. Restoring the original vtable checks selected the verified `0x18/+0x8`
layout. GWorld discovery independently selected the user-provided reference RVA;
it did not use that reference as an input.

## Requested fields

These are byte offsets within their owning type, not module RVAs. They come from
the original reflection traversal, not hardcoded camera profiles.

| Owner and member | Offset |
| --- | --- |
| UWorld::OwningGameInstance | `0x228` |
| UGameInstance::LocalPlayers | `0x38` |
| UPlayer::PlayerController | `0x30` |
| APlayerController::PlayerCameraManager | `0x360` |
| APlayerCameraManager::CameraCachePrivate | `0x15D0` |
| FCameraCacheEntry::POV | `0x10` |

FMinimalViewInfo has Location at 0, Rotation at 0x18 and FOV at 0x30. Location and
Rotation are 24-byte double-precision structures here. Fresh reads followed the
camera chain successfully; the offset-free run read FOV 69.8935089. That value is
an observation of a changing live scene, not a constant for later runs.

Validation checks 2,048 populated object indices/names/classes, twelve selected
reflected property bounds, and fresh camera pointers/FOV. `tests/validate_sdk.py`
cross-checks those twelve offsets and sizes against the generated C++ comments
and Dumpspace, verifies globals, nonempty files, JSON parsing and USMAP magic.
This does not prove every object/function or every frame of game state is valid.

## Generator adaptations

- Windows UTF-16 strings are read as 16-bit units on the Linux host.
- FText size comes from a reflected return property; its internal string data
  is opaque because upstream's internal-offset test executes ProcessEvent.
- Only the observed FFieldClass Name/CastFlags prefix is exposed.
- Explicit alignment/padding preserves target layouts under GCC, including
  inherited tail padding and genuinely empty Mass marker bases.
- Enum sentinels outside the underlying storage width are represented as
  separate raw constants instead of widening the enum and shifting fields.

Generated functions are still target-process SDK wrappers. They are not remote
call support for a Linux consumer. No injection, target function calls, target
writes or anti-cheat bypass was used. See LINUX.md for support limitations.

## Evidence files

- `build-linux/upstream-parity.log` and `upstream-comparison.json`
- `build-linux/complete-4888.log`: successful final offset-free SDK generation
- `build-linux/sdk-engine-syntax.log`: Engine/Core declarations and original
  generated layout assertions compile under GCC 13
- `/home/enki/Downloads/dad-research-tool-main/dumps/sdk-complete-4888/reflection-validation.json`
- `/home/enki/Downloads/dad-research-tool-main/dumps/sdk-complete-4888/sdk-validation.json`

The initial all-header check found empty-base layout issues in Mass fragments.
Only bases marked by upstream as reusing their padding are made empty; animation
data's nonempty size-one base retains its byte. The final compiler check is
recorded separately as `header_compilation` in `sdk-validation.json`.

Reproduce both output comparison and complete-header validation:

```sh
cd /home/enki/Downloads/dad-research-tool-main/dumper7
python3 tests/validate_sdk.py \
  /home/enki/Downloads/dad-research-tool-main/dumps/sdk-complete-4888 --compile
```

The compiler check includes the SDK's class, struct and parameter declarations
with its generated layout assertions. It does not link the generated function
implementations or invoke functions in the target.

## Final result

`sdk-complete-4888` passed all checks in `tests/validate_sdk.py --compile`:
14,515 nonempty generated files (407,794,095 bytes), twelve cross-format field
comparisons, global offset agreement, JSON parsing, USMAP magic, and compilation
of the complete SDK.hpp with generated layout assertions. GCC returned **0** in
104.83 seconds. The compiler log is empty because there were no errors and the
test command suppresses warnings; compiler status is recorded in the JSON report.

Fresh target reads passed the camera-chain check, with FOV 69.8935089. The six
requested field offsets above agree with reflection, C++ and Dumpspace. The
upstream-source fixture comparisons and the child-process inspection test also
passed. Earlier `sdk-final-*`, `sdk-auto-*` and `sdk-validated-*` directories are
development drafts; use **sdk-complete-4888** as the final artifact.

This is successful generation and the validation scope described here, not a
claim of universal UE support or a Windows DLL output-equivalence test. The
FText/target-execution limitations in LINUX.md still apply.
