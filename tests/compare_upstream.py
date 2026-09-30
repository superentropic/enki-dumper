"""Compile the original checked-in Dumper-7 validators as a test oracle."""
from pathlib import Path
import subprocess
import re
import shlex
import json
root = Path(__file__).resolve().parents[1]
out = root / 'build-linux'
source = subprocess.check_output(['git', 'show', 'HEAD:Dumper/Engine/Private/Unreal/ObjectArray.cpp'], cwd=root, text=True)
start = source.index('constexpr inline std::array FFixedUObjectArrayLayouts')
end = source.index('void ObjectArray::InitDecryption', start)
(out / 'upstream-object-array.inc').write_text(source[start:end])
subprocess.run(['c++', '-std=c++20', '-O2', '-I'+str(out), '-IDumper', '-IDumper/Engine', '-IDumper/Engine/Public', '-IDumper/Platform/Private',
                'tests/upstream_parity.cpp', 'Dumper/Platform/Private/PlatformLinux.cpp', 'Dumper/Platform/Private/LinuxProcess.cpp',
                '-o', str(out/'upstream-parity')], cwd=root, check=True)
subprocess.run([str(out/'upstream-parity')], cwd=root, check=True)

def function(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

# Ensure initialization has not silently become a fixed-offset profile again.
for path, signatures in {
    'Dumper/Engine/Private/OffsetFinder/Offsets.cpp': ['void Off::Init()', 'void PropertySizes::Init()'],
    'Dumper/Settings.cpp': ['void Settings::InitWeakObjectPtrSettings()',
        'void Settings::InitLargeWorldCoordinateSettings()',
        'void Settings::InitObjectPtrPropertySettings()',
        'void Settings::InitArrayDimSizeSettings()'],
}.items():
    original = subprocess.check_output(['git','show','HEAD:'+path], cwd=root, text=True)
    port = (root/path).read_text()
    for signature in signatures:
        normalize = lambda s: re.sub(r'\s+', '', s)
        assert normalize(function(original, signature)) == normalize(function(port, signature)), signature
        print('PASS: unchanged upstream discovery:', signature)

names = subprocess.check_output(['git','show','HEAD:Dumper/Engine/Private/Unreal/NameArray.cpp'], cwd=root, text=True)
(out/'upstream-name-pool.inc').write_text(function(names, 'bool NameArray::InitializeNamePool('))
flags = (out/'CMakeFiles/dumper7-linux.dir/flags.make').read_text()
includes = shlex.split(re.search(r'^CXX_INCLUDES = (.*)$', flags, re.M)[1])
objects = [str(p) for p in (out/'CMakeFiles/dumper7-linux.dir/Dumper').rglob('*.o') if p.name != 'LinuxMain.cpp.o']
subprocess.run(['c++','-std=c++20','-w',*includes,'-I'+str(out),'tests/names_parity.cpp',*objects,
                '-o',str(out/'names-parity')], cwd=root, check=True)
subprocess.run([str(out/'names-parity')], cwd=root, check=True)
print('Original source commit:', subprocess.check_output(['git','rev-parse','HEAD'], cwd=root, text=True).strip())
(out/'upstream-comparison.json').write_text(json.dumps({
    'status': 'passed',
    'upstream_commit': subprocess.check_output(['git','rev-parse','HEAD'], cwd=root, text=True).strip(),
    'object_array_oracle': 'verbatim upstream validators and InitializeFUObjectItem',
    'chunked_layouts': 5, 'item_pointer_offsets': [0, 8],
    'name_pool_oracle': 'verbatim upstream InitializeNamePool',
    'name_header_sizes': [2, 6], 'invalid_chunk_count_rejected': True,
    'unchanged_initializers': ['Off::Init', 'PropertySizes::Init',
        'Settings::InitWeakObjectPtrSettings', 'Settings::InitLargeWorldCoordinateSettings',
        'Settings::InitObjectPtrPropertySettings', 'Settings::InitArrayDimSizeSettings'],
    'windows_dll_executed': False,
}, indent=2)+'\n')
