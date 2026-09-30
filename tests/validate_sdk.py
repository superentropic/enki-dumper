"""Cross-check SDK declarations and Dumpspace against live reflection evidence."""
import json
import re
import sys
import argparse
import subprocess
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('output', type=Path)
parser.add_argument('--compile', action='store_true', help='Compile complete SDK.hpp with generated layout assertions')
parser.add_argument('--compiler', default='c++')
args = parser.parse_args()
root = args.output.resolve()
live = json.loads((root / 'reflection-validation.json').read_text())
assert live['reflection_validation'] == 'passed'
assert live['sdk_generation'] == 'completed'
sdk_candidates = list(root.glob('external-linux-*'))
assert len(sdk_candidates) == 1, 'expected one generated external-linux SDK directory'
sdk = sdk_candidates[0]
cpp = sdk / 'CppSDK'
all_files = list(sdk.rglob('*'))
files = [p for p in all_files if p.is_file()]
assert len(files) > 100
assert all(p.stat().st_size > 0 for p in files), 'empty SDK artifact'
headers = list((cpp/'SDK').glob('*_classes.hpp')) + list((cpp/'SDK').glob('*_structs.hpp'))
needed = {v['owner_cpp'] for v in live['properties'].values()}
bodies = {}
for path in headers:
    content = path.read_text(encoding='utf-8-sig')
    for owner in needed - bodies.keys():
        match = re.search(r'^(?:class|struct) (?:alignas\([^)]*\) )?' + re.escape(owner) + r'\b[^\n]*\n\{(.*?)^\};', content, re.M|re.S)
        if match:
            bodies[owner] = (path, match.group(1))
    if needed <= bodies.keys(): break
ds = {}
for filename in ['ClassesInfo.json', 'StructsInfo.json']:
    document = json.loads((sdk/'Dumpspace'/filename).read_text())
    for entry in document['data']:
        ds.update(entry)
results = []
for key, evidence in live['properties'].items():
    member = key.split('::')[1]
    owner = evidence['owner_cpp']
    path, body = bodies[owner]
    pattern = r'\b' + re.escape(member) + r';[^\n]*// 0x([0-9A-F]+)\(0x([0-9A-F]+)\)'
    match = re.search(pattern, body, re.I)
    assert match, (key, 'C++ declaration missing')
    assert int(match[1], 16) == evidence['offset'], (key, 'C++ offset mismatch')
    assert int(match[2], 16) == evidence['size'], (key, 'C++ size mismatch')
    properties = {k: v for row in ds[owner] for k,v in row.items()}
    assert properties[member][1:3] == [evidence['offset'], evidence['size']], (key, 'Dumpspace mismatch')
    results.append({'property': key, 'offset': hex(evidence['offset']), 'size': evidence['size'], 'header': str(path)})
offsets = dict(json.loads((sdk/'Dumpspace'/'OffsetsInfo.json').read_text())['data'])
for field, ds_key in [('GObjects','OFFSET_GOBJECTS'),('GNames','OFFSET_GNAMES'),('GWorld','OFFSET_GWORLD'),('ProcessEvent','OFFSET_PROCESSEVENT')]:
    assert offsets[ds_key] == live['globals'][field] != 0, field
for path in (sdk/'Dumpspace').glob('*.json'): json.loads(path.read_text())
mappings = list((sdk/'Mappings').glob('*.usmap'))
assert mappings and all(p.read_bytes()[:2] == b'\xc4\x30' for p in mappings), 'usmap magic'
assert any((sdk/'IDAMappings').iterdir())
result = {'status':'passed', 'upstream_commit':live['upstream_commit'], 'file_count':len(files),
          'total_bytes':sum(p.stat().st_size for p in files), 'checked_properties':results,
          'live_camera_chain': live['live_chain']}
if args.compile:
    command = [args.compiler, '-std=c++20', '-fshort-wchar', '-fms-extensions', '-w',
               '-fmax-errors=20', '-fsyntax-only', '-I'+str(cpp),
               str(Path(__file__).resolve().with_name('sdk_all_headers.cpp'))]
    log = root/'header-compilation.log'
    started = time.monotonic()
    with log.open('w') as output:
        compiled = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    result['header_compilation'] = {
        'status': 'passed' if compiled.returncode == 0 else 'failed',
        'exit_code': compiled.returncode, 'elapsed_seconds': round(time.monotonic()-started, 2),
        'command': command, 'log': str(log),
        'scope': 'complete SDK.hpp including class, struct and parameter declarations with generated layout assertions; no linking or target calls',
    }
    if compiled.returncode: result['status'] = 'failed'
(root/'sdk-validation.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k != 'checked_properties'}, indent=2))
sys.exit(0 if result['status'] == 'passed' else 1)
