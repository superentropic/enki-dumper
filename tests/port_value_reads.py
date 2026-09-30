"""Mechanical port of explicitly selected target-value dereferences.

Does not change algorithms or container reference operations. The resulting
diff is reviewed and remaining address-space operations are ported separately.
"""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
for relative in ["Dumper/Engine/Private/OffsetFinder/OffsetFinder.cpp",
                 "Dumper/Engine/Public/OffsetFinder/OffsetFinder.h",
                 "Dumper/Engine/Private/Unreal/UnrealObjects.cpp"]:
    path = root / relative
    text = path.read_text()
    cursor = 0
    count = 0
    while True:
        start = text.find("*reinterpret_cast<", cursor)
        if start == -1:
            break
        type_start = start + len("*reinterpret_cast<")
        end = type_start
        depth = 1
        while depth:
            if text[end] == '<': depth += 1
            if text[end] == '>': depth -= 1
            end += 1
        cast_type = text[type_start:end-1]
        if not cast_type.endswith('*') or 'TArray<' in cast_type or '&Map' in text[end:end+12]:
            cursor = end
            continue
        if text[end] != '(':
            raise RuntimeError(text[start:end+10])
        expr_start = end + 1
        end = expr_start
        depth = 1
        while depth:
            if text[end] == '(': depth += 1
            if text[end] == ')': depth -= 1
            end += 1
        expression = text[expr_start:end-1]
        # ReadRemoteField's non-Linux fallback is deliberately a local read.
        if 'const_cast' in expression or expression == '&Map':
            cursor = end
            continue
        replacement = 'TargetMemory::Read<' + cast_type[:-1].rstrip() + '>(' + expression + ')'
        text = text[:start] + replacement + text[end:]
        cursor = start + len(replacement)
        count += 1
    text = '#include "TargetMemory.h"\n' + text if '#include "TargetMemory.h"' not in text else text
    path.write_text(text)
    print(relative, count, 'value reads converted')
