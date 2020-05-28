top = '''---
id: dwarf
title: Dwarf
sidebar_label: Dwarf
---
\n'''

with open('dist/docs/classes/_api_.api.md', 'r') as f:
    data = f.read()

lines = [
]
count = 0
skip = False
for line in data.split('\n')[67:]:
    if line == '## Methods' or 'Defined in' in line:
        continue
    if line.startswith('###'):
        line = line[1:]
    if '`Static` ' in line:
        line = line.replace('`Static` ', '')
        count = 0
    if line == '___' and skip:
        skip = False
    if not skip and ('**Parameters:**' in line or '**Returns:**' in line):
        skip = True
    if skip:
        continue

    if count >= 0:
        count += 1
        if count == 5:
            count = -1
        elif count > 1:
            continue
    lines.append(line)

with open('../../multi/reSecRet/secRet/docs/dwarf.md', 'w') as f:
    f.write(top + '\n'.join(lines))
