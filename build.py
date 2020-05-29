import json
import os
import shutil

os.system('npm run build')

configs = None


def get_dwarf_py_path():
    return None if configs is None else configs['dwarf_path']


def generate_types(file):
    with open(file, 'r') as f:
        content = f.read()

    result = []
    lines = content.split('\n')
    for line in lines:
        if line.startswith('    /**') or line.startswith('     * ') or line.startswith('     */'):
            line = line[4:]
            result.append(line)
            continue
        try:
            line.index('static')

            try:
                line.index('private')
                continue
            except:
                line = line[line.index('static'):]
                line = line.replace('static', 'declare function')
                line = line[:-2] + ';'

                result.append(line)
        except:
            pass
    return '\n'.join(result) + '\n'


def apply_doc_markdown():
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


def build_types():
    types = generate_types('src/api.ts')

    with open('dwarf-typings/index.d.ts', 'w') as f:
        f.write(types)


if os.path.exists('.build_config.json'):
    with open('.build_config.json', 'r') as f:
        configs = json.load(f)

dwarf_py_path = get_dwarf_py_path()
if dwarf_py_path is not None:
    shutil.copy(os.sep.join(['dist', 'core.js']), dwarf_py_path)

os.system('npx typedoc --plugin typedoc-plugin-markdown --theme markdown '
          '--name Dwarf --excludePrivate --excludeExternals --hideGenerator src\\api.ts')
apply_doc_markdown()
build_types()
