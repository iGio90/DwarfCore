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


types = generate_types('src/api.ts')

with open('dwarf-typings/index.d.ts', 'w') as f:
    f.write(types)
