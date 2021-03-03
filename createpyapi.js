//TODO: fix this mess :D

const fs = require("fs");
const ts = require("typescript");

//https://stackoverflow.com/questions/54246477/how-to-convert-camelcase-to-snake-case-in-javascript
const camelToSnakeCase = (str) => str.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);

const prg = ts.createProgram(["./src/DwarfApi.ts"], {
    module: ts.ModuleKind.ES2015,
    moduleResolution: ts.ModuleResolutionKind.NodeJs,
    target: ts.ScriptTarget.ES5,
});
const chk = prg.getTypeChecker(); //!keep

const functions = [];

ts.forEachChild(prg.getSourceFile("./src/DwarfApi.ts"), (node) => {
    if (node.kind === ts.SyntaxKind.ClassDeclaration) {
        const cls = node;
        cls.forEachChild((m) => {
            if (m.kind === ts.SyntaxKind.PropertyDeclaration) {
                const method = m;
                const initializer = method.initializer;
                try {
                    const args = [];
                    initializer.parameters.forEach((p) => args.push(camelToSnakeCase(p.name.getText())));
                    functions.push(
                        "    def " +
                            camelToSnakeCase(method.name.getText()) +
                            "(self, " +
                            args.join(", ") +
                            '):\r\n        return self._dwarf_core._api_call("' +
                            method.name.getText() +
                            '", ' +
                            args.join(", ") +
                            ")\r\n\r\n"
                    );
                } catch (e) {}
            }
        });
    }
});

try {
    let template = fs.readFileSync("./src/py/dwarf_api_skeleton.py", "utf8");

    functions.forEach((fn) => {
        template += fn.replace(/(, \)+)/g, ")");
    });
    fs.writeFileSync("./dist/dwarf_api.py", template, { flag: "w+" });
} catch (err) {
    console.error(err);
}
