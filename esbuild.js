const esbuild = require("esbuild");
const fs = require("fs");
const CORE_VERSION = require("./package.json").version;

console.log("🧹 Cleaning up... 🧹");
fs.rm("dist", {recursive: true, force: true}, (err) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    fs.mkdir("dist", (err) => {
        if (err) {
            console.error(err);
            process.exit(1);
        }

        console.log("🚀 Building core... 🚀");
        esbuild
            .build({
                entryPoints: ["src/index.ts"],
                outfile: "dist/core.js",
                sourcemap: false,
                minify: true,
                bundle: true,
                write: false,
                plugins: [],
            })
            .then((result) => {
                if (result.warnings.length > 0) {
                    console.warn(result.warnings);
                }

                if (result.errors.length > 0) {
                    console.error(result.errors);
                    process.exit(1);
                }

                fs.readFile("src/license.tpl", "utf8", (err, data) => {
                    if (err) {
                        console.error(err);
                        process.exit(1);
                    }

                    const license = data.replace("{{YEAR}}", new Date().getFullYear().toString());
                    const code = result.outputFiles[0].text.replace("{{VERSION}}", CORE_VERSION);

                    fs.writeFile("dist/core.js", license + code, (err) => {
                        if (err) {
                            console.error(err);
                            process.exit(1);
                        }

                        console.log("⚡ Build complete! ⚡");
                    });
                });

            }).catch((reason) => {
            console.error(reason);
            process.exit(1);
        });
    });
});



