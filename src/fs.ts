/**
 Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>
 **/

export class FileSystem {
    private static _fclose: NativeFunction | null;
    private static _fcntl: NativeFunction | null;
    private static _fgets: NativeFunction | null;
    private static _fileno: NativeFunction | null;
    private static _fopen: NativeFunction | null;
    private static _fputs: NativeFunction | null;
    private static _fread: NativeFunction | null;
    private static _fseek: NativeFunction | null;
    private static _getline: NativeFunction | null;
    private static _pclose: NativeFunction | null;
    private static _popen: NativeFunction | null;

    static init() {
        FileSystem._fclose = FileSystem.exportToFunction('fclose', 'int', ['pointer']);
        FileSystem._fcntl = FileSystem.exportToFunction('fcntl', 'int', ['int', 'int', 'int']);
        FileSystem._fgets = FileSystem.exportToFunction('fgets', 'int', ['pointer', 'int', 'pointer']);
        FileSystem._fileno = FileSystem.exportToFunction('fileno', 'int', ['pointer']);
        FileSystem._fopen = FileSystem.exportToFunction('fopen', 'pointer', ['pointer', 'pointer']);
        FileSystem._fputs = FileSystem.exportToFunction('fputs', 'int', ['pointer', 'pointer']);
        FileSystem._fread = FileSystem.exportToFunction('fread', 'uint32', ['pointer', 'uint32', 'uint32', 'pointer']);
        FileSystem._fseek = FileSystem.exportToFunction('fseek', 'int', ['pointer', 'int', 'int']);
        FileSystem._getline = FileSystem.exportToFunction('getline', 'int', ['pointer', 'pointer', 'pointer']);
        FileSystem._pclose = FileSystem.exportToFunction('pclose', 'int', ['pointer']);
        FileSystem._popen = FileSystem.exportToFunction('popen', 'pointer', ['pointer', 'pointer']);
    }

    private static exportToFunction(exp: string, ret: string, args: string[]): NativeFunction | null {
        const p = Dwarf.getApi().findExport(exp);
        if (p !== null && !p.isNull()) {
            return new NativeFunction(p, ret, args);
        }
        return null;
    }

    /**
     * Allocate the given size in the heap
     */
    static allocateRw(size: number): NativePointer {
        const pt = Memory.alloc(size);
        Memory.protect(pt, size, 'rw-');
        return pt;
    };

    /**
     * Allocate and write the given string in the heap
     */
    static allocateString(what: string): NativePointer {
        return Memory.allocUtf8String(what);
    };

    /**
     * Call native fopen with filePath and perm
     */
    static fopen(filePath: string, perm: string): NativeReturnValue {
        if (FileSystem._fopen === null) {
            return NULL;
        }

        const filePathPtr = Memory.allocUtf8String(filePath);
        const p = Memory.allocUtf8String(perm);
        return FileSystem._fopen(filePathPtr, p);
    };

    /**
     * Call native popen with filePath and perm
     */
    static popen(filePath: string, perm: string): NativeReturnValue {
        if (FileSystem._popen === null) {
            return NULL;
        }

        const filePathPtr = Memory.allocUtf8String(filePath);
        const p = Memory.allocUtf8String(perm);
        return FileSystem._popen(filePathPtr, p);
    };

    /**
     * Read a file as string
     */
    static readStringFromFile(filePath: string): string {
        const fp = FileSystem.fopen(filePath, 'r');
        if (fp === NULL) {
            return "";
        }

        const ret = FileSystem.readStringFromFp(fp as NativePointer);

        if (FileSystem._fclose != null) {
            FileSystem._fclose(fp);
        }

        return ret;
    };

    /**
     * Read string from descriptor
     */
    static readStringFromFp(fp: NativePointer) {
        if (FileSystem._fgets === null) {
            return "";
        }

        let ret = "";
        if (fp !== null) {
            const buf = FileSystem.allocateRw(1024);
            while (FileSystem._fgets(buf, 1024, fp) > 0) {
                ret += buf.readUtf8String();
            }
            return ret;
        }

        return ret;
    };

    /**
     * Write string to file
     */
    static writeStringToFile(filePath: string, content: string, append: boolean) {
        // use frida api
        if (typeof append === 'undefined') {
            append = false;
        }
        const f = new File(filePath, (append ? 'wa' : 'w'));
        f.write(content);
        f.flush();
        f.close();
    };
}