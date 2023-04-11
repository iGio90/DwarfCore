/**
 * Dwarf - Copyright (C) 2018-2023 Giovanni Rocca (iGio90), PinkiePieStyle
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import { DwarfApi } from "./DwarfApi";

export class DwarfFS {
    protected _access: NativeFunction<number, [NativePointer, number]> | null;
    protected _fclose: NativeFunction<number, [NativePointer]> | null;
    protected _fcntl: NativeFunction<number, [number,number,number]> | null;
    protected _fgets: NativeFunction<number, [NativePointer, number, NativePointer]> | null;
    protected _fileno: NativeFunction<number, [NativePointer]> | null;
    protected _fopen: NativeFunction<NativePointer, [NativePointer, NativePointer]> | null;
    protected _fputs: NativeFunction<number, [NativePointer, NativePointer]> | null;
    protected _fread: NativeFunction<number, [NativePointer, number, number, NativePointer]> | null;
    protected _fseek: NativeFunction<number, [NativePointer, number, number]> | null;
    protected _ftell: NativeFunction<number, [NativePointer]> | null;
    protected _getline: NativeFunction<number, [NativePointer, NativePointer, NativePointer]> | null;
    protected _pclose: NativeFunction <number, [NativePointer]>| null;
    protected _popen: NativeFunction<NativePointer, [NativePointer, NativePointer]> | null;

    private static instanceRef: DwarfFS;

    /** @internal */
    static getInstance() {
        if (!DwarfFS.instanceRef) {
            DwarfFS.instanceRef = new this();
        }
        return DwarfFS.instanceRef;
    }

    /** @internal */
    private constructor() {
        if (DwarfFS.instanceRef) {
            throw new Error("DwarfFS already exists! Use DwarfFS.getInstance()/Dwarf.getFS()");
        }
        trace("DwarfFS()");

        const exportToFunction = (exp: string, ret: NativeFunctionReturnType, args: NativeFunctionArgumentType[]): NativeFunction<any,any> | null => {
            const p = Module.findExportByName(null, exp);
            if (p !== null && !p.isNull()) {
                return new NativeFunction(p, ret, args);
            }
            logDebug("DwarfFS: " + exp + " not available!");
            return null;
        };

        if (Process.platform === "windows") {
            this._access = exportToFunction("_access", "int", ["pointer", "int"]);
        } else {
            this._access = exportToFunction("access", "int", ["pointer", "int"]);
        }

        this._fclose = exportToFunction("fclose", "int", ["pointer"]);
        this._fcntl = exportToFunction("fcntl", "int", ["int", "int", "int"]);
        this._fgets = exportToFunction("fgets", "int", ["pointer", "int", "pointer"]);
        this._fileno = exportToFunction("fileno", "int", ["pointer"]);
        this._fopen = exportToFunction("fopen", "pointer", ["pointer", "pointer"]);
        this._fputs = exportToFunction("fputs", "int", ["pointer", "pointer"]);
        this._fread = exportToFunction("fread", "uint32", ["pointer", "uint32", "uint32", "pointer"]);
        this._fseek = exportToFunction("fseek", "int", ["pointer", "int", "int"]);
        this._getline = exportToFunction("getline", "int", ["pointer", "pointer", "pointer"]);
        this._pclose = exportToFunction("pclose", "int", ["pointer"]);
        this._popen = exportToFunction("popen", "pointer", ["pointer", "pointer"]);
        this._ftell = exportToFunction("ftell", "long", ["pointer"]);
    }

    access = (filePath: string, mode: number): number => {
        if (this._access === null || this._access.isNull()) {
            throw new Error("DwarfFS::access not available!");
        }
        const filePathPtr = Memory.allocUtf8String(filePath);
        return this._access(filePathPtr, mode) as number;
    };

    /**
     * Allocate the given size in the heap
     */
    allocateRw = (size: number): NativePointer => {
        const pt = Memory.alloc(size);
        Memory.protect(pt, size, "rw-");
        return pt;
    };

    fclose = (filePointer: NativePointer) => {
        if (this._fclose === null || this._fclose.isNull()) {
            throw new Error("DwarfFS::fclose not available!");
        }
        if (isDefined(filePointer) && !filePointer.isNull()) {
            return this._fclose(filePointer);
        }
    };

    fileno = (filePointer: NativePointer) => {
        if (this._fileno === null || this._fileno.isNull()) {
            throw new Error("DwarfFS::fileno not available!");
        }
        if (isDefined(filePointer) && !filePointer.isNull()) {
            return this._fileno(filePointer);
        }
    };

    /**
     * Call native fopen with filePath and perm
     */
    fopen = (filePath: string, perm: string): NativePointer => {
        if (this._fopen === null) {
            throw new Error("DwarfFS::fopen not available!");
        }

        const filePathPtr = Memory.allocUtf8String(filePath);
        const p = Memory.allocUtf8String(perm);
        return this._fopen(filePathPtr, p) as NativePointer;
    };

    fread = (ptr: NativePointer, size: number, count: number, filePointer: NativePointer) => {
        if (this._fread === null || this._fread.isNull()) {
            throw new Error("DwarfFS::fread not available!");
        }
        if (isDefined(ptr) && !ptr.isNull()) {
            if (isDefined(filePointer) && !filePointer.isNull()) {
                return this._fread(ptr, size, count, filePointer);
            }
        }
    };

    fseek = (filePointer: NativePointer, offset: number, origin: number) => {
        if (this._fseek === null || this._fseek.isNull()) {
            throw new Error("DwarfFS::fread not available!");
        }
        if (isDefined(filePointer) && !filePointer.isNull()) {
            return this._fseek(filePointer, offset, origin);
        }
    };

    ftell = (filePointer: NativePointer) => {
        if (this._ftell === null || this._ftell.isNull()) {
            throw new Error("DwarfFS::fread not available!");
        }
        if (isDefined(filePointer) && !filePointer.isNull()) {
            return this._ftell(filePointer);
        }
    };

    /**
     * Call native popen with filePath and perm
     */
    popen = (filePath: string, perm: string): NativeFunctionReturnValue => {
        if (this._popen === null) {
            return NULL;
        }

        const filePathPtr = Memory.allocUtf8String(filePath);
        const p = Memory.allocUtf8String(perm);
        return this._popen(filePathPtr, p);
    };

    /**
     * Read a file as string
     */
    readStringFromFile = (filePath: string): string => {
        const fp = this.fopen(filePath, "r");
        if (fp === NULL) {
            return "";
        }

        const ret = this.readStringFromFp(fp as NativePointer);

        if (this._fclose != null) {
            this._fclose(fp);
        }

        return ret;
    };

    /**
     * Read string from descriptor
     */
    readStringFromFp = (fp: NativePointer) => {
        if (this._fgets === null) {
            return "";
        }

        let ret = "";
        if (fp !== null) {
            const buf = DwarfApi.getInstance().allocRW(1024);
            while (this._fgets(buf, 1024, fp) > 0) {
                ret += buf.readUtf8String();
            }
            return ret;
        }

        return ret;
    };

    /**
     * Write string to file
     */
    writeStringToFile = (filePath: string, content: string, append: boolean) => {
        // use frida api
        if (typeof append === "undefined") {
            append = false;
        }
        const f = new File(filePath, append ? "wa" : "w");
        f.write(content);
        f.flush();
        f.close();
    };
}

export declare namespace DwarfFS {
    export const enum SeekDirection {
        /**
         * Beginning of file
         */
        SEEK_SET,
        /**
         * Current position of the file pointer
         */
        SEEK_CUR,
        /**
         * End of file
         */
        SEEK_END,
    }
}
