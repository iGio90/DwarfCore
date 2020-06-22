/**
 * @hidden
 * @ignore
 * @internal
 */

/*
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

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
*/

//POC

//TODO: add other platforms
//TODO: optimize android extract without (re)iteration
//TODO: add errors if filecreation fails
export class DwarfZip {
    protected _nativeFunctions: Array<NativeFunction>;
    protected _archivePath: NativePointer;

    constructor(archivePath: string) {
        if (Process.platform === "linux" && Java.available) {
            //https://android.googlesource.com/platform/system/core/+/refs/heads/marshmallow-release/libziparchive/zip_archive.cc
            let libZipArchive = Process.findModuleByName("libziparchive.so");
            if(libZipArchive === null) {
                libZipArchive = Module.load("libziparchive.so");
            }
            if (libZipArchive) {
                for (let moduleExportDetail of libZipArchive.enumerateExports()) {
                    if (moduleExportDetail.name.indexOf("OpenArchive") !== -1) {
                        if (moduleExportDetail.name.indexOf("OpenArchiveFd") === -1 && moduleExportDetail.name.indexOf("OpenArchiveInternal") === -1) {
                            //int32_t OpenArchive(const char* fileName, ZipArchiveHandle* handle)
                            this._nativeFunctions["openArchive"] = new NativeFunction(
                                libZipArchive.getExportByName(moduleExportDetail.name),
                                "int32",
                                ["pointer", "pointer"]
                            );
                        }
                    } else if (moduleExportDetail.name.indexOf("CloseArchive") !== -1) {
                        //void CloseArchive(ZipArchiveHandle handle)
                        this._nativeFunctions["closeArchive"] = new NativeFunction(
                            libZipArchive.getExportByName(moduleExportDetail.name),
                            "void",
                            ["pointer"]
                        );
                    } else if (moduleExportDetail.name.indexOf("Next") !== -1) {
                        //int32_t Next(void* cookie, ZipEntry* data, ZipEntryName* name)
                        this._nativeFunctions["nextEntry"] = new NativeFunction(libZipArchive.getExportByName(moduleExportDetail.name), "int32", [
                            "pointer",
                            "pointer",
                            "pointer",
                        ]);
                    } else if (moduleExportDetail.name.indexOf("ExtractEntryToFile") !== -1) {
                        //int32_t ExtractEntryToFile(ZipArchiveHandle handle, ZipEntry* entry, int fd)
                        this._nativeFunctions["extractEntryToFile"] = new NativeFunction(
                            libZipArchive.getExportByName(moduleExportDetail.name),
                            "int32",
                            ["pointer", "pointer", "int"]
                        );
                    } else if (moduleExportDetail.name.indexOf("StartIteration") !== -1) {
                        if (Dwarf.getAndroidApiLevel() <= 22) {
                            //int32_t StartIteration(ZipArchiveHandle handle, void** cookie_ptr, const ZipEntryName* optional_prefix)
                            this._nativeFunctions["startIteration"] = new NativeFunction(
                                libZipArchive.getExportByName(moduleExportDetail.name),
                                "int32",
                                ["pointer", "pointer", "pointer"]
                            );
                        } else {
                            //int32_t StartIteration(ZipArchiveHandle handle, void** cookie_ptr, const ZipEntryName* optional_prefix, const ZipEntryName* optional_suffix)
                            this._nativeFunctions["startIteration"] = new NativeFunction(
                                libZipArchive.getExportByName(moduleExportDetail.name),
                                "int32",
                                ["pointer", "pointer", "pointer", "pointer"]
                            );
                        }
                    }
                }
            } else {
                throw new Error('libziparchive.so missing!');
            }
        }

        //Check pointers
        if (Process.platform === "linux" && Java.available) {
            if(this._nativeFunctions.length !== 5) {
                throw new Error("DwarfZip: Init failed! Missing Functions");
            }
        }
        this._nativeFunctions.forEach((nativeFunc) => {
            if (nativeFunc === null || nativeFunc.isNull()) {
                throw new Error("DwarfZip: Init failed! Pointer === NULL");
            }
        });

        if (isString(archivePath)) {
            if (Process.platform === "linux" && Java.available) {
                this._archivePath = Memory.allocUtf8String(archivePath);
                this["_archiveHandle"] = Memory.alloc(Process.pointerSize);
                const result = this._nativeFunctions["openArchive"](this._archivePath, this["_archiveHandle"]);
                if (result !== 0) {
                    throw new Error("OpenArchive failed! Result: " + result);
                }
            } else {
                throw new Error("Not implemented!");
            }
        } else {
            throw new Error("Invalid usage!");
        }
    }

    getContents = (): Array<string> => {
        const zipContents = new Array<string>();
        if (Process.platform === "linux" && Java.available) {
            let cookie = Memory.alloc(Process.pointerSize);
            Memory.protect(cookie, Process.pointerSize, "rw-");
            if (Dwarf.getAndroidApiLevel() <= 22) {
                if (this._nativeFunctions["startIteration"](this["_archiveHandle"].readPointer(), cookie, NULL) === 0) {
                    var zipEntry = Memory.alloc(500); //TODO: calc real size
                    var zipName = Memory.alloc(Process.pointerSize + 3); // struct ZipEntryName { const char* name;  uint16_t name_length; };
                    Memory.protect(zipEntry, 500, "rw-");
                    Memory.protect(zipName, Process.pointerSize + 3, "rw-");
                    while (this._nativeFunctions["nextEntry"](cookie.readPointer(), zipEntry, zipName) === 0) {
                        var nameLen = zipName.add(Process.pointerSize).readU16();
                        var entryName = zipName.readPointer().readUtf8String(nameLen);
                        zipContents.push(entryName);
                    }
                } else {
                    throw new Error("Failed to get Content! Error: StartIteration");
                }
            } else {
                if (this._nativeFunctions["startIteration"](this["_archiveHandle"].readPointer(), cookie, NULL, NULL) === 0) {
                    var zipEntry = Memory.alloc(500); //TODO: calc real size
                    var zipName = Memory.alloc(Process.pointerSize + 3); // struct ZipEntryName { const char* name;  uint16_t name_length; };
                    Memory.protect(zipEntry, 500, "rw-");
                    Memory.protect(zipName, Process.pointerSize + 3, "rw-");
                    while (this._nativeFunctions["nextEntry"](cookie.readPointer(), zipEntry, zipName) === 0) {
                        var nameLen = zipName.add(Process.pointerSize).readU16();
                        var entryName = zipName.readPointer().readUtf8String(nameLen);
                        zipContents.push(entryName);
                    }
                } else {
                    throw new Error("Failed to get Content! Error: StartIteration");
                }
            }
        }
        return zipContents;
    };

    extractToDisk = (zipPath: string, diskPath: string) => {
        if (Process.platform === "linux" && Java.available) {
            let cookie = Memory.alloc(Process.pointerSize);
            Memory.protect(cookie, Process.pointerSize, "rw-");
            if (Dwarf.getAndroidApiLevel() <= 22) {
                if (this._nativeFunctions["startIteration"](this["_archiveHandle"].readPointer(), cookie, NULL) === 0) {
                    var zipEntry = Memory.alloc(500); //TODO: calc real size
                    var zipName = Memory.alloc(Process.pointerSize + 3); // struct ZipEntryName { const char* name;  uint16_t name_length; };
                    Memory.protect(zipEntry, 500, "rw-");
                    Memory.protect(zipName, Process.pointerSize + 3, "rw-");
                    while (this._nativeFunctions["nextEntry"](cookie.readPointer(), zipEntry, zipName) === 0) {
                        var nameLen = zipName.add(Process.pointerSize).readU16();
                        var entryName = zipName.readPointer().readUtf8String(nameLen);
                        if (entryName === zipPath) {
                            const dwarfFile = Dwarf.getFS().fopen(diskPath, "w");
                            const fd = Dwarf.getFS().fileno(dwarfFile);
                            if (this._nativeFunctions["extractEntryToFile"](this["_archiveHandle"].readPointer(), zipEntry, fd) === 0) {
                                Dwarf.getFS().fclose(dwarfFile);
                            } else {
                                throw new Error("Failed to extract!");
                            }
                            break;
                        }
                    }
                } else {
                    throw new Error("Failed to get Content! Error: StartIteration");
                }
            } else {
                if (this._nativeFunctions["startIteration"](this["_archiveHandle"].readPointer(), cookie, NULL, NULL) === 0) {
                    var zipEntry = Memory.alloc(500); //TODO: calc real size
                    var zipName = Memory.alloc(Process.pointerSize + 3); // struct ZipEntryName { const char* name;  uint16_t name_length; };
                    Memory.protect(zipEntry, 500, "rw-");
                    Memory.protect(zipName, Process.pointerSize + 3, "rw-");
                    while (this._nativeFunctions["nextEntry"](cookie.readPointer(), zipEntry, zipName) === 0) {
                        var nameLen = zipName.add(Process.pointerSize).readU16();
                        var entryName = zipName.readPointer().readUtf8String(nameLen);
                        if (entryName === zipPath) {
                            const dwarfFile = Dwarf.getFS().fopen(diskPath, "w");
                            const fd = Dwarf.getFS().fileno(dwarfFile);
                            if (this._nativeFunctions["extractEntryToFile"](this["_archiveHandle"].readPointer(), zipEntry, fd) === 0) {
                                Dwarf.getFS().fclose(dwarfFile);
                            } else {
                                throw new Error("Failed to extract!");
                            }
                            break;
                        }
                    }
                } else {
                    throw new Error("Failed to get Content! Error: StartIteration");
                }
            }
        }
    };

    close = () => {
        if (Process.platform === "linux" && Java.available) {
            this._nativeFunctions["closeArchive"](this["_archiveHandle"].readPointer());
            this._archivePath = ptr(0);
        }
    };
}
