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

import {DwarfCore} from "../DwarfCore";
import {DwarfZipArchive} from "./DwarfZipArchive";

// TODO: optimize android extract without (re)iteration
// TODO: add errors if file creation fails
export class DwarfAndroidZipArchive implements DwarfZipArchive {
    protected _nativeFunctions: {
        closeArchive: NativeFunction<void, [NativePointer]>;
        extractEntryToFile: NativeFunction<number, [NativePointer, NativePointer, number]>;
        nextEntry: NativeFunction<number, [NativePointer, NativePointer, NativePointer]>;
        openArchive: NativeFunction<number, [NativePointer, NativePointer]>;
        startIteration: NativeFunction<number, [NativePointer, NativePointer, NativePointer]> | NativeFunction<number, [NativePointer, NativePointer, NativePointer, NativePointer]>;
    };
    protected _archiveHandle: NativePointer;
    protected _archivePath: NativePointer;

    constructor(archivePath: string) {
        if (Process.platform !== "linux" || !Java.available) {
            throw new Error("DwarfAndroidZipArchive not available!");
        }

        // https://android.googlesource.com/platform/system/core/+/refs/heads/marshmallow-release/libziparchive/zip_archive.cc
        let libZipArchive = Process.findModuleByName("libziparchive.so");
        if (libZipArchive === null) {
            libZipArchive = Module.load("libziparchive.so");
        }

        if (!libZipArchive) {
            throw new Error("libziparchive.so missing!");
        }

        for (const moduleExportDetail of libZipArchive.enumerateExports()) {
            if (moduleExportDetail.name.indexOf("OpenArchive") !== -1) {
                if (moduleExportDetail.name.indexOf("OpenArchiveFd") === -1 && moduleExportDetail.name.indexOf("OpenArchiveInternal") === -1) {
                    // int32_t OpenArchive(const char* fileName, ZipArchiveHandle* handle)
                    this._nativeFunctions.openArchive = new NativeFunction(libZipArchive.getExportByName(moduleExportDetail.name), "int32", [
                        "pointer",
                        "pointer",
                    ]);
                }
            } else if (moduleExportDetail.name.indexOf("CloseArchive") !== -1) {
                // void CloseArchive(ZipArchiveHandle handle)
                this._nativeFunctions.closeArchive = new NativeFunction(libZipArchive.getExportByName(moduleExportDetail.name), "void", ["pointer"]);
            } else if (moduleExportDetail.name.indexOf("Next") !== -1) {
                // int32_t Next(void* cookie, ZipEntry* data, ZipEntryName* name)
                this._nativeFunctions.nextEntry = new NativeFunction(libZipArchive.getExportByName(moduleExportDetail.name), "int32", [
                    "pointer",
                    "pointer",
                    "pointer",
                ]);
            } else if (moduleExportDetail.name.indexOf("ExtractEntryToFile") !== -1) {
                // int32_t ExtractEntryToFile(ZipArchiveHandle handle, ZipEntry* entry, int fd)
                this._nativeFunctions.extractEntryToFile = new NativeFunction(libZipArchive.getExportByName(moduleExportDetail.name), "int32", [
                    "pointer",
                    "pointer",
                    "int",
                ]);
            } else if (moduleExportDetail.name.indexOf("StartIteration") !== -1) {
                if (DwarfCore.getInstance().getAndroidApiLevel() <= 22) {
                    // int32_t StartIteration(ZipArchiveHandle handle, void** cookie_ptr, const ZipEntryName* optional_prefix)
                    this._nativeFunctions.startIteration = new NativeFunction(libZipArchive.getExportByName(moduleExportDetail.name), "int32", [
                        "pointer",
                        "pointer",
                        "pointer",
                    ]);
                } else {
                    // int32_t StartIteration(ZipArchiveHandle handle, void** cookie_ptr, const ZipEntryName* optional_prefix, const ZipEntryName* optional_suffix)
                    this._nativeFunctions.startIteration = new NativeFunction(libZipArchive.getExportByName(moduleExportDetail.name), "int32", [
                        "pointer",
                        "pointer",
                        "pointer",
                        "pointer",
                    ]);
                }
            }
        }

        // Check pointers
        for (const [key, value] of Object.entries(this._nativeFunctions)) {
            if (!value || value.isNull()) {
                throw new Error("DwarfAndroidZipArchive: Missing pointer to " + key);
            }
        }

        if (isString(archivePath)) {
            this._archivePath = Memory.allocUtf8String(archivePath);
            this._archiveHandle = Memory.alloc(Process.pointerSize);
            const result = this._nativeFunctions.openArchive(this._archivePath, this._archiveHandle);
            if (result !== 0) {
                throw new Error("OpenArchive failed! Result: " + result);
            }
        } else {
            throw new Error("Invalid usage!");
        }
    }

    close = () => {
        if (Process.platform !== "linux" || !Java.available) {
            throw new Error("DwarfAndroidZipArchive not available!");
        }

        if (this._nativeFunctions.openArchive.isNull()) {
            throw new Error("DwarfAndroidZipArchive: Function not available!");
        }

        if (this._archiveHandle.isNull()) {
            throw new Error("DwarfAndroidZipArchive: Invalid handle!");
        }

        this._nativeFunctions.closeArchive(this._archiveHandle.readPointer());
        this._archiveHandle = NULL;
        this._archivePath = NULL;
    };

    extract = (zipPath: string, diskPath: string) => {
        if (Process.platform === "linux" && Java.available) {
            const cookie = Memory.alloc(Process.pointerSize);
            Memory.protect(cookie, Process.pointerSize, "rw-");
            if (DwarfCore.getInstance().getAndroidApiLevel() <= 22) {
                const startIterFn = this._nativeFunctions.startIteration as NativeFunction<number, [NativePointer, NativePointer, NativePointer]>;
                if (startIterFn && startIterFn(this._archiveHandle.readPointer(), cookie, NULL) === 0) {
                    const zipEntry = Memory.alloc(500); // TODO: calc real size
                    const zipName = Memory.alloc(Process.pointerSize + 3); // struct ZipEntryName { const char* name;  uint16_t name_length; };
                    Memory.protect(zipEntry, 500, "rw-");
                    Memory.protect(zipName, Process.pointerSize + 3, "rw-");
                    while (this._nativeFunctions.nextEntry(cookie.readPointer(), zipEntry, zipName) === 0) {
                        const nameLen = zipName.add(Process.pointerSize).readU16();
                        const entryName = zipName.readPointer().readUtf8String(nameLen);
                        if (entryName === zipPath) {
                            const dwarfFile = DwarfCore.getInstance().getFS().fopen(diskPath, "w");
                            const fd = DwarfCore.getInstance().getFS().fileno(dwarfFile);
                            if (this._nativeFunctions.extractEntryToFile(this._archiveHandle.readPointer(), zipEntry, fd) === 0) {
                                DwarfCore.getInstance().getFS().fclose(dwarfFile);
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
                if (this._nativeFunctions.startIteration(this._archiveHandle.readPointer(), cookie, NULL, NULL) === 0) {
                    const zipEntry = Memory.alloc(500); // TODO: calc real size
                    const zipName = Memory.alloc(Process.pointerSize + 3); // struct ZipEntryName { const char* name;  uint16_t name_length; };
                    Memory.protect(zipEntry, 500, "rw-");
                    Memory.protect(zipName, Process.pointerSize + 3, "rw-");
                    while (this._nativeFunctions.nextEntry(cookie.readPointer(), zipEntry, zipName) === 0) {
                        const nameLen = zipName.add(Process.pointerSize).readU16();
                        const entryName = zipName.readPointer().readUtf8String(nameLen);
                        if (entryName === zipPath) {
                            const dwarfFile = DwarfCore.getInstance().getFS().fopen(diskPath, "w");
                            const fd = DwarfCore.getInstance().getFS().fileno(dwarfFile);
                            if (this._nativeFunctions.extractEntryToFile(this._archiveHandle.readPointer(), zipEntry, fd) === 0) {
                                DwarfCore.getInstance().getFS().fclose(dwarfFile);
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

    getContents = (): string[] => {
        if (Process.platform !== "linux" || !Java.available) {
            throw new Error("DwarfAndroidZipArchive not available!");
        }

        const zipContents = new Array<string>();
        if (Process.platform === "linux" && Java.available) {
            const cookie = Memory.alloc(Process.pointerSize);
            Memory.protect(cookie, Process.pointerSize, "rw-");
            if (DwarfCore.getInstance().getAndroidApiLevel() <= 22) {
                const startIterFn = this._nativeFunctions.startIteration as NativeFunction<number, [NativePointer, NativePointer, NativePointer]>;
                if (startIterFn && startIterFn(this._archiveHandle.readPointer(), cookie, NULL) === 0) {
                    const zipEntry = Memory.alloc(500); // TODO: calc real size
                    const zipName = Memory.alloc(Process.pointerSize + 3); // struct ZipEntryName { const char* name;  uint16_t name_length; };
                    Memory.protect(zipEntry, 500, "rw-");
                    Memory.protect(zipName, Process.pointerSize + 3, "rw-");
                    while (this._nativeFunctions.nextEntry(cookie.readPointer(), zipEntry, zipName) === 0) {
                        const nameLen = zipName.add(Process.pointerSize).readU16();
                        const entryName = zipName.readPointer().readUtf8String(nameLen);
                        zipContents.push(entryName);
                    }
                } else {
                    throw new Error("Failed to get Content! Error: StartIteration");
                }
            } else {
                if (this._nativeFunctions.startIteration(this._archiveHandle.readPointer(), cookie, NULL, NULL) === 0) {
                    const zipEntry = Memory.alloc(500); // TODO: calc real size
                    const zipName = Memory.alloc(Process.pointerSize + 3); // struct ZipEntryName { const char* name;  uint16_t name_length; };
                    Memory.protect(zipEntry, 500, "rw-");
                    Memory.protect(zipName, Process.pointerSize + 3, "rw-");
                    while (this._nativeFunctions.nextEntry(cookie.readPointer(), zipEntry, zipName) === 0) {
                        const nameLen = zipName.add(Process.pointerSize).readU16();
                        const entryName = zipName.readPointer().readUtf8String(nameLen);
                        zipContents.push(entryName);
                    }
                } else {
                    throw new Error("Failed to get Content! Error: StartIteration");
                }
            }
        }
        return zipContents;
    };
}
