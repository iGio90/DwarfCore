/**
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
**/

import "./_global_funcs";

import { DwarfCore } from "./dwarf";
import { ThreadApi } from "./thread_api";
import { ELF_File } from "./types/elf_file";

global.Dwarf = DwarfCore.getInstance();
global["ELF_File"] = ELF_File;

rpc.exports = {
    api: function(tid: number, apiFunction, apiArguments) {
        trace("RPC::API() -> " + apiFunction);

        if (
            !DwarfCore.getInstance()
                .getApi()
                .hasOwnProperty(apiFunction) &&
            apiFunction !== "release"
        ) {
            throw new Error("Unknown ApiFunction!");
        }
        logDebug("[" + tid + "] RPC-API: " + apiFunction + " | " + "args: " + apiArguments + " (" + Process.getCurrentThreadId() + ")");

        if (typeof apiArguments === "undefined" || apiArguments === null) {
            apiArguments = [];
        }

        try {
            if (Object.keys(Dwarf.threadContexts).length > 0) {
                const threadContext = Dwarf.threadContexts[tid.toString()];
                if (isDefined(threadContext)) {
                    const threadApi = new ThreadApi(apiFunction, apiArguments);
                    threadContext.apiQueue.push(threadApi);
                    const start = Date.now();
                    while (!threadApi.consumed) {
                        Thread.sleep(0.5);

                        //logDebug("[" + tid + "] RPC-API: " + apiFunction + " waiting for api result");

                        if (Date.now() - start > 3 * 1000) {
                            threadApi.result = "";
                            break;
                        }
                    }

                    let ret = threadApi.result;
                    if (!isDefined(ret)) {
                        ret = "";
                    }

                    //logDebug("[" + tid + "] RPC-API: " + apiFunction + " api result: " + ret);

                    return ret;
                }
            }

            return DwarfCore.getInstance()
                .getApi()
                [apiFunction].apply(this, apiArguments);
        } catch (e) {
            logErr("Api()", e);
        }
    },
    init: function(proc_name, breakStart, debug, spawned, globalApiFuncs?: Array<string>) {
        //init dwarf
        DwarfCore.getInstance().init(proc_name, spawned, breakStart, debug, globalApiFuncs);
    },

    start: function() {
        DwarfCore.getInstance().start();
    },
    keywords: function() {
        const map = [];
        Object.getOwnPropertyNames(global).forEach(function(name) {
            map.push(name);

            // second level
            if (isDefined(global[name])) {
                Object.getOwnPropertyNames(global[name]).forEach(function(sec_name) {
                    map.push(sec_name);
                });
            }
        });
        return uniqueBy(map);
    },
    moduleinfo: function(moduleName: string) {
        if (Dwarf.modulesBlacklist.indexOf(moduleName) >= 0) {
            return "{}";
        }
        return new Promise(resolve => {
            let procModule = Process.findModuleByName(moduleName);
            if (isDefined(procModule)) {
                let moduleInfo = Object.assign({ imports: [], exports: [], symbols: [] }, procModule);
                moduleInfo.imports = procModule.enumerateImports();
                moduleInfo.exports = procModule.enumerateExports();
                moduleInfo.symbols = procModule.enumerateSymbols();
                resolve(moduleInfo);
            }
            resolve({});
        }).then(moduleInfo => {
            return JSON.stringify(moduleInfo);
        });
    },
    fetchmem: function(address, length = 0) {
        var nativePointer = ptr(address);
        return new Promise(function(resolve) {
            var memoryRange = Process.findRangeByAddress(nativePointer);
            if (isDefined(memoryRange)) {
                if (memoryRange && memoryRange.hasOwnProperty("protection") && memoryRange.protection.indexOf("r") === 0) {
                    if (!length) {
                        memoryRange["data"] = ba2hex(memoryRange.base.readByteArray(memoryRange.size) || new ArrayBuffer(0));
                    } else {
                        memoryRange["data"] = ba2hex(memoryRange.base.readByteArray(length) || new ArrayBuffer(0));
                    }
                    resolve(memoryRange);
                } else {
                    resolve("Memory not readable!");
                }
            } else {
                resolve("Failed to get Memory!");
            }
        });
    }
};
