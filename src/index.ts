/*
    Dwarf - Copyright (C) 2018-2021 Giovanni Rocca (iGio90)

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

import "./_global_funcs";
import "./_global_vars";

import { DwarfCore } from "./DwarfCore";
import { ThreadApi } from "./thread_api";
import { ELF_File } from "./types/elf_file";
import { DwarfHooksManager } from "./hooks_manager";
import { DwarfJavaHelper } from "./java";

global["ELF_File"] = ELF_File;

rpc.exports = {
    api: function (tid: number, apiFunction, apiArguments) {
        trace("RPC::API() -> " + apiFunction);

        if (!DwarfCore.getInstance().getApi().hasOwnProperty(apiFunction) && apiFunction !== "release") {
            throw new Error("Unknown ApiFunction!");
        }
        logDebug("[" + tid + "] RPC-API: " + apiFunction + " | " + "args: " + apiArguments + " (" + Process.getCurrentThreadId() + ")");

        if (typeof apiArguments === "undefined" || apiArguments === null) {
            apiArguments = [];
        }

        try {
            let context = DwarfCore.getInstance().getThreadContext(tid);

            if (isDefined(context)) {
                const threadApi = new ThreadApi(apiFunction, apiArguments);
                context.apiQueue.push(threadApi);
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

            return DwarfCore.getInstance().getApi()[apiFunction].apply(this, apiArguments);
        } catch (e) {
            logErr("Api()", e);
        }
    },
    init: function (procName, wasSpawned, breakStart, enableDebug, enableTrace, hasUI, globalApiFuncs?: Array<string>) {
        //init dwarf
        global.Dwarf = DwarfCore.getInstance();
        global.Dwarf.init(procName, wasSpawned, breakStart, enableDebug, enableTrace, hasUI, globalApiFuncs);
    },

    start: function () {
        DwarfCore.getInstance().start();
    },
    stop: function () {
        DwarfJavaHelper.getInstance().detach();
        DwarfHooksManager.getInstance()
            .getHooks()
            .forEach((dwarfHook) => {
                dwarfHook.remove(true);
            });
        MemoryAccessMonitor.disable();
    },
    keywords: function () {
        const map = [];
        Object.getOwnPropertyNames(global).forEach(function (name) {
            map.push(name);

            // second level
            if (isDefined(global[name])) {
                Object.getOwnPropertyNames(global[name]).forEach(function (sec_name) {
                    map.push(sec_name);
                });
            }
        });
        return uniqueBy(map);
    },
    moduleinfo: function (moduleName: string) {
        if (DwarfCore.getInstance().isBlacklistedModule(moduleName)) {
            return "{}";
        }
        return new Promise((resolve) => {
            let procModule = Process.findModuleByName(moduleName);
            if (isDefined(procModule)) {
                let moduleInfo = Object.assign({ imports: [], exports: [], symbols: [] }, procModule);
                moduleInfo.imports = procModule.enumerateImports();
                moduleInfo.exports = procModule.enumerateExports();
                moduleInfo.symbols = procModule.enumerateSymbols();
                resolve(moduleInfo);
            }
            resolve({});
        }).then((moduleInfo) => {
            return moduleInfo;
        });
    },
    fetchmem: function (address, length = 0) {
        length = parseInt(length);
        var nativePointer = makeNativePointer(address);
        var memoryRange = Process.getRangeByAddress(nativePointer);
        if (isDefined(memoryRange)) {
            if (memoryRange && memoryRange.hasOwnProperty("protection") && memoryRange.protection.indexOf("r") === 0) {
                Memory.protect(memoryRange.base, length, "rwx");
                if (!length) {
                    memoryRange["data"] = ba2hex(memoryRange.base.readByteArray(memoryRange.size));
                } else {
                    memoryRange["data"] = ba2hex(nativePointer.readByteArray(length));
                }
                return memoryRange;
            } else {
                return "Memory not readable!";
            }
        } else {
            return "Unable to find Memory!";
        }
    },
};
