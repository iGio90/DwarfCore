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


import { Api } from "./api";
import { Dwarf } from "./dwarf";
import { LogicBreakpoint } from "./logic_breakpoint";
import { LogicJava } from "./logic_java";
import { Utils } from "./utils";

export class LogicInitialization {
    static nativeModuleInitializationCallbacks = {};

    static hitModuleLoading(moduleName) {
        if (!Utils.isString(moduleName)) {
            return;
        }

        if (Dwarf.modulesBlacklist.indexOf(moduleName) >= 0) {
            return;
        }

        const module: Module = Process.findModuleByName(moduleName);
        if (module === null) {
            return;
        }

        const moduleInfo = Api.enumerateModuleInfo(module);

        const tid = Process.getCurrentThreadId();
        Dwarf.loggedSend('module_initialized:::' + tid + ':::' + JSON.stringify(moduleInfo));
        const modIndex = Object.keys(LogicInitialization.nativeModuleInitializationCallbacks).find(function (ownModuleName) {
            if (ownModuleName === moduleName) {
                return moduleName;
            }
        });

        if (Utils.isDefined(modIndex)) {
            const userCallback = LogicInitialization.nativeModuleInitializationCallbacks[modIndex];
            if (Utils.isDefined(userCallback)) {
                userCallback.call(this); //TODO: this == this class == LogicInitialization
            } else {
                Dwarf.loggedSend("breakpoint_module_initialization_callback:::" + tid + ':::' + JSON.stringify({
                    'module': moduleInfo['name'], 'moduleBase': moduleInfo['base'], 'moduleEntry': moduleInfo['entry']
                }));

                LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT_INITIALIZATION,
                    this['context'].pc, this['context']);
            }
        }
    }

    static init() {
        if (Process.platform === 'windows') {
            // windows native onload code
            const module = Process.findModuleByName('kernel32.dll');
            if (module !== null) {
                const symbols = module.enumerateExports();
                let loadliba_ptr = NULL;
                let loadlibexa_ptr = NULL;
                let loadlibw_ptr = NULL;
                let loadlibexw_ptr = NULL;

                symbols.forEach(symbol => {
                    if (symbol.name.indexOf('LoadLibraryA') >= 0) {
                        loadliba_ptr = symbol.address;
                    } else if (symbol.name.indexOf('LoadLibraryW') >= 0) {
                        loadlibw_ptr = symbol.address;
                    } else if (symbol.name.indexOf('LoadLibraryExA') >= 0) {
                        loadlibexa_ptr = symbol.address;
                    } else if (symbol.name.indexOf('LoadLibraryExW') >= 0) {
                        loadlibexw_ptr = symbol.address;
                    }

                    if ((loadliba_ptr != NULL) && (loadlibw_ptr != NULL) && (loadlibexa_ptr != NULL) && (loadlibexw_ptr != NULL)) {
                        return;
                    }
                });

                if ((loadliba_ptr != NULL) && (loadlibw_ptr != NULL) && (loadlibexa_ptr != NULL) && (loadlibexw_ptr != NULL)) {
                    Interceptor.attach(loadliba_ptr, function (args) {
                        try {
                            const w = args[0].readAnsiString();
                            LogicInitialization.hitModuleLoading.apply(this, [w]);
                        } catch (e) {
                            Utils.logErr('Dwarf.start', e);
                        }
                    });
                    Interceptor.attach(loadlibexa_ptr, function (args) {
                        try {
                            const w = args[0].readAnsiString();
                            LogicInitialization.hitModuleLoading.apply(this, [w]);
                        } catch (e) {
                            Utils.logErr('Dwarf.start', e);
                        }
                    });
                    Interceptor.attach(loadlibw_ptr, function (args) {
                        try {
                            const w = args[0].readUtf16String();
                            LogicInitialization.hitModuleLoading.apply(this, [w]);
                        } catch (e) {
                            Utils.logErr('Dwarf.start', e);
                        }
                    });
                    Interceptor.attach(loadlibexw_ptr, function (args) {
                        try {
                            const w = args[0].readUtf16String();
                            LogicInitialization.hitModuleLoading.apply(this, [w]);
                        } catch (e) {
                            Utils.logErr('Dwarf.start', e);
                        }
                    });
                }
            }
        } else if (LogicJava.available) {
            // android native onload code
            // taken from new core without onLeave!!!
            //https://android.googlesource.com/platform/art/+/android-6.0.0_r26/runtime/java_vm_ext.cc#596
            const artModule = Process.findModuleByName("libart.so");
            if (artModule) {
                for (let moduleExportDetail of artModule.enumerateExports()) {
                    if (moduleExportDetail.name.indexOf("LoadNativeLibrary") != -1) {
                        //changed in sdk 22, 23, 25 but we're only interested in path arg
                        //<=22 args = (void *JavaVMExt, std::string &path,...)
                        //>=23 args = (void *JavaVMExt, JNIEnv *env, std::string &path, ...)
                        const argNum = LogicJava.sdk <= 22 ? 1 : 2;
                        Interceptor.attach(moduleExportDetail.address, {
                            onEnter: function(args) {
                                const moduleName = Utils.readStdString(args[argNum]);
                                LogicInitialization.hitModuleLoading.apply(this, [moduleName]);
                            }
                        });
                    }
                }
            }
            //https://android.googlesource.com/platform/dalvik/+/eclair-release/vm/Native.c#443
            const dvmModule = Process.findModuleByName("libdvm.so");
            if (dvmModule) {
                for (let moduleExportDetail of dvmModule.enumerateExports()) {
                    if (moduleExportDetail.name.indexOf("dvmLoadNativeCode") != -1) {
                        Interceptor.attach(moduleExportDetail.address, {
                            onEnter: function(args) {
                                const moduleName = args[0].readUtf8String();
                                LogicInitialization.hitModuleLoading.apply(this, [moduleName]);
                            }
                        });
                    }
                }
            }
            /*if (LogicJava.sdk >= 23) {
                const module = Process.findModuleByName(Process.arch.indexOf('64') >= 0 ? 'linker64' : "linker");
                if (module !== null) {
                    const symbols = module.enumerateSymbols();
                    const call_constructors = symbols.find(symbol => symbol.name.indexOf('call_constructors') >= 0);

                    if (Utils.isDefined(call_constructors)) {
                        Interceptor.attach(call_constructors.address, function (args) {
                            try {
                                LogicInitialization.hitModuleLoading.apply(this, [args[4].readUtf8String()]);
                            } catch (e) {
                            }
                        });
                    }
                }
            } else {
                if (Process.arch === 'ia32') {
                    // this suck hard but it's the best way i can think
                    // working on latest nox emulator 5.1.1
                    const linkerRanges = Process.findModuleByName('linker').enumerateRanges('r-x');
                    for (let i = 0; i < linkerRanges.length; i++) {
                        const range = linkerRanges[i];
                        const res = Memory.scanSync(range.base, range.size, '89 FD C7 44 24 30 00 00 00 00');
                        if (res.length > 0) {
                            Interceptor.attach(res[0].address, function () {
                                const context = this.context as Ia32CpuContext;
                                if (context.ecx.toInt32() !== 0x8) {
                                    return;
                                }

                                try {
                                    const w = context.esi.readCString();
                                    LogicInitialization.hitModuleLoading.apply(this, [w]);
                                } catch (e) {
                                    Utils.logErr('Dwarf.onLoad setup', e);
                                }
                            });
                            break;
                        }
                    }
                }
            }*/
        }
    }

    static hookModuleInitialization(moduleName: string, callback: Function): boolean {
        if (!Utils.isString(moduleName) ||
            Utils.isDefined(LogicInitialization.nativeModuleInitializationCallbacks[moduleName])) {
            return false;
        }

        LogicInitialization.nativeModuleInitializationCallbacks[moduleName] = callback;
        return true;
    }

    static putModuleInitializationBreakpoint(moduleName: string) {
        const applied = LogicInitialization.hookModuleInitialization(moduleName, null);
        if (applied) {
            Dwarf.loggedSend('module_initialization_callback:::' + moduleName);
        }
        return applied;
    }

    static removeModuleInitializationBreakpoint(moduleName: string) {
        if (typeof LogicInitialization.nativeModuleInitializationCallbacks[moduleName] !== 'undefined') {
            delete LogicInitialization.nativeModuleInitializationCallbacks[moduleName];
            return true;
        }

        return false;
    }
}