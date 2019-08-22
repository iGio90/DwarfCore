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
            if (LogicJava.sdk >= 23) {
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
            }
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