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

import { DwarfHook } from "./types/DwarfHook";
import { NativeHook } from "./types/NativeHook";
import { JavaHook } from "./types/JavaHook";
import { MemoryHook } from "./types/MemoryHook";
import { DwarfCore } from "./DwarfCore";
import { DwarfHookType, DwarfMemoryAccessType } from "./consts";
import { DwarfObserver } from "./DwarfObserver";
import { ModuleLoadHook } from "./types/ModuleLoadHook";
import { ClassLoadHook } from "./types/ClassLoadHook";

/**
 * DwarfHooksManager Singleton
 *
 * use Dwarf.getHooksManager() or DwarfHooksManager.getInstance()
 */
export class DwarfHooksManager {
    protected dwarfHooks: DwarfHook[];

    static getInstance() {
        if (!DwarfHooksManager.instanceRef) {
            DwarfHooksManager.instanceRef = new this();
        }
        return DwarfHooksManager.instanceRef;
    }
    protected initDone: boolean;
    protected moduleLoadHook: ModuleLoadHook | null;
    protected nextHookID: number;
    private static instanceRef: DwarfHooksManager;

    private constructor() {
        if (DwarfHooksManager.instanceRef) {
            throw new Error(
                "DwarfHooksManager already exists! Use DwarfHooksManager.getInstance()/Dwarf.getHooksManager()"
            );
        }
        trace("DwarfHooksManager()");
        this.dwarfHooks = new Array<DwarfHook>();
        this.nextHookID = 0;
        this.moduleLoadHook = null;
        this.initDone = false;
    }

    public addClassLoadHook = (
        hookAddress: DwarfHookAddress,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ): ClassLoadHook => {
        trace("DwarfHooksManager::addClassLoadHook()");

        if (!isString(hookAddress)) {
            throw new Error("DwarfHooksManager::addClassLoadHook() => Invalid Arguments!");
        }

        this.checkExists(hookAddress);

        try {
            const classLoadHook = new ClassLoadHook(hookAddress as string, userCallback, isSingleShot, isEnabled);
            this.dwarfHooks.push(classLoadHook);
            this.update(true);
            return classLoadHook;
        } catch (e) {
            logErr("DwarfHooksManager::addClassLoadHook()", e);
            throw e;
        }
    };

    /**
     * @param  {DwarfHookType} bpType
     * @param  {NativePointer|string} hookAddress
     * @param  {boolean} bpEnabled?
     */
    public addHook = (
        bpType: DwarfHookType,
        hookAddress: DwarfHookAddress,
        userCallback: DwarfCallback,
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) => {
        trace("DwarfHooksManager::addHook()");

        switch (bpType) {
            case DwarfHookType.NATIVE:
                return this.addNativeHook(hookAddress, userCallback, isSingleShot, isEnabled);
            case DwarfHookType.JAVA: {
                const className = (hookAddress as string).substr(0, (hookAddress as string).lastIndexOf("."));
                const methodName = (hookAddress as string).substr((hookAddress as string).lastIndexOf(".") + 1);
                return this.addJavaHook(className, methodName, userCallback, isSingleShot, isEnabled);
            }
            case DwarfHookType.CLASS_LOAD:
                return this.addClassLoadHook(hookAddress, userCallback, isSingleShot, isEnabled);
            case DwarfHookType.OBJC:
                return this.addObjcHook(hookAddress as string, userCallback, isSingleShot, isEnabled);
            case DwarfHookType.MEMORY: {
                if (!isString(userCallback) && !isFunction(userCallback)) {
                    throw new Error("DwarfHooksManager::addHook() -> Invalid Callback!");
                }
                return this.addMemoryHook(
                    hookAddress,
                    // tslint:disable-next-line: no-bitwise
                    DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE,
                    userCallback as fEmptyReturn | string,
                    isSingleShot,
                    isEnabled
                );
            }
            case DwarfHookType.MODULE_LOAD:
                return this.addModuleLoadHook(hookAddress as string, userCallback, isSingleShot, isEnabled);
            default:
                break;
        }
        throw new Error("DwarfHooksManager::addHook() -> Unknown HookType!");
    };

    /**
     * @param  {string} hookAddress
     * @param  {boolean} bpEnabled?
     */
    public addJavaHook = (
        className: string,
        methodName: string = "$init",
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) => {
        trace("DwarfHooksManager::addJavaHook()");

        if (!Java.available) {
            throw new Error("Java not available!");
        }

        this.checkExists(className + "." + methodName);

        try {
            const javaHook = new JavaHook(className, methodName, userCallback, isEnabled, isSingleShot);
            if (isDefined(javaHook)) {
                this.dwarfHooks.push(javaHook);
                this.update(true);
                return javaHook;
            }
            throw new Error("failed");
        } catch (error) {
            logErr("DwarfHooksManager::addJavaHook()", error);
            throw error;
        }
    };

    public addMemoryHook = (
        hookAddress: NativePointer | string,
        // tslint:disable-next-line: no-bitwise
        bpFlags: number = DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE,
        userCallback: fEmptyReturn | string = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) => {
        trace("DwarfHooksManager::addMemoryHook()");

        this.checkExists(hookAddress);

        try {
            const memHook = new MemoryHook(
                makeNativePointer(hookAddress),
                bpFlags,
                userCallback,
                isSingleShot,
                isEnabled
            );
            this.dwarfHooks.push(memHook);
            this.updateMemoryHooks();
            this.update(true);
            return memHook;
        } catch (error) {
            logErr("DwarfHooksManager::addMemoryHook()", error);
            throw error;
        }
    };

    public addMemoryHookInternal = (memBp: MemoryHook) => {
        memBp.isInternal = true;
        this.dwarfHooks.push(memBp);
        this.updateMemoryHooks();
    };

    /**
     * @param  {string} hookAddress
     * @param  {boolean} bpEnabled?
     */
    public addModuleLoadHook = (
        moduleName: string,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) => {
        trace("DwarfHooksManager::addModuleLoadHook()");

        if (!isString(moduleName)) {
            throw new Error("DwarfHooksManager::addModuleLoadHook() -> Invalid Arguments!");
        }

        this.checkExists(moduleName);

        try {
            const moduleLoadHook = new ModuleLoadHook(moduleName, userCallback, isSingleShot, isEnabled);
            if (moduleLoadHook) {
                this.dwarfHooks.push(moduleLoadHook);
                this.update(true);
                return moduleLoadHook;
            }
        } catch (e) {
            console.log(JSON.stringify(e));
        }
    };

    public addNativeHook = (
        hookAddress: DwarfHookAddress,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ): NativeHook => {
        trace("DwarfHooksManager::addNativeHook()");

        hookAddress = makeNativePointer(hookAddress);

        if (!checkNativePointer(hookAddress)) {
            throw new Error("DwarfHooksManager::addNativeHook() => Invalid Address!");
        }

        this.checkExists(hookAddress);

        try {
            const nativeHook = new NativeHook(hookAddress, userCallback, isSingleShot, isEnabled);
            this.dwarfHooks.push(nativeHook);
            this.update(true);
            return nativeHook;
        } catch (error) {
            logErr("DwarfHooksManager::addNativeHook()", error);
            throw error;
        }
    };

    /**
     * @param  {string} hookAddress
     * @param  {boolean} bpEnabled?
     */
    public addObjcHook = (
        hookAddress: string,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) => {
        trace("DwarfHooksManager::addObjcHook()");

        this.checkExists(hookAddress);

        throw new Error("DwarfHooksManager::addObjcHook() -> Not implemented");
    };

    /**
     * @param  {NativePointer|string} hookAddress
     * @returns boolean
     */
    public disableHookAtAddress = (hookAddress: NativePointer | string): boolean => {
        trace("DwarfHooksManager::disableHookAtAddress()");

        const dwarfHook = this.getHookByAddress(hookAddress);
        if (dwarfHook !== null) {
            dwarfHook.disable();
            return dwarfHook.isEnabled();
        }
    };

    /**
     * @param  {NativePointer|string} hookAddress
     * @returns boolean
     */
    public enableHookAtAddress = (hookAddress: NativePointer | string): boolean => {
        trace("DwarfHooksManager::enableHookAtAddress()");

        const dwarfHook = this.getHookByAddress(hookAddress);
        if (dwarfHook !== null) {
            dwarfHook.enable();
            return dwarfHook.isEnabled();
        }
    };
    /**
     * @param  {NativePointer|string} hookAddress
     * @returns DwarfHook
     */
    public getHookByAddress = (
        hookAddress: NativePointer | string,
        checkEnabled: boolean = false,
        checkForType?: DwarfHookType
    ): DwarfHook | null => {
        trace("DwarfHooksManager::getHookByAddress()");

        let bpFindAddress;
        if (typeof hookAddress === "string") {
            bpFindAddress = hookAddress;
        } else if (typeof hookAddress === "number") {
            bpFindAddress = ptr(hookAddress).toString();
        } else {
            if (hookAddress.constructor.name !== "NativePointer" || hookAddress.isNull()) {
                throw new Error("DwarfHooksManager::getHookByAddress() -> Invalid Address!");
            }
            bpFindAddress = hookAddress.toString();
        }
        let dwarfHook = null;
        for (const bp of this.dwarfHooks) {
            if (bp.getAddress() === bpFindAddress) {
                if (checkEnabled && !bp.isEnabled()) {
                    continue;
                }
                if (checkForType && bp.getType() !== checkForType) {
                    continue;
                }
                dwarfHook = bp;
                break;
            }
        }

        return dwarfHook;
    };

    public getHookById = (hookID: number): DwarfHook => {
        trace("DwarfHooksManager::getHookById()");

        for (const dwarfHook of this.dwarfHooks) {
            if (dwarfHook.getHookId() === hookID) {
                return dwarfHook;
            }
        }
        return null;
    };

    public getHooks = (): DwarfHook[] => {
        trace("DwarfHooksManager::getHooks()");

        const dwarfHooks = this.dwarfHooks.filter((breakpoint) => {
            return !breakpoint.hasOwnProperty("isInternal");
        });
        return dwarfHooks;
    };

    public getNextHookID(): number {
        trace("DwarfHooksManager::getNextHookID()");

        this.nextHookID++;
        return this.nextHookID;
    }

    public handleMemoryHooks(details: MemoryAccessDetails) {
        trace("DwarfHooksManager::handleMemoryHooks()");

        MemoryAccessMonitor.disable();

        const memoryAddress = details.address;
        const dwarfHook = DwarfHooksManager.getInstance().getHookByAddress(memoryAddress, true, DwarfHookType.MEMORY);

        // not in hooks
        if (dwarfHook === null) {
            // let dwarfobserver handle
            DwarfObserver.getInstance().handleMemoryAccess(details);
        } else {
            const memoryHook = dwarfHook as MemoryHook;
            let handleBp = false;
            switch (details.operation) {
                case "read":
                    // tslint:disable-next-line: no-bitwise
                    if (memoryHook.getFlags() & DwarfMemoryAccessType.READ) {
                        handleBp = true;
                    }
                    break;
                case "write":
                    // tslint:disable-next-line: no-bitwise
                    if (memoryHook.getFlags() & DwarfMemoryAccessType.WRITE) {
                        handleBp = true;
                    }
                    break;
                case "execute":
                    // tslint:disable-next-line: no-bitwise
                    if (memoryHook.getFlags() & DwarfMemoryAccessType.EXECUTE) {
                        handleBp = true;
                    }
                    break;
            }
            if (handleBp) {
                memoryHook.onEnterCallback(memoryHook, this, arguments);
            }
        }
        DwarfHooksManager.getInstance().updateMemoryHooks();
    }

    public initialize() {
        trace("DwarfHooksManager::initialize()");

        if (this.initDone) {
            logDebug("DwarfHooksManager => Init already done!");
        }
        const self = this;
        if (Process.platform === "windows") {
            // windows native onload code
            const module = Process.findModuleByName("kernel32.dll");
            if (module !== null) {
                const dllExports = module.enumerateExports();
                let loadlibaPtr = NULL;
                let loadlibexaPtr = NULL;
                let loadlibwPtr = NULL;
                let loadlibexwPtr = NULL;

                dllExports.forEach((symbol) => {
                    if (symbol.name.indexOf("LoadLibraryA") >= 0) {
                        loadlibaPtr = symbol.address;
                    } else if (symbol.name.indexOf("LoadLibraryW") >= 0) {
                        loadlibwPtr = symbol.address;
                    } else if (symbol.name.indexOf("LoadLibraryExA") >= 0) {
                        loadlibexaPtr = symbol.address;
                    } else if (symbol.name.indexOf("LoadLibraryExW") >= 0) {
                        loadlibexwPtr = symbol.address;
                    }

                    if (
                        loadlibaPtr !== NULL &&
                        loadlibwPtr !== NULL &&
                        loadlibexaPtr !== NULL &&
                        loadlibexwPtr !== NULL
                    ) {
                        return;
                    }
                });

                if (loadlibaPtr !== NULL && loadlibwPtr !== NULL && loadlibexaPtr !== NULL && loadlibexwPtr !== NULL) {
                    Interceptor.attach(loadlibaPtr, {
                        onEnter(args) {
                            const moduleName = args[0].readAnsiString();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave(retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        },
                    });
                    Interceptor.attach(loadlibexaPtr, {
                        onEnter(args) {
                            const moduleName = args[0].readAnsiString();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave(retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        },
                    });
                    Interceptor.attach(loadlibwPtr, {
                        onEnter(args) {
                            const moduleName = args[0].readUtf16String();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave(retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        },
                    });
                    Interceptor.attach(loadlibexwPtr, {
                        onEnter(args) {
                            const moduleName = args[0].readUtf16String();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave(retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        },
                    });
                }
            }
        }

        // TODO: add some real android check
        else if (Java.available && Process.platform === "linux") {
            let useFallback = true;
            const linker = Process.findModuleByName(Process.pointerSize === 4 ? "linker" : "linker64");
            if (linker) {
                linker.enumerateSymbols().forEach((moduleSymbol) => {
                    // __dl__Z9do_dlopenPKciPK17android_dlextinfoPKv
                    if (moduleSymbol.name.includes("do_dlopen")) {
                        logDebug(
                            "DwarfHooksManager: Hooking (do_dlopen) -> " +
                                moduleSymbol.name +
                                " at " +
                                moduleSymbol.address
                        );
                        Interceptor.attach(moduleSymbol.address, {
                            onEnter(args) {
                                const modulePath = args[0].readUtf8String();
                                self.handleModuleLoadOnEnter.apply(null, [this, modulePath, args]);
                            },
                            onLeave(retVal) {
                                self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                            },
                        });
                        useFallback = false;
                    }
                });
            }

            if (useFallback) {
                // https://android.googlesource.com/platform/art/+/android-6.0.0_r26/runtime/java_vm_ext.cc#596
                const artModule = Process.findModuleByName("libart.so");
                if (artModule) {
                    artModule.enumerateExports().forEach((moduleExport) => {
                        if (moduleExport.name.includes("LoadNativeLibrary")) {
                            logDebug(
                                "DwarfHooksManager: Hooking (LoadNativeLibrary) -> " +
                                    moduleExport.name +
                                    " at " +
                                    moduleExport.address
                            );
                            // changed in sdk 22, 23, 25 but we're only interested in path arg
                            // <=22 args = (void *JavaVMExt, std::string &path,...)
                            // >=23 args = (void *JavaVMExt, JNIEnv *env, std::string &path, ...)
                            const argNum = DwarfCore.getInstance().getAndroidApiLevel() <= 22 ? 1 : 2;
                            Interceptor.attach(moduleExport.address, {
                                onEnter(args) {
                                    const modulePath = readStdString(args[argNum]);
                                    self.handleModuleLoadOnEnter.apply(null, [this, modulePath, args]);
                                },
                                onLeave(retVal) {
                                    self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                                },
                            });
                        }
                    });
                }
                // https://android.googlesource.com/platform/dalvik/+/eclair-release/vm/Native.c#443
                const dvmModule = Process.findModuleByName("libdvm.so");
                if (dvmModule) {
                    dvmModule.enumerateExports().forEach((moduleExport) => {
                        if (moduleExport.name.includes("dvmLoadNativeCode")) {
                            logDebug(
                                "DwarfHooksManager: Hooking (dvmLoadNativeCode) -> " +
                                    moduleExport.name +
                                    " at " +
                                    moduleExport.address
                            );
                            Interceptor.attach(moduleExport.address, {
                                onEnter(args) {
                                    const modulePath = args[0].readUtf8String();
                                    self.handleModuleLoadOnEnter.apply(null, [this, modulePath, args]);
                                },
                                onLeave(retVal) {
                                    self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                                },
                            });
                        }
                    });
                }
            }
        }
        this.initDone = true;
    }

    /**
     * @param  {NativePointer|string} hookAddress
     * @returns boolean
     */
    public removeHookAtAddress = (hookAddress: NativePointer | string, syncUi: boolean): boolean => {
        trace("DwarfHooksManager::removeHookAtAddress()");

        const dwarfHook = this.getHookByAddress(hookAddress);

        if (dwarfHook !== null) {
            dwarfHook.remove(syncUi);
            return true;
        }
        return false;
    };

    /**
     * @param  {number} hookID
     * @returns boolean
     */
    public removeHookById = (hookID: number): boolean => {
        trace("DwarfHooksManager::removeHookById()");

        for (const dwarfHook of this.dwarfHooks) {
            if (dwarfHook.getHookId() === hookID) {
                return this.removeHookAtAddress(dwarfHook.getAddress(), true);
            }
        }
        return false;
    };

    public removeModuleLoadHook = (moduleName: string): boolean => {
        trace("DwarfHooksManager::removeModuleLoadHook()");

        if (!isString(moduleName)) {
            throw new Error("DwarfHooksManager::removeModuleLoadHook() -> Invalid Arguments!");
        }
        return this.removeHookAtAddress(moduleName, true);
    };

    public replaceCallback = (hookID: number, userCallback: DwarfCallback) => {
        trace("DwarfHooksManager::replaceCallback()");

        const dwarfHook = this.getHookById(hookID);

        if (isDefined(dwarfHook)) {
            try {
                return dwarfHook.setCallback(userCallback);
            } catch (e) {
                logErr("DwarfHooksManager::replaceCallback()", e);
                throw e;
            }
        }
        throw new Error("DwarfHooksManager::replaceCallback() -> No Hook with id " + hookID);
    };

    /**
     * Removes SingleShots and syncs ui
     */
    public update = (syncUi: boolean) => {
        trace("DwarfHooksManager::update()");

        const newHooks = [];

        for (const i in DwarfHooksManager.getInstance().dwarfHooks) {
            if (
                DwarfHooksManager.getInstance().dwarfHooks[i].isSingleShot() &&
                DwarfHooksManager.getInstance().dwarfHooks[i].getHits() &&
                !DwarfHooksManager.getInstance().dwarfHooks[i].isActive()
            ) {
                delete DwarfHooksManager.getInstance().dwarfHooks[i];
            } else {
                newHooks.push(DwarfHooksManager.getInstance().dwarfHooks[i]);
            }
        }
        DwarfHooksManager.getInstance().dwarfHooks = newHooks;

        // sync ui
        if (syncUi) {
            DwarfCore.getInstance().sync({ dwarfHooks: DwarfHooksManager.getInstance().dwarfHooks });
        }
    };

    /**
     * Windows related stuff to handle MemoryHooks
     * Call it after something MemoryHook related changes
     */
    public updateMemoryHooks = (): void => {
        trace("DwarfHooksManager::updateMemoryHooks()");

        MemoryAccessMonitor.disable();

        const self = this;

        // Get Watchlocations
        const memoryHooks: MemoryAccessRange[] = DwarfObserver.getInstance().getLocationsInternal();

        // append our membreakpoints
        for (const memHook of self.dwarfHooks) {
            if (memHook.getType() === DwarfHookType.MEMORY) {
                if (memHook.isEnabled()) {
                    const memAddr = memHook.getAddress() as NativePointer;
                    memoryHooks.push({ base: memAddr, size: 1 });
                }
            }
        }

        if (memoryHooks.length > 0) {
            MemoryAccessMonitor.enable(memoryHooks, { onAccess: self.handleMemoryHooks });
        }
    };

    private checkExists(hookAddress: any): void {
        trace("DwarfHooksManager::checkExists()");

        for (const dwarfHook of this.dwarfHooks) {
            if (dwarfHook.getAddress().toString() === hookAddress.toString()) {
                throw new Error("DwarfHooksManager::addHook() -> Existing Hook at given Address!");
            }
        }
    }

    /**
     * Internal Helper to find the ModuleLoadHook and calling the hookCallback
     *
     * @param  {any} thisArg
     * @param  {string} modulePath
     * @param  {InvocationArguments} funcArgs
     */
    private handleModuleLoadOnEnter = (thisArg: any, modulePath: string, funcArgs: InvocationArguments) => {
        trace("DwarfHooksManager::handleModuleLoadOnEnter()");

        let moduleName = "";
        if (Process.platform === "windows") {
            moduleName = modulePath.includes("\\")
                ? modulePath.substring(modulePath.lastIndexOf("\\") + 1)
                : modulePath;
        } else {
            moduleName = modulePath.includes("/") ? modulePath.substring(modulePath.lastIndexOf("/") + 1) : modulePath;
        }

        this.dwarfHooks.forEach((dwarfHook) => {
            if (dwarfHook.getType() === DwarfHookType.MODULE_LOAD) {
                if (dwarfHook.getAddress() === moduleName || dwarfHook.getAddress() === modulePath) {
                    // store the hook so we can call onLeave then
                    this.moduleLoadHook = dwarfHook as ModuleLoadHook;
                    // handle userCallback
                    this.moduleLoadHook.onEnterCallback(dwarfHook, thisArg, funcArgs);
                }
            }
        });

        DwarfCore.getInstance().sync({
            moduleLoad: {
                name: moduleName,
                path: moduleName === modulePath ? Process.findModuleByName(moduleName)?.path || modulePath : modulePath,
            },
        });
    };

    /**
     * Internal Helper to call the onLeave
     *
     * @param  {any} thisArg
     * @param  {InvocationReturnValue} retVal
     */
    private handleModuleLoadOnLeave = (thisArg: any, retVal: InvocationReturnValue) => {
        trace("DwarfHooksManager::handleModuleLoadOnLeave()");

        // our stored hook
        if (isDefined(this.moduleLoadHook)) {
            this.moduleLoadHook.onLeaveCallback(this.moduleLoadHook, thisArg, retVal);
        }
        // reset
        this.moduleLoadHook = null;

        const procModule = Process.findModuleByAddress(retVal);

        DwarfCore.getInstance().sync({
            moduleLoaded: {
                name: procModule.name,
                base: procModule.base.toString(),
                size: procModule.size,
                path: procModule.path,
                imports: procModule.enumerateImports(),
                exports: procModule.enumerateExports(),
                symbols: procModule.enumerateSymbols(),
            },
        });
    };
}
