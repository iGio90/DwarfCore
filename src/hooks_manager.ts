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

import { DwarfHook } from "./types/dwarf_hook";
import { NativeHook } from "./types/native_hook";
import { JavaHook } from "./types/java_hook";
import { MemoryHook } from "./types/memory_hook";
import { DwarfCore } from "./dwarf";
import { DwarfHookType, DwarfMemoryAccessType } from "./consts";
import { DwarfObserver } from "./dwarf_observer";
import { ModuleLoadHook } from "./types/module_load_hook";
import { ClassLoadHook } from "./types/class_load_hook";

/**
 * DwarfHooksManager Singleton
 *
 * use Dwarf.getHooksManager() or DwarfHooksManager.getInstance()
 */
export class DwarfHooksManager {
    private static instanceRef: DwarfHooksManager;
    protected nextHookID: number;
    protected dwarfHooks: Array<DwarfHook>;
    protected moduleLoadHook: ModuleLoadHook | null;
    protected initDone: boolean;

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

    static getInstance() {
        if (!DwarfHooksManager.instanceRef) {
            DwarfHooksManager.instanceRef = new this();
        }
        return DwarfHooksManager.instanceRef;
    }

    public initialize() {
        if (this.initDone) {
            logDebug("DwarfHooksManager => Init already done!");
        }
        const self = this;
        if (Process.platform === "windows") {
            // windows native onload code
            const module = Process.findModuleByName("kernel32.dll");
            if (module !== null) {
                const symbols = module.enumerateExports();
                let loadliba_ptr = NULL;
                let loadlibexa_ptr = NULL;
                let loadlibw_ptr = NULL;
                let loadlibexw_ptr = NULL;

                symbols.forEach(symbol => {
                    if (symbol.name.indexOf("LoadLibraryA") >= 0) {
                        loadliba_ptr = symbol.address;
                    } else if (symbol.name.indexOf("LoadLibraryW") >= 0) {
                        loadlibw_ptr = symbol.address;
                    } else if (symbol.name.indexOf("LoadLibraryExA") >= 0) {
                        loadlibexa_ptr = symbol.address;
                    } else if (symbol.name.indexOf("LoadLibraryExW") >= 0) {
                        loadlibexw_ptr = symbol.address;
                    }

                    if (
                        loadliba_ptr != NULL &&
                        loadlibw_ptr != NULL &&
                        loadlibexa_ptr != NULL &&
                        loadlibexw_ptr != NULL
                    ) {
                        return;
                    }
                });

                if (loadliba_ptr != NULL && loadlibw_ptr != NULL && loadlibexa_ptr != NULL && loadlibexw_ptr != NULL) {
                    Interceptor.attach(loadliba_ptr, {
                        onEnter: function(args) {
                            const moduleName = args[0].readAnsiString();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave: function(retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        }
                    });
                    Interceptor.attach(loadlibexa_ptr, {
                        onEnter: function(args) {
                            const moduleName = args[0].readAnsiString();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave: function(retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        }
                    });
                    Interceptor.attach(loadlibw_ptr, {
                        onEnter: function(args) {
                            const moduleName = args[0].readUtf16String();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave: function(retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        }
                    });
                    Interceptor.attach(loadlibexw_ptr, {
                        onEnter: function(args) {
                            const moduleName = args[0].readUtf16String();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave: function(retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        }
                    });
                }
            }
        } else if (Java.available) {
            //https://android.googlesource.com/platform/art/+/android-6.0.0_r26/runtime/java_vm_ext.cc#596
            const artModule = Process.findModuleByName("libart.so");
            if (artModule) {
                for (let moduleExportDetail of artModule.enumerateExports()) {
                    if (moduleExportDetail.name.indexOf("LoadNativeLibrary") != -1) {
                        //changed in sdk 22, 23, 25 but we're only interested in path arg
                        //<=22 args = (void *JavaVMExt, std::string &path,...)
                        //>=23 args = (void *JavaVMExt, JNIEnv *env, std::string &path, ...)
                        const argNum = Dwarf.getAndroidApiLevel() <= 22 ? 1 : 2;
                        Interceptor.attach(moduleExportDetail.address, {
                            onEnter: function(args) {
                                const moduleName = readStdString(args[argNum]);
                                self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                            },
                            onLeave: function(retVal) {
                                self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
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
                                self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                            },
                            onLeave: function(retVal) {
                                self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                            }
                        });
                    }
                }
            }
        }
        this.initDone = true;
    }

    public getNextHookID(): number {
        this.nextHookID++;
        return this.nextHookID;
    }

    public getHooks = (): Array<DwarfHook> => {
        trace("DwarfHooksManager::getHooks()");

        const dwarfHooks = this.dwarfHooks.filter(breakpoint => {
            return !breakpoint.hasOwnProperty("isInternal");
        });
        return dwarfHooks;
    };

    private checkExists(hookAddress: any): void {
        for (let dwarfHook of this.dwarfHooks) {
            if (dwarfHook.getAddress().toString() == hookAddress.toString()) {
                throw new Error("DwarfHooksManager::addHook() -> Existing Hook at given Address!");
            }
        }
    }

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
            case DwarfHookType.MEMORY:
                return this.addMemoryHook(
                    hookAddress,
                    DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE,
                    userCallback,
                    isSingleShot,
                    isEnabled
                );
            case DwarfHookType.MODULE_LOAD:
                return this.addModuleLoadHook(hookAddress as string, userCallback, isSingleShot, isEnabled);
            default:
                break;
        }
        throw new Error("DwarfHooksManager::addHook() -> Unknown HookType!");
    };

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
            this.update();
            return classLoadHook;
        } catch (e) {
            logErr("DwarfHooksManager::addClassLoadHook()", e);
            throw e;
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
            this.update();
            return nativeHook;
        } catch (error) {
            logErr("DwarfHooksManager::addNativeHook()", error);
            throw error;
        }
    };

    public addMemoryHook = (
        hookAddress: NativePointer | string,
        bpFlags: number = DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE,
        userCallback: DwarfCallback = "breakpoint",
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
            this.update();
            return memHook;
        } catch (error) {
            logErr("DwarfHooksManager::addMemoryHook()", error);
            throw error;
        }
    };

    public addMemoryHookInternal = (memBp: MemoryHook) => {
        memBp["isInternal"] = true;
        this.dwarfHooks.push(memBp);
        this.updateMemoryHooks();
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
                this.update();
                return javaHook;
            }
            throw new Error("failed");
        } catch (error) {
            logErr("DwarfHooksManager::addJavaHook()", error);
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
                this.update();
                return moduleLoadHook;
            }
        } catch (e) {
            console.log(JSON.stringify(e));
        }
    };

    public removeModuleLoadHook = (moduleName: string): boolean => {
        trace("DwarfHooksManager::removeModuleLoadHook()");

        if (!isString(moduleName)) {
            throw new Error("DwarfHooksManager::removeModuleLoadHook() -> Invalid Arguments!");
        }
        return this.removeHookAtAddress(moduleName);
    };

    /**
     * @param  {NativePointer|string} hookAddress
     * @returns boolean
     */
    public removeHookAtAddress = (hookAddress: NativePointer | string): boolean => {
        trace("DwarfHooksManager::removeHookAtAddress()");
        let dwarfHook = this.getHookByAddress(hookAddress);

        if (dwarfHook !== null) {
            if (dwarfHook.getType() == DwarfHookType.NATIVE) {
                (dwarfHook as NativeHook).detach();
            }

            const newHooks = new Array<DwarfHook>();
            for (const i in this.dwarfHooks) {
                if (dwarfHook.getHookId() === this.dwarfHooks[i].getHookId()) {
                    delete this.dwarfHooks[i];
                } else {
                    newHooks.push(this.dwarfHooks[i]);
                }
            }
            if (newHooks.length > 0) {
                this.dwarfHooks = newHooks;
            }
            this.update();
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

        for (let dwarfHook of this.dwarfHooks) {
            if (dwarfHook.getHookId() === hookID) {
                return this.removeHookAtAddress(dwarfHook.getAddress());
            }
        }
        return false;
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
        for (let bp of this.dwarfHooks) {
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

    /**
     * @param  {NativePointer|string} hookAddress
     * @returns boolean
     */
    public enableHookAtAddress = (hookAddress: NativePointer | string): boolean => {
        trace("DwarfHooksManager::enableHookAtAddress()");
        let dwarfHook = this.getHookByAddress(hookAddress);
        if (dwarfHook !== null) {
            dwarfHook.enable();
            return dwarfHook.isEnabled();
        }
    };

    /**
     * @param  {NativePointer|string} hookAddress
     * @returns boolean
     */
    public disableHookAtAddress = (hookAddress: NativePointer | string): boolean => {
        trace("DwarfHooksManager::disableHookAtAddress()");
        let dwarfHook = this.getHookByAddress(hookAddress);
        if (dwarfHook !== null) {
            dwarfHook.disable();
            return dwarfHook.isEnabled();
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

        //Get Watchlocations
        let MemoryHooks: Array<MemoryAccessRange> = DwarfObserver.getInstance().getLocationsInternal();

        //append our membreakpoints
        for (let memHook of self.dwarfHooks) {
            if (memHook.getType() === DwarfHookType.MEMORY) {
                if (memHook.isEnabled()) {
                    MemoryHooks.push({ base: memHook.getAddress() as NativePointer, size: 1 });
                }
            }
        }
        console.log(JSON.stringify(MemoryHooks));
        if (MemoryHooks.length > 0) {
            console.log("MemMonitor: enabled");
            MemoryAccessMonitor.enable(MemoryHooks, { onAccess: this.handleMemoryHooks });
        }
    };

    public handleMemoryHooks = (details: MemoryAccessDetails) => {
        trace("DwarfHooksManager::handleMemoryHooks()");

        const memoryAddress = details.address;
        const dwarfHook = this.getHookByAddress(memoryAddress, true, DwarfHookType.MEMORY);

        //not in hooks
        if (dwarfHook === null) {
            //let dwarfobserver handle
            DwarfObserver.getInstance().handleMemoryAccess(details);
        } else {
            const MemoryHook = dwarfHook as MemoryHook;
            MemoryHook.onHit(details);
        }
    };

    /**
     * Internal Helper to find the ModuleLoadHook and calling the hookCallback
     *
     * @param  {any} thisArg
     * @param  {string} moduleName
     * @param  {InvocationArguments} funcArgs
     */
    private handleModuleLoadOnEnter = (thisArg: any, moduleName: string, funcArgs: InvocationArguments) => {
        trace("DwarfHooksManager::handleModuleLoadOnEnter()");

        let moduleBaseName = "";
        if (moduleName.indexOf("/") != -1) {
            moduleBaseName = moduleName.substring(moduleName.lastIndexOf("/") + 1);
        }

        for (let dwarfHook of this.dwarfHooks) {
            if (dwarfHook.getType() === DwarfHookType.MODULE_LOAD) {
                if (dwarfHook.getAddress() === moduleName || dwarfHook.getAddress() === moduleBaseName) {
                    //store the hook so we can call onLeave then
                    this.moduleLoadHook = dwarfHook as ModuleLoadHook;
                    //handle userCallback
                    this.moduleLoadHook.onEnterCallback(thisArg, funcArgs);
                }
            }
        }
        Dwarf.sync({ module_loaded: { name: moduleName } });
    };

    /**
     * Internal Helper to call the onLeave
     *
     * @param  {any} thisArg
     * @param  {InvocationReturnValue} retVal
     */
    private handleModuleLoadOnLeave = (thisArg: any, retVal: InvocationReturnValue) => {
        trace("DwarfHooksManager::handleModuleLoadOnLeave()");

        //our stored hook
        if (isDefined(this.moduleLoadHook)) {
            this.moduleLoadHook.onLeaveCallback(thisArg, retVal);
        }
        //reset
        this.moduleLoadHook = null;
    };

    /**
     * Removes SingleShots and syncs ui
     */
    public update = () => {
        trace("DwarfHooksManager::update()");

        const newHooks = [];
        for (let dwarfHook of this.dwarfHooks) {
            if (dwarfHook.isSingleShot() && dwarfHook.getHits()) {
                if (dwarfHook.getType() == DwarfHookType.NATIVE) {
                    //detaches the interceptor
                    (dwarfHook as NativeHook).detach();
                }
            } else {
                newHooks.push(dwarfHook);
            }
        }
        this.dwarfHooks = newHooks;

        //sync ui
        DwarfCore.getInstance().sync({ dwarfHooks: this.dwarfHooks });
    };
}
