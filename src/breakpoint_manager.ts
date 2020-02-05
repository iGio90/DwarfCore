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

import { DwarfBreakpoint } from "./types/dwarf_breakpoint"
import { NativeBreakpoint } from "./types/native_breakpoint";
import { JavaBreakpoint } from "./types/java_breakpoint";
import { MemoryBreakpoint } from "./types/memory_breakpoint";
import { DwarfCore } from "./dwarf";
import { DwarfBreakpointType, DwarfMemoryAccessType, DwarfHaltReason } from "./consts";
import { DwarfObserver } from "./dwarf_observer";
import { ModuleLoadBreakpoint } from "./types/module_load_breakpoint";

/**
 * DwarfBreakpointManager Singleton
 *
 * use Dwarf.getBreakpointManager() or DwarfBreakpointManager.getInstance()
 */
export class DwarfBreakpointManager {
    private static instanceRef: DwarfBreakpointManager;
    protected nextBPID: number;
    protected dwarfBreakpoints: Array<DwarfBreakpoint>;
    protected moduleLoadBreakpoint: ModuleLoadBreakpoint;

    private constructor() {
        if (DwarfBreakpointManager.instanceRef) {
            throw new Error("DwarfBreakpointManager already exists! Use DwarfBreakpointManager.getInstance()/Dwarf.getBreakpointManager()");
        }
        trace('DwarfBreakpointManager()');
        this.dwarfBreakpoints = new Array<DwarfBreakpoint>();
        this.nextBPID = 0;
        this.moduleLoadBreakpoint = null;
    }

    static getInstance() {
        if (!DwarfBreakpointManager.instanceRef) {
            DwarfBreakpointManager.instanceRef = new this();
        }
        return DwarfBreakpointManager.instanceRef;
    }

    public attachModuleLoadingHooks() {
        const self = this;
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
                    Interceptor.attach(loadliba_ptr, {
                        onEnter: function (args) {
                            const moduleName = args[0].readAnsiString();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave: function (retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        }
                    });
                    Interceptor.attach(loadlibexa_ptr, {
                        onEnter: function (args) {
                            const moduleName = args[0].readAnsiString();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave: function (retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        }
                    });
                    Interceptor.attach(loadlibw_ptr, {
                        onEnter: function (args) {
                            const moduleName = args[0].readUtf16String();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave: function (retVal) {
                            self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                        }
                    });
                    Interceptor.attach(loadlibexw_ptr, {
                        onEnter: function (args) {
                            const moduleName = args[0].readUtf16String();
                            self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                        },
                        onLeave: function (retVal) {
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
                    if (moduleExportDetail.name.indexOf('LoadNativeLibrary') != -1) {
                        //changed in sdk 22, 23, 25 but we're only interested in path arg
                        //<=22 args = (void *JavaVMExt, std::string &path,...)
                        //>=23 args = (void *JavaVMExt, JNIEnv *env, std::string &path, ...)
                        const argNum = (Dwarf.getAndroidApiLevel() <= 22) ? 1 : 2;
                        Interceptor.attach(moduleExportDetail.address, {
                            onEnter: function (args) {
                                const moduleName = readStdString(args[argNum]);
                                self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                            },
                            onLeave: function (retVal) {
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
                    if (moduleExportDetail.name.indexOf('dvmLoadNativeCode') != -1) {
                        Interceptor.attach(moduleExportDetail.address, {
                            onEnter: function (args) {
                                const moduleName = args[0].readUtf8String();
                                self.handleModuleLoadOnEnter.apply(null, [this, moduleName, args]);
                            },
                            onLeave: function (retVal) {
                                self.handleModuleLoadOnLeave.apply(null, [this, retVal]);
                            }
                        });
                    }
                }
            }
        }
    }

    public getNextBreakpointID(): number {
        this.nextBPID++;
        return this.nextBPID;
    }

    private checkExists(bpAddress: any): void {
        for (let dwarfBreakpoint of this.dwarfBreakpoints) {
            if (dwarfBreakpoint.getAddress().toString() == bpAddress.toString()) {
                throw new Error('DwarfBreakpointManager::addBreakpoint() -> Existing Breakpoint at given Address!')
            }
        }
    }

    /**
     * @param  {DwarfBreakpointType} bpType
     * @param  {NativePointer|string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addBreakpoint = (bpType: DwarfBreakpointType, bpAddress: NativePointer | string, bpEnabled?: boolean, bpCallback?) => {

        trace('DwarfBreakpointManager::addBreakpoint()');

        switch (bpType) {
            case DwarfBreakpointType.NATIVE:
                return this.addNativeBreakpoint(bpAddress, bpEnabled);
            case DwarfBreakpointType.JAVA:
                {
                    const className = (bpAddress as string).substr(0, (bpAddress as string).lastIndexOf('.'));
                    const methodName = (bpAddress as string).substr((bpAddress as string).lastIndexOf('.') + 1)
                    return this.addJavaBreakpoint(className, methodName, bpEnabled, bpCallback);
                }
            case DwarfBreakpointType.OBJC:
                return this.addObjCBreakpoint(bpAddress as string, bpEnabled);
            case DwarfBreakpointType.MEMORY:
                return this.addMemoryBreakpoint(bpAddress, (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled);
            case DwarfBreakpointType.MODULE_LOAD:
                return this.addModuleLoadBreakpoint(bpAddress as string, bpCallback);
            default:
                break;
        }
        throw new Error('DwarfBreakpointManager::addBreakpoint() -> Unknown BreakpointType!');
    }

    public addNativeBreakpoint = (bpAddress: NativePointer | string, bpEnabled?: boolean, bpCallback?): NativeBreakpoint => {
        trace('DwarfBreakpointManager::addNativeBreakpoint()');

        bpAddress = makeNativePointer(bpAddress);

        if (!checkNativePointer(bpAddress)) {
            throw new Error('DwarfBreakpointManager::addNativeBreakpoint() => Invalid Address!');
        }

        this.checkExists(bpAddress);

        try {
            const nativeBreakpoint = new NativeBreakpoint(bpAddress, bpEnabled, bpCallback);
            if (isDefined(nativeBreakpoint)) {
                this.dwarfBreakpoints.push(nativeBreakpoint);
                this.update();
                return nativeBreakpoint;
            }
            return null;
        } catch (error) {
            logDebug('DwarfBreakpointManager::addNativeBreakpoint()', error);
            return null;
        }
    }

    public addMemoryBreakpoint = (bpAddress: NativePointer | string, bpFlags: number = (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled?: boolean) => {
        trace('DwarfBreakpointManager::addMemoryBreakpoint()');

        this.checkExists(bpAddress);

        try {
            const memBreakpoint = new MemoryBreakpoint(makeNativePointer(bpAddress), (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled);
            this.dwarfBreakpoints.push(memBreakpoint);
            this.updateMemoryBreakpoints();
            this.update();
            return memBreakpoint;
        } catch (error) {
            logErr('DwarfBreakpointManager::addMemoryBreakpoint', error);
        }
    }

    public addMemoryBreakpointInternal = (memBp: MemoryBreakpoint) => {
        memBp['isInternal'] = true;
        this.dwarfBreakpoints.push(memBp);
        this.updateMemoryBreakpoints();
    }

    /**
     * @param  {string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addJavaBreakpoint = (
        className: string,
        methodName: string = '$init',
        bpEnabled: boolean = true,
        bpCallbacks: ScriptInvocationListenerCallbacks | Function | string = 'breakpoint') => {

        trace('DwarfBreakpointManager::addJavaBreakpoint()');

        if (!Java.available) {
            throw new Error('Java not available!');
        }

        this.checkExists(className + '.' + methodName);

        try {
            const javaBreakpoint = new JavaBreakpoint(className, methodName, bpEnabled, bpCallbacks);
            if (isDefined(javaBreakpoint)) {
                this.dwarfBreakpoints.push(javaBreakpoint);
                this.update();
                return javaBreakpoint;
            }
            throw new Error('failed');
        } catch (error) {

        }
    }

    /**
     * @param  {string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addObjCBreakpoint = (bpAddress: string, bpEnabled?: boolean) => {
        trace('DwarfBreakpointManager::addObjCBreakpoint()');

        this.checkExists(bpAddress);


        throw new Error('DwarfBreakpointManager::addObjCBreakpoint() -> Not implemented');
    }

    /**
    * @param  {string} bpAddress
    * @param  {boolean} bpEnabled?
    */
    public addModuleLoadBreakpoint = (moduleName: string, bpCallback?: ScriptInvocationListenerCallbacks | Function | string, bpEnabled?: boolean) => {
        trace('DwarfBreakpointManager::addModuleLoadBreakpoint()');

        if (!isString(moduleName)) {
            throw new Error('DwarfBreakpointManager::addModuleLoadBreakpoint() -> Invalid Arguments!');
        }

        this.checkExists(moduleName);

        try {
            const moduleLoadBreakpoint = new ModuleLoadBreakpoint(moduleName, bpEnabled, bpCallback);
            if (moduleLoadBreakpoint) {
                this.dwarfBreakpoints.push(moduleLoadBreakpoint);
                this.update();
                return moduleLoadBreakpoint;
            }
        } catch (e) {
            console.log(JSON.stringify(e));
        }
    }

    public removeModuleLoadBreakpoint = (moduleName: string): boolean => {
        trace('DwarfBreakpointManager::removeModuleLoadBreakpoint()');

        if (!isString(moduleName)) {
            throw new Error('DwarfBreakpointManager::removeModuleLoadBreakpoint() -> Invalid Arguments!');
        }
        return this.removeBreakpointAtAddress(moduleName);
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public removeBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        trace('DwarfBreakpointManager::removeBreakpointAtAddress()');
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);

        if (dwarfBreakpoint !== null) {
            if (dwarfBreakpoint.getType() == DwarfBreakpointType.NATIVE) {
                (dwarfBreakpoint as NativeBreakpoint).detach();
            }
            this.dwarfBreakpoints = this.dwarfBreakpoints.filter((breakpoint) => {
                return breakpoint !== dwarfBreakpoint;
            });
            this.update();
            return true;
        }
        return false;
    }

    /**
     * @param  {number} bpID
     * @returns boolean
     */
    public removeBreakpointByID = (bpID: number): boolean => {
        trace('DwarfBreakpointManager::removeBreakpointByID()');

        for (let dwarfBreakpoint of this.dwarfBreakpoints) {
            if (dwarfBreakpoint.getID() === bpID) {
                return this.removeBreakpointAtAddress(dwarfBreakpoint.getAddress());
            }
        }
        return false;
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns DwarfBreakpoint
     */
    public getBreakpointByAddress = (bpAddress: NativePointer | string, checkEnabled: boolean = false, checkForType?: DwarfBreakpointType): DwarfBreakpoint | null => {
        trace('DwarfBreakpointManager::getBreakpointByAddress()');
        let bpFindAddress;
        if (typeof bpAddress === 'string') {
            bpFindAddress = bpAddress;
        } else if (typeof bpAddress === 'number') {
            bpFindAddress = ptr(bpAddress).toString();
        } else {
            if (bpAddress.constructor.name !== 'NativePointer' || bpAddress.isNull()) {
                throw new Error('DwarfBreakpointManager::getBreakpointByAddress() -> Invalid Address!');
            }
            bpFindAddress = bpAddress.toString();
        }
        let dwarfBreakpoint = null;
        for (let bp of this.dwarfBreakpoints) {
            if (bp.getAddress() === bpFindAddress) {
                if (checkEnabled && !bp.isEnabled()) {
                    continue;
                }
                if (checkForType && bp.getType() !== checkForType) {
                    continue;
                }
                dwarfBreakpoint = bp;
                break;
            }
        }

        return dwarfBreakpoint;
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public toggleBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        trace('DwarfBreakpointManager::toggleBreakpointAtAddress()');
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.toggleActive();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public enableBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        trace('DwarfBreakpointManager::enableBreakpointAtAddress()');
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.enable();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public disableBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        trace('DwarfBreakpointManager::disableBreakpointAtAddress()');
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.disable();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * Windows related stuff to handle MemoryBreakpoints
     * Call it after something MemoryBreakpoint related changes
     */
    public updateMemoryBreakpoints = (): void => {
        trace('DwarfBreakpointManager::updateMemoryBreakpoints()');

        MemoryAccessMonitor.disable();

        const self = this;

        //Get Watchlocations
        let memoryBreakpoints: Array<MemoryAccessRange> = DwarfObserver.getInstance().getLocationsInternal();

        //append our membreakpoints
        for (let memBreakpoint of self.dwarfBreakpoints) {
            if (memBreakpoint.getType() === DwarfBreakpointType.MEMORY) {
                if (memBreakpoint.isEnabled()) {
                    memoryBreakpoints.push({ 'base': (memBreakpoint.getAddress() as NativePointer), 'size': 1 });
                }
            }
        }
        console.log(JSON.stringify(memoryBreakpoints));
        if (memoryBreakpoints.length > 0) {
            console.log('MemMonitor: enabled');
            MemoryAccessMonitor.enable(memoryBreakpoints, { onAccess: this.handleMemoryBreakpoints });
        }
    }

    public handleMemoryBreakpoints = (details: MemoryAccessDetails) => {
        trace('DwarfBreakpointManager::handleMemoryBreakpoints()');

        const memoryAddress = details.address;
        const dwarfBreakpoint = this.getBreakpointByAddress(memoryAddress, true, DwarfBreakpointType.MEMORY);

        //not in breakpoints
        if (dwarfBreakpoint === null) {
            //let dwarfobserver handle
            DwarfObserver.getInstance().handleMemoryAccess(details);
        } else {
            const memoryBreakpoint = dwarfBreakpoint as MemoryBreakpoint;
            memoryBreakpoint.onHit(details);
        }
    }

    public handleModuleLoadOnEnter = (thisArg: any, moduleName: string, funcArgs: InvocationArguments) => {
        if (moduleName.indexOf('/') != -1) {
            moduleName = moduleName.substring(moduleName.lastIndexOf('/') + 1);
        }

        for (let bp of this.dwarfBreakpoints) {
            if (bp.getType() === DwarfBreakpointType.MODULE_LOAD) {
                if (bp.getAddress() === moduleName) {
                    this.moduleLoadBreakpoint = (bp as ModuleLoadBreakpoint);
                    this.moduleLoadBreakpoint.onEnterCallback(thisArg, funcArgs);
                }
            }
        }
        Dwarf.sync({ module_loaded: { name: moduleName } });
    }

    public handleModuleLoadOnLeave = (thisArg: any, retVal: InvocationReturnValue) => {
        if (isDefined(this.moduleLoadBreakpoint)) {
            this.moduleLoadBreakpoint.onLeaveCallback(thisArg, retVal);
        }
        this.moduleLoadBreakpoint = null;
    }

    public getBreakpoints = (): Array<DwarfBreakpoint> => {
        trace('DwarfBreakpointManager::getBreakpoints()');
        const dwarfBreakpoints = this.dwarfBreakpoints.filter((breakpoint) => {
            return !breakpoint.hasOwnProperty('isInternal');
        });
        return dwarfBreakpoints;
    }

    public update = () => {
        trace('DwarfBreakpointManager::update()');
        //remove singleshots

        const newBreakpoints = [];
        for(let dwarfBreakpoint of this.dwarfBreakpoints) {
            if(dwarfBreakpoint.isSingleShot() && dwarfBreakpoint.getHits()) {
                if(dwarfBreakpoint.getType() == DwarfBreakpointType.NATIVE) {
                    (dwarfBreakpoint as NativeBreakpoint).detach();
                }
            } else {
                newBreakpoints.push(dwarfBreakpoint);
            }
        }
        this.dwarfBreakpoints = newBreakpoints;

        //sync ui
        DwarfCore.getInstance().sync({ breakpoints: this.dwarfBreakpoints });
    }
}