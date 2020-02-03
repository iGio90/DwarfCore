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

import { DwarfFS } from "./DwarfFS";
import { LogicBreakpoint } from "./logic_breakpoint";
import { LogicJava } from "./logic_java";
import { LogicObjC } from "./logic_objc";
import { LogicInitialization } from "./logic_initialization";
import { LogicStalker } from "./logic_stalker";
import { ThreadWrapper } from "./thread_wrapper";
import { DwarfMemoryAccessType, DwarfBreakpointType } from "./consts";
import { DwarfCore } from "./dwarf";
import { MemoryBreakpoint } from "./types/memory_breakpoint";
import { DwarfBreakpointManager } from "./breakpoint_manager";
import { DwarfObserver } from "./dwarf_observer";
import { NativeBreakpoint } from "./types/native_breakpoint";
import { JavaBreakpoint } from "./types/java_breakpoint";
import { ObjcBreakpoint } from "./types/objc_breakpoint";
import { DwarfJavaHelper } from "./java";

export class DwarfApi {
    private static instanceRef: DwarfApi;

    private constructor() {
        if (DwarfApi.instanceRef) {
            throw new Error("DwarfApi already exists! Use DwarfApi.getInstance()/Dwarf.getApi()");
        }
        logDebug('DwarfApi()');
    }

    static getInstance() {
        if (!DwarfApi.instanceRef) {
            DwarfApi.instanceRef = new this();
        }
        return DwarfApi.instanceRef;
    }

    /**
     * Create Breakpoint on given address
     *
     * @param  {DwarfBreakpointType|string|number} breakpointType
     * @param  {NativePointer|string|number} bpAddress
     * @param  {boolean} bpEnabled? (default: enabled)
     *
     * TODO: add ObjcBreakpoints
     */
    public addBreakpoint = (breakpointType: DwarfBreakpointType | string | number, bpAddress: NativePointer | string | number, bpEnabled?: boolean): NativeBreakpoint | MemoryBreakpoint | JavaBreakpoint => {
        trace('DwarfApi::addBreakpoint()');

        let bpType: DwarfBreakpointType = 0;
        let checkedAddress: NativePointer | string = null;

        //check type
        if (!isDefined(breakpointType)) {
            throw new Error('DwarfApi::addBreakpoint() => No BreakpointType given!');
        } else {
            if (isString(breakpointType)) {
                switch ((breakpointType as string).toLowerCase()) {
                    case 'native':
                        bpType = DwarfBreakpointType.NATIVE;
                        break;
                    case 'memory':
                        bpType = DwarfBreakpointType.MEMORY;
                        break;
                    case 'java':
                        bpType = DwarfBreakpointType.JAVA;
                        break;
                    case 'objc':
                        bpType = DwarfBreakpointType.OBJC;
                        break;
                    default:
                        throw new Error('DwarfApi::addBreakpoint() => Invalid BreakpointType!');
                }
            } else if (isNumber(breakpointType)) {
                bpType = breakpointType as number;
            } else {
                throw new Error('DwarfApi::addBreakpoint() => Invalid BreakpointType!');
            }
        }

        if ((bpType < DwarfBreakpointType.NATIVE) || (bpType > DwarfBreakpointType.MEMORY)) {
            throw new Error('DwarfApi::addBreakpoint() => Invalid BreakpointType!');
        }

        if ((bpType == DwarfBreakpointType.JAVA) && !Java.available) {
            throw new Error('DwarfApi::addBreakpoint() => No JAVA Breakpoints available!');
        }

        if ((bpType == DwarfBreakpointType.OBJC) && !ObjC.available) {
            throw new Error('DwarfApi::addBreakpoint() => No OBJC Breakpoints available!');
        }

        //check address
        if (!isDefined(bpAddress)) {
            throw new Error('DwarfApi::addBreakpoint() => No Address given!');
        } else {
            if (bpType == DwarfBreakpointType.NATIVE || bpType == DwarfBreakpointType.MEMORY) {
                bpAddress = makeNativePointer(bpAddress);
                if (checkNativePointer(bpAddress)) {
                    checkedAddress = bpAddress;
                } else {
                    throw new Error('DwarfApi::addBreakpoint() => Invalid Address!');
                }
            } else {
                //java+objc addresses
                if (!isString(bpAddress)) {
                    throw new Error('DwarfApi::addBreakpoint() => Invalid Address!');
                } else {
                    if (!Java.available && !ObjC.available) {
                        throw new Error('DwarfApi::addBreakpoint() => Invalid Address!');
                    }
                    if ((bpAddress as string).length > 0) {
                        checkedAddress = bpAddress as string;
                    }
                }
            }
        }

        if (!isDefined(checkedAddress)) {
            throw new Error('DwarfApi::addBreakpoint() => Something is wrong!');
        }

        //add to bpman
        return DwarfBreakpointManager.getInstance().addBreakpoint(bpType, checkedAddress, bpEnabled);
    }

    /**
     * Create a MemoryBreakpoint on the given address
     *
     * ```javascript
     * addMemoryBreakpoint(0x1000, 'r');
     *
     * var target = findExport('memcpy');
     * Interceptor.attach(target, {
     *     onLeave: function(ret) {
     *         addMemoryBreakpoint(this.context.x0, 'rw', function() {
     *            log(backtrace(this.context));
     *         });
     *     }
     * });
     * ```
     * @param address
     * @param flags
     * @param callback
     */
    public addMemoryBreakpoint = (memoryAddress: NativePointer | string | number, bpFlags: string | number, bpCallback?: Function | string | null): MemoryBreakpoint => {
        trace('DwarfApi::addMemoryBreakpoint()');

        let bpAddress = makeNativePointer(memoryAddress);
        if (!checkNativePointer(bpAddress)) {
            throw new Error('DwarfApi::addMemoryBreakpoint() => Invalid Address!');
        }

        const rangeDetails = Process.findRangeByAddress(bpAddress);

        if (!isDefined(rangeDetails)) {
            throw new Error('DwarfApi::addMemoryBreakpoint() => Unable to find Range for ' + bpAddress.toString());
        }

        if (rangeDetails.protection.indexOf('r') === -1) {
            throw new Error('DwarfApi::addMemoryBreakpoint() => Unable to access Memory at ' + bpAddress.toString());
        }

        let intFlags = 0;
        if (typeof bpFlags === 'string') {
            if (bpFlags.indexOf('r') >= 0) {
                intFlags |= DwarfMemoryAccessType.READ;
            }
            if (bpFlags.indexOf('w') >= 0) {
                intFlags |= DwarfMemoryAccessType.WRITE;
            }
            if (bpFlags.indexOf('x') >= 0) {
                intFlags |= DwarfMemoryAccessType.EXECUTE;
            }
        } else if (typeof bpFlags === 'number') {
            intFlags = bpFlags;
        } else {
            throw new Error('DwarfApi::addMemoryBreakpoint() -> Unknown FlagsType! (allowed string|number)');
        }

        try {
            const memoryBreakpoint = DwarfBreakpointManager.getInstance().addMemoryBreakpoint(bpAddress, intFlags);
            if (isDefined(memoryBreakpoint)) {
                if (isFunction(bpCallback)) {
                    memoryBreakpoint.setCallback(bpCallback as Function);
                } else {
                    if (isString(bpCallback)) {
                        //TODO: add func wich converts string to function
                    } else {
                        throw new Error('DwarfApi::addMemoryBreakpoint() => Unable to set callback!');
                    }
                }
            }
            return memoryBreakpoint;
        } catch (error) {
            logErr('DwarfApi::addMemoryBreakpoint()', error);
            return null;
        }
    }


    public addNativeBreakpoint = (bpAddress: NativePointer | string | number, bpCallback?: InvocationListenerCallbacks | Function | string | null): NativeBreakpoint => {
        trace('DwarfApi::addNativeBreakpoint()');

        try {
            bpAddress = makeNativePointer(bpAddress);
            if (!checkNativePointer(bpAddress)) {
                throw new Error('DwarfApi::addNativeBreakpoint() => Invalid Address!');
            }
            const nativeBreakpoint = DwarfBreakpointManager.getInstance().addNativeBreakpoint(bpAddress, true, bpCallback);
            return nativeBreakpoint;
        } catch (error) {
            logErr('DwarfApi::addNativeBreakpoint()', error);
            return null;
        }
    }

    public addJavaBreakpoint = (className: string, methodName:string='$init', bpCallback?: ScriptInvocationListenerCallbacks | Function | string | null): JavaBreakpoint => {
        trace('DwarfApi::addJavaBreakpoint()');

        if (!isString(className)) {
            throw new Error('DwarfApi::addJavaBreakpoint() => Invalid Adddress!');
        }

        if (!isString(methodName)) {
            throw new Error('DwarfApi::addJavaBreakpoint() => Invalid Adddress!');
        }

        try {
            const javaBreakpoint = DwarfBreakpointManager.getInstance().addJavaBreakpoint(className, methodName, true, bpCallback);
            return javaBreakpoint;
        } catch (error) {
            logErr('DwarfApi::addNativeBreakpoint()', error);
            return null;
        }
    }

    public addObjcBreakpoint = (bpAddress: string, bpCallback?: InvocationListenerCallbacks | Function | string | null): ObjcBreakpoint => {
        trace('DwarfApi::addObjcBreakpoint()');

        throw new Error('Not implemented!');
    }


    /**
     * Adds Bookmark in UI
     *
     * @param  {NativePointer|string} bmAddress
     * @param  {string} bmNote
     */
    public addBookmark = (bmAddress: NativePointer | string, bmNote: string) => {
        trace('DwarfApi::addBookmark()');
        if (bmAddress.constructor.name === 'NativePointer') {
            bmAddress = bmAddress.toString();
        }
        if (!isString(bmAddress)) {
            if (bmAddress.hasOwnProperty('toString')) {
                bmAddress = bmAddress.toString();
            } else {
                logErr('DwarfApi::addBookmark()', 'Value Error');
                return;
            }
        }
        DwarfCore.getInstance().sync({ bookmark: { address: bmAddress, note: bmNote } });
    }
    /**
     * Adds Location to DwarfObserver
     *
     * @param  {string} name
     * @param  {NativePointer|string} npAddress
     * @param  {string} watchType
     * @param  {number} nSize (required for watchType 'bytes')
     * @param  {string} watchMode
     * @param  {string|Function} handler ('breakpoint' or function)
     */
    public addObserveLocation = (name: string, npAddress: NativePointer | string, watchType: string, watchMode: string, handler: string | Function, bytesLength: number = 0) => {
        trace('DwarfApi::addObserveLocation()');

        if (isString(handler) && handler !== 'breakpoint') {
            //TODO: convert handlerstr from ui to func
        }
        return DwarfObserver.getInstance().addLocation(name, npAddress, watchType, bytesLength, watchMode, handler);
    }

    /**
     * Removes Location from DwarfObserver
     *
     * @param  {number} observeId
     */
    public removeObserveLocation = (observeId: number) => {
        trace('DwarfApi::removeObserveLocation()');

        return DwarfObserver.getInstance().removeById(observeId);
    }

    /**
     * Removes Location from DwarfObserver
     *
     * @param  {string} observeName
     */
    public removeObserveLocationByName = (observeName: string) => {
        trace('DwarfApi::removeObserveLocationByName()');

        return DwarfObserver.getInstance().removeByName(observeName);
    }

    public hookModuleInitialization = (libraryName: string, callback: ScriptInvocationListenerCallbacks | Function | string) => {
        if(Java.available) {
            return DwarfJavaHelper.getInstance().addLibraryLoaderHook(libraryName, callback);
        }
    }

    public removeModuleInitializationBreakpoint = (libraryName: string) => {
        if(Java.available) {
            return DwarfJavaHelper.getInstance().removeLibraryLoadHook(libraryName);
        }
    }

    private _internalMemoryScan(start, size, pattern) {
        if (size > 4096) {
            // scan in chunks of 4096
            let _start = parseInt(start);
            const end = _start + size;
            let result = [];
            let _break = false;
            while (true) {
                let s = 4096;
                if (_start + s > end) {
                    s = end - _start;
                    _break = true;
                }
                result = result.concat(Memory.scanSync(start, s, pattern));
                if (_break || result.length >= 100) {
                    break;
                }
                start = start.add(size);
                _start += s;
            }
            return result;
        } else {
            return Memory.scanSync(start, size, pattern);
        }
    }

    /**
     * Shortcut to retrieve native backtrace
     * @param context: the CpuContext object
     */
    public backtrace = (context?: CpuContext): DebugSymbol[] | null => {
        if (!isDefined(context)) {
            context = Dwarf.threadContexts[Process.getCurrentThreadId()];
            if (!isDefined(context)) {
                return null;
            }
        }

        return Thread.backtrace(context, Backtracer.FUZZY)
            .map(DebugSymbol.fromAddress);
    }

    /**
     * Enumerate exports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    public enumerateExports = (module: any): Array<ModuleExportDetails> => {
        if (typeof module !== 'object') {
            module = this.findModule(module);
        }
        if (module !== null) {
            if (Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
                return [];
            }
            return module.enumerateExports();
        }
        return [];
    }

    /**
     * Enumerate imports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    public enumerateImports = (module): Array<ModuleImportDetails> => {
        if (typeof module !== 'object') {
            module = this.findModule(module);
        }
        if (module !== null) {
            if (Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
                return [];
            }
            return module.enumerateImports();
        }
        return [];
    }

    /**
    *   TODO: this is used to populate ui we should remove it from api
     * Enumerate method for the given class
     */
    public enumerateJavaMethods = (className: string): void => {
        if (Java.available) {
            Java.performNow(function () {
                // 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
                const clazz = Java.use(className);
                const methods = clazz.class.getDeclaredMethods();
                clazz.$dispose();

                const parsedMethods = [];
                methods.forEach(function (method) {
                    parsedMethods.push(method.toString().replace(className + ".",
                        "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
                });
                const result = uniqueBy(parsedMethods);

                Dwarf.sync({ class_methods: result });
            });
        }
    }

    /**
     * Enumerate modules for ObjC inspector panel
     */
    public enumerateObjCModules = (className: string): void => {
        const modules = Process.enumerateModules();
        const names = modules.map(m => m.name);
        Dwarf.loggedSend('enumerate_objc_modules:::' + JSON.stringify(names));
    }

    /**
     * Enumerate objc classes
     * @param useCache false by default
     */
    public enumerateObjCClasses = (moduleName: string) => {
        Dwarf.loggedSend('enumerate_objc_classes_start:::');
        try {
            ObjC.enumerateLoadedClasses({ ownedBy: new ModuleMap((m) => { return moduleName === m['name']; }) }, {
                onMatch: function (className) {
                    if (LogicObjC !== null) {
                        LogicObjC.objcClasses.push(className);
                    }
                    send('enumerate_objc_classes_match:::' + className);
                },
                onComplete: function () {
                    send('enumerate_objc_classes_complete:::');
                }
            });
        } catch (e) {
            logErr('enumerateObjCClasses', e);
            Dwarf.loggedSend('enumerate_objc_classes_complete:::');
        }
    }

    /**
     * Enumerate method for the given class
     */
    public enumerateObjCMethods = (className: string): void => {
        if (ObjC.available) {
            Dwarf.loggedSend('enumerate_objc_methods_start:::');
            const that = this;
            const clazz = ObjC.classes[className];
            const methods = clazz.$ownMethods;

            methods.forEach(function (method) {
                send('enumerate_objc_methods_match:::' + method);
            });
            Dwarf.loggedSend('enumerate_objc_methods_complete:::');
        }
    }

    /**
     * Enumerate loaded modules
     */
    public enumerateModules = (fillInformation?: boolean) => {
        fillInformation = fillInformation || false;

        const modules = Process.enumerateModules();
        if (fillInformation) {
            for (let i = 0; i < modules.length; i++) {
                if (Dwarf.modulesBlacklist.indexOf(modules[i].name) >= 0) {
                    continue;
                }

                // skip ntdll on windoof (access_violation)
                if (Process.platform === 'windows') {
                    if (modules[i].name === 'ntdll.dll') {
                        continue;
                    }
                } else if (Process.platform === 'linux') {
                    if (LogicJava !== null) {
                        if (LogicJava.sdk <= 23) {
                            if (modules[i].name === 'app_process') {
                                continue;
                            }
                        }
                    }
                }

                modules[i] = this.enumerateModuleInfo(modules[i]);
            }
        }
        return modules;
    }

    /**
     * Enumerate all information about the module (imports / exports / symbols)
     * @param fridaModule object from frida-gum
     */
    /*
        TODO: recheck! when doc says object from frida-gum it shouldnt used by dwarf with string
              fix on pyside and remove the string stuff here
              return should also DwarfModule as Module is altered

        module_info.py
        def update_details(self, dwarf, base_info):
            details = Dwarf.dwarf_api('enumerateModuleInfo', base_info['name'])
    */
    public enumerateModuleInfo = (fridaModule: Module | string): Module => {
        let _module: Module = null;

        if (isString(fridaModule)) {
            _module = Process.findModuleByName(fridaModule as string);
        } else {
            _module = fridaModule as Module;
        }

        if (Dwarf.modulesBlacklist.indexOf(_module.name) >= 0) {
            this.log('Error: Module ' + _module.name + ' is blacklisted');
            return _module;
        }

        try {
            _module['imports'] = _module.enumerateImports();
            _module['exports'] = _module.enumerateExports();
            _module['symbols'] = _module.enumerateSymbols();
        } catch (e) {
            return _module;
        }

        _module['entry'] = null;
        const header = _module.base.readByteArray(4);
        if (header[0] !== 0x7f && header[1] !== 0x45 && header[2] !== 0x4c && header[3] !== 0x46) {
            // Elf
            _module['entry'] = _module.base.add(24).readPointer();
        }

        return _module;
    }

    /**
     * Enumerate all mapped ranges
     */
    public enumerateRanges = (): RangeDetails[] => {
        return Process.enumerateRanges('---');
    }

    /**
     * Enumerate symbols for the given module name or pointer
     * @param module an hex/int address or string name
     */
    public enumerateSymbols = (module): Array<ModuleSymbolDetails> => {
        if (typeof module !== 'object') {
            module = this.findModule(module);
        }
        if (module !== null) {
            if (Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
                return [];
            }
            return module.enumerateSymbols();
        }
        return [];
    }

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    public evaluate = (w): any => {
        const Thread = ThreadWrapper;
        try {
            return eval(w);
        } catch (e) {
            this.log(e.toString());
            return null;
        }
    }

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    public evaluateFunction = (w): any => {
        try {
            const fn = new Function('Thread', w);
            return fn.apply(this, [ThreadWrapper]);
        } catch (e) {
            this.log(e.toString());
            return null;
        }
    }

    /**
     * Evaluate any input and return a NativePointer
     * @param w
     */
    public evaluatePtr = (w: any): NativePointer => {
        try {
            return ptr(eval(w));
        } catch (e) {
            return NULL;
        }
    }

    /**
     * Shortcut to quickly retrieve an export
     *
     * ```javascript
     * const openAddress = findExport('open');
     * const myTargetAddress = findExport('target_func', 'target_module.so');
     * ```
     *
     * @param name: the name of the export
     * @param module: optional name of the module
     */
    public findExport = (exportName: string, moduleName?: string): NativePointer | null => {
        if (!isString(exportName)) {
            throw new Error('DwarfApi::findExport() => No exportName given!');
        }

        if (!isString(moduleName)) {
            moduleName = null;
        }
        return Module.findExportByName(moduleName, exportName);
    }

    /**
     * Find a module providing any argument. Could be a string/int pointer or module name
     */
    public findModule = (module: any): Module | Module[] | null => {
        let _module;
        if (isString(module) && module.substring(0, 2) !== '0x') {
            _module = Process.findModuleByName(module);
            if (isDefined(_module)) {
                return _module;
            } else {
                // do wildcard search
                if (module.indexOf('*') !== -1) {
                    const modules = Process.enumerateModules();
                    const searchName = module.toLowerCase().split('*')[0];
                    for (let i = 0; i < modules.length; i++) {
                        // remove non matching
                        if (modules[i].name.toLowerCase().indexOf(searchName) === -1) {
                            modules.splice(i, 1);
                            i--;
                        }
                    }
                    if (modules.length === 1) {
                        return modules[0];
                    } else {
                        return modules;
                    }
                }
            }
        } else {
            _module = Process.findModuleByAddress(ptr(module));
            if (!isDefined(_module)) {
                _module = {};
            }
            return _module;
        }
        return null;
    }

    /**
     * Find a symbol matching the given pattern
     */
    public findSymbol = (pattern: string): NativePointer[] => {
        if (!isString(pattern)) {
            throw new Error("DwarfApi::findSymbol() => No pattern given!");
        }
        return DebugSymbol.findFunctionsMatching(pattern);
    }

    /**
     * get telescope information for the given pointer argument
     * @param p: pointer
     */
    public getAddressTs = (p): [number, any] => {
        const _ptr = ptr(p);
        const _range = Process.findRangeByAddress(_ptr);
        if (isDefined(_range)) {
            if (_range.protection.indexOf('r') !== -1) {
                try {
                    const s = this.readString(_ptr);
                    if (s !== "") {
                        return [0, s];
                    }
                } catch (e) { }
                try {
                    const ptrVal = _ptr.readPointer();
                    return [1, ptrVal];
                } catch (e) {
                }
                return [2, p];
            }
        }
        return [-1, p];
    }

    /**
     * Return an array of DebugSymbol for the requested pointers
     * @param ptrs: an array of NativePointer
     */
    public getDebugSymbols = (ptrs): DebugSymbol[] => {
        const symbols = [];
        if (isDefined(ptrs)) {
            try {
                ptrs = JSON.parse(ptrs);
            } catch (e) {
                logErr('getDebugSymbols', e);
                return symbols;
            }
            for (let i = 0; i < ptrs.length; i++) {
                symbols.push(this.getSymbolByAddress(ptrs[i]));
            }
        }
        return symbols;
    };

    /**
     * Shortcut to retrieve an Instruction object for the given address
     */
    public getInstruction = (address) => {
        try {
            const instruction = Instruction.parse(ptr(address));
            return JSON.stringify({
                'string': instruction.toString()
            });
        } catch (e) {
            logErr('getInstruction', e);
        }
        return null;
    }

    /**
     * Return a RangeDetails object or null for the requested pointer
     */
    public getRange = (address: any): RangeDetails | null => {
        try {
            const nativeAddress = ptr(address);
            if (nativeAddress === null || parseInt(nativeAddress.toString()) === 0) {
                return null;
            }
            const ret = Process.findRangeByAddress(nativeAddress);
            if (ret == null) {
                return null;
            }
            return ret;
        } catch (e) {
            logErr('getRange', e);
            return null;
        }
    }

    /**
     * Return DebugSymbol or null for the given pointer
     */
    public getSymbolByAddress = (npAddress: NativePointer | string): DebugSymbol | null => {
        try {
            npAddress = makeNativePointer(npAddress);
            return DebugSymbol.fromAddress(npAddress);
        } catch (e) {
            logErr('getSymbolByAddress', e);
            return null;
        }
    }

    /**
     * Hook all the methods for the given java class
     *
     * ```javascript
     * hookAllJavaMethods('android.app.Activity', function() {
     *     console.log('hello from:', this.className, this.method);
     * })
     * ```
     * @param className
     * @param callback
     */
    public hookAllJavaMethods = (className: string, callback: Function): boolean => {
        return LogicJava.hookAllJavaMethods(className, callback);
    }

    /**
     * Receive a callback whenever a java class is going to be loaded by the class loader.
     *
     * ```javascript
     * //custom callback
     * addClassLoaderHook('com.target.classname', function() {
     *     console.log('target is being loaded');
     * });
     *
     * //breakpoint
     * addClassLoaderHook('com.target.classname');
     * addClassLoaderHook('com.target.classname', 'breakpoint');
     * ```
     * @param className
     * @param callback
     */
    public addClassLoaderHook = (className: string, callback?: ScriptInvocationListenerCallbacks | Function | string) => {
        trace('DwarfApi::addClassLoaderHook()');

        if(!isDefined(callback) || callback === void 0) {
            callback = 'breakpoint';
        }

        if(isString(callback) && callback !== 'breakpoint') {
            throw new Error('DwarfApi::addClassLoaderHook() => Invalid arguments!');
        }

        if (!isDefined(className)) {
            throw new Error('DwarfApi::addClassLoaderHook() => Invalid arguments!');
        }
        return DwarfJavaHelper.getInstance().addClassLoaderHook(className, callback);
    }

    /**
     * Hook the constructor of the given java class
     * ```javascript
     * hookJavaConstructor('android.app.Activity', function() {
     *     console.log('activity created');
     * })
     * ```
     * @param className
     * @param callback
     */
    public hookJavaConstructor = (className: string, callback: Function): boolean => {
        return LogicJava.hook(className, '$init', callback);
    }

    /**
     * Hook the constructor of the given java class
     * ```javascript
     * hookJavaConstructor('android.app.Activity.onCreate', function() {
     *     console.log('activity created');
     *     var savedInstanceState = arguments[0];
     *     if (savedInstanceState !== null) {
     *         return this.finish();
     *     } else {
     *         return this.overload.call(this, arguments);
     *     }
     * })
     * ```
     * @param targetClassMethod
     * @param callback
     */
    public hookJavaMethod = (targetClassMethod: string, callback: Function): boolean => {
        return LogicJava.hookJavaMethod(targetClassMethod, callback);
    }

    /**
     * Receive a callback when the native module is being loaded
     * ```javascript
     * hookModuleInitialization('libtarget.so', function() {
     *     console.log('libtarget is being loaded');
     * });
     * ```
     * @param moduleName
     * @param callback
     */
    public hookModuleInitialization = (moduleName: string, callback: Function): boolean => {
        return LogicInitialization.hookModuleInitialization(moduleName, callback);
    }

    /**
     * Map the given blob as hex string using memfd:create with the given name
     *
     * @return a negative integer if error or fd
     */
    public injectBlob = (name: string, blob: string) => {
        // arm syscall memfd_create
        let sys_num = 385;
        if (Process.arch === 'ia32') {
            sys_num = 356;
        } else if (Process.arch === 'x64') {
            sys_num = 319;
        }

        const syscall_ptr = this.findExport('syscall');
        const write_ptr = this.findExport('write');
        const dlopen_ptr = this.findExport('dlopen');

        if (syscall_ptr !== null && !syscall_ptr.isNull()) {
            const syscall = new NativeFunction(syscall_ptr, 'int', ['int', 'pointer', 'int']);
            if (write_ptr !== null && !write_ptr.isNull()) {
                const write = new NativeFunction(write_ptr, 'int', ['int', 'pointer', 'int']);
                if (dlopen_ptr !== null && !dlopen_ptr.isNull()) {
                    const dlopen = new NativeFunction(dlopen_ptr, 'int', ['pointer', 'int']);

                    const m = DwarfFS.getInstance().allocateRw(128);
                    m.writeUtf8String(name);
                    const fd = syscall(sys_num, m, 0);
                    if (fd > 0) {
                        const hexArr = hex2a(blob);
                        const blob_space = Memory.alloc(hexArr.length);
                        Memory.protect(blob_space, hexArr.length, 'rwx');
                        blob_space.writeByteArray(hexArr);
                        write(fd, blob_space, hexArr.length);
                        m.writeUtf8String('/proc/' + Process.id + '/fd/' + fd);
                        return dlopen(m, 1);
                    } else {
                        return -4;
                    }
                } else {
                    return -3;
                }
            } else {
                return -2;
            }
        } else {
            return -1;
        }
    }

    /**
     * @return a boolean indicating if the given pointer is currently watched
     * TODO:
     */
    public isAddressWatched = (pt: any): boolean => {
        const memoryBreakpoint = DwarfBreakpointManager.getInstance().getBreakpointByAddress(pt);
        if (memoryBreakpoint.isEnabled()) {
            return true;
        }
        return false;
    }

    private isPrintable = (char) => {
        try {
            const isprint_ptr = this.findExport('isprint');
            if (isDefined(isprint_ptr)) {
                const isprint_fn = new NativeFunction(isprint_ptr, 'int', ['int']);
                if (isDefined(isprint_fn)) {
                    return isprint_fn(char);
                }
            }
            else {
                if ((char > 31) && (char < 127)) {
                    return true;
                }
            }
            return false;
        } catch (e) {
            logErr('isPrintable', e);
            return false;
        }
    };

    /**
     * @return a java stack trace. Must be executed in JVM thread
     */
    public javaBacktrace = () => {
        return LogicJava.backtrace();
    }

    /**
     * @return the explorer object for the given java handle
     */
    public jvmExplorer = (handle): {} => {
        return LogicJava.jvmExplorer(handle);
    }

    /**
     * log whatever to Dwarf console
     */
    public log = (what): void => {
        if (isDefined(what)) {
            Dwarf.loggedSend('log:::' + what);
        }
    }

    private memoryScan = (start, size, pattern) => {
        let result = [];
        try {
            result = this._internalMemoryScan(ptr(start), size, pattern);
        } catch (e) {
            logErr('memoryScan', e);
        }
        Dwarf.loggedSend('memoryscan_result:::' + JSON.stringify(result));
    }

    private memoryScanList = (ranges, pattern) => {
        ranges = JSON.parse(ranges);
        let result = [];
        for (let i = 0; i < ranges.length; i++) {
            try {
                result = result.concat(this._internalMemoryScan(ptr(ranges[i]['start']), ranges[i]['size'], pattern));
            } catch (e) {
                logErr('memoryScanList', e);
            }
            if (result.length >= 100) {
                break;
            }
        }
        Dwarf.loggedSend('memoryscan_result:::' + JSON.stringify(result));
    }

    /**
     * put a breakpoint on a native pointer or a java class with an optional evaluated condition
     *
     * ```javascript
     * var nativeTarget = findExport('memcpy');
     *
     * putBreakpoint(nativeTarget);
     *
     * nativeTarget = findExport('open');
     * putBreakpoint(target, function() {
     *     if (this.context.x0.readUtf8String().indexOf('prefs.json') >= 0) {
     *         return true;
     *     }
     *
     *     return false;
     * });
     *
     * var javaTarget = 'android.app.Activity.onCreate';
     * putBreakpoint(javaTarget);
     * ```
     *
     * @param address_or_class
     * @param condition
     *
     * TODO: remove or change to addBreakpoint
     */
    public putBreakpoint = (address_or_class: any, condition?: string | Function): boolean => {
        return false;
        //return LogicBreakpoint.putBreakpoint(address_or_class, condition);
    }

    /**
     * Put a java class initialization breakpoint
     *
     * ```javascript
     * putJavaClassInitializationBreakpoint('android.app.Activity');
     * ```
     * @param className
     */
    public putJavaClassInitializationBreakpoint = (className: string): boolean => {
        return LogicJava.putJavaClassInitializationBreakpoint(className);
    }

    /**
     * Put a native module initialization breakpoint
     *
     * ```javascript
     * putModuleInitializationBreakpoint('libtarget.so');
     * ```
     * @param moduleName
     */
    public putModuleInitializationBreakpoint = (moduleName: string): boolean => {
        return LogicInitialization.putModuleInitializationBreakpoint(moduleName);
    }



    /**
     * A shortcut and secure way to read a string from a pointer with frida on any os
     *
     * @return the string pointed by address until termination or optional length
     */
    public readString = (address, length?) => {
        try {
            address = ptr(address);
            let fstring = "";
            if (!isNumber(length)) {
                length = -1;
            }
            const range = Process.findRangeByAddress(address);
            if (!isDefined(range)) {
                return "";
            }
            if (isString(range.protection) && range.protection.indexOf('r') === -1) {
                //Access violation
                return "";
            }
            const _np = new NativePointer(address);
            if (!isDefined(_np)) {
                return "";
            }
            if (Process.platform === 'windows') {
                fstring = _np.readAnsiString(length);

                if (fstring === null) {
                    fstring = _np.readUtf16String(length);
                }
            }
            if (fstring === null) {
                fstring = _np.readCString(length);
            }
            if (fstring === null) {
                fstring = _np.readUtf8String(length);
            }
            if (isString(fstring) && fstring.length) {
                for (let i = 0; i < fstring.length; i++) {
                    if (!this.isPrintable(fstring.charCodeAt(i))) {
                        fstring = null;
                        break;
                    }
                }
            }
            if (fstring !== null && isString(fstring) && fstring.length) {
                return fstring;
            } else {
                return "";
            }
        } catch (e) {
            logErr('readString', e);
            return "";
        }
    }

    /**
     * A shortcut for safely reading from memory
     *
     * @return an ArrayBuffer of the given length filled with data starting from target address
     */
    public readBytes = (address, length) => {
        try {
            address = ptr(address);

            // make sure all involved ranges are read-able
            const ranges = [];

            let range;
            let tmp = ptr(address);
            const tail = parseInt(tmp.add(length).toString(), 16);
            while (true) {
                try {
                    range = Process.findRangeByAddress(tmp);
                } catch (e) {
                    break;
                }
                if (range) {
                    if (range.protection[0] !== 'r') {
                        Memory.protect(range.base, range.size, 'r--');
                        ranges.push(range);
                    }

                    tmp = tmp.add(range.size);
                    if (parseInt(tmp.toString(), 16) >= tail) {
                        break;
                    }
                } else {
                    break;
                }
            }

            const data = ptr(address).readByteArray(length);

            ranges.forEach(range => {
                Memory.protect(range.base, range.size, range.protection);
            });

            return data;
        } catch (e) {
            logErr('readBytes', e);
            return [];
        }
    }

    /**
     * @return a pointer from the given address
     */
    public readPointer = (pt) => {
        try {
            return ptr(pt).readPointer();
        } catch (e) {
            logErr('readPointer', e);
            return NULL;
        }
    }

    /**
     * resume the execution of the given thread id
     */
    public releaseFromJs = (tid): void => {
        Dwarf.loggedSend('release_js:::' + tid);
    }

    /**
     * Removes Breakpoint with id
     *
     * @param  {number} breakpointID
     * @return a boolean indicating if removal was successful
     */
    public removeBreakpoint = (breakpointID: number): boolean => {
        trace('DwarfApi::removeBreakpoint()');

        if (!isNumber(breakpointID) || breakpointID < 1) {
            throw new Error('DwarfApi::removeBreakpoint() => Invalid argument!');
        }
        return DwarfBreakpointManager.getInstance().removeBreakpointByID(breakpointID);
    }

    /**
     * Removes Breakpoint at given Address
     *
     * @param  {NativePointer|string|number} breakpointAddress
     * @returns boolean indicating if removal was successful
     */
    public removeBreakpointAtAddress = (breakpointAddress: NativePointer | string | number): boolean => {
        trace('DwarfApi::removeBreakpointAtAddress()');

        if (!isDefined(breakpointAddress)) {
            throw new Error('DwarfApi::removeBreakpointAtAddress() => Invalid argument!');
        }

        let bpAddress: NativePointer | string = null;

        //convert address
        if (isString(breakpointAddress) && (breakpointAddress as string).startsWith('0x')) {
            breakpointAddress = parseInt((breakpointAddress as string), 16);
        }

        //check address
        if (!isString(breakpointAddress)) {
            bpAddress = makeNativePointer(breakpointAddress);
            if (!checkNativePointer(bpAddress)) {
                throw new Error('DwarfApi::removeBreakpointAtAddress() => Invalid address!');
            }
        } else {
            if ((breakpointAddress as string).length > 0) {
                bpAddress = breakpointAddress as string;
            } else {
                throw new Error('DwarfApi::removeBreakpointAtAddress() => Invalid address!');
            }
        }

        return DwarfBreakpointManager.getInstance().removeBreakpointAtAddress(bpAddress);
    }

    /**
     * Remove a java class initialization breakpoint on moduleName
     * @return a boolean indicating if removal was successful
     */
    public removeClassLoaderHook = (className: string): boolean => {
        trace('DwarfApi::removeClassLoaderHook()');

        if (!isDefined(className)) {
            throw new Error('DwarfApi::removeClassLoaderHook() => Invalid arguments!');
        }

        return DwarfJavaHelper.getInstance().removeClassLoaderHook(className);
    }

    /**
     * Remove a module initialization breakpoint on moduleName
     * @return a boolean indicating if removal was successful
     */
    public removeModuleInitializationBreakpoint = (moduleName: string): boolean => {
        const ret = LogicInitialization.removeModuleInitializationBreakpoint(moduleName);
        if (ret) {
            Dwarf.loggedSend('breakpoint_deleted:::module_initialization:::' + moduleName);
        }
        return ret;
    }

    public removeNativeBreakpoint = (breakpointAddress: NativePointer | string | number): boolean => {
        trace('DwarfApi::removeNativeBreakpoint()');

        return this.removeBreakpointAtAddress(breakpointAddress);
    }

    /**
     * Remove a MemoryBreakpoint on the given address
     * @return a boolean indicating if removal was successful
     */
    public removeMemoryBreakpoint = (memoryAddress: NativePointer | string): boolean => {
        trace('DwarfApi::removeMemoryBreakpoint()');

        return this.removeBreakpointAtAddress(memoryAddress);
    }

    public removeJavaBreakpoint = (breakpointAddress: string): boolean => {
        trace('DwarfApi::removeJavaBreakpoint()');

        return this.removeBreakpointAtAddress(breakpointAddress);
    }

    public removeObjcBreakpoint = (breakpointAddress: string): boolean => {
        trace('DwarfApi::removeObjcBreakpoint()');
        throw new Error('Not implemented');
    }

    /**
     * Restart the application
     *
     * Android only
     * TODO: public?
     */
    public restart = (): boolean => {
        if (LogicJava.available) {
            return LogicJava.restartApplication();
        }

        return false;
    }

    private resume = () => {
        if (Dwarf.PROC_RESUMED) {
            Dwarf.PROC_RESUMED = true;
            Dwarf.loggedSend('resume:::0');
        } else {
            console.log('Error: Process already resumed');
        }
    }

    private setBreakpointCondition = (address_or_class: any, condition?: string | Function): boolean => {
        return LogicBreakpoint.setBreakpointCondition(address_or_class, condition);
    }

    /**
     * Send whatever to the data panel
     *
     * ```javascript
     * var sendCount = 0;
     * Interceptor.attach(findExport('send'), function() {
     *     setData(sendCount + '', this.context.x1.readByteArray(parseInt(this.context.x2)))
     *     sendCount++;
     * });
     * ```
     */
    public setData = (key, data) => {
        if (typeof key !== 'string' && key.length < 1) {
            return;
        }

        if (data.constructor.name === 'ArrayBuffer') {
            Dwarf.loggedSend('set_data:::' + key, data)
        } else {
            if (typeof data === 'object') {
                data = JSON.stringify(data, null, 4);
            }
            Dwarf.loggedSend('set_data:::' + key + ':::' + data)
        }
    }

    /**
     * Start the java tracer on the given classes
     */
    public startJavaTracer = (classes: string[], callback: Function) => {
        return LogicJava.startTrace(classes, callback);
    }

    /**
     * Start the native tracer on the current thread
     *
     * ```javascript
     * startNativeTracer(function() {
     *     log('===============');
     *     log(this.instruction);
     *     log(this.context);
     *     log('===============');
     *     if (shouldStopTracer) {
     *         this.stop();
     *     }
     * });
     * ```
     */
    public startNativeTracer = (callback) => {
        const stalkerInfo = LogicStalker.stalk();
        if (stalkerInfo !== null) {
            stalkerInfo.currentMode = callback;
            return true;
        }

        return false;
    }

    /**
     * Stop the java tracer
     */
    public stopJavaTracer = (): boolean => {
        return LogicJava.stopTrace();
    }

    /**
     * start strace
     */
    public strace = (callback): boolean => {
        return LogicStalker.strace(callback);
    }

    public updateModules = () => {
        const modules = this.enumerateModules();
        Dwarf.loggedSend('update_modules:::' + Process.getCurrentThreadId() + ':::' + JSON.stringify(modules));
    }

    private updateRanges = () => {
        try {
            Dwarf.loggedSend('update_ranges:::' + Process.getCurrentThreadId() + ':::' +
                JSON.stringify(Process.enumerateRanges('---')))
        } catch (e) {
            logErr('updateRanges', e);
        }
    }

    private updateSearchableRanges = () => {
        try {
            Dwarf.loggedSend('update_searchable_ranges:::' + Process.getCurrentThreadId() + ':::' +
                JSON.stringify(Process.enumerateRanges('r--')))
        } catch (e) {
            logErr('updateSearchableRanges', e);
        }
    }

    /**
     * Write the given hex string or ArrayBuffer into the given address
     */
    public writeBytes = (address: any, what: string | ArrayBuffer) => {
        try {
            address = ptr(address);
            if (typeof what === 'string') {
                this.writeUtf8(address, hex2a(what));
            } else {
                address.writeByteArray(what);
            }
            return true;
        } catch (e) {
            logErr('writeBytes', e);
            return false;
        }
    }

    private writeUtf8 = (address: any, str: any) => {
        try {
            address = ptr(address);
            address.writeUtf8String(str);
            return true;
        } catch (e) {
            logErr('writeUtf8', e);
            return false;
        }
    }
}