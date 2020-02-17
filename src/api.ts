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
import { LogicJava } from "./logic_java";
import { LogicStalker } from "./logic_stalker";
import { ThreadWrapper } from "./thread_wrapper";
import { DwarfMemoryAccessType, DwarfHookType, DwarfDataDisplayType } from "./consts";
import { DwarfCore } from "./dwarf";
import { MemoryHook } from "./types/memory_hook";
import { DwarfHooksManager } from "./hooks_manager";
import { DwarfObserver } from "./dwarf_observer";
import { NativeHook } from "./types/native_hook";
import { JavaHook } from "./types/java_hook";
import { ObjcHook } from "./types/objc_hook";
import { DwarfJavaHelper } from "./java";
import { ModuleLoadHook } from "./types/module_load_hook";

export class DwarfApi {
    private static instanceRef: DwarfApi;
    private isPrintFunc: NativeFunction;

    private constructor() {
        if (DwarfApi.instanceRef) {
            throw new Error("DwarfApi already exists! Use DwarfApi.getInstance()/Dwarf.getApi()");
        }
        logDebug("DwarfApi()");
        let isPrintPtr = this.findExport("isprint");
        if (checkNativePointer(isPrintPtr)) {
            this.isPrintFunc = new NativeFunction(isPrintPtr, "int", ["int"]);
        }
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
     * @param  {DwarfHookType|string|number} breakpointType
     * @param  {NativePointer|string|number} bpAddress
     * @param  {boolean} bpEnabled? (default: enabled)
     *
     * TODO: add ObjcHooks
     */
    public addHook = (
        breakpointType: DwarfHookType | string | number,
        bpAddress: NativePointer | string | number,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ): NativeHook | MemoryHook | JavaHook | ModuleLoadHook => {
        trace("DwarfApi::addHook()");

        let bpType: DwarfHookType = 0;
        let checkedAddress: DwarfHookAddress = null;

        //check type
        if (!isDefined(breakpointType)) {
            throw new Error("DwarfApi::addHook() => No BreakpointType given!");
        } else {
            if (isString(breakpointType)) {
                switch ((breakpointType as string).toLowerCase()) {
                    case "native":
                        bpType = DwarfHookType.NATIVE;
                        break;
                    case "memory":
                        bpType = DwarfHookType.MEMORY;
                        break;
                    case "java":
                        bpType = DwarfHookType.JAVA;
                        break;
                    case "objc":
                        bpType = DwarfHookType.OBJC;
                        break;
                    case "module_load":
                        bpType = DwarfHookType.MODULE_LOAD;
                        break;
                    default:
                        throw new Error("DwarfApi::addHook() => Invalid BreakpointType!");
                }
            } else if (isNumber(breakpointType)) {
                bpType = breakpointType as number;
            } else {
                throw new Error("DwarfApi::addHook() => Invalid BreakpointType!");
            }
        }

        if (bpType < DwarfHookType.NATIVE || bpType > DwarfHookType.CLASS_LOAD) {
            throw new Error("DwarfApi::addHook() => Invalid BreakpointType!");
        }

        if (bpType == DwarfHookType.JAVA && !Java.available) {
            throw new Error("DwarfApi::addHook() => No JAVA Breakpoints available!");
        }

        if (bpType == DwarfHookType.OBJC && !ObjC.available) {
            throw new Error("DwarfApi::addHook() => No OBJC Breakpoints available!");
        }

        //check address
        if (!isDefined(bpAddress)) {
            throw new Error("DwarfApi::addHook() => No Address given!");
        } else {
            if (bpType == DwarfHookType.NATIVE || bpType == DwarfHookType.MEMORY) {
                bpAddress = makeNativePointer(bpAddress);
                if (checkNativePointer(bpAddress)) {
                    checkedAddress = bpAddress;
                } else {
                    throw new Error("DwarfApi::addHook() => Invalid Address!");
                }
            } else {
                //java+objc addresses
                if (!isString(bpAddress)) {
                    throw new Error("DwarfApi::addHook() => Invalid Address!");
                } else {
                    if (!Java.available && !ObjC.available) {
                        throw new Error("DwarfApi::addHook() => Invalid Address!");
                    }
                    if ((bpAddress as string).length > 0) {
                        checkedAddress = bpAddress as string;
                    }
                }
            }
        }

        if (!isDefined(checkedAddress)) {
            throw new Error("DwarfApi::addHook() => Something is wrong!");
        }

        //add to bpman
        return DwarfHooksManager.getInstance().addHook(bpType, checkedAddress, userCallback, isSingleShot, isEnabled);
    };

    /**
     * Create a MemoryHook on the given address
     *
     * ```javascript
     * addMemoryHook(0x1000, 'r');
     *
     * var target = findExport('memcpy');
     * Interceptor.attach(target, {
     *     onLeave: function(ret) {
     *         addMemoryHook(this.context.x0, 'rw', function() {
     *            log(backtrace(this.context));
     *         });
     *     }
     * });
     * ```
     * @param address
     * @param flags
     * @param callback
     */
    public addMemoryHook = (
        memoryAddress: NativePointer | string | number,
        bpFlags: string | number,
        userCallback: Function | string = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ): MemoryHook => {
        trace("DwarfApi::addMemoryHook()");

        let bpAddress = makeNativePointer(memoryAddress);
        if (!checkNativePointer(bpAddress)) {
            throw new Error("DwarfApi::addMemoryHook() => Invalid Address!");
        }

        const rangeDetails = Process.findRangeByAddress(bpAddress);

        if (!isDefined(rangeDetails)) {
            throw new Error("DwarfApi::addMemoryHook() => Unable to find Range for " + bpAddress.toString());
        }

        if (rangeDetails && rangeDetails.protection.indexOf("r") === -1) {
            throw new Error("DwarfApi::addMemoryHook() => Unable to access Memory at " + bpAddress.toString());
        }

        let intFlags = 0;
        if (typeof bpFlags === "string") {
            if (bpFlags.indexOf("r") >= 0) {
                intFlags |= DwarfMemoryAccessType.READ;
            }
            if (bpFlags.indexOf("w") >= 0) {
                intFlags |= DwarfMemoryAccessType.WRITE;
            }
            if (bpFlags.indexOf("x") >= 0) {
                intFlags |= DwarfMemoryAccessType.EXECUTE;
            }
        } else if (typeof bpFlags === "number") {
            intFlags = bpFlags;
        } else {
            throw new Error("DwarfApi::addMemoryHook() -> Unknown FlagsType! (allowed string|number)");
        }

        try {
            const memoryHook = DwarfHooksManager.getInstance().addMemoryHook(
                bpAddress,
                intFlags,
                userCallback,
                isSingleShot,
                isEnabled
            );
            return memoryHook;
        } catch (error) {
            logErr("DwarfApi::addMemoryHook()", error);
            throw error;
        }
    };

    public addNativeHook = (
        bpAddress: NativePointer | string | number,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ): NativeHook => {
        trace("DwarfApi::addNativeHook()");

        try {
            bpAddress = makeNativePointer(bpAddress);
            if (!checkNativePointer(bpAddress)) {
                throw new Error("DwarfApi::addNativeHook() => Invalid Address!");
            }
            const NativeHook = DwarfHooksManager.getInstance().addNativeHook(
                bpAddress,
                userCallback,
                isSingleShot,
                isEnabled
            );
            return NativeHook;
        } catch (error) {
            logErr("DwarfApi::addNativeHook()", error);
            throw error;
        }
    };

    public addJavaHook = (
        className: string,
        methodName: string = "$init",
        userCallback: DwarfCallback = "breakpoint",
        isEnabled: boolean = true,
        isSingleShot: boolean = false
    ): JavaHook => {
        trace("DwarfApi::addJavaHook()");

        if (!isString(className)) {
            throw new Error("DwarfApi::addJavaHook() => Invalid Adddress!");
        }

        if (!isString(methodName)) {
            throw new Error("DwarfApi::addJavaHook() => Invalid Adddress!");
        }

        try {
            const JavaHook = DwarfHooksManager.getInstance().addJavaHook(
                className,
                methodName,
                userCallback,
                isSingleShot,
                isEnabled
            );
            return JavaHook;
        } catch (error) {
            logErr("DwarfApi::addNativeHook()", error);
            throw error;
        }
    };

    public addObjcHook = (
        bpAddress: string,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ): ObjcHook => {
        trace("DwarfApi::addObjcHook()");

        throw new Error("Not implemented!");
    };

    public addModuleLoadHook = (
        moduleName: string,
        userCallback: DwarfCallback,
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ): ModuleLoadHook => {
        return DwarfHooksManager.getInstance().addModuleLoadHook(moduleName, userCallback, isSingleShot, isEnabled);
    };

    /**
     * Adds Bookmark in UI
     *
     * @param  {NativePointer|string} bmAddress
     * @param  {string} bmNote
     */
    public addBookmark = (bmAddress: NativePointer | string, bmNote: string) => {
        trace("DwarfApi::addBookmark()");

        if (bmAddress.constructor.name === "NativePointer") {
            bmAddress = bmAddress.toString();
        }
        if (isString(bmAddress)) {
            if (bmAddress.hasOwnProperty("toString")) {
                bmAddress = bmAddress.toString();
            }
            DwarfCore.getInstance().sync({ bookmark: { address: bmAddress, note: bmNote } });
        } else {
            throw new Error("Invalid Arguments!");
        }
    };
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
    public addObserveLocation = (
        name: string,
        npAddress: NativePointer | string,
        watchType: string,
        watchMode: string,
        handler: string | Function,
        bytesLength: number = 0
    ) => {
        trace("DwarfApi::addObserveLocation()");

        if (isString(handler) && handler !== "breakpoint") {
            //TODO: convert handlerstr from ui to func
        }
        return DwarfObserver.getInstance().addLocation(name, npAddress, watchType, bytesLength, watchMode, handler);
    };

    /**
     * Removes Location from DwarfObserver
     *
     * @param  {number} observeId
     */
    public removeObserveLocation = (observeId: number) => {
        trace("DwarfApi::removeObserveLocation()");

        return DwarfObserver.getInstance().removeById(observeId);
    };

    /**
     * Removes Location from DwarfObserver
     *
     * @param  {string} observeName
     */
    public removeObserveLocationByName = (observeName: string) => {
        trace("DwarfApi::removeObserveLocationByName()");

        return DwarfObserver.getInstance().removeByName(observeName);
    };

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

        return Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress);
    };

    /**
     * Enumerate exports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    public enumerateModuleExports = (module: Module | NativePointer | number | string): Array<ModuleExportDetails> => {
        let fridaModule: Module | null = null;

        if (!isDefined(module)) {
            throw new Error("DwarfApi::enumerateExports() -> Invalid Arguments!");
        }

        try {
            const nativePtr = makeNativePointer(module);
            fridaModule = Process.findModuleByAddress(nativePtr);
        } catch (e) {
            logErr("DwarfApi::enumerateExports()", e);
        }

        if (!isDefined(fridaModule)) {
            if (isString(module)) {
                fridaModule = Process.findModuleByName(module as string);
            } else if (typeof module === "object" && module.hasOwnProperty("enumerateExports")) {
                fridaModule = module as Module;
            }
        }

        if (!isDefined(fridaModule)) {
            throw new Error("DwarfApi::enumerateExports() -> Module not found!");
        }

        if (fridaModule && Dwarf.modulesBlacklist.indexOf(fridaModule.name) !== -1) {
            throw new Error("DwarfApi::enumerateExports() -> Module is blacklisted!");
        }

        //@ts-ignore
        return fridaModule.enumerateExports();
    };

    /**
     * Enumerate imports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    public enumerateModuleImports = (module: Module | NativePointer | number | string): Array<ModuleImportDetails> => {
        let fridaModule: Module | null = null;

        if (!isDefined(module)) {
            throw new Error("DwarfApi::enumerateImports() -> Invalid Arguments!");
        }

        try {
            const nativePtr = makeNativePointer(module);
            fridaModule = Process.findModuleByAddress(nativePtr);
        } catch (e) {
            logErr("DwarfApi::enumerateImports()", e);
        }

        if (!isDefined(fridaModule)) {
            if (isString(module)) {
                fridaModule = Process.findModuleByName(module as string);
            } else if (typeof module === "object" && module.hasOwnProperty("enumerateImports")) {
                fridaModule = module as Module;
            }
        }

        if (!isDefined(fridaModule)) {
            throw new Error("DwarfApi::enumerateImports() -> Module not found!");
        }

        if (fridaModule && Dwarf.modulesBlacklist.indexOf(fridaModule.name) !== -1) {
            throw new Error("DwarfApi::enumerateImports() -> Module is blacklisted!");
        }

        //@ts-ignore
        return fridaModule.enumerateImports();
    };

    /**
     * Enumerate symbols for the given module name or pointer
     * @param module an hex/int address or string name
     */
    public enumerateModuleSymbols = (module: Module | NativePointer | number | string): Array<ModuleSymbolDetails> => {
        let fridaModule: Module | null = null;

        if (!isDefined(module)) {
            throw new Error("DwarfApi::enumerateSymbols() -> Invalid Arguments!");
        }

        try {
            const nativePtr = makeNativePointer(module);
            fridaModule = Process.findModuleByAddress(nativePtr);
        } catch (e) {
            logErr("DwarfApi::enumerateSymbols()", e);
        }

        if (!isDefined(fridaModule)) {
            if (isString(module)) {
                fridaModule = Process.findModuleByName(module as string);
            } else if (typeof module === "object" && module.hasOwnProperty("enumerateSymbols")) {
                fridaModule = module as Module;
            }
        }

        if (!isDefined(fridaModule)) {
            throw new Error("DwarfApi::enumerateSymbols() -> Module not found!");
        }

        if (fridaModule && Dwarf.modulesBlacklist.indexOf(fridaModule.name) !== -1) {
            throw new Error("DwarfApi::enumerateSymbols() -> Module is blacklisted!");
        }

        //@ts-ignore
        return fridaModule.enumerateSymbols();
    };

    /**
     * Enumerates memory ranges of module with the `name` as seen in `Process#enumerateModules()`.
     *
     * @param protection Minimum protection of ranges to include.
     */
    public enumerateModuleRanges = (
        module: Module | NativePointer | number | string,
        protection: string = "r--"
    ): Array<RangeDetails> => {
        let fridaModule: Module | null = null;

        if (!isDefined(module) || !isString(protection)) {
            throw new Error("DwarfApi::enumerateModuleRanges() -> Invalid Arguments!");
        }

        try {
            const nativePtr = makeNativePointer(module);
            fridaModule = Process.findModuleByAddress(nativePtr);
        } catch (e) {
            logErr("DwarfApi::enumerateModuleRanges()", e);
        }

        if (!isDefined(fridaModule)) {
            if (isString(module)) {
                fridaModule = Process.findModuleByName(module as string);
            } else if (typeof module === "object" && module.hasOwnProperty("enumerateRanges")) {
                fridaModule = module as Module;
            }
        }

        if (!isDefined(fridaModule)) {
            throw new Error("DwarfApi::enumerateModuleRanges() -> Module not found!");
        }

        if (fridaModule && Dwarf.modulesBlacklist.indexOf(fridaModule.name) !== -1) {
            throw new Error("DwarfApi::enumerateModuleRanges() -> Module is blacklisted!");
        }

        //@ts-ignore
        return fridaModule.enumerateRanges(protection);
    };

    /**
     *   TODO: this is used to populate ui we should remove it from api
     * Enumerate method for the given class
     */
    public enumerateJavaMethods = (className: string): void => {
        if (Java.available) {
            Java.performNow(function() {
                // 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
                const clazz = Java.use(className);
                const methods: Array<Java.Method> = clazz.class.getDeclaredMethods();
                clazz.$dispose();

                const parsedMethods: Array<string> = new Array<string>();

                for (const method of methods) {
                    const methodName = method.toString().replace(className + ".", "TOKEN");
                    const regexMatch = methodName.match(/\sTOKEN(.*)\(/);

                    if (regexMatch && regexMatch.length >= 2) {
                        parsedMethods.push(regexMatch[1]);
                    }
                }

                if (parsedMethods.length > 0) {
                    Dwarf.sync({ classInfo: { className: className, classMethods: uniqueBy(parsedMethods) } });
                }
            });
        }
    };

    /**
     * Enumerate modules for ObjC inspector panel
     */
    public enumerateObjCModules = (className: string): void => {
        const modules = Process.enumerateModules();
        const names = modules.map(m => m.name);
        Dwarf.loggedSend("enumerate_objc_modules:::" + JSON.stringify(names));
    };

    /**
     * Enumerate loaded modules
     */
    public enumerateModules = (fillInformation?: boolean) => {
        fillInformation = fillInformation || false;

        const modules = Process.enumerateModules();
        if (fillInformation) {
            for (let i = 0; i < modules.length; i++) {
                if (Dwarf.modulesBlacklist.indexOf(modules[i].name) !== -1) {
                    continue;
                }

                modules[i] = this.getModuleInfo(modules[i]);
            }
        }
        return modules;
    };

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
    public getModuleInfo = (fridaModule: Module | string): Module => {
        let _module: Module = null;

        if (isString(fridaModule)) {
            _module = Process.findModuleByName(fridaModule as string);
        } else {
            _module = fridaModule as Module;
        }

        if (Dwarf.modulesBlacklist.indexOf(_module.name) >= 0) {
            console.error("Module " + _module.name + " is blacklisted");
            return _module;
        }

        try {
            _module["imports"] = _module.enumerateImports();
            _module["exports"] = _module.enumerateExports();
            _module["symbols"] = _module.enumerateSymbols();
        } catch (e) {
            return _module;
        }

        _module["entry"] = null;
        const header = _module.base.readByteArray(4);
        if (header[0] !== 0x7f && header[1] !== 0x45 && header[2] !== 0x4c && header[3] !== 0x46) {
            // Elf
            _module["entry"] = _module.base.add(24).readPointer();
        }

        return _module;
    };

    /**
     * Enumerate all mapped ranges
     */
    public enumerateRanges = (): RangeDetails[] => {
        return Process.enumerateRanges("---");
    };

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    public evaluate = (js_code: string): any => {
        js_code = js_code.replace(/\'/g, '"');
        const Thread = ThreadWrapper;
        try {
            return eval(js_code);
        } catch (e) {
            logErr("evaluate", e);
            return null;
        }
    };

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    public evaluateFunction = (js_code: string): any => {
        try {
            js_code = js_code.replace(/\'/g, '"');
            const fn = new Function("Thread", js_code);
            return fn.apply(this, [ThreadWrapper]);
        } catch (e) {
            logErr("evaluateFunction", e);
            return null;
        }
    };

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
    };

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
            throw new Error("DwarfApi::findExport() => No exportName given!");
        }

        if (!isString(moduleName)) {
            moduleName = null;
        }
        return Module.findExportByName(moduleName, exportName);
    };

    /**
     * Find a module providing any argument. Could be a string/int pointer or module name
     */
    public findModule = (module: any): Module | Module[] | null => {
        let _module;
        if (isString(module) && module.substring(0, 2) !== "0x") {
            _module = Process.findModuleByName(module);
            if (isDefined(_module)) {
                return _module;
            } else {
                // do wildcard search
                if (module.indexOf("*") !== -1) {
                    const modules = Process.enumerateModules();
                    const searchName = module.toLowerCase().split("*")[0];
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
    };

    /**
     * Find a symbol matching the given pattern
     */
    public findSymbol = (pattern: string): NativePointer[] => {
        if (!isString(pattern)) {
            throw new Error("DwarfApi::findSymbol() => No pattern given!");
        }
        return DebugSymbol.findFunctionsMatching(pattern);
    };

    /**
     * get telescope information for the given pointer argument
     * @param p: pointer
     */
    public getAddressTs = (p): [number, any] => {
        const _ptr = ptr(p);
        const _range = Process.findRangeByAddress(_ptr);
        if (isDefined(_range)) {
            if (_range.protection.indexOf("r") !== -1) {
                try {
                    let string = this.readString(_ptr);
                    if (isString(string)) {
                        for (let i = 0; i < string.length; i++) {
                            if (!this.isPrintable(string.charCodeAt(i))) {
                                if (i > 0) {
                                    string = string.substr(0, i);
                                } else {
                                    string = "";
                                }
                                break;
                            }
                        }
                        if (string.length > 0) {
                            return [0, string];
                        }
                    }
                } catch (e) {}
                try {
                    const ptrVal = _ptr.readPointer();
                    return [1, ptrVal];
                } catch (e) {}
                return [2, p];
            }
        }
        return [-1, p];
    };

    public showStrings = (
        startAddress: NativePointer | number | string,
        scanLength: number,
        minLen: number = 3,
        filter?: string
    ) => {
        console.log("Searching for Strings, Please wait...");
        this.enumerateStrings(startAddress, scanLength, minLen, filter, true);
        console.log("***** Done *****");
    };

    public enumerateStrings = (
        startAddress: NativePointer | number | string,
        scanLength: number,
        minLen: number = 3,
        filter?: string,
        fromUi?: boolean
    ) => {
        startAddress = makeNativePointer(startAddress);

        let searchResults = new Array<StringSearchResult>();

        const rangeDetails = Process.findRangeByAddress(startAddress);
        let oldProtection = "";

        //TODO: we need something here when scanlen is > range.size
        if (isDefined(rangeDetails)) {
            oldProtection = rangeDetails.protection;
        }

        Memory.protect(startAddress, scanLength, "rwx");

        //@ts-ignore
        let arrayBuffer = new Uint8Array(ArrayBuffer.wrap(startAddress, scanLength));

        if (isString(filter)) {
            minLen = filter.length;
        }

        for (var i = 0; i < scanLength; i++) {
            if (this.isPrintable(arrayBuffer[i])) {
                let string = "" + String.fromCharCode(arrayBuffer[i]);
                while (i < scanLength) {
                    let u8 = arrayBuffer[++i];
                    if (this.isPrintable(u8)) {
                        string += String.fromCharCode(u8);
                    } else {
                        if (string.length >= minLen) {
                            if (isString(filter) && string.indexOf(filter) != -1) {
                                const result = {
                                    string: string,
                                    length: string.length,
                                    address: startAddress.add(i)
                                };
                                if (isDefined(fromUi) && fromUi === true) {
                                    Dwarf.sync({
                                        stringResult: result
                                    });
                                } else {
                                    searchResults.push(result);
                                }
                            } else if (!isDefined(filter)) {
                                const result = {
                                    string: string,
                                    length: string.length,
                                    address: startAddress.add(i)
                                };
                                if (isDefined(fromUi) && fromUi === true) {
                                    Dwarf.sync({
                                        stringResult: result
                                    });
                                } else {
                                    searchResults.push(result);
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        if (isDefined(fromUi) && fromUi === true) {
            return;
        }
        return searchResults;
    };

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
                logErr("getDebugSymbols", e);
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
    public getInstruction = address => {
        try {
            const instruction = Instruction.parse(ptr(address));
            return JSON.stringify({
                string: instruction.toString()
            });
        } catch (e) {
            logErr("getInstruction", e);
        }
        return null;
    };

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
            logErr("getRange", e);
            return null;
        }
    };

    /**
     * Return DebugSymbol or null for the given pointer
     */
    public getSymbolByAddress = (npAddress: NativePointer | string): DebugSymbol | null => {
        try {
            npAddress = makeNativePointer(npAddress);
            return DebugSymbol.fromAddress(npAddress);
        } catch (e) {
            logErr("getSymbolByAddress", e);
            return null;
        }
    };

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
    };

    /**
     * Receive a callback whenever a java class is going to be loaded by the class loader.
     *
     * ```javascript
     * //custom callback
     * addClassLoadHook('com.target.classname', function() {
     *     console.log('target is being loaded');
     * });
     *
     * //breakpoint
     * addClassLoadHook('com.target.classname');
     * addClassLoadHook('com.target.classname', 'breakpoint');
     * ```
     *
     * @param  className
     * @param  userCallback
     * @param  isSingleShot
     * @param  isEnabled
     * @returns `ClassLoadHook`
     */
    public addClassLoadHook = (
        className: string,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) => {
        trace("DwarfApi::addClassLoaderHook()");

        if (!isString(className)) {
            throw new Error("DwarfApi::addClassLoadHook() => Invalid arguments!");
        }

        return DwarfHooksManager.getInstance().addClassLoadHook(className, userCallback, isSingleShot, isEnabled);
    };

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
        return LogicJava.hook(className, "$init", callback);
    };

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
    };

    /**
     * Map the given blob as hex string using memfd:create with the given name
     *
     * @return a negative integer if error or fd
     */
    public injectBlob = (name: string, blob: string) => {
        // arm syscall memfd_create
        let sys_num = 385;
        if (Process.arch === "ia32") {
            sys_num = 356;
        } else if (Process.arch === "x64") {
            sys_num = 319;
        }

        const syscall_ptr = this.findExport("syscall");
        const write_ptr = this.findExport("write");
        const dlopen_ptr = this.findExport("dlopen");

        if (syscall_ptr !== null && !syscall_ptr.isNull()) {
            const syscall = new NativeFunction(syscall_ptr, "int", ["int", "pointer", "int"]);
            if (write_ptr !== null && !write_ptr.isNull()) {
                const write = new NativeFunction(write_ptr, "int", ["int", "pointer", "int"]);
                if (dlopen_ptr !== null && !dlopen_ptr.isNull()) {
                    const dlopen = new NativeFunction(dlopen_ptr, "int", ["pointer", "int"]);

                    const m = DwarfFS.getInstance().allocateRw(128);
                    m.writeUtf8String(name);
                    const fd = syscall(sys_num, m, 0);
                    if (fd > 0) {
                        const hexArr = hex2a(blob);
                        const blob_space = Memory.alloc(hexArr.length);
                        Memory.protect(blob_space, hexArr.length, "rwx");
                        blob_space.writeByteArray(hexArr);
                        write(fd, blob_space, hexArr.length);
                        m.writeUtf8String("/proc/" + Process.id + "/fd/" + fd);
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
    };

    /**
     * @return a boolean indicating if the given pointer is currently watched
     * TODO:
     */
    public isAddressWatched = (pt: any): boolean => {
        const MemoryHook = DwarfHooksManager.getInstance().getHookByAddress(pt);
        if (MemoryHook.isEnabled()) {
            return true;
        }
        return false;
    };

    private isPrintable = (char: number): boolean => {
        try {
            if (isDefined(this.isPrintFunc)) {
                return this.isPrintFunc(char) as boolean;
            } else {
                if (char > 31 && char < 127) {
                    return true;
                }
            }
            return false;
        } catch (e) {
            logErr("isPrintable", e);
            return false;
        }
    };

    /**
     * @return a java stack trace. Must be executed in JVM thread
     */
    public javaBacktrace = () => {
        return LogicJava.backtrace();
    };

    /**
     * @return the explorer object for the given java handle
     */
    public jvmExplorer = (handle): {} => {
        return LogicJava.jvmExplorer(handle);
    };

    /**
     * A shortcut and secure way to read a string from a pointer with frida on any os
     *
     * @return the string pointed by address until termination or optional length
     */
    public readString = (address: NativePointer | number | string, length: number = -1): string => {
        address = makeNativePointer(address);
        let fstring = "";
        if (!isNumber(length)) {
            length = -1;
        }
        const rangeDetails = Process.getRangeByAddress(address);

        if (rangeDetails.protection.indexOf("r") === -1) {
            if (!Memory.protect(rangeDetails.base, rangeDetails.size, "rwx")) {
                //Access violation
                throw new Error("Unable to access Memory!");
            }
        }

        if (Process.platform === "windows") {
            try {
                fstring = address.readAnsiString(length);
                return fstring;
            } catch (e) {}

            try {
                fstring = address.readUtf16String(length);
                return fstring;
            } catch (e) {}
        }

        try {
            fstring = address.readCString(length);
            return fstring;
        } catch (e) {}

        try {
            fstring = address.readUtf8String(length);
            return fstring;
        } catch (e) {}

        return fstring;
    };

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
                    if (range.protection[0] !== "r") {
                        Memory.protect(range.base, range.size, "r--");
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
            logErr("readBytes", e);
            return [];
        }
    };

    /**
     * @return a pointer from the given address
     */
    public readPointer = pt => {
        try {
            return ptr(pt).readPointer();
        } catch (e) {
            logErr("readPointer", e);
            return NULL;
        }
    };

    /**
     * resume the execution of the given thread id
     */
    public releaseFromJs = (tid): void => {
        Dwarf.loggedSend("release_js:::" + tid);
    };

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
    };

    private resume = () => {
        if (Dwarf.PROC_RESUMED) {
            Dwarf.PROC_RESUMED = true;
            Dwarf.loggedSend("resume:::0");
        } else {
            console.error("Process already resumed");
        }
    };

    /**
     * ### Shows CustomData in UI
     *
     * dataTypes allowed `DwarfDataDisplayType` or ['text', 'json', 'hex', 'disasm', 'sqlite3']
     *
     * for `DwarfDataDisplayType.DISASM` you can pass an optional Base (as hex) and Mode 'thumb'
     *
     *
     * #### Examples:
     * ```javascript
     * showData('text', 'Test', 'Hello World');
     * ```
     *
     * ```javascript
     * showData('hex', 'Bytes at eax', this.context['eax'].readByteArray(100));
     * ```
     *
     * ```javascript
     * var baseAddr = ptr(this.context['eax']).toString();
     * showData('diasm', 'Disasm from ' + baseAddr, this.context['eax'].readByteArray(100), baseAddr);
     * showData('diasm', 'Disasm from ' + baseAddr, this.context['eax'].readByteArray(100), baseAddr, 'thumb');
     * ```
     *
     * ```javascript
     * showData(2, 'Sample JSON', { name: 'Test', otherItem: 1 });
     * ```
     *
     * ```javascript
     * showData('sqlite3', 'Sample Database', '/full/path/to/file.db'); //on Android it pulls db from Device
     * ```
     *
     *
     * @param  {DwarfDataDisplayType} dataType - default `DwarfDataDisplayType.TEXT`
     * @param  {string} dataIdentifier - some identifier string
     * @param  {any} data - your data to display for ['hex', 'disasm'] use ArrayBuffer
     * @param  {number} base? optional as hex
     * @param  {string} mode? allowed: 'thumb' switches Disassembler from ARM to  THUMB on arm targets
     */
    public showData = (
        dataType: DwarfDataDisplayType | string = DwarfDataDisplayType.TEXT,
        dataIdentifier: string,
        data: any,
        base?: number,
        mode?: string
    ) => {
        trace("DwarfApi::showData()");

        if (!isDefined(dataType) || !isString(dataIdentifier) || !isDefined(data)) {
            throw new Error("DwarfApi::showData() -> Invalid Arguments!");
        }

        if (isString(dataType)) {
            switch (dataType as string) {
                case "text":
                    dataType = DwarfDataDisplayType.TEXT;
                    break;
                case "json":
                    dataType = DwarfDataDisplayType.JSON;
                    break;
                case "hex":
                    dataType = DwarfDataDisplayType.HEX;
                    break;
                case "disasm":
                    dataType = DwarfDataDisplayType.DISASM;
                    break;
                case "sqlite3":
                    dataType = DwarfDataDisplayType.SQLITE3;
                    break;
                default:
                    dataType = DwarfDataDisplayType.TEXT;
                    break;
            }
        }

        if (isNumber(dataType)) {
            if (dataType < DwarfDataDisplayType.TEXT || dataType > DwarfDataDisplayType.SQLITE3) {
                throw new Error("DwarfApi::showData() -> Invalid Arguments!");
            }
        } else {
            throw new Error("DwarfApi::showData() -> Invalid Arguments!");
        }

        if (data.constructor.name === "ArrayBuffer") {
            if (dataType !== DwarfDataDisplayType.HEX && dataType !== DwarfDataDisplayType.DISASM) {
                dataType = DwarfDataDisplayType.HEX;
            }
        }

        if ((dataType === DwarfDataDisplayType.TEXT || dataType === DwarfDataDisplayType.SQLITE3) && isString(data)) {
            if (data.length) {
                DwarfCore.getInstance().sync({ showData: { type: dataType, ident: dataIdentifier, data: data } });
            }
        } else if (dataType === DwarfDataDisplayType.JSON && (typeof data === "object" || isString(data))) {
            const data_json = JSON.stringify(data);
            if (data_json.length) {
                DwarfCore.getInstance().sync({ showData: { type: dataType, ident: dataIdentifier, data: data_json } });
            }
        } else if (
            (dataType === DwarfDataDisplayType.HEX || dataType === DwarfDataDisplayType.DISASM) &&
            data.constructor.name === "ArrayBuffer"
        ) {
            if ((data as ArrayBuffer).byteLength) {
                const ptr_size = Dwarf.processInfo.getPointerSize();
                const arch = Dwarf.processInfo.getArchitecture();
                DwarfCore.getInstance().sync({
                    showData: {
                        type: dataType,
                        ident: dataIdentifier,
                        data: ba2hex(data),
                        ptr_size: ptr_size,
                        arch: arch,
                        base: base,
                        mode: mode
                    }
                });
            }
        }
    };

    /**
     * Start the java tracer on the given classes
     */
    public startJavaTracer = (classes: string[], callback: Function) => {
        return LogicJava.startTrace(classes, callback);
    };

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
    public startNativeTracer = callback => {
        const stalkerInfo = LogicStalker.stalk();
        if (stalkerInfo !== null) {
            stalkerInfo.currentMode = callback;
            return true;
        }

        return false;
    };

    /**
     * Stop the java tracer
     */
    public stopJavaTracer = (): boolean => {
        return LogicJava.stopTrace();
    };

    /**
     * start strace
     */
    public strace = (callback): boolean => {
        return LogicStalker.strace(callback);
    };

    public updateModules = () => {
        const modules = this.enumerateModules();
        Dwarf.loggedSend("update_modules:::" + Process.getCurrentThreadId() + ":::" + JSON.stringify(modules));
    };

    private updateRanges = () => {
        try {
            Dwarf.loggedSend(
                "update_ranges:::" +
                    Process.getCurrentThreadId() +
                    ":::" +
                    JSON.stringify(Process.enumerateRanges("---"))
            );
        } catch (e) {
            logErr("updateRanges", e);
        }
    };

    private updateSearchableRanges = () => {
        try {
            Dwarf.loggedSend(
                "update_searchable_ranges:::" +
                    Process.getCurrentThreadId() +
                    ":::" +
                    JSON.stringify(Process.enumerateRanges("r--"))
            );
        } catch (e) {
            logErr("updateSearchableRanges", e);
        }
    };

    /**
     * Write the given hex string or ArrayBuffer into the given address
     */
    public writeBytes = (address: any, what: string | ArrayBuffer) => {
        try {
            address = ptr(address);
            if (typeof what === "string") {
                this.writeUtf8(address, hex2a(what));
            } else {
                address.writeByteArray(what);
            }
            return true;
        } catch (e) {
            logErr("writeBytes", e);
            return false;
        }
    };

    private writeUtf8 = (address: any, str: any) => {
        try {
            address = ptr(address);
            address.writeUtf8String(str);
            return true;
        } catch (e) {
            logErr("writeUtf8", e);
            return false;
        }
    };
}
