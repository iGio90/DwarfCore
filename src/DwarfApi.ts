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

import { DwarfFS } from "./DwarfFS";
import { LogicJava } from "./logic_java";
import { ThreadWrapper } from "./thread_wrapper";
import { DwarfMemoryAccessType, DwarfHookType, DwarfDataDisplayType } from "./consts";
import { DwarfCore } from "./DwarfCore";
import { MemoryHook } from "./types/MemoryHook";
import { DwarfHooksManager } from "./DwarfHooksManager";
import { DwarfObserver } from "./DwarfObserver";
import { NativeHook } from "./types/NativeHook";
import { JavaHook } from "./types/JavaHook";
import { ObjcHook } from "./types/ObjcHook";
import { DwarfJavaHelper } from "./DwarfJavaHelper";
import { ModuleLoadHook } from "./types/ModuleLoadHook";
import { ELFFile } from "./types/ELFFile";

export class DwarfApi {
    /** @internal */
    static getInstance() {
        if (!DwarfApi.instanceRef) {
            DwarfApi.instanceRef = new this();
        }
        return DwarfApi.instanceRef;
    }
    private static instanceRef: DwarfApi;
    private _isPrintFunc: NativeFunction;

    /** @internal */
    private constructor() {
        if (DwarfApi.instanceRef) {
            throw new Error("DwarfApi already exists! Use DwarfApi.getInstance()/Dwarf.getApi()");
        }
        logDebug("DwarfApi()");
        const isPrintPtr = this.findExport("isprint");
        if (checkNativePointer(isPrintPtr)) {
            this._isPrintFunc = new NativeFunction(isPrintPtr, "int", ["int"]);
        }
    }

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
    public addClassLoadHook = (className: string, userCallback: DwarfCallback = "breakpoint", isSingleShot: boolean = false, isEnabled: boolean = true) => {
        trace("DwarfApi::addClassLoaderHook()");

        if (!isString(className)) {
            throw new Error("DwarfApi::addClassLoadHook() => Invalid arguments!");
        }

        return DwarfHooksManager.getInstance().addClassLoadHook(className, userCallback, isSingleShot, isEnabled);
    };

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
    ): NativeHook | MemoryHook | JavaHook | ObjcHook | ModuleLoadHook => {
        trace("DwarfApi::addHook()");

        let bpType: DwarfHookType = 0;
        let checkedAddress: DwarfHookAddress = null;

        // check type
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

        if (bpType === DwarfHookType.JAVA && !Java.available) {
            throw new Error("DwarfApi::addHook() => No JAVA Breakpoints available!");
        }

        if (bpType === DwarfHookType.OBJC && !ObjC.available) {
            throw new Error("DwarfApi::addHook() => No OBJC Breakpoints available!");
        }

        // check address
        if (!isDefined(bpAddress)) {
            throw new Error("DwarfApi::addHook() => No Address given!");
        } else {
            if (bpType === DwarfHookType.NATIVE || bpType === DwarfHookType.MEMORY) {
                bpAddress = makeNativePointer(bpAddress);
                if (checkNativePointer(bpAddress)) {
                    checkedAddress = bpAddress;
                } else {
                    throw new Error("DwarfApi::addHook() => Invalid Address!");
                }
            } else {
                // java+objc addresses
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

        // add to bpman
        return DwarfHooksManager.getInstance().addHook(bpType, checkedAddress, userCallback, isSingleShot, isEnabled);
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
            return DwarfHooksManager.getInstance().addJavaHook(className, methodName, userCallback, isSingleShot, isEnabled);
        } catch (error) {
            logErr("DwarfApi::addNativeHook()", error);
            throw error;
        }
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
        userCallback: fArgReturn | string = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ): MemoryHook => {
        trace("DwarfApi::addMemoryHook()");

        const bpAddress = makeNativePointer(memoryAddress);
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
            /* tslint:disable:no-bitwise */
            if (bpFlags.indexOf("r") >= 0) {
                intFlags |= DwarfMemoryAccessType.READ;
            }
            if (bpFlags.indexOf("w") >= 0) {
                intFlags |= DwarfMemoryAccessType.WRITE;
            }
            if (bpFlags.indexOf("x") >= 0) {
                intFlags |= DwarfMemoryAccessType.EXECUTE;
            }
            /* tslint:enable:no-bitwise */
        } else if (typeof bpFlags === "number") {
            intFlags = bpFlags;
        } else {
            throw new Error("DwarfApi::addMemoryHook() -> Unknown FlagsType! (allowed string|number)");
        }

        try {
            const memoryHook = DwarfHooksManager.getInstance().addMemoryHook(bpAddress, intFlags, userCallback, isSingleShot, isEnabled);
            return memoryHook;
        } catch (error) {
            logErr("DwarfApi::addMemoryHook()", error);
            throw error;
        }
    };

    public addModuleLoadHook = (moduleName: string, userCallback: DwarfCallback, isSingleShot: boolean = false, isEnabled: boolean = true): ModuleLoadHook => {
        return DwarfHooksManager.getInstance().addModuleLoadHook(moduleName, userCallback, isSingleShot, isEnabled);
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
            return DwarfHooksManager.getInstance().addNativeHook(bpAddress, userCallback, isSingleShot, isEnabled);
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
        handler: string | fEmptyReturn,
        bytesLength: number = 0
    ) => {
        trace("DwarfApi::addObserveLocation()");

        if (isString(handler) && handler !== "breakpoint") {
            // TODO: convert handlerstr from ui to func
        }
        return DwarfObserver.getInstance().addLocation(name, npAddress, watchType, bytesLength, watchMode, handler);
    };

    /**
     * Allocates `size` bytes of memory on Frida's private heap, or, if `size` is a multiple of Process#pageSize,
     * one or more raw memory pages managed by the OS. The allocated memory will be released when the returned
     * NativePointer value gets garbage collected. This means you need to keep a reference to it while the pointer
     * is being used by code outside the JavaScript runtime.
     *
     * @param size Number of bytes to allocate.
     * @param options Options to customize the memory allocation.
     */
    alloc = (size: number, options?: MemoryAllocOptions): NativePointer => {
        trace("DwarfApi::alloc()");

        return Memory.alloc(size, options);
    };

    /**
     * Allocates, encodes and writes out `str` as an ANSI string on Frida's private heap.
     * See Memory#alloc() for details about its lifetime.
     *
     * @param str String to allocate.
     */
    allocAString = (str: string): NativePointer => {
        trace("DwarfApi::allocAString()");

        return Memory.allocAnsiString(str);
    };

    /**
     * Allocates `size` bytes of memory on Frida's private heap, or, if `size` is a multiple of Process#pageSize,
     * one or more raw memory pages managed by the OS. The allocated memory will be released when the returned
     * NativePointer value gets garbage collected. This means you need to keep a reference to it while the pointer
     * is being used by code outside the JavaScript runtime.
     *
     * Protection for allocated memory is set to "rw-"
     *
     * @param size Number of bytes to allocate.
     * @param options Options to customize the memory allocation.
     */
    allocRW = (size: number, options?: MemoryAllocOptions): NativePointer => {
        trace("DwarfApi::allocRW()");

        const ptr = this.alloc(size, options);
        if (checkNativePointer(ptr)) {
            if (!Memory.protect(ptr, size, "rw-")) {
                console.log("Failed to set protection for: " + ptr.toString());
            }
            return ptr;
        }
        throw new Error("Failed to allocate memory");
    };

    /**
     * Allocates, encodes and writes out `str` as a UTF-8 string on Frida's private heap.
     * See Memory#alloc() for details about its lifetime.
     *
     * @param str String to allocate.
     */
    allocUString = (str: string): NativePointer => {
        trace("DwarfApi::allocUString()");

        return Memory.allocUtf8String(str);
    };

    /**
     * Shortcut to retrieve native backtrace
     * @param context: the CpuContext object
     */
    public backtrace = (context?: CpuContext): DebugSymbol[] | null => {
        if (!isDefined(context)) {
            context = DwarfCore.getInstance().getThreadContext[Process.getCurrentThreadId()];
            if (!isDefined(context)) {
                return null;
            }
        }

        return Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress);
    };

    /**
     *   TODO: this is used to populate ui we should remove it from api
     * Enumerate method for the given class
     */
    public enumerateJavaMethods = (className: string): void => {
        if (Java.available) {
            Java.performNow(function () {
                // 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
                const clazz = Java.use(className);
                const methods: Java.Method[] = clazz.class.getDeclaredMethods();
                clazz.$dispose();

                const parsedMethods: string[] = new Array<string>();

                for (const method of methods) {
                    const methodName = method.toString().replace(className + ".", "TOKEN");
                    const regexMatch = methodName.match(/\sTOKEN(.*)\(/);

                    if (regexMatch && regexMatch.length >= 2) {
                        parsedMethods.push(regexMatch[1]);
                    }
                }

                if (parsedMethods.length > 0) {
                    DwarfCore.getInstance().sync({ classInfo: { name: className, methods: uniqueBy(parsedMethods) } });
                }
            });
        }
    };

    /**
     * Enumerate exports for the given module name or pointer
     *
     * ```JSON
     * [
     *  {
     *      type: "function" | "variable",
     *      name: string,
     *      address: NativePointer
     *  }
     * ]
     * ```
     * @param module an hex/int address or string name
     */
    public enumerateModuleExports = (moduleInput: Module | NativePointer | number | string): ModuleExportDetails[] => {
        let fridaModule: Module;

        if (!isDefined(moduleInput)) {
            throw new Error("DwarfApi::enumerateExports() -> Invalid Arguments!");
        }

        try {
            const nativePtr = makeNativePointer(moduleInput);
            fridaModule = Process.findModuleByAddress(nativePtr);
        } catch (e) {
            logErr("DwarfApi::enumerateExports()", e);
        }

        if (!isDefined(fridaModule)) {
            if (isString(moduleInput)) {
                fridaModule = Process.findModuleByName(moduleInput as string);
            } else if (typeof moduleInput === "object" && moduleInput.hasOwnProperty("enumerateExports")) {
                fridaModule = moduleInput as Module;
            }
        }

        if (!isDefined(fridaModule)) {
            throw new Error("DwarfApi::enumerateExports() -> Module not found!");
        }

        if (fridaModule && DwarfCore.getInstance().isBlacklistedModule(fridaModule.name)) {
            throw new Error("DwarfApi::enumerateExports() -> Module is blacklisted!");
        }

        return fridaModule.enumerateExports();
    };

    /**
     * Enumerate imports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    public enumerateModuleImports = (moduleInput: Module | NativePointer | number | string): ModuleImportDetails[] => {
        let fridaModule: Module;

        if (!isDefined(moduleInput)) {
            throw new Error("DwarfApi::enumerateImports() -> Invalid Arguments!");
        }

        try {
            const nativePtr = makeNativePointer(moduleInput);
            fridaModule = Process.findModuleByAddress(nativePtr);
        } catch (e) {
            logErr("DwarfApi::enumerateImports()", e);
        }

        if (!isDefined(fridaModule)) {
            if (isString(moduleInput)) {
                fridaModule = Process.findModuleByName(moduleInput as string);
            } else if (typeof moduleInput === "object" && moduleInput.hasOwnProperty("enumerateImports")) {
                fridaModule = moduleInput as Module;
            }
        }

        if (!isDefined(fridaModule)) {
            throw new Error("DwarfApi::enumerateImports() -> Module not found!");
        }

        if (fridaModule && DwarfCore.getInstance().isBlacklistedModule(fridaModule.name)) {
            throw new Error("DwarfApi::enumerateImports() -> Module is blacklisted!");
        }

        return fridaModule.enumerateImports();
    };

    /**
     * Enumerates memory ranges of module with the `name` as seen in `Process#enumerateModules()`.
     *
     * @param protection Minimum protection of ranges to include.
     */
    public enumerateModuleRanges = (module: Module | NativePointer | number | string, protection: string = "r--"): RangeDetails[] => {
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

        if (fridaModule && DwarfCore.getInstance().isBlacklistedModule(fridaModule.name)) {
            throw new Error("DwarfApi::enumerateModuleRanges() -> Module is blacklisted!");
        }

        return fridaModule.enumerateRanges(protection);
    };

    /**
     * Enumerate loaded modules
     */
    public enumerateModules = (fillInformation?: boolean) => {
        fillInformation = fillInformation || false;

        const modules = Process.enumerateModules();
        if (fillInformation) {
            for (let i = 0; i < modules.length; i++) {
                if (DwarfCore.getInstance().isBlacklistedModule(modules[i].name)) {
                    continue;
                }

                modules[i] = this.getModuleInfo(modules[i]);
            }
        }
        return modules;
    };

    /**
     * Enumerate symbols for the given module name or pointer
     * @param module an hex/int address or string name
     */
    public enumerateModuleSymbols = (module: Module | NativePointer | number | string): ModuleSymbolDetails[] => {
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

        if (fridaModule && DwarfCore.getInstance().isBlacklistedModule(fridaModule.name)) {
            throw new Error("DwarfApi::enumerateSymbols() -> Module is blacklisted!");
        }

        return fridaModule.enumerateSymbols();
    };

    /**
     * Enumerate modules for ObjC inspector panel
     */
    public enumerateObjCModules = (className: string): void => {
        throw new Error("DwarfApi::enumerateObjCModules() not implemented");
    };

    /**
     * Enumerate all mapped ranges
     */
    public enumerateRanges = (): RangeDetails[] => {
        return Process.enumerateRanges("---");
    };

    public enumerateStrings = (startAddress: NativePointer | number | string, scanLength: number, minLen: number = 3, filter?: string, fromUi?: boolean) => {
        startAddress = makeNativePointer(startAddress);

        const searchResults = new Array<StringSearchResult>();

        const rangeDetails = Process.findRangeByAddress(startAddress);
        let oldProtection = "";

        // TODO: we need something here when scanlen is > range.size
        if (isDefined(rangeDetails)) {
            oldProtection = rangeDetails.protection;
        }

        Memory.protect(startAddress, scanLength, "rwx");

        // @ts-ignore
        const arrayBuffer = new Uint8Array(ArrayBuffer.wrap(startAddress, scanLength));

        if (isString(filter)) {
            minLen = filter.length;
        }

        for (let i = 0; i < scanLength; i++) {
            if (this.isPrintable(arrayBuffer[i])) {
                let str = "" + String.fromCharCode(arrayBuffer[i]);
                while (i < scanLength) {
                    const u8 = arrayBuffer[++i];
                    if (this.isPrintable(u8)) {
                        str += String.fromCharCode(u8);
                    } else {
                        if (str.length >= minLen) {
                            if (isString(filter) && str.indexOf(filter) !== -1) {
                                const result = {
                                    string: str,
                                    length: str.length,
                                    address: startAddress.add(i),
                                };
                                if (isDefined(fromUi) && fromUi === true) {
                                    DwarfCore.getInstance().sync({
                                        stringResult: result,
                                    });
                                } else {
                                    searchResults.push(result);
                                }
                            } else if (!isDefined(filter)) {
                                const result = {
                                    string: str,
                                    length: str.length,
                                    address: startAddress.add(i),
                                };
                                if (isDefined(fromUi) && fromUi === true) {
                                    DwarfCore.getInstance().sync({
                                        stringResult: result,
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

    public enumModExp = (moduleInput: Module | NativePointer | number | string): ModuleExportDetails[] => {
        return this.enumerateModuleExports(moduleInput);
    };

    public enumModImp = (moduleInput: Module | NativePointer | number | string): ModuleImportDetails[] => {
        return this.enumerateModuleImports(moduleInput);
    };

    public enumModSym = (moduleInput: Module | NativePointer | number | string): ModuleSymbolDetails[] => {
        return this.enumerateModuleSymbols(moduleInput);
    };

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    public evaluate = (jsCode: string): any => {
        jsCode = jsCode.replace(/\'/g, '"');
        const Thread = ThreadWrapper;
        try {
            // tslint:disable-next-line: no-eval
            return eval(jsCode);
        } catch (e) {
            logErr("evaluate", e);
            return null;
        }
    };

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    public evaluateFunction = (jsCode: string): any => {
        try {
            jsCode = jsCode.replace(/\'/g, '"');
            const fn = new Function("Thread", jsCode);
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
            // tslint:disable-next-line: no-eval
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
                    let str = this.readString(_ptr);
                    if (isString(str)) {
                        for (let i = 0; i < str.length; i++) {
                            if (!this.isPrintable(str.charCodeAt(i))) {
                                if (i > 0) {
                                    str = str.substr(0, i);
                                } else {
                                    str = "";
                                }
                                break;
                            }
                        }
                        if (str.length > 0) {
                            return [0, str];
                        }
                    }
                } catch (e) {
                    logErr("getAddressTS", e);
                }
                try {
                    const ptrVal = _ptr.readPointer();
                    return [1, ptrVal];
                } catch (e) {
                    logErr("getAddressTS", e);
                }
                return [2, p];
            }
        }
        return [-1, p];
    };

    getAndroidSystemProperty = (name: string) => {
        if (!Java.available) {
            return;
        }

        // TODO: check buf alloc in core
        return DwarfCore.getInstance().getAndroidSystemProperty(name);
    };

    public getApiNames = () => {
        return DwarfCore.getInstance().getApiFunctions();
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
            for (const p of ptrs) {
                symbols.push(this.getSymbolByAddress(p));
            }
        }
        return symbols;
    };

    /**
     * Return elf headers of module
     *
     * ```javascript
     * getELFHeader(); //returns elfheader of MainProcess
     *
     * getELFHeader('libwhatever.so');
     * ```
     */
    // TODO: allow path use
    public getELFHeader = (moduleName: string = DwarfCore.getInstance().getProcessInfo().getName()) => {
        if (!isString(moduleName)) {
            throw new Error("DwarfApi::getELFHeader() => No moduleName given!");
        }
        const fridaModule = Process.findModuleByName(moduleName);
        if (isDefined(fridaModule) && isString(fridaModule.path)) {
            try {
                const elfFile = new ELFFile(fridaModule.path);
                if (isDefined(elfFile)) {
                    DwarfCore.getInstance().sync({ elf_info: elfFile });
                    return elfFile;
                }
            } catch (error) {
                console.log(error);
            }
        } else {
            throw new Error("DwarfApi::getELFHeader() => Module not found!");
        }
    };

    /**
     * Shortcut to retrieve an Instruction object for the given address
     */
    public getInstruction = (address) => {
        try {
            const instruction = Instruction.parse(ptr(address));
            return JSON.stringify({
                string: instruction.toString(),
            });
        } catch (e) {
            logErr("getInstruction", e);
        }
        return null;
    };

    /**
     * Enumerate all information about the module (imports / exports / symbols)
     * @param fridaModule object from frida-gum
     */
    public getModuleInfo = (fridaModule: Module | string): DwarfModule => {
        let _module: DwarfModule = null;

        if (isString(fridaModule)) {
            _module = Object.assign({ imports: [], exports: [], symbols: [] }, Process.findModuleByName(fridaModule as string));
        } else {
            _module = Object.assign({ imports: [], exports: [], symbols: [] }, fridaModule as Module);
        }

        if (DwarfCore.getInstance().isBlacklistedModule(_module.name)) {
            console.error("Module " + _module.name + " is blacklisted");
            return _module;
        }

        try {
            _module.imports = _module.enumerateImports();
            _module.exports = _module.enumerateExports();
            _module.symbols = _module.enumerateSymbols();
        } catch (e) {
            return _module;
        }

        return _module;
    };

    /**
     * Return a RangeDetails object or null for the requested pointer
     */
    public getRange = (address: any): RangeDetails | null => {
        try {
            const nativeAddress = ptr(address);
            if (nativeAddress === null || parseInt(nativeAddress.toString(), 16) === 0) {
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
    public hookAllJavaMethods = (className: string, callback: fArgReturn): boolean => {
        return LogicJava.hookAllJavaMethods(className, callback);
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
    public hookJavaConstructor = (className: string, callback: fArgReturn): boolean => {
        return LogicJava.hook(className, "$init", callback);
    };

    /**
     * Helper for addJavaHook('class', 'method')
     *
     * ```javascript
     * hookJavaMethod('android.app.Activity.onCreate', function() {
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
     * @param userCallback
     * @param isEnabled
     * @param isSingleShot
     *
     * @returns {JavaHook}
     */
    public hookJavaMethod = (targetClassMethod: string, userCallback?: DwarfCallback, isEnabled?: boolean, isSingleShot?: boolean): JavaHook => {
        const i = targetClassMethod.lastIndexOf(".");
        const className = targetClassMethod.substr(0, i);
        const methodName = targetClassMethod.substr(i + 1);
        return this.addJavaHook(className, methodName, userCallback, isSingleShot, isEnabled);
    };

    /**
     * Map the given blob as hex string using memfd:create with the given name
     *
     * @return a negative integer if error or fd
     */
    public injectBlob = (name: string, blob: string) => {
        // arm syscall memfd_create
        let sysNum = 385;
        if (Process.arch === "ia32") {
            sysNum = 356;
        } else if (Process.arch === "x64") {
            sysNum = 319;
        }

        const syscallPtr = this.findExport("syscall");
        const writePtr = this.findExport("write");
        const dlopenPtr = this.findExport("dlopen");

        if (syscallPtr !== null && !syscallPtr.isNull()) {
            const syscall = new NativeFunction(syscallPtr, "int", ["int", "pointer", "int"]);
            if (writePtr !== null && !writePtr.isNull()) {
                const write = new NativeFunction(writePtr, "int", ["int", "pointer", "int"]);
                if (dlopenPtr !== null && !dlopenPtr.isNull()) {
                    const dlopen = new NativeFunction(dlopenPtr, "int", ["pointer", "int"]);

                    const m = DwarfFS.getInstance().allocateRw(128);
                    m.writeUtf8String(name);
                    const fd = syscall(sysNum, m, 0);
                    if (fd > 0) {
                        const hexArr = hex2a(blob);
                        const blobMem = Memory.alloc(hexArr.length);
                        Memory.protect(blobMem, hexArr.length, "rwx");
                        blobMem.writeByteArray(hexArr);
                        write(fd, blobMem, hexArr.length);
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
        const memHook = DwarfHooksManager.getInstance().getHookByAddress(pt);
        if (memHook.isEnabled()) {
            return true;
        }
        return false;
    };

    public isBlacklistedApi = (apiName: string): boolean => {
        return DwarfCore.getInstance().isBlacklistedApi(apiName);
    };

    public isBlacklistedModule = (module: string | Module): boolean => {
        return DwarfCore.getInstance().isBlacklistedModule(module);
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

            ranges.forEach((r) => {
                Memory.protect(r.base, r.size, r.protection);
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
    public readPointer = (pt) => {
        try {
            return ptr(pt).readPointer();
        } catch (e) {
            logErr("readPointer", e);
            return NULL;
        }
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
                // Access violation
                throw new Error("Unable to access Memory!");
            }
        }

        if (Process.platform === "windows") {
            try {
                fstring = address.readAnsiString(length);
                return fstring;
            } catch (e) {
                logErr("readString", e);
            }

            try {
                fstring = address.readUtf16String(length);
                return fstring;
            } catch (e) {
                logErr("readString", e);
            }
        }

        try {
            fstring = address.readCString(length);
            return fstring;
        } catch (e) {
            logErr("readString", e);
        }

        try {
            fstring = address.readUtf8String(length);
            return fstring;
        } catch (e) {
            logErr("readString", e);
        }

        return fstring;
    };

    public registerApiFunction = (apiFunction) => {
        DwarfCore.getInstance().registerApiFunction(apiFunction);
    };

    public registerApiFunctions = (object) => {
        DwarfCore.getInstance().registerApiFunctions(object);
    };

    /**
     * resume the execution of the given thread id
     */
    public releaseFromJs = (tid): void => {
        // DwarfCore.getInstance().loggedSend("release_js:::" + tid);
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

    /**
     * ### Shows CustomData in UI
     *
     * dataTypes allowed `DwarfDataDisplayType` or ['text', 'json', 'hex', 'disasm', 'sqlite3']
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
     * @param  {DwarfDataDisplayType} dataType - default `TEXT`
     * @param  {string} dataIdentifier - some identifier string
     * @param  {any} userData - your data to display for ['hex', 'disasm'] use ArrayBuffer
     * @param  {number} baseAddr? optional as hex
     * @param  {boolean} thumbMode? switches Disassembler from ARM to  THUMB on arm targets
     */
    public showData = (
        dataType: DwarfDataDisplayType | string = DwarfDataDisplayType.TEXT,
        dataIdentifier: string,
        userData: any,
        baseAddr?: number,
        thumbMode?: boolean
    ) => {
        trace("DwarfApi::showData()");

        if (!isDefined(dataType) || !isString(dataIdentifier) || !isDefined(userData)) {
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

        if (userData.constructor.name === "ArrayBuffer") {
            if (dataType !== DwarfDataDisplayType.HEX && dataType !== DwarfDataDisplayType.DISASM) {
                dataType = DwarfDataDisplayType.HEX;
            }
        }

        if ((dataType === DwarfDataDisplayType.TEXT || dataType === DwarfDataDisplayType.SQLITE3) && isString(userData)) {
            if (userData.length) {
                DwarfCore.getInstance().sync({ showData: { type: dataType, ident: dataIdentifier, data: userData } });
            }
        } else if (dataType === DwarfDataDisplayType.JSON && (typeof userData === "object" || isString(userData))) {
            const strJSON = JSON.stringify(userData);
            if (strJSON.length) {
                DwarfCore.getInstance().sync({ showData: { type: dataType, ident: dataIdentifier, data: strJSON } });
            }
        } else if ((dataType === DwarfDataDisplayType.HEX || dataType === DwarfDataDisplayType.DISASM) && userData.constructor.name === "ArrayBuffer") {
            if ((userData as ArrayBuffer).byteLength) {
                const ptrSize = DwarfCore.getInstance().getProcessInfo().getPointerSize();
                const dwarfArch = DwarfCore.getInstance().getProcessInfo().getArchitecture();
                DwarfCore.getInstance().sync({
                    showData: {
                        type: dataType,
                        ident: dataIdentifier,
                        data: ba2hex(userData),
                        ptr_size: ptrSize,
                        arch: dwarfArch,
                        base: baseAddr,
                        mode: thumbMode,
                    },
                });
            }
        }
    };

    public showStrings = (startAddress: NativePointer | number | string, scanLength: number, minLen: number = 3, filter?: string) => {
        console.log("Searching for Strings, Please wait...");
        this.enumerateStrings(startAddress, scanLength, minLen, filter, true);
        console.log("***** Done *****");
    };

    /**
     * Start the java tracer on the given classes
     */
    public startJavaTracer = (classes: string[], callback: fArgVoid) => {
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

    // TODO: add
    /* public startNativeTracer = (callback) => {
        const stalkerInfo = LogicStalker.stalk();
        if (stalkerInfo !== null) {
            stalkerInfo.currentMode = callback;
            return true;
        }

        return false;
    };*/

    /**
     * Stop the java tracer
     */
    public stopJavaTracer = (): boolean => {
        return LogicJava.stopTrace();
    };

    /**
     * start strace
     */
    // TODO: fix stalker
    /*public strace = (callback): boolean => {
        return LogicStalker.strace(callback);
    };*/

    public updateModules = () => {
        const modules = this.enumerateModules();
        // DwarfCore.getInstance().loggedSend("update_modules:::" + Process.getCurrentThreadId() + ":::" + JSON.stringify(modules));
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

    private isPrintable = (char: number): boolean => {
        try {
            if (isDefined(this._isPrintFunc)) {
                return this._isPrintFunc(char) as boolean;
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

    private updateRanges = () => {
        try {
            DwarfCore.getInstance().loggedSend("update_ranges:::" + Process.getCurrentThreadId() + ":::" + JSON.stringify(Process.enumerateRanges("---")));
        } catch (e) {
            logErr("updateRanges", e);
        }
    };

    private updateSearchableRanges = () => {
        try {
            DwarfCore.getInstance().loggedSend(
                "update_searchable_ranges:::" + Process.getCurrentThreadId() + ":::" + JSON.stringify(Process.enumerateRanges("r--"))
            );
        } catch (e) {
            logErr("updateSearchableRanges", e);
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
