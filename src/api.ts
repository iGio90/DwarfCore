import { Dwarf } from "./dwarf";
import { FileSystem } from "./fs";
import { LogicBreakpoint } from "./logic_breakpoint";
import { LogicJava } from "./logic_java";
import { LogicInitialization } from "./logic_initialization";
import { LogicStalker } from "./logic_stalker";
import { LogicWatchpoint } from "./logic_watchpoint";
import { ThreadWrapper } from "./thread_wrapper";
import { Utils } from "./utils";
import { MEMORY_ACCESS_EXECUTE, MEMORY_ACCESS_READ, MEMORY_ACCESS_WRITE } from "./watchpoint";

export class Api {
    private static _internalMemoryScan(start, size, pattern) {
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
    };

    /**
     * Shortcut to retrieve native backtrace
     * @param context: the CpuContext object
     */
    static backtrace(context?: CpuContext): DebugSymbol[] | null {
        if (!Utils.isDefined(context)) {
            context = Dwarf.threadContexts[Process.getCurrentThreadId()];
            if (!Utils.isDefined(context)) {
                return null;
            }
        }

        return Thread.backtrace(context, Backtracer.FUZZY)
            .map(DebugSymbol.fromAddress);
    };

    /**
     * Enumerate exports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    static enumerateExports(module: any): Array<ModuleExportDetails> {
        if (typeof module !== 'object') {
            module = Api.findModule(module);
        }
        if (module !== null) {
            if (Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
                return [];
            }
            return module.enumerateExports();
        }
        return [];
    };

    /**
     * Enumerate imports for the given module name or pointer
     * @param module an hex/int address or string name
     */
    static enumerateImports(module): Array<ModuleExportDetails> {
        if (typeof module !== 'object') {
            module = Api.findModule(module);
        }
        if (module !== null) {
            if (Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
                return [];
            }
            return module.enumerateImports();
        }
        return [];
    };

    /**
     * Enumerate java classes
     * @param useCache false by default
     */
    static enumerateJavaClasses(useCache?) {
        if (!Utils.isDefined(useCache)) {
            useCache = false;
        }

        if (useCache && LogicJava !== null && LogicJava.javaClasses.length > 0) {
            Dwarf.loggedSend('enumerate_java_classes_start:::');
            for (let i = 0; i < LogicJava.javaClasses.length; i++) {
                send('enumerate_java_classes_match:::' + LogicJava.javaClasses[i]);
            }
            Dwarf.loggedSend('enumerate_java_classes_complete:::');
        } else {
            // invalidate cache
            if (LogicJava !== null) {
                LogicJava.javaClasses = [];
            }

            Java.performNow(function () {
                Dwarf.loggedSend('enumerate_java_classes_start:::');
                try {
                    Java.enumerateLoadedClasses({
                        onMatch: function (className) {
                            if (LogicJava !== null) {
                                LogicJava.javaClasses.push(className);
                            }
                            send('enumerate_java_classes_match:::' + className);
                        },
                        onComplete: function () {
                            send('enumerate_java_classes_complete:::');
                        }
                    });
                } catch (e) {
                    Utils.logErr('enumerateJavaClasses', e);
                    Dwarf.loggedSend('enumerate_java_classes_complete:::');
                }
            });
        }
    };

    /**
     * Enumerate method for the given class
     */
    static enumerateJavaMethods(className: string): void {
        if (Java.available) {
            const that = this;
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
                const result = Utils.uniqueBy(parsedMethods);
                Dwarf.loggedSend('enumerate_java_methods_complete:::' + className + ':::' +
                    JSON.stringify(result));
            });
        }
    };

    /**
     * Enumerate loaded modules
     */
    static enumerateModules(fillInformation?: boolean) {
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

                modules[i] = Api.enumerateModuleInfo(modules[i]);
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
            details = dwarf.dwarf_api('enumerateModuleInfo', base_info['name'])
    */
    static enumerateModuleInfo(fridaModule: Module | string): Module {
        let _module: Module = null;

        if (Utils.isString(fridaModule)) {
            _module = Process.findModuleByName(fridaModule as string);
        } else {
            _module = fridaModule as Module;
        }

        if (Dwarf.modulesBlacklist.indexOf(_module.name) >= 0) {
            Api.log('Error: Module ' + _module.name + ' is blacklisted');
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
    };

    /**
     * Enumerate all mapped ranges
     */
    static enumerateRanges(): RangeDetails[] {
        return Process.enumerateRanges('---');
    };

    /**
     * Enumerate symbols for the given module name or pointer
     * @param module an hex/int address or string name
     */
    static enumerateSymbols(module): Array<ModuleSymbolDetails> {
        if (typeof module !== 'object') {
            module = Api.findModule(module);
        }
        if (module !== null) {
            if (Dwarf.modulesBlacklist.indexOf(module.name) >= 0) {
                return [];
            }
            return module.enumerateSymbols();
        }
        return [];
    };

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    static evaluate(w) {
        const Thread = ThreadWrapper;
        try {
            return eval(w);
        } catch (e) {
            Api.log(e.toString());
            return null;
        }
    };

    /**
     * Evaluate javascript. Used from the UI to inject javascript code into the process
     * @param w
     */
    static evaluateFunction(w) {
        try {
            const fn = new Function('Thread', w);
            return fn.apply(this, [ThreadWrapper]);
        } catch (e) {
            Api.log(e.toString());
            return null;
        }
    };

    /**
     * Evaluate any input and return a NativePointer
     * @param w
     */
    static evaluatePtr(w: any): NativePointer {
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
    static findExport(name, module?): NativePointer | null {
        if (typeof module === 'undefined') {
            module = null;
        }
        return Module.findExportByName(module, name);
    };

    /**
     * Find a module providing any argument. Could be a string/int pointer or module name
     */
    static findModule(module: any): Module | Module[] | null {
        let _module;
        if (Utils.isString(module) && module.substring(0, 2) !== '0x') {
            _module = Process.findModuleByName(module);
            if (Utils.isDefined(_module)) {
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
            if (!Utils.isDefined(_module)) {
                _module = {};
            }
            return _module;
        }
        return null;
    };

    /**
     * Find a symbol matching the given pattern
     */
    static findSymbol(pattern) {
        return DebugSymbol.findFunctionsMatching(pattern);
    };

    /**
     * get telescope information for the given pointer argument
     * @param p: pointer
     */
    static getAddressTs(p) {
        const _ptr = ptr(p);
        const _range = Process.findRangeByAddress(_ptr);
        if (Utils.isDefined(_range)) {
            if (_range.protection.indexOf('r') !== -1) {
                try {
                    const s = Api.readString(_ptr);
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
    };

    /**
     * Return an array of DebugSymbol for the requested pointers
     * @param ptrs: an array of NativePointer
     */
    static getDebugSymbols(ptrs): DebugSymbol[] {
        const symbols = [];
        if (Utils.isDefined(ptrs)) {
            try {
                ptrs = JSON.parse(ptrs);
            } catch (e) {
                Utils.logErr('getDebugSymbols', e);
                return symbols;
            }
            for (let i = 0; i < ptrs.length; i++) {
                symbols.push(Api.getSymbolByAddress(ptrs[i]));
            }
        }
        return symbols;
    };

    /**
     * Shortcut to retrieve an Instruction object for the given address
     */
    static getInstruction(address) {
        try {
            const instruction = Instruction.parse(ptr(address));
            return JSON.stringify({
                'string': instruction.toString()
            });
        } catch (e) {
            Utils.logErr('getInstruction', e);
        }
        return null;
    };

    /**
     * Return a RangeDetails object or null for the requested pointer
     */
    static getRange(pt): RangeDetails | null {
        try {
            pt = ptr(pt);
            if (pt === null || parseInt(pt) === 0) {
                return null;
            }
            const ret = Process.findRangeByAddress(pt);
            if (ret == null) {
                return null;
            }
            return ret;
        } catch (e) {
            Utils.logErr('getRange', e);
            return null;
        }
    };

    /**
     * Return DebugSymbol or null for the given pointer
     */
    static getSymbolByAddress(pt): DebugSymbol | null {
        try {
            pt = ptr(pt);
            return DebugSymbol.fromAddress(pt);
        } catch (e) {
            Utils.logErr('getSymbolByAddress', e);
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
    static hookAllJavaMethods(className: string, callback: Function): boolean {
        return LogicJava.hookAllJavaMethods(className, callback);
    };

    /**
     * Receive a callback whenever a java class is going to be loaded by the class loader.
     *
     * ```javascript
     * hookClassLoaderClassInitialization('com.target.classname', function() {
     *     console.log('target is being loaded');
     * })
     * ```
     * @param className
     * @param callback
     */
    static hookClassLoaderClassInitialization(className: string, callback: Function): boolean {
        return LogicJava.hookClassLoaderClassInitialization(className, callback);
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
    static hookJavaConstructor(className: string, callback: Function): boolean {
        return LogicJava.hook(className, '$init', callback);
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
    static hookJavaMethod(targetClassMethod: string, callback: Function): boolean {
        return LogicJava.hookJavaMethod(targetClassMethod, callback);
    };

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
    static hookModuleInitialization(moduleName: string, callback: Function): boolean {
        return LogicInitialization.hookModuleInitialization(moduleName, callback);
    }

    /**
     * Map the given blob as hex string using memfd:create with the given name
     *
     * @return a negative integer if error or fd
     */
    static injectBlob(name: string, blob: string) {
        // arm syscall memfd_create
        let sys_num = 385;
        if (Process.arch === 'ia32') {
            sys_num = 356;
        } else if (Process.arch === 'x64') {
            sys_num = 319;
        }

        const syscall_ptr = Api.findExport('syscall');
        const write_ptr = Api.findExport('write');
        const dlopen_ptr = Api.findExport('dlopen');

        if (syscall_ptr !== null && !syscall_ptr.isNull()) {
            const syscall = new NativeFunction(syscall_ptr, 'int', ['int', 'pointer', 'int']);
            if (write_ptr !== null && !write_ptr.isNull()) {
                const write = new NativeFunction(write_ptr, 'int', ['int', 'pointer', 'int']);
                if (dlopen_ptr !== null && !dlopen_ptr.isNull()) {
                    const dlopen = new NativeFunction(dlopen_ptr, 'int', ['pointer', 'int']);

                    const m = FileSystem.allocateRw(128);
                    m.writeUtf8String(name);
                    const fd = syscall(sys_num, m, 0);
                    if (fd > 0) {
                        const hexArr = Utils.hex2a(blob);
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
    };

    /**
     * @return a boolean indicating if the given pointer is currently watched
     */
    static isAddressWatched(pt: any): boolean {
        const watchpoint = LogicWatchpoint.memoryWatchpoints[ptr(pt).toString()];
        return Utils.isDefined(watchpoint);
    };

    private static isPrintable(char) {
        try {
            const isprint_ptr = Api.findExport('isprint');
            if (Utils.isDefined(isprint_ptr)) {
                const isprint_fn = new NativeFunction(isprint_ptr, 'int', ['int']);
                if (Utils.isDefined(isprint_fn)) {
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
            Utils.logErr('isPrintable', e);
            return false;
        }
    };

    /**
     * @return a java stack trace. Must be executed in JVM thread
     */
    static javaBacktrace() {
        return LogicJava.backtrace();
    };

    /**
     * @return the explorer object for the given java handle
     */
    static jvmExplorer(handle) {
        return LogicJava.jvmExplorer(handle);
    }

    /**
     * log whatever to Dwarf console
     */
    static log(what): void {
        if (Utils.isDefined(what)) {
            Dwarf.loggedSend('log:::' + what);
        }
    };

    private static memoryScan(start, size, pattern) {
        let result = [];
        try {
            result = Api._internalMemoryScan(ptr(start), size, pattern);
        } catch (e) {
            Utils.logErr('memoryScan', e);
        }
        Dwarf.loggedSend('memoryscan_result:::' + JSON.stringify(result));
    };

    private static memoryScanList(ranges, pattern) {
        ranges = JSON.parse(ranges);
        let result = [];
        for (let i = 0; i < ranges.length; i++) {
            try {
                result = result.concat(Api._internalMemoryScan(ptr(ranges[i]['start']), ranges[i]['size'], pattern));
            } catch (e) {
                Utils.logErr('memoryScanList', e);
            }
            if (result.length >= 100) {
                break;
            }
        }
        Dwarf.loggedSend('memoryscan_result:::' + JSON.stringify(result));
    };

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
     */
    static putBreakpoint(address_or_class: any, condition?: string | Function): boolean {
        return LogicBreakpoint.putBreakpoint(address_or_class, condition);
    }

    /**
     * Put a java class initialization breakpoint
     *
     * ```javascript
     * putJavaClassInitializationBreakpoint('android.app.Activity');
     * ```
     * @param className
     */
    static putJavaClassInitializationBreakpoint(className: string): boolean {
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
    static putModuleInitializationBreakpoint(moduleName: string): boolean {
        return LogicInitialization.putModuleInitializationBreakpoint(moduleName);
    }

    /**
     * Put a watchpoint on the given address
     *
     * ```javascript
     * putWatchpoint(0x1000, 'r');
     *
     * var target = findExport('memcpy');
     * Interceptor.attach(target, {
     *     onLeave: function(ret) {
     *         putWatchpoint(this.context.x0, 'rw', function() {
     *            log(backtrace(this.context));
     *         });
     *     }
     * });
     * ```
     * @param address
     * @param flags
     * @param callback
     */
    static putWatchpoint(address: any, flags: string, callback?: Function) {
        let intFlags = 0;
        if (flags.indexOf('r') >= 0) {
            intFlags |= MEMORY_ACCESS_READ;
        }
        if (flags.indexOf('w') >= 0) {
            intFlags |= MEMORY_ACCESS_WRITE;
        }
        if (flags.indexOf('x') >= 0) {
            intFlags |= MEMORY_ACCESS_EXECUTE;
        }

        return LogicWatchpoint.putWatchpoint(address, intFlags, callback);
    };

    /**
     * A shortcut and secure way to read a string from a pointer with frida on any os
     *
     * @return the string pointed by address until termination or optional length
     */
    static readString(address, length?) {
        try {
            address = ptr(address);
            let fstring = "";
            if (!Utils.isNumber(length)) {
                length = -1;
            }
            const range = Process.findRangeByAddress(address);
            if (!Utils.isDefined(range)) {
                return "";
            }
            if (Utils.isString(range.protection) && range.protection.indexOf('r') === -1) {
                //Access violation
                return "";
            }
            const _np = new NativePointer(address);
            if (!Utils.isDefined(_np)) {
                return "";
            }
            if (Process.platform === 'windows') {
                fstring = _np.readAnsiString(length);
            }
            if (Utils.isString(fstring) && (fstring.length === 0)) {
                fstring = _np.readCString(length);
            }
            if (Utils.isString(fstring) && (fstring.length === 0)) {
                fstring = _np.readUtf8String(length);
            }
            if (Utils.isString(fstring) && fstring.length) {
                for (let i = 0; i < fstring.length; i++) {
                    if (!Api.isPrintable(fstring.charCodeAt(i))) {
                        fstring = null;
                        break;
                    }
                }
            }
            if (fstring !== null && Utils.isString(fstring) && fstring.length) {
                return fstring;
            } else {
                return "";
            }
        } catch (e) {
            Utils.logErr('readString', e);
            return "";
        }
    };

    /**
     * A shortcut for safely reading from memory
     *
     * @return an ArrayBuffer of the given length filled with data starting from target address
     */
    static readBytes(address, length) {
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
            Utils.logErr('readBytes', e);
            return [];
        }
    };

    /**
     * @return a pointer from the given address
     */
    static readPointer(pt) {
        try {
            return ptr(pt).readPointer();
        } catch (e) {
            Utils.logErr('readPointer', e);
            return NULL;
        }
    };

    /**
     * resume the execution of the given thread id
     */
    static releaseFromJs(tid): void {
        Dwarf.loggedSend('release_js:::' + tid);
    };

    /**
     * Remove a breakpoint on address_or_class
     * @return a boolean indicating if removal was successful
     */
    static removeBreakpoint(address_or_class: any): boolean {
        return LogicBreakpoint.removeBreakpoint(address_or_class);
    }

    /**
     * Remove a java class initialization breakpoint on moduleName
     * @return a boolean indicating if removal was successful
     */
    static removeJavaClassInitializationBreakpoint(moduleName: string): boolean {
        const ret = LogicJava.removeModuleInitializationBreakpoint(moduleName);
        if (ret) {
            Dwarf.loggedSend('breakpoint_deleted:::java_class_initialization:::' + moduleName);
        }
        return ret;
    }

    /**
     * Remove a module initialization breakpoint on moduleName
     * @return a boolean indicating if removal was successful
     */
    static removeModuleInitializationBreakpoint(moduleName: string): boolean {
        const ret = LogicInitialization.removeModuleInitializationBreakpoint(moduleName);
        if (ret) {
            Dwarf.loggedSend('breakpoint_deleted:::module_initialization:::' + moduleName);
        }
        return ret;
    }

    /**
     * Remove a watchpoint on the given address
     * @return a boolean indicating if removal was successful
     */
    static removeWatchpoint(address: any): boolean {
        return LogicWatchpoint.removeWatchpoint(address);
    }

    /**
     * Restart the application
     *
     * Android only
     */
    static restart(): boolean {
        if (LogicJava.available) {
            return LogicJava.restartApplication();
        }

        return false;
    };

    private static resume() {
        if (Dwarf.PROC_RESUMED) {
            Dwarf.PROC_RESUMED = true;
            Dwarf.loggedSend('resume:::0');
        } else {
            console.log('Error: Process already resumed');
        }
    };

    private static setBreakpointCondition(address_or_class: any, condition?: string | Function): boolean {
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
    static setData(key, data) {
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
    };

    /**
     * Start the java tracer on the given classes
     */
    static startJavaTracer(classes: string[], callback: Function) {
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
    static startNativeTracer(callback) {
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
    static stopJavaTracer(): boolean {
        return LogicJava.stopTrace();
    };
    
    static strace(callback): boolean {
        Process.enumerateThreads().forEach(thread => {
            const stalkerInfo = LogicStalker.stalk(thread.id);
            if (stalkerInfo !== null) {
                stalkerInfo.instructionsFilter.push('svc');
                stalkerInfo.instructionsFilter.push('int');
                stalkerInfo.currentMode = callback;
            }
        });
        
        return true;
    }

    private static updateModules() {
        const modules = Api.enumerateModules();
        Dwarf.loggedSend('update_modules:::' + Process.getCurrentThreadId() + ':::' + JSON.stringify(modules));
    };

    private static updateRanges() {
        try {
            Dwarf.loggedSend('update_ranges:::' + Process.getCurrentThreadId() + ':::' +
                JSON.stringify(Process.enumerateRanges('---')))
        } catch (e) {
            Utils.logErr('updateRanges', e);
        }
    };

    private static updateSearchableRanges() {
        try {
            Dwarf.loggedSend('update_searchable_ranges:::' + Process.getCurrentThreadId() + ':::' +
                JSON.stringify(Process.enumerateRanges('r--')))
        } catch (e) {
            Utils.logErr('updateSearchableRanges', e);
        }
    };

    /**
     * Write the given hex string or ArrayBuffer into the given address
     */
    static writeBytes(address: any, what: string | ArrayBuffer) {
        try {
            address = ptr(address);
            if (typeof what === 'string') {
                Api.writeUtf8(address, Utils.hex2a(what));
            } else {
                address.writeByteArray(what);
            }
            return true;
        } catch (e) {
            Utils.logErr('writeBytes', e);
            return false;
        }
    };

    private static writeUtf8(address: any, str: any) {
        try {
            address = ptr(address);
            address.writeUtf8String(str);
            return true;
        } catch (e) {
            Utils.logErr('writeUtf8', e);
            return false;
        }
    };
}