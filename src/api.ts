import {Dwarf} from "./dwarf";
import {FileSystem} from "./fs";
import {LogicBreakpoint} from "./logic_breakpoint";
import {LogicJava} from "./logic_java";
import {LogicStalker} from "./logic_stalker";
import {LogicWatchpoint} from "./logic_watchpoint";
import {ThreadWrapper} from "./thread_wrapper";
import {Utils} from "./utils";
import {LogicInitialization} from "./logic_initialization";
import setExceptionHandler = Process.setExceptionHandler;

export class Api {
    private static internalMemoryScan(start, size, pattern) {
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

    static backtrace(context?) {
        if (!Utils.isDefined(context)) {
            context = Dwarf.threadContexts[Process.getCurrentThreadId()];
            if (!Utils.isDefined(context)) {
                return null;
            }
        }

        return Thread.backtrace(context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress);
    };

    static enumerateExports(module) {
        if (typeof module !== 'object') {
            module = Api.findModule(module);
        }
        if (module !== null) {
            return module.enumerateExports();
        }
        return {};
    };

    static enumerateImports(module) {
        if (typeof module !== 'object') {
            module = Api.findModule(module);
        }
        if (module !== null) {
            return module.enumerateImports();
        }
        return {};
    };

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

    static enumerateJavaMethods(className): void {
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

    static enumerateModules() {
        const modules = Process.enumerateModules();
        for (let i = 0; i < modules.length; i++) {
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
        return modules;
    };

    static enumerateModuleInfo(m) {
        try {
            m.imports = Api.enumerateImports(m);
            m.exports = Api.enumerateExports(m);
            m.symbols = Api.enumerateSymbols(m);
        } catch(e) {}

        m.entry = null;
        const header = m.base.readByteArray(4);
        if (header[0] !== 0x7f && header[1] !== 0x45 && header[2] !== 0x4c && header[3] !== 0x46) {
            // Elf
            m.entry = m.base.add(24).readPointer();
        }

        return m;
    };

    static enumerateRanges() {
        return Process.enumerateRanges('---');
    };

    static enumerateSymbols(module) {
        if (typeof module !== 'object') {
            module = Api.findModule(module);
        }
        if (module !== null) {
            return module.enumerateSymbols();
        }
        return {};
    };

    static evaluate(w) {
        const Thread = ThreadWrapper;
        try {
            return eval(w);
        } catch (e) {
            Api.log(e.toString());
            return null;
        }
    };

    static evaluateFunction(w) {
        try {
            const fn = new Function('Thread', w);
            return fn.apply(this, [ThreadWrapper]);
        } catch (e) {
            Api.log(e.toString());
            return null;
        }
    };

    static evaluatePtr(w): NativePointer {
        try {
            return ptr(eval(w));
        } catch (e) {
            return NULL;
        }
    };

    static findExport(name, module?) {
        if (typeof module === 'undefined') {
            module = null;
        }
        return Module.findExportByName(module, name);
    };

    static findModule(module) {
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
                        return JSON.stringify(modules);
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
        return {};
    };

    static findSymbol(pattern) {
        return DebugSymbol.findFunctionsMatching(pattern);
    };

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
                } catch(e) {
                }
                return [2, p];
            }
        }
        return [-1, p];
    };

    static getDebugSymbols(ptrs) {
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

    static getRange(pt) {
        try {
            pt = ptr(pt);
            if (pt === null || parseInt(pt) === 0) {
                return [];
            }
            const ret = Process.findRangeByAddress(pt);
            if (ret == null) {
                return [];
            }
            return ret;
        } catch (e) {
            Utils.logErr('getRange', e);
            return [];
        }
    };

    static getSymbolByAddress(pt) {
        try {
            pt = ptr(pt);
            return DebugSymbol.fromAddress(pt);
        } catch (e) {
            Utils.logErr('getSymbolByAddress', e);
            return {};
        }
    };

    static hookAllJavaMethods(className: string, implementation: Function): boolean {
        return LogicJava.hookAllJavaMethods(className, implementation);
    };

    static hookClassLoaderClassInitialization(clazz, callback?: Function): boolean {
        return LogicJava.hookClassLoaderClassInitialization(clazz, callback);
    };

    static hookJavaConstructor(className, implementation: Function): boolean {
        return LogicJava.hook(className, '$init', implementation);
    };

    static hookJavaMethod(targetClassMethod, implementation: Function): boolean {
        return LogicJava.hookJavaMethod(targetClassMethod, implementation);
    };

    static hookModuleInitialization(moduleName: string, callback: Function): boolean {
        return LogicInitialization.hookModuleInitialization(moduleName, callback);
    }

    static injectBlob(name, blob) {
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
                        blob = Utils.hex2a(blob);
                        const blob_space = Memory.alloc(blob.length);
                        Memory.protect(blob_space, blob.length, 'rwx');
                        blob_space.writeByteArray(blob);
                        write(fd, blob_space, blob.length);
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

    static isAddressWatched(pt) {
        const watchpoint = LogicWatchpoint.memoryWatchpoints[ptr(pt).toString()];
        return Utils.isDefined(watchpoint);
    };

    static isPrintable(char) {
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

    static isValidPointerfunction(pt) {
        const _ptr = ptr(pt);
        const _range = Process.findRangeByAddress(_ptr);
        if (Utils.isDefined(_range)) {
            if (_range.protection.indexOf('r') !== -1) {
                try {
                    _ptr.readPointer();
                    return true;
                } catch (e) { }
            }
        }
        return false;
    };

    static javaBacktrace() {
        return LogicJava.backtrace();
    };

    static jvmExplorer(handle) {
        return LogicJava.jvmExplorer(handle);
    }

    static log(what) {
        if (Utils.isDefined(what)) {
            Dwarf.loggedSend('log:::' + what);
        }
    };

    static memoryScan(start, size, pattern) {
        let result = [];
        try {
            result = Api.internalMemoryScan(ptr(start), size, pattern);
        } catch (e) {
            Utils.logErr('memoryScan', e);
        }
        Dwarf.loggedSend('memoryscan_result:::' + JSON.stringify(result));
    };

    static memoryScanList(ranges, pattern) {
        ranges = JSON.parse(ranges);
        let result = [];
        for (let i = 0; i < ranges.length; i++) {
            try {
                result = result.concat(Api.internalMemoryScan(ptr(ranges[i]['start']), ranges[i]['size'], pattern));
            } catch (e) {
                Utils.logErr('memoryScanList', e);
            }
            if (result.length >= 100) {
                break;
            }
        }
        Dwarf.loggedSend('memoryscan_result:::' + JSON.stringify(result));
    };

    static putBreakpoint(address_or_class: any, condition?: string | Function): boolean {
        return LogicBreakpoint.putBreakpoint(address_or_class, condition);
    }

    static putJavaClassInitializationBreakpoint(className: string): boolean {
        return LogicJava.putJavaClassInitializationBreakpoint(className);
    }

    static putModuleInitializationBreakpoint(moduleName: string): boolean {
        return LogicInitialization.putModuleInitializationBreakpoint(moduleName);
    }

    static putWatchpoint(address: NativePointer, flags: number, callback?: Function) {
        return LogicWatchpoint.putWatchpoint(address, flags, callback);
    };

    static readString(pt, l?) {
        try {
            pt = ptr(pt);
            let fstring = "";
            let length = -1;
            if (Utils.isNumber(l)) {
                length = l;
            }
            const range = Process.findRangeByAddress(pt);
            if (!Utils.isDefined(range)) {
                return "";
            }
            if (Utils.isString(range.protection) && range.protection.indexOf('r') === -1) {
                //Access violation
                return "";
            }
            const _np = new NativePointer(pt);
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

    static readBytes(pt, l) {
        try {
            pt = ptr(pt);

            // make sure all involved ranges are read-able
            const ranges = [];

            let range;
            let tmp = ptr(pt);
            const tail = parseInt(tmp.add(l).toString(), 16);
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

            const data = ptr(pt).readByteArray(l);

            ranges.forEach(range => {
                Memory.protect(range.base, range.size, range.protection);
            });

            return data;
        } catch (e) {
            Utils.logErr('readBytes', e);
            return [];
        }
    };

    static readPointer(pt) {
        try {
            return ptr(pt).readPointer();
        } catch (e) {
            Utils.logErr('readPointer', e);
            return NULL;
        }
    };

    static releaseFromJs(tid) {
        Dwarf.loggedSend('release_js:::' + tid);
    };

    static removeBreakpoint(address_or_class: any) {
        return LogicBreakpoint.removeBreakpoint(address_or_class);
    }

    static removeJavaClassInitializationBreakpoint(moduleName: string) {
        const ret = LogicJava.removeModuleInitializationBreakpoint(moduleName);
        if (ret) {
            Dwarf.loggedSend('breakpoint_deleted:::java_class_initialization:::' + moduleName);
        }
        return ret;
    }

    static removeModuleInitializationBreakpoint(moduleName: string) {
        const ret = LogicInitialization.removeModuleInitializationBreakpoint(moduleName);
        if (ret) {
            Dwarf.loggedSend('breakpoint_deleted:::module_initialization:::' + moduleName);
        }
        return ret;
    }

    static removeWatchpoint(address: NativePointer) {
        return LogicWatchpoint.removeWatchpoint(address);
    }

    static restart(): boolean {
        if (LogicJava.available) {
            return LogicJava.restartApplication();
        }

        return false;
    };

    static resume() {
        if (Dwarf.PROC_RESUMED) {
            Dwarf.PROC_RESUMED = true;
            Dwarf.loggedSend('resume:::0');
        } else {
            console.log('Error: Process already resumed');
        }
    };

    static setBreakpointCondition(address_or_class: any, condition?: string | Function): boolean {
        return LogicBreakpoint.setBreakpointCondition(address_or_class, condition);
    }

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

    static startJavaTracer(classes, callback) {
        return LogicJava.startTrace(classes, callback);
    };

    static startNativeTracer(callback) {
        const stalkerInfo = LogicStalker.stalk();
        if (stalkerInfo !== null) {
            stalkerInfo.currentMode = callback;
            return true;
        }

        return false;
    };

    static stopJavaTracer() {
        return LogicJava.stopTrace();
    };

    static updateModules() {
        const modules = Api.enumerateModules();
        Dwarf.loggedSend('update_modules:::' + Process.getCurrentThreadId() + ':::' + JSON.stringify(modules));
    };

    static updateRanges() {
        try {
            Dwarf.loggedSend('update_ranges:::' + Process.getCurrentThreadId() + ':::' +
                JSON.stringify(Process.enumerateRanges('---')))
        } catch (e) {
            Utils.logErr('updateRanges', e);
        }
    };

    static updateSearchableRanges() {
        try {
            Dwarf.loggedSend('update_searchable_ranges:::' + Process.getCurrentThreadId() + ':::' +
                JSON.stringify(Process.enumerateRanges('r--')))
        } catch (e) {
            Utils.logErr('updateSearchableRanges', e);
        }
    };

    static writeBytes(pt, what) {
        try {
            pt = ptr(pt);
            if (typeof what === 'string') {
                Api.writeUtf8(pt, Utils.hex2a(what));
            } else {
                pt.writeByteArray(what);
            }
            return true;
        } catch (e) {
            Utils.logErr('writeBytes', e);
            return false;
        }
    };

    static writeUtf8(pt, str) {
        try {
            pt = ptr(pt);
            pt.writeUtf8String(str);
            return true;
        } catch (e) {
            Utils.logErr('writeUtf8', e);
            return false;
        }
    };
}