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

import { LogicJava } from "./logic_java";
import { DwarfInterceptor } from "./interceptor";
import { DwarfApi } from "./api";
import { DwarfHooksManager } from "./hooks_manager";
import { ThreadContext } from "./thread_context";
import { ThreadApi } from "./thread_api";
import { LogicStalker } from "./logic_stalker";
import { DwarfHaltReason } from "./consts";
import { DwarfProcessInfo } from "./types/dwarf_processinfo";
import { DwarfFS } from "./DwarfFS";
import { DwarfObserver } from "./dwarf_observer";
import { DwarfJavaHelper } from "./java";
import { DwarfStalker } from "./stalker";

export class DwarfCore {
    PROC_RESUMED = false;

    threadContexts: { [index: string]: ThreadContext } = {};

    modulesBlacklist: Array<string> = new Array<string>();

    protected processInfo: DwarfProcessInfo | null;

    private dwarfApi: DwarfApi;
    private DwarfHooksManager: DwarfHooksManager;
    private dwarfFS: DwarfFS;
    private dwarfObserver: DwarfObserver;
    private dwarfJavaHelper: DwarfJavaHelper;
    private dwarfStalker: DwarfStalker;

    private _systemPropertyGet: NativeFunction | null;
    private static instanceRef: DwarfCore;
    private breakAtStart: boolean;
    private androidApiLevel: number;

    //Singleton class
    private constructor() {
        //get maxstack
        let i = 0;
        function inc() {
            i++;
            inc();
        }
        try {
            inc();
        } catch (e) {
            global.MAX_STACK_SIZE = i;
        }
        global.DEBUG = true;
        trace("DwarfCoreJS start");
        this.processInfo = null;
        this._systemPropertyGet = null;

        this.dwarfApi = DwarfApi.getInstance();
        this.DwarfHooksManager = DwarfHooksManager.getInstance();
        this.dwarfFS = DwarfFS.getInstance();
        this.dwarfJavaHelper = DwarfJavaHelper.getInstance();
        this.dwarfObserver = DwarfObserver.getInstance();
        this.dwarfStalker = DwarfStalker.getInstance();
        this.breakAtStart = false;
        this.androidApiLevel = 0;
    }

    /**
     * DwarfCore Instance
     *
     * @returns DwarfCore
     */
    static getInstance() {
        if (!DwarfCore.instanceRef) {
            DwarfCore.instanceRef = new this();
        }
        trace("Dwarf::getInstance()");
        return DwarfCore.instanceRef;
    }

    getApi = (): DwarfApi => {
        trace("Dwarf::getApi()");
        return this.dwarfApi;
    };

    getHooksManager = (): DwarfHooksManager => {
        trace("Dwarf::getHooksManager()");
        return this.DwarfHooksManager;
    };

    getFS = (): DwarfFS => {
        trace("Dwarf::getFS()");
        return this.dwarfFS;
    };

    getJavaHelper = (): DwarfJavaHelper => {
        trace("Dwarf::getJavaHelper()");
        if (this.dwarfJavaHelper === null) {
            throw new Error("JavaHelper not initialized!");
        }
        return this.dwarfJavaHelper;
    };

    getStalker = (): DwarfStalker => {
        trace("Dwarf::getStalker()");
        return this.dwarfStalker;
    };

    enableDebug = (): void => {
        trace("DwarfCore::enableDebug()");
        DEBUG = true;
    };
    disableDebug = (): void => {
        trace("DwarfCore::disableDebug()");
        DEBUG = false;
    };
    toggleDebug = (): void => {
        trace("DwarfCore::toggleDebug()");
        DEBUG = !DEBUG;
    };

    init = (procName: string, wasSpawned: boolean, breakStart: boolean, debug: boolean, globalApiFuncs?: Array<string>): void => {
        trace("DwarfCore::init()");

        if (debug) {
            DEBUG = true;
        }

        if (breakStart) {
            this.breakAtStart = true;
        }

        this.processInfo = new DwarfProcessInfo(
            procName,
            wasSpawned,
            Process.id,
            Process.getCurrentThreadId(),
            Process.arch,
            Process.platform,
            Process.pageSize,
            Process.pointerSize,
            Java.available,
            ObjC.available
        );

        //send initdata
        let initData = {
            process: this.processInfo,
            modules: Process.enumerateModules(),
            regions: Process.enumerateRanges("---"),
            threads: Process.enumerateThreads()
        };
        send("coresync:::" + JSON.stringify(initData));

        if (Java.available) {
            this.dwarfJavaHelper.initalize();
            this.androidApiLevel = this.getAndroidApiLevel();
            LogicJava.init();
        }

        //LogicInitialization.init();
        DwarfHooksManager.getInstance().attachModuleLoadingHooks();
        DwarfInterceptor.init();

        // register global api functions
        /*if (globalApiFuncs && globalApiFuncs.length > 0) {

        }*/
        const exclusions = ["constructor", "length", "name", "prototype"];
        Object.getOwnPropertyNames(this.dwarfApi).forEach(prop => {
            if (exclusions.indexOf(prop) < 0) {
                global[prop] = this.dwarfApi[prop];
            }
        });

        if (Process.platform === "windows") {
            this.modulesBlacklist.push("ntdll.dll");
            if (Process.arch === "x64") {
                //TODO: debug later why module needs blacklisted on x64 targets only
                this.modulesBlacklist.push("win32u.dll");
            }
        } else if (Process.platform === "linux") {
            if (Java.available && this.getAndroidApiLevel() <= 23) {
                this.modulesBlacklist.push("app_process");
            }
        }

        Process.setExceptionHandler(this.handleException);
    };

    start = () => {
        //attach init breakpoints
        if (Java.available && this.processInfo.wasSpawned && this.breakAtStart) {
            //android init breakpoint
            if (this.getAndroidApiLevel() >= 23) {
                const initBreakpoint = this.getHooksManager().addJavaHook("com.android.internal.os.RuntimeInit", "commonInit", 'breakpoint', true, true);
                if(!isDefined(initBreakpoint)) {
                    logDebug('Failed to attach initHook!');
                }
            } else {
                const initBreakpoint = this.getHooksManager().addJavaHook("android.app.Application", "onCreate", 'breakpoint', true, true);
                if(!isDefined(initBreakpoint)) {
                    logDebug('Failed to attach initHook!');
                }
            }
        }

        if (Process.platform === "windows") {
            // break proc at main
            if (this.processInfo.wasSpawned && this.breakAtStart) {
                //Inital breakpoint
                const invocationListener = Interceptor.attach(this.getApi().findExport("RtlUserThreadStart"), function() {
                    trace("Creating startbreakpoint");
                    const invocationContext: InvocationContext = this;
                    let address = null;
                    if (Process.arch === "ia32") {
                        const context = invocationContext.context as Ia32CpuContext;
                        address = context.eax;
                    } else if (Process.arch === "x64") {
                        const context = invocationContext.context as X64CpuContext;
                        address = context.rax;
                    }

                    if (isDefined(address)) {
                        const initBreakpoint = DwarfCore.getInstance()
                            .getHooksManager()
                            .addNativeHook(address, "breakpoint", true, true);
                        invocationListener.detach();
                    }
                });
            }
        }
    };

    handleException = (exception: ExceptionDetails) => {
        trace("DwarfCore::handleException()");

        if (DEBUG) {
            let dontLog = false;
            if (Process.platform === "windows") {
                // hide SetThreadName - https://github.com/frida/glib/blob/master/glib/gthread-win32.c#L579
                let reg = null;
                if (Process.arch === "x64") {
                    reg = exception["context"]["rax"];
                } else if (Process.arch === "ia32") {
                    reg = exception["context"]["eax"];
                }
                if (reg !== null && reg.readInt() === 0x406d1388) {
                    dontLog = true;
                }
            }
            if (!dontLog) {
                console.log("[" + Process.getCurrentThreadId() + "] exception handler: " + JSON.stringify(exception));
            }
        }

        //handle MemoryHooks
        if (exception.type === "access-violation") {
            if (Process.platform === "windows") {
                return true;
            }
            //return this.getHooksManager().handleMemoryHooks(exception);
        }
    };

    loggedSend = (message: any, data?: ArrayBuffer | number[] | null): void => {
        trace("DwarfCore::loggedSend()");
        logDebug("[" + Process.getCurrentThreadId() + "] send | " + message);
        return send(message, data);
    };

    onBreakpoint = (breakpointId: number, threadId: number, haltReason: DwarfHaltReason, address_or_class, context, java_handle?, condition?: Function) => {
        trace("DwarfCore::onBreakpoint()");
        //const tid = Process.getCurrentThreadId();

        threadId = Process.getCurrentThreadId();

        logDebug("[" + threadId + "] breakpoint " + address_or_class + " - reason: " + haltReason);

        const breakpointData = {
            hookid: breakpointId,
            tid: threadId,
            reason: haltReason
        };

        if (isDefined(context)) {
            logDebug("[" + threadId + "] sendInfos - preparing infos for valid context");

            breakpointData["context"] = context;
            if (isDefined(context["pc"])) {
                let symbol = null;
                breakpointData["address"] = address_or_class;

                try {
                    symbol = DebugSymbol.fromAddress(context.pc);
                } catch (e) {
                    logErr("_sendInfos", e);
                }

                logDebug("[" + threadId + "] sendInfos - preparing native backtrace");

                breakpointData["backtrace"] = { bt: Dwarf.dwarfApi.backtrace(context), type: "native" };

                logDebug("[" + threadId + "] sendInfos - preparing context registers");

                const newCtx = {};

                for (let reg in context) {
                    const val = context[reg];
                    let isValidPtr = false;

                    logDebug("[" + threadId + "] getting register information:", reg, val);

                    const ts = Dwarf.dwarfApi.getAddressTs(val);
                    isValidPtr = ts[0] > 0;
                    newCtx[reg] = {
                        value: val,
                        isValidPointer: isValidPtr,
                        telescope: ts
                    };
                    if (reg === "pc") {
                        if (symbol !== null) {
                            newCtx[reg]["symbol"] = symbol;
                        }
                        try {
                            const inst = Instruction.parse(val);
                            newCtx[reg]["instruction"] = {
                                size: inst.size,
                                groups: inst.groups,
                                thumb: inst.groups.indexOf("thumb") >= 0 || inst.groups.indexOf("thumb2") >= 0
                            };
                        } catch (e) {
                            logErr("_sendInfos", e);
                        }
                    }
                }

                breakpointData["rawcontext"] = context;
                breakpointData["context"] = newCtx;
            } else {
                breakpointData["java"] = true;
                breakpointData["address"] = address_or_class;

                logDebug("[" + threadId + "] sendInfos - preparing java backtrace");

                breakpointData["backtrace"] = { bt: Dwarf.dwarfApi.javaBacktrace(), type: "java" };
            }
        }

        let threadContext: ThreadContext = Dwarf.threadContexts[threadId.toString()];

        if (!isDefined(threadContext) && isDefined(context)) {
            threadContext = new ThreadContext(threadId);
            threadContext.context = context;
            Dwarf.threadContexts[threadId.toString()] = threadContext;
        }

        if (isDefined(condition)) {
            if (!condition.call(threadContext)) {
                delete Dwarf.threadContexts[threadId.toString()];
                return;
            }
        }

        if (!isDefined(threadContext) || !threadContext.preventSleep) {
            logDebug("[" + threadId + "] break " + address_or_class + " - dispatching context info");
            Dwarf.sync({ breakpoint: breakpointData, threads: Process.enumerateThreads() });

            logDebug("[" + threadId + "] break " + address_or_class + " - sleeping context. goodnight!");
            Dwarf.loopApi(threadId, threadContext);

            logDebug("[" + threadId + "] ThreadContext has been released");
            Dwarf.sync({ threads: [], breakpoint: {} });
            DwarfHooksManager.getInstance().update();
        }
    };

    loopApi = (threadId: number, that) => {
        trace("DwarfCore::loopApi()");

        console.log("[" + threadId + "] looping api");

        const op = recv("" + threadId, function() {});
        op.wait();

        const threadContext: ThreadContext = this.threadContexts[threadId.toString()];

        if (isDefined(threadContext)) {
            while (threadContext.apiQueue.length === 0) {
                logDebug("[" + threadId + "] waiting api queue to be populated");
                Thread.sleep(0.2);
            }

            let release = false;

            while (threadContext.apiQueue.length > 0) {
                const threadApi: ThreadApi = threadContext.apiQueue.shift();

                logDebug("[" + threadId + "] executing " + threadApi.apiFunction);

                try {
                    if (isDefined(this.getApi()[threadApi.apiFunction])) {
                        threadApi.result = this.getApi()[threadApi.apiFunction].apply(that, threadApi.apiArguments);
                    } else {
                        threadApi.result = null;
                    }
                } catch (e) {
                    threadApi.result = null;
                    if (DEBUG) {
                        logDebug("[" + threadId + "] error executing " + threadApi.apiFunction + ":\n" + e);
                    }
                }
                threadApi.consumed = true;

                let stalkerInfo = LogicStalker.stalkerInfoMap[threadId];
                if (threadApi.apiFunction === "_step") {
                    if (!isDefined(stalkerInfo)) {
                        LogicStalker.stalk(threadId);
                    }
                    release = true;
                    break;
                } else if (threadApi.apiFunction === "release") {
                    if (isDefined(stalkerInfo)) {
                        stalkerInfo.terminated = true;
                    }

                    release = true;
                    break;
                }
            }

            if (!release) {
                this.loopApi(threadId, that);
            }
        }
    };

    getProcessInfo = () => {
        return this.processInfo;
    };

    /** @internal */
    sync = (extraData = {}) => {
        trace("DwarfCore::sync()");
        //let coreSyncMsg = { breakpoints: this.getHooksManager().getBreakpoints() };
        let coreSyncMsg = {};
        coreSyncMsg = Object.assign(coreSyncMsg, extraData);

        send("coresync:::" + JSON.stringify(coreSyncMsg));
    };

    //from https://github.com/frida/frida-java-bridge/blob/master/lib/android.js
    getAndroidSystemProperty = (name: string) => {
        if (!this.processInfo.isJavaAvailable()) {
            return;
        }

        trace("DwarfCore::getAndroidSystemProperty()");
        if (this._systemPropertyGet === null) {
            this._systemPropertyGet = new NativeFunction(Module.findExportByName("libc.so", "__system_property_get"), "int", ["pointer", "pointer"], {
                exceptions: "propagate"
            });
        }
        const buf = Memory.alloc(92);
        this._systemPropertyGet(Memory.allocUtf8String(name), buf);
        return buf.readUtf8String();
    };

    //from https://github.com/frida/frida-java-bridge/blob/master/lib/android.js
    getAndroidApiLevel = () => {
        if (!Java.available) {
            return;
        }

        trace("DwarfCore::getAndroidApiLevel()");
        if (this.androidApiLevel) {
            return this.androidApiLevel;
        }

        return parseInt(this.getAndroidSystemProperty("ro.build.version.sdk"), 10);
    };

    memoryScan = (startAddress, size, pattern) => {
        const self = this;
        startAddress = makeNativePointer(startAddress);
        Memory.scan(startAddress, size, pattern, {
            onMatch: (foundAddress, foundSize) => {
                self.sync({ search_result: { address: foundAddress, size: foundSize } });
            },
            onComplete: () => {
                self.sync({ search_finished: true });
            },
            onError: reason => {
                self.sync({ search_error: reason });
            }
        });
    };
}
