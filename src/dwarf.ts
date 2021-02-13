/**
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
    private dwarfHooksManager: DwarfHooksManager;
    private dwarfFS: DwarfFS;
    private dwarfObserver: DwarfObserver;
    private dwarfJavaHelper: DwarfJavaHelper;
    private dwarfStalker: DwarfStalker;

    private _systemPropertyGet: NativeFunction | null;
    private static instanceRef: DwarfCore;
    private breakAtStart: boolean;
    private androidApiLevel: number;
    private packagePath: string;

    private hasUI: boolean;

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

        trace("DwarfCoreJS start");
        this.processInfo = null;
        this._systemPropertyGet = null;

        this.dwarfApi = DwarfApi.getInstance();
        this.dwarfHooksManager = DwarfHooksManager.getInstance();
        this.dwarfFS = DwarfFS.getInstance();
        this.dwarfJavaHelper = DwarfJavaHelper.getInstance();
        this.dwarfObserver = DwarfObserver.getInstance();
        this.dwarfStalker = DwarfStalker.getInstance();
        this.breakAtStart = false;
        this.androidApiLevel = 0;
        this.hasUI = false;
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
        return this.dwarfHooksManager;
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
    debugEnabled = (): boolean => {
        return DEBUG;
    };

    enableTrace = (): void => {
        trace("DwarfCore::enableTrace()");
        TRACE = true;
    };
    disableTrace = (): void => {
        trace("DwarfCore::disableTrace()");
        TRACE = false;
    };
    toggleTrace = (): void => {
        trace("DwarfCore::toggleTrace()");
        TRACE = !TRACE;
    };
    traceEnabled = (): boolean => {
        return TRACE;
    };

    init = (
        procName: string,
        wasSpawned: boolean,
        breakStart: boolean,
        enableDebug: boolean = false,
        enableTrace: boolean = false,
        hasUI: boolean = false,
        globalApiFuncs?: Array<string>
    ): void => {
        trace("DwarfCore::init()");

        if (enableDebug) {
            DEBUG = true;
        }

        if (enableTrace) {
            TRACE = true;
        }

        if (breakStart) {
            this.breakAtStart = true;
        }

        if (hasUI) {
            this.hasUI = true;
        }

        if (Java.available) {
            this.androidApiLevel = this.getAndroidApiLevel();
        }

        if (procName.indexOf("|") !== -1) {
            let s = procName.split("|");
            procName = s[0];
            this.packagePath = s[1];
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

        /**
         * ** DONT add some Java.xxx stuff in here!!! put to start() ***
         */

        //send initdata
        let initData = {
            frida: Frida.version,
            process: this.processInfo,
            modules: Process.enumerateModules(),
            regions: Process.enumerateRanges("---"),
            threads: Process.enumerateThreads(),
        };

        if (hasUI) {
            send({ initData: initData });
        }

        // register global api functions
        /*if (globalApiFuncs && globalApiFuncs.length > 0) {

        }*/
        const exclusions = ["constructor", "length", "name", "prototype"];
        Object.getOwnPropertyNames(this.dwarfApi).forEach((prop) => {
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
        this.dwarfHooksManager.initialize();

        //attach init breakpoints
        if (Java.available) {
            if (this.processInfo.wasSpawned && this.breakAtStart) {
                //TODO: to add this bp 3x Java.performNow is used before resume try to reduce
                //android init breakpoint
                if (this.getAndroidApiLevel() >= 23) {
                    const initBreakpoint = this.getHooksManager().addJavaHook("com.android.internal.os.RuntimeInit", "commonInit", "breakpoint", true, true);
                    if (!isDefined(initBreakpoint)) {
                        logDebug("Failed to attach initHook!");
                    }
                } else {
                    const initBreakpoint = this.getHooksManager().addJavaHook("android.app.Application", "onCreate", "breakpoint", true, true);
                    if (!isDefined(initBreakpoint)) {
                        logDebug("Failed to attach initHook!");
                    }
                }
            } //breakatinit

            this.dwarfJavaHelper.initalize(this.packagePath);
            LogicJava.init();
        } //java.available

        DwarfInterceptor.init();

        if (Process.platform === "windows") {
            // break proc at main
            if (this.processInfo.wasSpawned && this.breakAtStart) {
                //Inital breakpoint
                const invocationListener = Interceptor.attach(this.dwarfApi.findExport("RtlUserThreadStart"), function () {
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
                        const initBreakpoint = DwarfCore.getInstance().getHooksManager().addNativeHook(address, "breakpoint", true, true);
                        invocationListener.detach();
                    }
                });
            } //breakatinit
        } //platform==windows
    };

    handleException = (exception: ExceptionDetails) => {
        trace("DwarfCore::handleException()");

        //TODO: remove
        /*
        if (
            exception.memory.operation === "read" &&
            exception.memory.address.toString() === NULL.toString()
        ) {
            return false;
        }*/

        Dwarf.sync({ exception: exception });
        let isHandled = false;
        const op = recv("exception", function (value) {
            isHandled = value.payload == 1;
            logDebug("Exception handled: " + isHandled);
        });
        op.wait();
        logDebug("Handled: " + isHandled);
        return isHandled;
    };

    loggedSend = (message: any, data?: ArrayBuffer | number[] | null): void => {
        trace("DwarfCore::loggedSend()");
        logDebug("[" + Process.getCurrentThreadId() + "] send | " + message);
        return send(message, data);
    };

    onBreakpoint = (breakpointId: number, threadId: number, haltReason: DwarfHaltReason, address_or_class, context, java_handle?, condition?: Function) => {
        trace("DwarfCore::onBreakpoint()");
        //const tid = Process.getCurrentThreadId();

        if (!isDefined(threadId)) {
            threadId = Process.getCurrentThreadId();
        }

        logDebug("[" + threadId + "] breakpoint " + address_or_class + " - reason: " + haltReason);

        const breakpointData = {
            hookid: breakpointId,
            tid: threadId,
            reason: haltReason,
            address: address_or_class,
        };

        if (!isDefined(context) && isDefined(this["context"])) {
            context = this["context"];
        }

        if (isDefined(context)) {
            logDebug("[" + threadId + "] sendInfos - preparing infos for valid context");

            breakpointData["context"] = context;
            if (isDefined(context["pc"])) {
                let symbol = null;

                try {
                    symbol = DebugSymbol.fromAddress(context.pc);
                } catch (e) {
                    logErr("_sendInfos", e);
                }

                logDebug("[" + threadId + "] sendInfos - preparing native backtrace");

                breakpointData["backtrace"] = {
                    bt: Dwarf.dwarfApi.backtrace(context),
                    type: "native",
                };

                logDebug("[" + threadId + "] sendInfos - preparing context registers");

                const newCtx = {};

                for (let reg in context) {
                    const val = context[reg];
                    let isValidPtr = false;

                    logDebug("[" + threadId + "] getting register information:", reg, val);

                    const ts = Dwarf.dwarfApi.getAddressTs(val);
                    isValidPtr = ts[0] != -1;
                    newCtx[reg] = {
                        value: val,
                        isValidPointer: isValidPtr,
                        telescope: ts,
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
                                //TODO: see https://github.com/iGio90/DwarfCore/pull/6
                                //it was for disasm?
                                thumb: inst.groups.indexOf("thumb") >= 0 || inst.groups.indexOf("thumb2") >= 0,
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

                logDebug("[" + threadId + "] sendInfos - preparing java backtrace");

                breakpointData["backtrace"] = {
                    bt: Dwarf.dwarfApi.javaBacktrace(),
                    type: "java",
                };
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
            Dwarf.sync({
                breakpoint: breakpointData,
                threads: Process.enumerateThreads(),
            });

            logDebug("[" + threadId + "] break " + address_or_class + " - sleeping context. goodnight!");
            Dwarf.loopApi(threadId, threadContext);

            logDebug("[" + threadId + "] ThreadContext has been released");
            Dwarf.sync({ threads: [], breakpoint: {} });
        }
    };

    loopApi = (threadId: number, that) => {
        trace("DwarfCore::loopApi()");

        logDebug("[" + threadId + "] looping api");

        const op = recv("" + threadId, function () {});
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
    sync = (extraData = {}, rawData?: ArrayBuffer | number[]) => {
        if (!this.hasUI) {
            return;
        }

        trace("DwarfCore::sync()");
        //let coreSyncMsg = { breakpoints: this.getHooksManager().getBreakpoints() };
        let coreSyncMsg = {};
        coreSyncMsg = Object.assign(coreSyncMsg, extraData);

        send(coreSyncMsg, rawData);
        /*JSON.stringify(coreSyncMsg, function (key, val) {
                if (isFunction(val)) {
                    return val.toString().replace(/\'/g, '"');
                } else {
                    return val;
                }
            })
        );*/
    };

    //from https://github.com/frida/frida-java-bridge/blob/master/lib/android.js
    getAndroidSystemProperty = (name: string) => {
        if (!Java.available) {
            return;
        }

        trace("DwarfCore::getAndroidSystemProperty()");
        if (this._systemPropertyGet === null) {
            this._systemPropertyGet = new NativeFunction(Module.findExportByName("libc.so", "__system_property_get"), "int", ["pointer", "pointer"], {
                exceptions: "propagate",
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
                self.sync({
                    search_result: { address: foundAddress, size: foundSize },
                });
            },
            onComplete: () => {
                self.sync({ search_finished: true });
            },
            onError: (reason) => {
                self.sync({ search_error: reason });
            },
        });
    };
}
