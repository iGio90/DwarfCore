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

import { LogicJava } from "./logic_java";
import { DwarfApi } from "./DwarfApi";
import { DwarfHooksManager } from "./DwarfHooksManager";
import { ThreadContext } from "./thread_context";
import { ThreadApi } from "./thread_api";
import { DwarfHaltReason } from "./consts";
import { DwarfProcessInfo } from "./types/DwarfProcessInfo";
import { DwarfFS } from "./DwarfFS";
import { DwarfObserver } from "./DwarfObserver";
import { DwarfJavaHelper } from "./DwarfJavaHelper";
import { DwarfStalker } from "./DwarfStalker";

export class DwarfCore {
    /**
     * DwarfCore Instance
     *
     * @returns DwarfCore
     */
    static getInstance() {
        if (!DwarfCore.instanceRef) {
            DwarfCore.instanceRef = new this();
        }
        trace("DwarfCore::getInstance()");
        return DwarfCore.instanceRef;
    }
    protected modulesBlacklist: string[] = new Array<string>();
    protected processInfo: DwarfProcessInfo | null;
    protected threadContexts: { [index: string]: ThreadContext } = {};
    private static instanceRef: DwarfCore;

    private _systemPropertyGet: NativeFunction | null;
    private androidApiLevel: number;
    private breakAtStart: boolean;

    private dwarfApi: DwarfApi;
    private dwarfFS: DwarfFS;
    private dwarfHooksManager: DwarfHooksManager;
    private dwarfJavaHelper: DwarfJavaHelper;
    private dwarfObserver: DwarfObserver;
    private dwarfStalker: DwarfStalker;

    private hasUI: boolean;
    private packagePath: string;

    /** @internal */
    private constructor() {
        // get maxstack
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

    _prepareNativeContext = (context: CpuContext) => {
        trace("DwarfCore::_prepareNativeContext()");

        if (context.hasOwnProperty("pc") || !context.pc) {
            logDebug("_prepNatContext: Invalid Argument!");
            return context;
        }

        const newCtx = {};

        for (const [reg, val] of Object.entries(context)) {
            const ts = DwarfCore.getInstance().getApi().getAddressTs(val);
            newCtx[reg] = {
                value: val,
                isValidPointer: ts[0] !== -1,
                telescope: ts,
                debugSymbol: DebugSymbol.fromAddress(context.pc),
            };
            if (reg === "pc") {
                try {
                    const inst = Instruction.parse(val);
                    newCtx[reg].instruction = {
                        size: inst.size,
                        groups: inst.groups,
                        thumb: inst.groups.indexOf("thumb") >= 0 || inst.groups.indexOf("thumb2") >= 0,
                    };
                } catch (e) {
                    logErr("_sendInfos", e);
                }
            }
        }
        return newCtx;
    };

    addThreadContext = (threadId: number, context: ThreadContext) => {
        trace("DwarfCore::addThreadContext()");

        this.threadContexts[threadId.toString()] = context;
    };
    debugEnabled = (): boolean => {
        return DEBUG;
    };

    deleteThreadContext = (threadId: number): boolean => {
        trace("DwarfCore::deleteThreadContext()");

        if (!this.threadContexts.hasOwnProperty(threadId.toString())) {
            return false;
        }
        delete this.threadContexts[threadId.toString()];
        return true;
    };

    disableDebug = (): void => {
        trace("DwarfCore::disableDebug()");
        DEBUG = false;
    };

    disableTrace = (): void => {
        trace("DwarfCore::disableTrace()");
        TRACE = false;
    };

    enableDebug = (): void => {
        trace("DwarfCore::enableDebug()");
        DEBUG = true;
    };

    enableTrace = (): void => {
        trace("DwarfCore::enableTrace()");
        TRACE = true;
    };

    // from https://github.com/frida/frida-java-bridge/blob/master/lib/android.js
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

    // from https://github.com/frida/frida-java-bridge/blob/master/lib/android.js
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

    getApi = (): DwarfApi => {
        trace("DwarfCore::getApi()");
        return this.dwarfApi;
    };

    getFS = (): DwarfFS => {
        trace("DwarfCore::getFS()");
        return this.dwarfFS;
    };

    getHooksManager = (): DwarfHooksManager => {
        trace("DwarfCore::getHooksManager()");
        return this.dwarfHooksManager;
    };

    getJavaHelper = (): DwarfJavaHelper => {
        trace("DwarfCore::getJavaHelper()");
        if (this.dwarfJavaHelper === null) {
            throw new Error("JavaHelper not initialized!");
        }
        return this.dwarfJavaHelper;
    };

    getObserver = (): DwarfObserver => {
        trace("DwarfCore::getObserver()");
        return this.dwarfObserver;
    };

    getProcessInfo = () => {
        trace("DwarfCore::getProcessInfo()");
        return this.processInfo;
    };

    getStalker = (): DwarfStalker => {
        trace("DwarfCore::getStalker()");
        return this.dwarfStalker;
    };

    getThreadContext = (threadId: number): ThreadContext => {
        trace("DwarfCore::getThreadContext()");

        if (!this.threadContexts.hasOwnProperty(threadId.toString())) {
            return null;
        }
        return this.threadContexts[threadId.toString()];
    };

    handleException = (exception: ExceptionDetails) => {
        trace("DwarfCore::handleException()");

        // TODO: remove
        /*
        if (
            exception.memory.operation === "read" &&
            exception.memory.address.toString() === NULL.toString()
        ) {
            return false;
        }*/

        this.sync({ exception });
        let isHandled = false;
        const op = recv("exception", function (value) {
            isHandled = value.payload === 1;
            logDebug("Exception handled: " + isHandled);
        });
        op.wait();
        logDebug("Handled: " + isHandled);
        return isHandled;
    };

    init = (
        procName: string,
        wasSpawned: boolean,
        breakStart: boolean,
        enableDebug: boolean = false,
        enableTrace: boolean = false,
        hasUI: boolean = false,
        globalApiFuncs?: string[]
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
            const s = procName.split("|");
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

        // send initdata
        const initData = {
            frida: Frida.version,
            process: this.processInfo,
            modules: Process.enumerateModules(),
            regions: Process.enumerateRanges("---"),
            threads: Process.enumerateThreads(),
        };

        if (hasUI) {
            send({ initData });
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
                // TODO: debug later why module needs blacklisted on x64 targets only
                this.modulesBlacklist.push("win32u.dll");
            }
        } else if (Process.platform === "linux") {
            if (Java.available && this.getAndroidApiLevel() <= 23) {
                this.modulesBlacklist.push("app_process");
            }
        }

        Process.setExceptionHandler(this.handleException);
    };

    initInterceptor = () => {
        trace("DwarfCore::initInterceptor()");

        global.FridaInterceptor = Interceptor;
        global.Interceptor = Object.assign({}, Interceptor);

        global.Interceptor.attach = function (
            target: NativePointerValue,
            callbacksOrProbe: InvocationListenerCallbacks | InstructionProbeCallback,
            data?: NativePointerValue
        ): InvocationListener {
            let modifiedCallback;
            if (typeof callbacksOrProbe === "function") {
                modifiedCallback = function () {
                    const ret = callbacksOrProbe.apply(this, arguments);
                    DwarfCore.getInstance().deleteThreadContext(Process.getCurrentThreadId());
                    return ret;
                };
            } else if (typeof callbacksOrProbe === "object") {
                if (isValidFridaListener(callbacksOrProbe)) {
                    modifiedCallback = {};
                    if (callbacksOrProbe.hasOwnProperty("onEnter")) {
                        modifiedCallback.onEnter = function () {
                            const retVal = (callbacksOrProbe as ScriptInvocationListenerCallbacks).onEnter.apply(this, arguments);
                            DwarfCore.getInstance().deleteThreadContext(Process.getCurrentThreadId());
                            return retVal;
                        };
                    }

                    if (callbacksOrProbe.hasOwnProperty("onLeave")) {
                        modifiedCallback.onLeave = callbacksOrProbe.onLeave;
                    }
                }
            }

            if (typeof modifiedCallback === "undefined") {
                throw new Error("DwarfInterceptor::attach() no callback");
            }

            return FridaInterceptor.attach(target, modifiedCallback, data);
        };
    };

    isBlacklistedModule = (module: Module | string): boolean => {
        trace("DwarfCore::isBlacklistedModule()");

        if (module.constructor.name === "Module") {
            return this.modulesBlacklist.indexOf((module as Module).name) !== -1;
        } else if (isString(module)) {
            return this.modulesBlacklist.indexOf(module as string) !== -1;
        } else {
            throw new Error("Invalid Argument!");
        }

        return false;
    };

    loggedSend = (what: string) => {
        throw new Error("DEPRECATED");
    };

    loopApi = (threadId: number, that) => {
        trace("DwarfCore::loopApi()");

        logDebug("[" + threadId + "] looping api");

        const op = recv("" + threadId, function (value: any) {
            logDebug("loopApi::recv()");
        });
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

                // TODO: fix stalker
                if (threadApi.apiFunction === "release") {
                    release = true;
                    break;
                }

                /*
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
                }*/
            }

            if (!release) {
                DwarfCore.getInstance().loopApi(threadId, that);
            }
        }
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

    onBreakpoint = function (
        breakpointId: number,
        threadId: number,
        haltReason: DwarfHaltReason,
        addrOrClass,
        context: CpuContext,
        javaHandle?,
        condition?: fEmptyVoid
    ) {
        trace("DwarfCore::onBreakpoint()");

        if (!isDefined(threadId)) {
            threadId = Process.getCurrentThreadId();
        }

        logDebug("[" + threadId + "] breakpoint " + addrOrClass + " - reason: " + haltReason);

        const breakpointData = {
            hookid: breakpointId,
            tid: threadId,
            reason: haltReason,
            address: addrOrClass,
            context: null,
            backtrace: null,
            java: false,
            rawcontext: null,
        };

        if (!isDefined(context) && isDefined(this.context)) {
            context = this.context;
        }

        if (isDefined(context)) {
            logDebug("[" + threadId + "] sendInfos - preparing infos for valid context");

            breakpointData.context = context;
            if (isDefined(context.pc)) {
                logDebug("[" + threadId + "] sendInfos - preparing native backtrace");

                breakpointData.backtrace = {
                    bt: DwarfCore.getInstance().getApi().backtrace(context),
                    type: "native",
                };

                logDebug("[" + threadId + "] sendInfos - preparing context registers");

                breakpointData.context = DwarfCore.getInstance()._prepareNativeContext(context);
                breakpointData.rawcontext = context;
            } else {
                breakpointData.java = true;

                logDebug("[" + threadId + "] sendInfos - preparing java backtrace");

                breakpointData.backtrace = {
                    bt: DwarfCore.getInstance().getApi().javaBacktrace(),
                    type: "java",
                };
            }
        }

        let threadContext: ThreadContext = DwarfCore.getInstance().getThreadContext(threadId);

        if (!isDefined(threadContext) && isDefined(context)) {
            threadContext = new ThreadContext(threadId);
            threadContext.context = context;
            DwarfCore.getInstance().addThreadContext(threadId, threadContext);
        }

        if (isDefined(condition)) {
            if (!condition.call(threadContext)) {
                DwarfCore.getInstance().deleteThreadContext(threadId);
                return;
            }
        }

        if (!isDefined(threadContext) || !threadContext.preventSleep) {
            logDebug("[" + threadId + "] break " + addrOrClass + " - dispatching context info");
            DwarfCore.getInstance().sync({
                breakpoint: breakpointData,
                threads: Process.enumerateThreads(),
                dwarfHooks: DwarfCore.getInstance().getHooksManager().getHooks(),
            });

            logDebug("[" + threadId + "] break " + addrOrClass + " - sleeping context. goodnight!");
            DwarfCore.getInstance().loopApi(threadId, threadContext);

            logDebug("[" + threadId + "] ThreadContext has been released");
            DwarfCore.getInstance().sync({ threads: [], breakpoint: {} });
        }
    };

    start = () => {
        this.dwarfHooksManager.initialize();

        // attach init breakpoints
        if (Java.available) {
            if (this.processInfo.wasSpawned && this.breakAtStart) {
                // TODO: to add this bp 3x Java.performNow is used before resume try to reduce
                // android init breakpoint
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
            } // breakatinit

            this.dwarfJavaHelper.initalize(this.packagePath);
            LogicJava.init();
        } // java.available

        this.initInterceptor();

        if (Process.platform === "windows") {
            // break proc at main
            if (this.processInfo.wasSpawned && this.breakAtStart) {
                // Inital breakpoint
                const invocationListener = Interceptor.attach(this.dwarfApi.findExport("RtlUserThreadStart"), function () {
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
                        if (!initBreakpoint || (initBreakpoint && !initBreakpoint.isAttached())) {
                            logDebug("Failed to attach initBP!");
                        }
                    }
                    invocationListener.detach();
                });
            } // breakatinit
        } // platform==windows
    };

    sync = (extraData = {}, rawData?: ArrayBuffer | number[]) => {
        if (!this.hasUI) {
            return;
        }

        trace("DwarfCore::sync()");

        let coreSyncMsg = {};
        coreSyncMsg = Object.assign(coreSyncMsg, extraData);

        send(coreSyncMsg, rawData);
    };

    toggleDebug = (): void => {
        trace("DwarfCore::toggleDebug()");
        DEBUG = !DEBUG;
    };

    toggleTrace = (): void => {
        trace("DwarfCore::toggleTrace()");
        TRACE = !TRACE;
    };

    traceEnabled = (): boolean => {
        return TRACE;
    };
}
