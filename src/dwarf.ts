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
import { LogicInitialization } from "./logic_initialization";
import { DwarfInterceptor } from "./interceptor";
import { DwarfApi } from "./api";
import { LogicBreakpoint } from "./logic_breakpoint";
import { DwarfBreakpointManager } from "./breakpoint_manager";
import { ThreadContext } from "./thread_context";
import { ThreadApi } from "./thread_api";
import { LogicStalker } from "./logic_stalker";
import { DwarfHaltReason } from "./consts";
import { DwarfProcessInfo } from "./types/dwarf_processinfo";
import { NativeBreakpoint } from "./types/native_breakpoint";
import { DwarfFS } from "./DwarfFS";
import { DwarfObserver } from "./dwarf_observer";
import { DwarfJavaHelper } from "./java";
import { DwarfStalker } from "./stalker";

export class DwarfCore {
    PROC_RESUMED = false;

    threadContexts = {};

    modulesBlacklist = [];

    protected processInfo: DwarfProcessInfo;

    private dwarfApi: DwarfApi;
    private dwarfBreakpointManager: DwarfBreakpointManager;
    private dwarfFS: DwarfFS;
    private dwarfObserver: DwarfObserver;
    private dwarfJavaHelper:DwarfJavaHelper;
    private dwarfStalker:DwarfStalker;

    private _systemPropertyGet: NativeFunction;
    private static instanceRef: DwarfCore;

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
        global.DEBUG = false;
        trace('DwarfCoreJS start');
        this._systemPropertyGet = null;
        this.dwarfApi = DwarfApi.getInstance();
        this.dwarfBreakpointManager = DwarfBreakpointManager.getInstance();
        this.dwarfFS = DwarfFS.getInstance();
        this.dwarfObserver = DwarfObserver.getInstance();
        this.dwarfJavaHelper = null;
        this.dwarfStalker = DwarfStalker.getInstance();
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
        trace('Dwarf::getInstance()');
        return DwarfCore.instanceRef;
    }

    getApi = (): DwarfApi => {
        trace('Dwarf::getApi()');
        return this.dwarfApi;
    }

    getBreakpointManager = (): DwarfBreakpointManager => {
        trace('Dwarf::getBreakpointManager()');
        return this.dwarfBreakpointManager;
    }

    getFS = (): DwarfFS => {
        trace('Dwarf::getFS()');
        return this.dwarfFS;
    }

    getJavaHelper = ():DwarfJavaHelper => {
        trace('Dwarf::getJavaHelper()');
        if(this.dwarfJavaHelper === null) {
            throw new Error('JavaHelper not initialized!');
        }
        return this.dwarfJavaHelper;
    }

    getStalker = ():DwarfStalker => {
        trace('Dwarf::getStalker()');
        return this.dwarfStalker;
    }

    enableDebug = (): void => {
        trace('DwarfCore::enableDebug()');
        DEBUG = true;
    }
    disableDebug = (): void => {
        trace('DwarfCore::disableDebug()');
        DEBUG = false
    }
    toggleDebug = (): void => {
        trace('DwarfCore::toggleDebug()');
        DEBUG = !DEBUG
    }

    init = (
        procName: string,
        wasSpawned: boolean,
        breakStart: boolean,
        debug: boolean,
        globalApiFuncs?: Array<string>
    ): void => {
        trace('DwarfCore::init()');

        if (debug) {
            DEBUG = true;
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
            'process': this.processInfo,
            'modules': Process.enumerateModules(),
            'regions': Process.enumerateRanges('---'),
            'threads': Process.enumerateThreads()
        }
        send('coresync:::' + JSON.stringify(initData));


        //Init JavaHelper
        try {
            this.dwarfJavaHelper = DwarfJavaHelper.getInstance();
        } catch(e) {
            logDebug(e);
        }

        LogicInitialization.init();
        DwarfInterceptor.init();

        // register global api functions
        if (globalApiFuncs && globalApiFuncs.length > 0) {

        }
        const exclusions = ['constructor', 'length', 'name', 'prototype'];
        Object.getOwnPropertyNames(this.dwarfApi).forEach(prop => {
            if (exclusions.indexOf(prop) < 0) {
                global[prop] = this.dwarfApi[prop];
            }
        });

        if (Process.platform === 'windows') {
            this.modulesBlacklist.push('ntdll.dll');
            if (Process.arch === 'x64') {
                //TODO: debug later why module needs blacklisted on x64 targets only
                this.modulesBlacklist.push('win32u.dll');
            }
        } else if (Process.platform === 'linux') {
            if (isDefined(LogicJava) && LogicJava.sdk <= 23) {
                this.modulesBlacklist.push('app_process');
            }
        }

        Process.setExceptionHandler(this.handleException);

        if (Process.platform === 'windows') {
            // break proc at main
            if (wasSpawned && breakStart) {
                //Inital breakpoint
                const invocationListener = Interceptor.attach(this.getApi().findExport('RtlUserThreadStart'), function () {
                    trace('Creating startbreakpoint');
                    const invocationContext = this;
                    let address = null;
                    if (Process.arch === 'ia32') {
                        const context = invocationContext.context as Ia32CpuContext;
                        address = context.eax;
                    } else if (Process.arch === 'x64') {
                        const context = invocationContext.context as X64CpuContext;
                        address = context.rax;
                    }

                    if (isDefined(address)) {
                        const initBreakpoint = DwarfCore.getInstance().getBreakpointManager().addNativeBreakpoint(address, true);
                        initBreakpoint.setSingleShot(true);
                        invocationListener.detach();
                    }
                });
            }
        }
        if (Java.available && wasSpawned && breakStart) {
            //android init breakpoint
            if (LogicJava.sdk >= 23) {
                const initBreakpoint = this.getBreakpointManager().addJavaBreakpoint('com.android.internal.os.RuntimeInit.commonInit');
                initBreakpoint.setSingleShot(true);
            } else {
                const initBreakpoint = this.getBreakpointManager().addJavaBreakpoint('android.app.Application.onCreate');
                initBreakpoint.setSingleShot(true);
            }
        }
    }

    handleException = (exception: ExceptionDetails) => {
        trace('DwarfCore::handleException()');
        if (DEBUG) {
            let dontLog = false;
            if (Process.platform === 'windows') {
                // hide SetThreadName - https://github.com/frida/glib/blob/master/glib/gthread-win32.c#L579
                let reg = null;
                if (Process.arch === 'x64') {
                    reg = exception['context']['rax'];
                } else if (Process.arch === 'ia32') {
                    reg = exception['context']['eax'];
                }
                if (reg !== null && reg.readInt() === 0x406d1388) {
                    dontLog = true;
                }
            }
            if (!dontLog) {
                console.log('[' + Process.getCurrentThreadId() + '] exception handler: ' + JSON.stringify(exception));
            }
        }

        //handle MemoryBreakpoints
        if (exception.type === 'access-violation') {
            if (Process.platform === 'windows') {
                return true;
            }
            //return this.getBreakpointManager().handleMemoryBreakpoints(exception);
        }
    }

    loggedSend = (message: any, data?: ArrayBuffer | number[] | null): void => {
        trace('DwarfCore::loggedSend()');
        logDebug('[' + Process.getCurrentThreadId() + '] send | ' + message);
        return send(message, data);
    }

    onBreakpoint = (haltReason: DwarfHaltReason, address_or_class, context, java_handle?, condition?: Function) => {
        trace('DwarfCore::onBreakpoint()');
        const tid = Process.getCurrentThreadId();

        logDebug('[' + tid + '] breakpoint ' + address_or_class + ' - reason: ' + haltReason);

        const breakpointData = {
            "tid": tid,
            "reason": haltReason
        };

        if (isDefined(context)) {
            logDebug('[' + tid + '] sendInfos - preparing infos for valid context');

            breakpointData['context'] = context;
            if (isDefined(context['pc'])) {
                let symbol = null;
                breakpointData['ptr'] = address_or_class;

                try {
                    symbol = DebugSymbol.fromAddress(context.pc);
                } catch (e) {
                    logErr('_sendInfos', e);
                }

                logDebug('[' + tid + '] sendInfos - preparing native backtrace');

                breakpointData['backtrace'] = { 'bt': this.getApi().backtrace(context), 'type': 'native' };

                logDebug('[' + tid + '] sendInfos - preparing context registers');

                const newCtx = {};

                for (let reg in context) {
                    const val = context[reg];
                    let isValidPtr = false;

                    logDebug('[' + tid + '] getting register information:', reg, val);

                    const ts = this.getApi().getAddressTs(val);
                    isValidPtr = ts[0] > 0;
                    newCtx[reg] = {
                        'value': val,
                        'isValidPointer': isValidPtr,
                        'telescope': ts
                    };
                    if (reg === 'pc') {
                        if (symbol !== null) {
                            newCtx[reg]['symbol'] = symbol;
                        }
                        try {
                            const inst = Instruction.parse(val);
                            newCtx[reg]['instruction'] = {
                                'size': inst.size,
                                'groups': inst.groups,
                                'thumb': inst.groups.indexOf('thumb') >= 0 ||
                                    inst.groups.indexOf('thumb2') >= 0
                            };
                        } catch (e) {
                            logErr('_sendInfos', e);
                        }
                    }
                }

                breakpointData['rawcontext'] = context;
                breakpointData['context'] = newCtx;
            } else {
                breakpointData['is_java'] = true;
                breakpointData['class'] = address_or_class;

                logDebug('[' + tid + '] sendInfos - preparing java backtrace');

                breakpointData['backtrace'] = { 'bt': this.dwarfApi.javaBacktrace(), 'type': 'java' };
            }
        }

        let threadContext: ThreadContext = this.threadContexts[tid];

        if (!isDefined(threadContext) && isDefined(context)) {
            threadContext = new ThreadContext(tid);
            threadContext.context = context;
            this.threadContexts[tid] = threadContext;
        }

        if (isDefined(condition)) {
            if (!condition.call(threadContext)) {
                delete this.threadContexts[tid];
                return;
            }
        }

        if (!isDefined(threadContext) || !threadContext.preventSleep) {
            logDebug('[' + tid + '] break ' + address_or_class + ' - dispatching context info');
            this.sync({ 'breakpoint': breakpointData, 'threads': Process.enumerateThreads() });

            logDebug('[' + tid + '] break ' + address_or_class + ' - sleeping context. goodnight!');
            this.loopApi(tid, threadContext);

            logDebug('[' + tid + '] ThreadContext has been released');
            this.loggedSend('release:::' + tid + ':::' + haltReason);
        }
    }

    loopApi = (tid: number, that) => {
        trace('DwarfCore::loopApi()');

        logDebug('[' + tid + '] looping api');

        const op = recv('' + tid, function () {
        });
        op.wait();

        const threadContext: ThreadContext = this.threadContexts[tid];

        if (isDefined(threadContext)) {
            while (threadContext.apiQueue.length === 0) {
                logDebug('[' + tid + '] waiting api queue to be populated');
                Thread.sleep(0.2);
            }

            let release = false;

            while (threadContext.apiQueue.length > 0) {
                const threadApi: ThreadApi = threadContext.apiQueue.shift();

                logDebug('[' + tid + '] executing ' + threadApi.apiFunction);

                try {
                    if (isDefined(this.getApi()[threadApi.apiFunction])) {
                        threadApi.result = this.getApi()[threadApi.apiFunction].apply(that, threadApi.apiArguments);
                    } else {
                        threadApi.result = null;
                    }
                } catch (e) {
                    threadApi.result = null;
                    if (DEBUG) {
                        logDebug('[' + tid + '] error executing ' +
                            threadApi.apiFunction + ':\n' + e);
                    }
                }
                threadApi.consumed = true;

                let stalkerInfo = LogicStalker.stalkerInfoMap[tid];
                if (threadApi.apiFunction === '_step') {
                    if (!isDefined(stalkerInfo)) {
                        LogicStalker.stalk(tid);
                    }
                    release = true;
                    break
                } else if (threadApi.apiFunction === 'release') {
                    if (isDefined(stalkerInfo)) {
                        stalkerInfo.terminated = true;
                    }

                    release = true;
                    break;
                }
            }

            if (!release) {
                this.loopApi(tid, that);
            }
        }
    }

    getProcessInfo = () => {
        return this.processInfo;
    }

    /** @internal */
    sync = (extraData = {}) => {
        trace('DwarfCore::sync()');
        let coreSyncMsg = { breakpoints: this.getBreakpointManager().getBreakpoints() };
        coreSyncMsg = Object.assign(coreSyncMsg, extraData);
        send('coresync:::' + JSON.stringify(coreSyncMsg));
    }

    //from https://github.com/frida/frida-java-bridge/blob/master/lib/android.js
    getAndroidSystemProperty = (name: string) => {
        if (!this.processInfo.isJavaAvailable()) { return; }

        trace('DwarfCore::getAndroidSystemProperty()');
        if (this._systemPropertyGet === null) {
            this._systemPropertyGet = new NativeFunction(Module.findExportByName('libc.so', '__system_property_get'), 'int', ['pointer', 'pointer'], {
                exceptions: 'propagate'
            });
        }
        const buf = Memory.alloc(92);
        this._systemPropertyGet(Memory.allocUtf8String(name), buf);
        return buf.readUtf8String();
    }

    //from https://github.com/frida/frida-java-bridge/blob/master/lib/android.js
    getAndroidApiLevel = () => {
        if (!this.processInfo.isJavaAvailable()) { return; }

        trace('DwarfCore::getAndroidApiLevel()');
        return parseInt(this.getAndroidSystemProperty('ro.build.version.sdk'), 10);
    }
}