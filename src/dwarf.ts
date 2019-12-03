/**
    Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

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
import { LogicWatchpoint } from "./logic_watchpoint";

export class DwarfCore {
    BREAK_START: boolean;
    SPAWNED: boolean;
    PROC_RESUMED = false;

    threadContexts = {};

    modulesBlacklist = [];

    private dwarfApi: DwarfApi;

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
        console.log('DwarfCoreJS start');
        this.dwarfApi = DwarfApi.getInstance();
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
        return DwarfCore.instanceRef;
    }

    getApi = (): DwarfApi => {
        return this.dwarfApi;
    }

    enableDebug = (): void => {
        DEBUG = true;
    }
    disableDebug = (): void => {
        DEBUG = false
    }
    toggleDebug = (): void => {
        DEBUG = !DEBUG
    }

    init = (breakStart: boolean, debug: boolean, spawned: boolean, globalApiFuncs?: Array<string>): void => {
        this.BREAK_START = breakStart;
        if (debug) {
            DEBUG = true;
        }
        this.SPAWNED = spawned;

        if (LogicJava.available) {
            LogicJava.init();
        }

        LogicInitialization.init();
        DwarfInterceptor.init();

        // register global api functions
        if (globalApiFuncs && globalApiFuncs.length > 0) {

        }
        const exclusions = ['constructor', 'length', 'name', 'prototype'];
        Object.getOwnPropertyNames(this.dwarfApi).forEach(prop => {
            if (exclusions.indexOf(prop) < 0) {
                global[prop] = this.getApi()[prop];
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
            if (this.SPAWNED && this.BREAK_START) {
                const initialHook = Interceptor.attach(this.dwarfApi.findExport('RtlUserThreadStart'), function () {
                    let address = null;
                    if (Process.arch === 'ia32') {
                        const context = this.context as Ia32CpuContext;
                        address = context.eax;
                    } else if (Process.arch === 'x64') {
                        const context = this.context as X64CpuContext;
                        address = context.rax;
                    }

                    if (isDefined(address)) {
                        const startInterceptor = Interceptor.attach(address, function () {
                            LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, this.context.pc, this.context);
                            startInterceptor.detach();
                        });
                        initialHook.detach();
                    }
                });
            }
        }

        this.dispatchContextInfo(LogicBreakpoint.REASON_SET_INITIAL_CONTEXT);
    }

    dispatchContextInfo = (reason, address_or_class?, context?) => {
        const tid = Process.getCurrentThreadId();

        const data = {
            "tid": tid,
            "reason": reason,
            "ptr": address_or_class
        };

        if (reason === LogicBreakpoint.REASON_SET_INITIAL_CONTEXT) {
            data['arch'] = Process.arch;
            data['platform'] = Process.platform;
            data['java'] = Java.available;
            data['objc'] = ObjC.available;
            data['pid'] = Process.id;
            data['pointerSize'] = Process.pointerSize;
        }

        if (isDefined(context)) {
            logDebug('[' + tid + '] sendInfos - preparing infos for valid context');

            data['context'] = context;
            if (isDefined(context['pc'])) {
                let symbol = null;
                try {
                    symbol = DebugSymbol.fromAddress(context.pc);
                } catch (e) {
                    logErr('_sendInfos', e);
                }

                logDebug('[' + tid + '] sendInfos - preparing native backtrace');

                data['backtrace'] = { 'bt': this.dwarfApi.backtrace(context), 'type': 'native' };
                data['is_java'] = false;

                logDebug('[' + tid + '] sendInfos - preparing context registers');

                const newCtx = {};

                for (let reg in context) {
                    const val = context[reg];
                    let isValidPtr = false;

                    logDebug('[' + tid + '] getting register information:', reg, val);

                    const ts = this.dwarfApi.getAddressTs(val);
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

                data['context'] = newCtx;
            } else {
                data['is_java'] = true;

                logDebug('[' + tid + '] sendInfos - preparing java backtrace');

                data['backtrace'] = { 'bt': this.dwarfApi.javaBacktrace(), 'type': 'java' };
            }
        }


        logDebug('[' + tid + '] sendInfos - dispatching infos');


        this.loggedSend('set_context:::' + JSON.stringify(data));
    }

    handleException = (exception) => {
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

        if (Process.platform === 'windows') {
            if (exception['type'] === 'access-violation') {
                return true;
            }
        }

        const watchpoint = LogicWatchpoint.handleException(exception);
        return watchpoint !== null;
    }

    loggedSend = (w, p?) => {
        if (DEBUG) {
            console.log('[' + Process.getCurrentThreadId() + '] send | ' + w);
        }

        return send(w, p);
    }
}