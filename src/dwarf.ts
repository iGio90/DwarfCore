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


import { Api } from "./api";
import { LogicBreakpoint } from "./logic_breakpoint";
import { DwarfInterceptor } from "./interceptor";
import { LogicJava } from "./logic_java";
import { LogicInitialization } from "./logic_initialization";
import { LogicWatchpoint } from "./logic_watchpoint";
import { Utils } from "./utils";

export class Dwarf {
    static DEBUG: boolean;
    static BREAK_START: boolean;
    static SPAWNED: boolean;

    static PROC_RESUMED = false;

    static threadContexts = {};

    static modulesBlacklist = [];

    static init(breakStart, debug, spawned) {
        Dwarf.BREAK_START = breakStart;
        Dwarf.DEBUG = debug;
        Dwarf.SPAWNED = spawned;

        if (LogicJava.available) {
            LogicJava.init();
        }

        LogicInitialization.init();
        DwarfInterceptor.init();

        // register all api as global
        const exclusions = ['constructor', 'length', 'name', 'prototype'];
        Object.getOwnPropertyNames(Api).forEach(prop => {
            if (exclusions.indexOf(prop) < 0) {
                global[prop] = Api[prop];
            }
        });

        if (Process.platform === 'windows') {
            this.modulesBlacklist.push('ntdll.dll');
            if (Process.arch === 'x64') {
                //TODO: debug later why module needs blacklisted on x64 targets only
                this.modulesBlacklist.push('win32u.dll');
            }
        } else if (Process.platform === 'linux') {
            if (Utils.isDefined(LogicJava) && LogicJava.sdk <= 23) {
                this.modulesBlacklist.push('app_process');
            }
        }

        Process.setExceptionHandler(Dwarf.handleException);

        if (Process.platform === 'windows') {
            // break proc at main
            if (Dwarf.SPAWNED && Dwarf.BREAK_START) {
                const initialHook = Interceptor.attach(Api.findExport('RtlUserThreadStart'), function () {
                    let address = null;
                    if (Process.arch === 'ia32') {
                        const context = this.context as Ia32CpuContext;
                        address = context.eax;
                    } else if (Process.arch === 'x64') {
                        const context = this.context as X64CpuContext;
                        address = context.rax;
                    }

                    if (Utils.isDefined(address)) {
                        const startInterceptor = Interceptor.attach(address, function () {
                            LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, this.context.pc, this.context);
                            startInterceptor.detach();
                        });
                        initialHook.detach();
                    }
                });
            }
        }

        Dwarf.dispatchContextInfo(LogicBreakpoint.REASON_SET_INITIAL_CONTEXT);
    }

    static dispatchContextInfo(reason, address_or_class?, context?) {
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

        if (Utils.isDefined(context)) {
            if (Dwarf.DEBUG) {
                Utils.logDebug('[' + tid + '] sendInfos - preparing infos for valid context');
            }

            data['context'] = context;
            if (Utils.isDefined(context['pc'])) {
                let symbol = null;
                try {
                    symbol = DebugSymbol.fromAddress(context.pc);
                } catch (e) {
                    Utils.logErr('_sendInfos', e);
                }
                if (Dwarf.DEBUG) {
                    Utils.logDebug('[' + tid + '] sendInfos - preparing native backtrace');
                }

                data['backtrace'] = { 'bt': Api.backtrace(context), 'type': 'native' };
                data['is_java'] = false;

                if (Dwarf.DEBUG) {
                    Utils.logDebug('[' + tid + '] sendInfos - preparing context registers');
                }

                const newCtx = {};

                for (let reg in context) {
                    const val = context[reg];
                    let isValidPtr = false;
                    if (Dwarf.DEBUG) {
                        Utils.logDebug('[' + tid + '] getting register information:', reg, val);
                    }
                    const ts = Api.getAddressTs(val);
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
                            Utils.logErr('_sendInfos', e);
                        }
                    }
                }

                data['context'] = newCtx;
            } else {
                data['is_java'] = true;
                if (Dwarf.DEBUG) {
                    Utils.logDebug('[' + tid + '] sendInfos - preparing java backtrace');
                }
                data['backtrace'] = { 'bt': Api.javaBacktrace(), 'type': 'java' };
            }
        }

        if (Dwarf.DEBUG) {
            Utils.logDebug('[' + tid + '] sendInfos - dispatching infos');
        }

        Dwarf.loggedSend('set_context:::' + JSON.stringify(data));
    }

    static handleException(exception) {
        if (Dwarf.DEBUG) {
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

    static loggedSend(w, p?) {
        if (Dwarf.DEBUG) {
            console.log('[' + Process.getCurrentThreadId() + '] send | ' + w);
        }

        return send(w, p);
    }
}