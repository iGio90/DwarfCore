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
import { Breakpoint } from "./breakpoint";
import { Dwarf } from "./dwarf";
import { LogicJava } from "./logic_java";
import { LogicObjC } from "./logic_objc";
import { LogicStalker } from "./logic_stalker";
import { ThreadApi } from "./thread_api";
import { ThreadContext } from "./thread_context";
import { Utils } from "./utils";
import {StalkerInfo} from "./stalker_info";
import {kStringMaxLength} from "buffer";

export class LogicBreakpoint {
    static REASON_SET_INITIAL_CONTEXT = -1;
    static REASON_BREAKPOINT = 0;
    static REASON_WATCHPOINT = 1;
    static REASON_BREAKPOINT_INITIALIZATION = 2;
    static REASON_STEP = 3;

    static breakpoints = {};

    static breakpoint(reason, address_or_class, context, java_handle?, condition?) {
        const tid = Process.getCurrentThreadId();

        if (!Utils.isDefined(reason)) {
            reason = LogicBreakpoint.REASON_BREAKPOINT;
        }

        if (Dwarf.DEBUG) {
            Utils.logDebug('[' + tid + '] breakpoint ' + address_or_class + ' - reason: ' + reason);
        }

        let threadContext: ThreadContext = Dwarf.threadContexts[tid];

        if (!Utils.isDefined(threadContext) && Utils.isDefined(context)) {
            threadContext = new ThreadContext(tid);
            threadContext.context = context;
            Dwarf.threadContexts[tid] = threadContext;
        }

        if (Utils.isDefined(condition)) {
            if (typeof condition === "string") {
                condition = new Function(condition);
            }

            if (!condition.call(threadContext)) {
                delete Dwarf.threadContexts[tid];
                return;
            }
        }

        if (!Utils.isDefined(threadContext) || !threadContext.preventSleep) {
            if (Dwarf.DEBUG) {
                Utils.logDebug('[' + tid + '] break ' + address_or_class + ' - dispatching context info');
            }

            Dwarf.dispatchContextInfo(reason, address_or_class, context);

            if (Dwarf.DEBUG) {
                Utils.logDebug('[' + tid + '] break ' + address_or_class + ' - sleeping context. goodnight!');
            }

            LogicBreakpoint.loopApi(threadContext);

            if (Dwarf.DEBUG) {
                Utils.logDebug('[' + tid + '] ThreadContext has been released');
            }

            Dwarf.loggedSend('release:::' + tid + ':::' + reason);
        }
    }

    private static loopApi(that) {
        const tid = Process.getCurrentThreadId();

        if (Dwarf.DEBUG) {
            Utils.logDebug('[' + tid + '] looping api');
        }

        const op = recv('' + tid, function () {
        });
        op.wait();

        const threadContext: ThreadContext = Dwarf.threadContexts[tid];

        if (Utils.isDefined(threadContext)) {
            while (threadContext.apiQueue.length === 0) {
                if (Dwarf.DEBUG) {
                    Utils.logDebug('[' + tid + '] waiting api queue to be populated');
                }
                Thread.sleep(0.2);
            }

            let release = false;

            while (threadContext.apiQueue.length > 0) {
                const threadApi: ThreadApi = threadContext.apiQueue.shift();
                if (Dwarf.DEBUG) {
                    Utils.logDebug('[' + tid + '] executing ' + threadApi.apiFunction);
                }
                try {
                    if (Utils.isDefined(Api[threadApi.apiFunction])) {
                        threadApi.result = Api[threadApi.apiFunction].apply(that, threadApi.apiArguments);
                    } else {
                        threadApi.result = null;
                    }
                } catch (e) {
                    threadApi.result = null;
                    if (Dwarf.DEBUG) {
                        Utils.logDebug('[' + tid + '] error executing ' +
                            threadApi.apiFunction + ':\n' + e);
                    }
                }
                threadApi.consumed = true;

                let stalkerInfo = LogicStalker.stalkerInfoMap[tid];
                if (threadApi.apiFunction === '_step') {
                    if (!Utils.isDefined(stalkerInfo)) {
                        LogicStalker.stalk(tid);
                    }
                    release = true;
                    break
                } else if (threadApi.apiFunction === 'release') {
                    if (Utils.isDefined(stalkerInfo)) {
                        stalkerInfo.terminated = true;
                    }

                    release = true;
                    break;
                }
            }

            if (!release) {
                LogicBreakpoint.loopApi(that);
            }
        }
    }

    static putBreakpoint(target: any, condition?: string | Function): boolean {
        if (typeof target === 'string') {
            if (target.startsWith('0x')) {
                target = ptr(target);
            } else if (target.indexOf('.') >= 0 && LogicJava.available) {
                const added = LogicJava.putBreakpoint(target, condition);
                if (added) {
                    Dwarf.loggedSend('breakpoint_java_callback:::' + target + ':::' +
                        (Utils.isDefined(condition) ? condition.toString() : ''));
                }
                return added;
            } else if (target.indexOf('.') >= 0 && LogicObjC.available) {
                const added = LogicObjC.putBreakpoint(target, condition);
                if (added) {
                    Dwarf.loggedSend('breakpoint_objc_callback:::' + target + ':::' +
                        (Utils.isDefined(condition) ? condition.toString() : ''));
                }
                return added;
            }
        } else if (typeof target === 'number') {
            target = ptr(target)
        }

        if (Utils.isDefined(LogicBreakpoint.breakpoints[target.toString()])) {
            console.log(target + ' already has a breakpoint');
            return false;
        }

        if (target.constructor.name === 'NativePointer') {
            target = target as NativePointer;
            const breakpoint = new Breakpoint(target);

            if (!Utils.isDefined(condition)) {
                condition = null;
            }
            breakpoint.condition = condition;

            LogicBreakpoint.breakpoints[target.toString()] = breakpoint;
            LogicBreakpoint.putNativeBreakpoint(breakpoint);

            Dwarf.loggedSend('breakpoint_native_callback:::' + breakpoint.target.toString() + ':::' +
                (Utils.isDefined(breakpoint.condition) ? breakpoint.condition.toString() : ''));

            return true;
        }

        return false;
    }

    private static putNativeBreakpoint(breakpoint: Breakpoint): boolean {
        breakpoint.interceptor = Interceptor.attach(breakpoint.target as NativePointer, function () {
            breakpoint.interceptor.detach();
            Interceptor['flush']();

            LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, this.context.pc,
                this.context, null, breakpoint.condition);

            if (typeof LogicBreakpoint.breakpoints[breakpoint.target.toString()] !== 'undefined') {
                LogicBreakpoint.putNativeBreakpoint(breakpoint);
            }
        });
        return true;
    }

    static removeBreakpoint(target: any): boolean {
        if (typeof target === 'string') {
            if (target.startsWith('0x')) {
                target = ptr(target);
            } else if (target.indexOf('.') >= 0 && LogicJava.available) {
                const removed = LogicJava.removeBreakpoint(target);
                if (removed) {
                    Dwarf.loggedSend('breakpoint_deleted:::java:::' + target);
                }
                return removed;
            } else if (target.indexOf('.') >= 0 && LogicObjC.available) {
                const removed = LogicObjC.removeBreakpoint(target);
                if (removed) {
                    Dwarf.loggedSend('breakpoint_deleted:::objc:::' + target);
                }
                return removed;
            }
        } else if (typeof target === 'number') {
            target = ptr(target)
        }

        let breakpoint = LogicBreakpoint.breakpoints[target.toString()];
        console.log(breakpoint.interceptor);
        if (Utils.isDefined(breakpoint)) {
            if (Utils.isDefined(breakpoint.interceptor)) {
                breakpoint.interceptor.detach();
            }
            delete LogicBreakpoint.breakpoints[target.toString()];

            Dwarf.loggedSend('breakpoint_deleted:::native:::' + target.toString());

            return true;
        }
        return false;
    }

    static setBreakpointCondition(target: any, condition?: string | Function): boolean {
        if (typeof target === 'string') {
            if (target.startsWith('0x')) {
                target = ptr(target);
            }
        } else if (typeof target === 'number') {
            target = ptr(target)
        }

        const breakpoint: Breakpoint = LogicBreakpoint.breakpoints[target.toString()];
        if (!Utils.isDefined(breakpoint)) {
            console.log(target + ' is not in breakpoint list');
            return false;
        }

        breakpoint.condition = condition;
        return true;
    }
}
