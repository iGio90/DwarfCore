import {Api} from "./api";
import {Breakpoint} from "./breakpoint";
import {Dwarf} from "./dwarf";
import {ThreadContext} from "./thread_context";
import {Utils} from "./utils";
import {LogicStalker} from "./logic_stalker";
import {ThreadApi} from "./thread_api";
import {LogicJava} from "./logic_java";
import isDefined = Utils.isDefined;

export class LogicBreakpoint {
    static REASON_SET_INITIAL_CONTEXT = -1;
    static REASON_BREAKPOINT = 0;
    static REASON_WATCHPOINT = 1;
    static REASON_BREAKPOINT_INITIALIZATION = 2;
    static REASON_STEP = 3;

    static breakpoints = {};

    static breakpoint(reason, address_or_class, context, java_handle?, condition?) {
        const tid = Process.getCurrentThreadId();

        if (Utils.isDefined(Dwarf.threadContexts[tid])) {
            console.log('thread ' + tid + ' is already break');
            return;
        }

        if (!Utils.isDefined(reason)) {
            reason = LogicBreakpoint.REASON_BREAKPOINT;
        }

        if (Dwarf.DEBUG) {
            Utils.logDebug('[' + tid + '] breakpoint ' + address_or_class + ' - reason: ' + reason);
        }

        const that = {};
        let proxiedContext = null;

        if (context !== null) {
            proxiedContext = new Proxy(context, {
                get: function (object, prop) {
                    return object[prop];
                },
                set: function (object, prop, value) {
                    if (Dwarf.DEBUG) {
                        Utils.logDebug('[' + tid + '] setting context ' + prop.toString() + ': ' + value);
                    }
                    send('set_context_value:::' + prop.toString() + ':::' + value);
                    object[prop] = value;
                    return true;
                }
            });
        }

        that['context'] = proxiedContext;
        that['handle'] = java_handle;

        if (Dwarf.DEBUG) {
            Utils.logDebug('[' + tid + '] break ' + address_or_class + ' - creating dwarf context');
        }

        const threadContext = new ThreadContext(tid);
        threadContext.context = context;
        threadContext.javaHandle = java_handle;
        Dwarf.threadContexts[tid] = threadContext;

        if (Utils.isDefined(condition)) {
            if (typeof condition === "string") {
                condition = new Function(condition);
            }

            if (!condition.call(that)) {
                delete Dwarf.threadContexts[tid];
                return;
            }
        }

        if (!threadContext.preventSleep) {
            if (Dwarf.DEBUG) {
                Utils.logDebug('[' + tid + '] break ' + address_or_class + ' - dispatching context info');
            }

            Dwarf.dispatchContextInfo(reason, address_or_class, context);

            if (Dwarf.DEBUG) {
                Utils.logDebug('[' + tid + '] break ' + address_or_class + ' - sleeping context. goodnight!');
            }

            LogicBreakpoint.loopApi(that);

            if (Dwarf.DEBUG) {
                Utils.logDebug('[' + tid + '] ThreadContext has been released');
            }

            Dwarf.loggedSend('release:::' + tid + ':::' + reason);
        }

        delete Dwarf.threadContexts[tid];
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

        if (isDefined(threadContext)) {
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

                if (threadApi.apiFunction === '_step') {
                    release = true;
                    break
                } else if (threadApi.apiFunction === 'release') {
                    const stalkerInfo = LogicStalker.stalkerInfoMap[tid];
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
        const interceptor = Interceptor.attach(breakpoint.target as NativePointer, function () {
            interceptor.detach();
            Interceptor['flush']();

            breakpoint.interceptor = interceptor;

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
            }
        } else if (typeof target === 'number') {
            target = ptr(target)
        }

        let breakpoint = LogicBreakpoint.breakpoints[target.toString()];
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