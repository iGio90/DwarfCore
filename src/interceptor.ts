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

import { DwarfCore } from "./DwarfCore";
import { ThreadContext } from "./thread_context";

/** @internal */

/*export class DwarfInterceptor {

    private static onAttach(context) {
        const tid = Process.getCurrentThreadId();
        const that = {};
        let proxiedContext = null;

        if (context !== null) {
            proxiedContext = new Proxy(context, {
                get (target, prop, receiver) {
                    return Reflect.get(target, prop, receiver);
                },
                set (target, prop, value, receiver) {
                    logDebug("[" + tid + "] setting context " + prop.toString() + ": " + value);

                    DwarfCore.getInstance().sync({context:})
                    target[prop] = value;
                    return true;
                },
            });
        }

        // TODO: ???
        // that["context"] = proxiedContext;

        const threadContext = new ThreadContext(tid);
        threadContext.context = context;
        DwarfCore.getInstance().addThreadContext(tid, threadContext);
    }

    private static onDetach() {
        DwarfCore.getInstance().deleteThreadContext(Process.getCurrentThreadId());
    }

    static init() {
        const clone = Object.assign({ realAttach: null }, Interceptor);
        clone.realAttach = clone.attach;

        clone.attach = function (
            target: NativePointerValue,
            callbacksOrProbe: InvocationListenerCallbacks | InstructionProbeCallback,
            data?: NativePointerValue
        ): InvocationListener {
            if (target.hasOwnProperty("handle")) {
                (target as ObjectWrapper).handle.readU8();
            } else {
                (target as NativePointer).readU8();
            }
            let replacement;
            if (typeof callbacksOrProbe === "function") {
                replacement = function () {
                    DwarfInterceptor.onAttach(this.context);
                    const ret = callbacksOrProbe.apply(this, arguments);
                    DwarfInterceptor.onDetach();
                    return ret;
                };
            } else if (typeof callbacksOrProbe === "object") {
                if (isDefined(callbacksOrProbe.onEnter)) {
                    replacement = {
                        onEnter () {
                            DwarfInterceptor.onAttach(this.context);
                            const ret = (callbacksOrProbe as ScriptInvocationListenerCallbacks).onEnter.apply(this, arguments);
                            DwarfInterceptor.onDetach();
                            return ret;
                        },
                    };

                    if (isDefined(callbacksOrProbe.onLeave)) {
                        replacement.onLeave = callbacksOrProbe.onLeave;
                    }
                } else {
                    replacement = callbacksOrProbe;
                }
            }
            if (typeof replacement === "undefined") {
                throw new Error("Error: replacement");
            }
            return clone.realAttach(target, replacement, data);
        };
        global.Interceptor = clone;
    }
}
*/