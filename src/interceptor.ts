import {Utils} from "./utils";
import {Dwarf} from "./dwarf";
import {ThreadContext} from "./thread_context";

export class DwarfInterceptor {

    private static onAttach(context) {
        const tid = Process.getCurrentThreadId();
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

        const threadContext = new ThreadContext(tid);
        threadContext.context = context;
        Dwarf.threadContexts[tid] = threadContext;
    }

    private static onDetach() {
        const tid = Process.getCurrentThreadId();
        delete Dwarf.threadContexts[tid];
    }

    static init() {
        const clone = Object.assign({}, Interceptor);
        clone.attach = function attach(target: NativePointer, callbacks): InvocationListener {
            target.readU8();
            let replacement;
            if (typeof callbacks === 'function') {
                replacement = function () {
                    DwarfInterceptor.onAttach(this.context);
                    const ret = callbacks.apply(this, arguments);
                    DwarfInterceptor.onDetach();
                    return ret;
                };
            } else if (typeof callbacks === 'object') {
                if (Utils.isDefined(callbacks['onEnter'])) {
                    replacement = {
                        onEnter: function () {
                            DwarfInterceptor.onAttach(this.context);
                            const ret = callbacks['onEnter'].apply(this, arguments);
                            DwarfInterceptor.onDetach();
                            return ret;
                        }
                    };

                    if (Utils.isDefined(callbacks['onLeave'])) {
                        replacement['onLeave'] = callbacks['onLeave'];
                    }
                } else {
                    replacement = callbacks;
                }
            }
            return Interceptor['_attach'](target, replacement);
        };
        global['Interceptor'] = clone;
    }
}