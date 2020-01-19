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


import { Breakpoint } from "./breakpoints";
import { LogicBreakpoint } from "./logic_breakpoint";
import { DwarfHaltReason } from "./consts";
import { DwarfCore } from "./dwarf";


export class LogicObjC {
    static available = ObjC.available;
    static breakpoints = {};
    static objcClasses = [];
    static objcClassLoaderCallbacks = {};
    static objcContexts = {};
    static objcHandles = {};
    static tracedClasses = [];
    static tracing = false;
    static sdk = 0;

    private static applyTracerImplementation(attach, callback?) {
        /*ObjC.performNow(() => {
            LogicObjC.tracedClasses.forEach((className) => {
                try {
                    const clazz = ObjC.use(className);

                    const overloadCount = clazz["$init"].overloads.length;
                    if (overloadCount > 0) {
                        for (let i = 0; i < overloadCount; i++) {
                            if (attach) {
                                clazz["$init"].overloads[i].implementation =
                                    LogicObjC.traceImplementation(callback, className, '$init');
                            } else {
                                clazz["$init"].overloads[i].implementation = null;
                            }
                        }
                    }

                    let methods = clazz.class.getDeclaredMethods();
                    const parsedMethods = [];
                    methods.forEach(function (method) {
                        parsedMethods.push(method.toString().replace(className + ".",
                            "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
                    });
                    methods = uniqueBy(parsedMethods);
                    methods.forEach((method) => {
                        const overloadCount = clazz[method].overloads.length;
                        if (overloadCount > 0) {
                            for (let i = 0; i < overloadCount; i++) {
                                if (attach) {
                                    clazz[method].overloads[i].implementation =
                                        LogicObjC.traceImplementation(callback, className, method);
                                } else {
                                    clazz[method].overloads[i].implementation = null;
                                }
                            }
                        }
                    });

                    clazz.$dispose();
                } catch (e) {
                    logErr('LogicObjC.startTrace', e);
                }
            });
        });*/
        Dwarf.loggedSend('Not implemented');
    };

    static backtrace() {
        /*return ObjC.use("android.util.Log")
            .getStackTraceString(ObjC.use("objc.lang.Exception").$new());*/
        Dwarf.loggedSend('Not implemented');
    }

    static getApplicationContext() {
        /*if (!LogicObjC.available) {
            return;
        }

        const ActivityThread = ObjC.use('android.app.ActivityThread');
        const Context = ObjC.use('android.content.Context');

        const context = ObjC.cast(ActivityThread.currentApplication().getApplicationContext(), Context);

        ActivityThread.$dispose();
        Context.$dispose();

        return context;*/
        Dwarf.loggedSend('Not implemented');
    };

    static hookAllObjCMethods(className, implementation): boolean {
        /*if (!ObjC.available) {
            return false;
        }

        if (!isDefined(className)) {
            return false;
        }

        const that = this;

        ObjC.performNow(function () {
            const clazz = ObjC.use(className);
            const methods = clazz.class.getDeclaredMethods();

            const parsedMethods = [];
            methods.forEach(function (method) {
                parsedMethods.push(method.toString().replace(className + ".",
                    "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
            });
            const result = uniqueBy(parsedMethods);
            result.forEach(method => {
                LogicObjC.hook(className, method, implementation);
            });
            clazz.$dispose();
        });
        return true;*/
        Dwarf.loggedSend('Not implemented');
        return false;
    }

    static hookClassLoaderClassInitialization(clazz: string, callback?: Function): boolean {
        /*if (!isString(clazz) || isDefined(LogicObjC.objcClassLoaderCallbacks[clazz])) {
            return false;
        }

        LogicObjC.objcClassLoaderCallbacks[clazz] = callback;
        return true;*/
        Dwarf.loggedSend('Not implemented');
        return false;
    }

    static hook(className, method, implementation): boolean {
        if (!LogicObjC.available) {
            return false;
        }

        let handler = ObjC.classes[className];

        try {
            handler = ObjC.classes[className];
        } catch (err) {

            logErr('LogicObjC.hook', err);
            if (handler === null) {
                return;
            }
        }

        try {
            if (handler == null || typeof handler[method] === 'undefined') {
                return;
            }
        } catch (e) {
            // catching here not supported overload error from frida
            logErr('LogicObjC.hook', e);
            return;
        }

        const overloadCount = handler[method].overloads.length;
        if (overloadCount > 0) {
            for (let i = 0; i < overloadCount; i++) {
                const overload = handler[method].overloads[i];
                if (isDefined(implementation)) {
                    overload.implementation = function () {
                        LogicObjC.objcContexts[Process.getCurrentThreadId()] = this;
                        this.className = className;
                        this.method = method;
                        this.overload = overload;
                        const ret = implementation.apply(this, arguments);
                        if (typeof ret !== 'undefined') {
                            return ret;
                        }
                        delete LogicObjC.objcContexts[Process.getCurrentThreadId()];
                        return this.overload.apply(this, arguments);
                    };
                } else {
                    overload.implementation = implementation;
                }
            }
        }
        return true;
    };

    static hookObjCMethod(targetClassMethod, implementation): boolean {
        if (isDefined(targetClassMethod)) {
            const delim = targetClassMethod.indexOf(".");
            if (delim === -1) {
                return false;
            }

            const targetClass = targetClassMethod.slice(0, delim);
            const targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);
            LogicObjC.hook(targetClass, targetMethod, implementation);
            return true;
        }
        return false;
    }

    static init(breakAtStart:boolean = false) {
        /*
            LogicObjC.sdk = ObjC.use('android.os.Build$VERSION')['SDK_INT']['value'];
            if (Dwarf.DEBUG) {
                logDebug('[' + Process.getCurrentThreadId() + '] ' +
                    'initializing logicObjC with sdk: ' + LogicObjC.sdk);
            }

            if (DwarfCore.getInstance().getProcessInfo().wasSpawned && breakAtStart) {
                if (LogicObjC.sdk >= 23) {
                    // attach to commonInit for init debugging
                    LogicObjC.hook('com.android.internal.os.RuntimeInit',
                        'commonInit', function () {
                            LogicObjC.jvmBreakpoint.call(this, 'com.android.internal.os.RuntimeInit',
                            'commonInit', arguments, this.overload.argumentTypes)
                    });
                } else {
                    LogicObjC.hook('android.app.Application', 'onCreate',
                        function () {
                            LogicObjC.jvmBreakpoint.call(this, 'android.app.Application',
                                'onCreate', arguments, this.overload.argumentTypes)
                        });
                }
            }

            // attach to ClassLoader to notify for new loaded class
            const handler = ObjC.use('objc.lang.ClassLoader');
            const overload = handler.loadClass.overload('objc.lang.String', 'boolean');
            overload.implementation = function(clazz, resolve) {
                if (LogicObjC.objcClasses.indexOf(clazz) === -1) {
                    LogicObjC.objcClasses.push(clazz);
                    Dwarf.loggedSend('class_loader_loading_class:::' + Process.getCurrentThreadId() + ':::' + clazz);

                    const userCallback = LogicObjC.objcClassLoaderCallbacks[clazz];
                    if (typeof userCallback !== 'undefined') {
                        if (userCallback !== null) {
                            userCallback.call(this);
                        } else {
                            Dwarf.loggedSend("objc_class_initialization_callback:::" + clazz + ':::' + Process.getCurrentThreadId());
                            LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, clazz, {}, this);
                        }
                    }
                }
                return overload.call(this, clazz, resolve);
            };
        });*/
        Dwarf.loggedSend('Not implemented');
    };

    static jvmBreakpoint(className, method, args, types, condition?) {
        /*const classMethod = className + '.' + method;
        const newArgs = {};
        for (let i = 0; i < args.length; i++) {
            let value = '';
            if (args[i] === null || typeof args[i] === 'undefined') {
                value = 'null';
            } else {
                if (typeof args[i] === 'object') {
                    value = JSON.stringify(args[i]);
                    if (types[i]['className'] === '[B') {
                        value += ' (' + ObjC.use('objc.lang.String').$new(args[i]) + ")";
                    }
                } else {
                    value = args[i].toString();
                }
            }
            newArgs[i] = {
                arg: value,
                name: types[i]['name'],
                handle: args[i],
                className: types[i]['className'],
            }
        }

        LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, classMethod, newArgs, this, condition);*/
        Dwarf.loggedSend('Not implemented');
    };

    static jvmExplorer(what?: any) {
        /*let handle;
        if (typeof what === 'undefined') {
            // flush handles
            LogicObjC.objcHandles = {};

            handle = LogicObjC.objcContexts[Process.getCurrentThreadId()];
            if (!isDefined(handle)) {
                console.log('jvm explorer outside context scope');
                return null;
            }
        } else if (typeof what === 'object') {
            if (typeof what['handle_class'] !== 'undefined') {
                const cl = ObjC.use(what['handle_class']);
                handle = what['handle'];
                if (typeof handle === 'string') {
                    handle = LogicObjC.objcHandles[handle];
                    if (typeof handle === 'undefined') {
                        return null;
                    }
                } else if (typeof handle === 'object') {
                    try {
                        handle = ObjC.cast(ptr(handle['$handle']), cl);
                    } catch (e) {
                        logErr('jvmExplorer', e + ' | ' + handle['$handle']);
                        return null;
                    }
                } else {
                    try {
                        handle = ObjC.cast(ptr(handle), cl);
                    } catch (e) {
                        logErr('jvmExplorer', e + ' | ' + handle);
                        return null;
                    }
                }
                cl.$dispose();
            } else {
                handle = what;
            }
        } else {
            console.log('Explorer handle not found');
            return {};
        }
        if (handle === null || typeof handle === 'undefined') {
            console.log('Explorer handle null');
            return {};
        }
        let ol;
        try {
            ol = Object.getOwnPropertyNames(handle.__proto__);
        } catch (e) {
            logErr('jvmExplorer-1', e);
            return null;
        }
        let clazz = '';
        if (typeof handle['$className'] !== 'undefined') {
            clazz = handle['$className'];
        }
        const ret = {
            'class': clazz,
            'data': {}
        };
        for (const o in ol) {
            const name = ol[o];
            try {
                const overloads = [];
                let t = typeof handle[name];
                let value = '';
                let sub_handle = null;
                let sub_handle_class = '';

                if (t === 'function') {
                    if (typeof handle[name].overloads !== 'undefined') {
                        const overloadCount = handle[name].overloads.length;
                        if (overloadCount > 0) {
                            for (const i in handle[name].overloads) {
                                overloads.push({
                                    'args': handle[name].overloads[i].argumentTypes,
                                    'return': handle[name].overloads[i].returnType
                                });
                            }
                        }
                    }
                } else if (t === 'object') {
                    if (handle[name] !== null) {
                        sub_handle_class = handle[name]['$className'];
                    }

                    if (typeof handle[name]['$handle'] !== 'undefined' && handle[name]['$handle'] !== null) {
                        value = handle[name]['$handle'];
                        sub_handle = handle[name]['$handle'];
                    } else {
                        if (handle[name] !== null && handle[name]['value'] !== null) {
                            sub_handle_class = handle[name]['value']['$className'];
                        }

                        if (handle[name] !== null && handle[name]['value'] !== null &&
                            typeof handle[name]['value'] === 'object') {
                            if (typeof handle[name]['fieldReturnType'] !== 'undefined') {
                                sub_handle = handle[name]['value'];
                                if (typeof sub_handle['$handle'] !== 'undefined') {
                                    const pt = sub_handle['$handle'];
                                    LogicObjC.objcHandles[pt] = sub_handle;
                                    sub_handle = pt;
                                    value = handle[name]['fieldReturnType']['className'];
                                    sub_handle_class = value;
                                } else {
                                    t = handle[name]['fieldReturnType']['type'];
                                    sub_handle_class = handle[name]['fieldReturnType']['className'];

                                    if (handle[name]['fieldReturnType']['type'] !== 'pointer') {
                                        value = sub_handle_class;
                                    } else {
                                        if (handle[name]['value'] !== null) {
                                            value = handle[name]['value'].toString();
                                            t = typeof (value);
                                        }
                                    }
                                }
                            } else if (handle[name]['value'] !== null) {
                                value = handle[name]['value'].toString();
                                t = typeof (value);
                            }
                        } else if (handle[name]['value'] !== null) {
                            t = typeof (handle[name]['value']);
                            value = handle[name]['value'].toString();
                        }
                    }
                } else {
                    value = handle[name];
                }

                ret['data'][name] = {
                    'value': value,
                    'handle': sub_handle,
                    'handle_class': sub_handle_class,
                    'type': t,
                    'overloads': overloads
                };
            } catch (e) {
                logErr('jvmExplorer-2', e);
            }
        }
        return ret;*/
        Dwarf.loggedSend('Not implemented');
    }

    static putBreakpoint(target: string, condition?: string | Function): boolean {
        if (!isString(target) || isDefined(LogicObjC.breakpoints[target])) {
            return false;
        }

        const parts = target.split('.');
        const targetAddress = ptr(ObjC.classes[parts[0]][parts[1]].implementation.toString());
        const breakpoint = new Breakpoint(targetAddress);

        if (!isDefined(condition)) {
            condition = null;
        }
        breakpoint.condition = condition;

        LogicObjC.breakpoints[target] = breakpoint;
        return LogicObjC.putObjCBreakpoint(breakpoint, target);
    }

    private static putObjCBreakpoint(breakpoint: Breakpoint, target: string): boolean {
        breakpoint.interceptor = Interceptor.attach(breakpoint.target as NativePointer, function () {
            breakpoint.interceptor.detach();
            Interceptor['flush']();

            DwarfCore.getInstance().onBreakpoint(0, Process.getCurrentThreadId(), DwarfHaltReason.BREAKPOINT, this.context.pc,
                this.context, null, breakpoint.condition as Function);

            if (typeof LogicObjC.breakpoints[target] !== 'undefined') {
                LogicObjC.putObjCBreakpoint(breakpoint, target);
            }
        });
        return true;
    }

    static putObjCClassInitializationBreakpoint(className: string): boolean {
        /*const applied = LogicObjC.hookClassLoaderClassInitialization(className, null);
        if (applied) {
            Dwarf.loggedSend('objc_class_initialization_callback:::' + className);
        }
        return applied;*/
        Dwarf.loggedSend('Not implemented');
        return false;
    }

    static removeBreakpoint(target: string): boolean {
        if (!isString(target)) {
            return false;
        }

        let breakpoint: Breakpoint = LogicObjC.breakpoints[target];
        if (isDefined(breakpoint)) {
            breakpoint.interceptor.detach();
            delete LogicObjC.breakpoints[target.toString()];
            //LogicObjC.hookObjCMethod(target, null);
            return true;
        }

        return false;
    }

    static removeModuleInitializationBreakpoint(clazz: string) {
        /*if (typeof LogicObjC.objcClassLoaderCallbacks[clazz] !== 'undefined') {
            delete LogicObjC.objcClassLoaderCallbacks[clazz];
            return true;
        }

        return false;*/
        Dwarf.loggedSend('Not implemented');
    }

    static restartApplication(): boolean {
        /*if (!LogicObjC.available) {
            return false;
        }

        ObjC.performNow(function () {
            const Intent = ObjC.use('android.content.Intent');
            const ctx = LogicObjC.getApplicationContext();
            const intent = ctx.getPackageManager().getLaunchIntentForPackage(ctx.getPackageName());
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP['value']);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK['value']);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK['value']);
            ctx.startActivity(intent);
        });
        return true;*/
        Dwarf.loggedSend('Not implemented');
        return false;
    }

    static startTrace(classes, callback): boolean {
        /*if (!LogicObjC.available || LogicObjC.tracing) {
            return false;
        }

        LogicObjC.tracing = true;
        LogicObjC.tracedClasses = classes;
        LogicObjC.applyTracerImplementation(true, callback);

        return true;*/
        Dwarf.loggedSend('Not implemented');
        return false;
    };

    static stopTrace(): boolean {
        /*if (!LogicObjC.available || !LogicObjC.tracing) {
            return false;
        }

        LogicObjC.tracing = false;
        LogicObjC.applyTracerImplementation(true);

        return true;*/
        Dwarf.loggedSend('Not implemented');
        return false;
    };

    static traceImplementation(callback, className, method) {
        /*return function () {
            const uiCallback = !isDefined(callback);
            const classMethod = className + '.' + method;

            if (uiCallback) {
                Dwarf.loggedSend('objc_trace:::enter:::' + classMethod + ':::' + JSON.stringify(arguments));
            } else {
                if (isDefined(callback['onEnter'])) {
                    callback['onEnter'](arguments);
                }
            }

            let ret = this[method].apply(this, arguments);

            if (uiCallback) {
                let traceRet = ret;
                if (typeof traceRet === 'object') {
                    traceRet = JSON.stringify(ret);
                } else if (typeof traceRet === 'undefined') {
                    traceRet = "";
                }
                Dwarf.loggedSend('objc_trace:::leave:::' + classMethod + ':::' + traceRet);
            } else {
                if (isDefined(callback['onLeave'])) {
                    let tempRet = callback['onLeave'](ret);
                    if (typeof tempRet !== 'undefined') {
                        ret = tempRet;
                    }
                }
            }
            return ret;
        }*/
        Dwarf.loggedSend('Not implemented');
    }
}
