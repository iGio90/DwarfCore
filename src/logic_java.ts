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


import { Breakpoint } from "./breakpoint";
import { Dwarf } from "./dwarf";
import { LogicBreakpoint } from "./logic_breakpoint";
import { Utils } from "./utils";
import isDefined = Utils.isDefined;

export class LogicJava {
    static available = Java.available;
    static breakpoints = {};
    static javaClasses = [];
    static javaClassLoaderCallbacks = {};
    static javaContexts = {};
    static javaHandles = {};
    static tracedClasses = [];
    static tracing = false;
    static tracerDepth = 1;
    static sdk = 0;

    private static applyTracerImplementationAtClass(className, attach, callback?) {
        try {
            const clazz = Java.use(className);

            const overloadCount = clazz["$init"].overloads.length;
            if (overloadCount > 0) {
                for (let i = 0; i < overloadCount; i++) {
                    if (attach) {
                        clazz["$init"].overloads[i].implementation =
                            LogicJava.traceImplementation(callback, className, '$init');
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
            methods = Utils.uniqueBy(parsedMethods);
            methods.forEach((method) => {
                const overloadCount = clazz[method].overloads.length;
                if (overloadCount > 0) {
                    for (let i = 0; i < overloadCount; i++) {
                        if (attach) {
                            clazz[method].overloads[i].implementation =
                                LogicJava.traceImplementation(callback, className, method);
                        } else {
                            clazz[method].overloads[i].implementation = null;
                        }
                    }
                }
            });

            clazz.$dispose();
        } catch (e) {
            if (e.toString().indexOf('ClassNotFoundException') >= 0) {
                LogicJava.hookClassLoaderClassInitialization(className, function (clazz) {
                    LogicJava.applyTracerImplementationAtClass(clazz, attach, callback);
                });
            } else if (e.toString().indexOf('no supported overloads') < 0) {
                Utils.logErr('LogicJava.startTrace', e);
            }
        }
    }

    private static applyTracerImplementation(attach, callback?) {
        Java.performNow(() => {
            LogicJava.tracedClasses.forEach((className) => {
                LogicJava.applyTracerImplementationAtClass(className, attach, callback);
            });
        });
    };

    static backtrace() {
        return Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
    }

    static getApplicationContext() {
        if (!LogicJava.available) {
            return;
        }

        const ActivityThread = Java.use('android.app.ActivityThread');
        const Context = Java.use('android.content.Context');

        const context = Java.cast(ActivityThread.currentApplication().getApplicationContext(), Context);

        ActivityThread.$dispose();
        Context.$dispose();

        return context;
    };

    static hook(className, method, implementation): boolean {
        if (!LogicJava.available) {
            return false;
        }

        let result = false;
        Java.performNow(function () {
            result = LogicJava.hookInJVM(className, method, implementation);
        });

        return result;
    };

    static hookAllJavaMethods(className, implementation): boolean {
        if (!Java.available) {
            return false;
        }

        if (!Utils.isDefined(className)) {
            return false;
        }

        const that = this;

        Java.performNow(function () {
            const clazz = Java.use(className);
            const methods = clazz.class.getDeclaredMethods();

            const parsedMethods = [];
            methods.forEach(function (method) {
                parsedMethods.push(method.toString().replace(className + ".",
                    "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
            });
            const result = Utils.uniqueBy(parsedMethods);
            result.forEach(method => {
                LogicJava.hookInJVM(className, method, implementation);
            });
            clazz.$dispose();
        });
        return true;
    }

    static hookClassLoaderClassInitialization(clazz: string, callback?: Function): boolean {
        if (!Utils.isString(clazz) || Utils.isDefined(LogicJava.javaClassLoaderCallbacks[clazz])) {
            return false;
        }

        LogicJava.javaClassLoaderCallbacks[clazz] = callback;
        return true;
    }

    static hookInJVM(className, method, implementation) {
        let handler = null;

        try {
            handler = Java.use(className);
        } catch (err) {
            try {
                className = className + '.' + method;
                method = '$init';
                handler = Java.use(className);
            } catch (err) {
                return false;
            }

            Utils.logErr('LogicJava.hook', err);
            if (handler === null) {
                return false;
            }
        }

        try {
            if (handler == null || typeof handler[method] === 'undefined') {
                return false;
            }
        } catch (e) {
            // catching here not supported overload error from frida
            Utils.logErr('LogicJava.hook', e);
            return false;
        }

        const overloadCount = handler[method].overloads.length;
        if (overloadCount > 0) {
            for (let i = 0; i < overloadCount; i++) {
                const overload = handler[method].overloads[i];
                if (Utils.isDefined(implementation)) {
                    overload.implementation = function () {
                        LogicJava.javaContexts[Process.getCurrentThreadId()] = this;
                        this.className = className;
                        this.method = method;
                        this.overload = overload;
                        const ret = implementation.apply(this, arguments);
                        if (typeof ret !== 'undefined') {
                            return ret;
                        }
                        delete LogicJava.javaContexts[Process.getCurrentThreadId()];
                        return this.overload.apply(this, arguments);
                    };
                } else {
                    overload.implementation = implementation;
                }
            }
        }

        handler.$dispose();
        return true
    };

    static hookJavaMethod(targetClassMethod, implementation): boolean {
        if (Utils.isDefined(targetClassMethod)) {
            const delim = targetClassMethod.lastIndexOf(".");
            if (delim === -1) {
                return false;
            }

            const targetClass = targetClassMethod.slice(0, delim);
            const targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);
            return LogicJava.hook(targetClass, targetMethod, implementation);
        }
        return false;
    }

    static init() {
        Java.performNow(function () {
            LogicJava.sdk = Java.use('android.os.Build$VERSION')['SDK_INT']['value'];
            if (Dwarf.DEBUG) {
                Utils.logDebug('[' + Process.getCurrentThreadId() + '] ' +
                    'initializing logicJava with sdk: ' + LogicJava.sdk);
            }

            if (Dwarf.SPAWNED && Dwarf.BREAK_START) {
                if (LogicJava.sdk >= 23) {
                    // attach to commonInit for init debugging
                    LogicJava.hookInJVM('com.android.internal.os.RuntimeInit',
                        'commonInit', function () {
                            LogicJava.jvmBreakpoint.call(this, 'com.android.internal.os.RuntimeInit',
                                'commonInit', arguments, this.overload.argumentTypes)
                        });
                } else {
                    LogicJava.hookInJVM('android.app.Application', 'onCreate',
                        function () {
                            LogicJava.jvmBreakpoint.call(this, 'android.app.Application',
                                'onCreate', arguments, this.overload.argumentTypes)
                        });
                }
            }

            // attach to ClassLoader to notify for new loaded class
            const handler = Java.use('java.lang.ClassLoader');
            const overload = handler.loadClass.overload('java.lang.String', 'boolean');
            overload.implementation = function (clazz, resolve) {
                if (LogicJava.javaClasses.indexOf(clazz) === -1) {
                    LogicJava.javaClasses.push(clazz);
                    Dwarf.loggedSend('class_loader_loading_class:::' + Process.getCurrentThreadId() + ':::' + clazz);

                    const userCallback = LogicJava.javaClassLoaderCallbacks[clazz];
                    if (typeof userCallback !== 'undefined') {
                        if (userCallback !== null) {
                            userCallback.call(this, clazz);
                        } else {
                            Dwarf.loggedSend("java_class_initialization_callback:::" + clazz + ':::' + Process.getCurrentThreadId());
                            LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, clazz, {}, this);
                        }
                    }
                }
                return overload.call(this, clazz, resolve);
            };
        });
    };

    static jvmBreakpoint(className, method, args, types, condition?) {
        const classMethod = className + '.' + method;
        const newArgs = {};
        for (let i = 0; i < args.length; i++) {
            let value = '';
            if (args[i] === null || typeof args[i] === 'undefined') {
                value = 'null';
            } else {
                if (typeof args[i] === 'object') {
                    value = JSON.stringify(args[i]);
                    if (types[i]['className'] === '[B') {
                        value += ' (' + Java.use('java.lang.String').$new(args[i]) + ")";
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

        LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_BREAKPOINT, classMethod, newArgs, this, condition);
    };

    static jvmExplorer(what?: any) {
        let handle;
        if (typeof what === 'undefined') {
            // flush handles
            LogicJava.javaHandles = {};

            handle = LogicJava.javaContexts[Process.getCurrentThreadId()];
            if (!isDefined(handle)) {
                console.log('jvm explorer outside context scope');
                return null;
            }
        } else if (typeof what === 'object') {
            if (typeof what['handle_class'] !== 'undefined') {
                const cl = Java.use(what['handle_class']);
                handle = what['handle'];
                if (typeof handle === 'string') {
                    handle = LogicJava.javaHandles[handle];
                    if (typeof handle === 'undefined') {
                        return null;
                    }
                } else if (typeof handle === 'object') {
                    try {
                        handle = Java.cast(ptr(handle['$handle']), cl);
                    } catch (e) {
                        Utils.logErr('jvmExplorer', e + ' | ' + handle['$handle']);
                        return null;
                    }
                } else {
                    try {
                        handle = Java.cast(ptr(handle), cl);
                    } catch (e) {
                        Utils.logErr('jvmExplorer', e + ' | ' + handle);
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
            Utils.logErr('jvmExplorer-1', e);
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
                        if (Utils.isDefined(handle[name])) {
                            sub_handle_class = handle[name]['$className'];
                        }
                    }

                    if (typeof handle[name] !== 'undefined' &&
                        typeof handle[name]['$handle'] !== 'undefined' &&
                        handle[name]['$handle'] !== null) {
                        value = handle[name]['$handle'];
                        sub_handle = handle[name]['$handle'];
                    } else {
                        if (Utils.isDefined(handle[name]) && Utils.isDefined(handle[name]['value'])) {
                            sub_handle_class = handle[name]['value']['$className'];
                        }

                        if (handle[name] !== null && handle[name]['value'] !== null &&
                            typeof handle[name]['value'] === 'object') {
                            if (typeof handle[name]['fieldReturnType'] !== 'undefined') {
                                sub_handle = handle[name]['value'];
                                if (typeof sub_handle['$handle'] !== 'undefined') {
                                    const pt = sub_handle['$handle'];
                                    LogicJava.javaHandles[pt] = sub_handle;
                                    sub_handle = pt;
                                    value = handle[name]['fieldReturnType']['className'];
                                    sub_handle_class = value;
                                } else {
                                    t = handle[name]['fieldReturnType']['type'];
                                    sub_handle_class = handle[name]['fieldReturnType']['className'];

                                    if (handle[name]['fieldReturnType']['type'] !== 'pointer') {
                                        value = sub_handle_class;
                                    } else {
                                        if (Utils.isDefined(handle[name]['value'])) {
                                            value = handle[name]['value'].toString();
                                            t = typeof (value);
                                        }
                                    }
                                }
                            } else if (Utils.isDefined(handle[name]['value'])) {
                                value = handle[name]['value'].toString();
                                t = typeof (value);
                            }
                        } else if (Utils.isDefined(handle[name]['value'])) {
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
                Utils.logErr('jvmExplorer-2', e);
            }
        }
        return ret;
    }

    static putBreakpoint(target: string, condition?: string | Function): boolean {
        if (!Utils.isString(target) || Utils.isDefined(LogicJava.breakpoints[target])) {
            return false;
        }

        const breakpoint = new Breakpoint(target);

        if (!Utils.isDefined(condition)) {
            condition = null;
        }
        breakpoint.condition = condition;

        LogicJava.breakpoints[target] = breakpoint;
        let result = false;
        if (target.endsWith('.$init')) {
            result = LogicJava.hook(target, '$init', function () {
                LogicJava.jvmBreakpoint(this.className, this.method, arguments, this.overload.argumentTypes, condition);
            });
        } else {
            result = LogicJava.hookJavaMethod(target, function () {
                LogicJava.jvmBreakpoint(this.className, this.method, arguments, this.overload.argumentTypes, condition);
            });
        }

        return result;
    }

    static putJavaClassInitializationBreakpoint(className: string): boolean {
        const applied = LogicJava.hookClassLoaderClassInitialization(className, null);
        if (applied) {
            Dwarf.loggedSend('java_class_initialization_callback:::' + className);
        }
        return applied;
    }

    static removeBreakpoint(target: string): boolean {
        if (!Utils.isString(target)) {
            return false;
        }

        let breakpoint: Breakpoint = LogicJava.breakpoints[target];
        if (Utils.isDefined(breakpoint)) {
            delete LogicBreakpoint.breakpoints[target.toString()];
            LogicJava.hookJavaMethod(breakpoint.target, null);
            return true;
        }

        return false;
    }

    static removeModuleInitializationBreakpoint(clazz: string) {
        if (typeof LogicJava.javaClassLoaderCallbacks[clazz] !== 'undefined') {
            delete LogicJava.javaClassLoaderCallbacks[clazz];
            return true;
        }

        return false;
    }

    static restartApplication(): boolean {
        if (!LogicJava.available) {
            return false;
        }

        Java.performNow(function () {
            const Intent = Java.use('android.content.Intent');
            const ctx = LogicJava.getApplicationContext();
            const intent = ctx.getPackageManager().getLaunchIntentForPackage(ctx.getPackageName());
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP['value']);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK['value']);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK['value']);
            ctx.startActivity(intent);
        });
        return true;
    }

    static startTrace(classes, callback): boolean {
        if (!LogicJava.available || LogicJava.tracing) {
            return false;
        }

        LogicJava.tracing = true;
        LogicJava.tracerDepth = 1;
        LogicJava.tracedClasses = classes;
        LogicJava.applyTracerImplementation(true, callback);

        return true;
    };

    static stopTrace(): boolean {
        if (!LogicJava.available || !LogicJava.tracing) {
            return false;
        }

        LogicJava.tracing = false;
        LogicJava.tracerDepth = 1;
        LogicJava.applyTracerImplementation(true);

        return true;
    };

    static traceImplementation(callback, className, method) {
        return function () {
            const uiCallback = !Utils.isDefined(callback);
            const classMethod = className + '.' + method;
            const thatObject = {
                $className: className,
                method: method,
                depth: LogicJava.tracerDepth
            }
            if (uiCallback) {
                Dwarf.loggedSend('java_trace:::enter:::' + classMethod + ':::' + JSON.stringify(arguments));
            } else {
                if (Utils.isDefined(callback['onEnter'])) {
                    callback['onEnter'].apply(thatObject, arguments);
                } else if (typeof callback === 'function') {
                    callback.apply(thatObject, arguments);
                }
            }

            LogicJava.tracerDepth += 1;
            let ret = this[method].apply(this, arguments);
            LogicJava.tracerDepth -= 1;

            if (uiCallback) {
                let traceRet = ret;
                if (typeof traceRet === 'object') {
                    traceRet = JSON.stringify(ret);
                } else if (typeof traceRet === 'undefined') {
                    traceRet = "";
                }
                Dwarf.loggedSend('java_trace:::leave:::' + classMethod + ':::' + traceRet);
            } else {
                if (Utils.isDefined(callback['onLeave'])) {
                    let tempRet = callback['onLeave'].apply(thatObject, ret);
                    if (typeof tempRet !== 'undefined') {
                        ret = tempRet;
                    }
                }
            }
            return ret;
        }
    }
}
