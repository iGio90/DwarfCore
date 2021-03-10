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

import { DwarfHaltReason } from "./consts";
import { DwarfCore } from "./DwarfCore";

export class LogicJava {
    static available = Java.available;
    static breakpoints = {};
    static javaClasses = [];
    static javaClassLoaderCallbacks = {};
    static javaContexts = {};
    static javaHandles = {};
    static sdk = 0;
    static tracedClasses = [];
    static tracing = false;

    private static applyTracerImplementation(attach, callback?) {
        Java.performNow(() => {
            LogicJava.tracedClasses.forEach(className => {
                try {
                    const clazz = Java.use(className);

                    const overloadCount = clazz.$init.overloads.length;
                    if (overloadCount > 0) {
                        for (let i = 0; i < overloadCount; i++) {
                            if (attach) {
                                clazz.$init.overloads[i].implementation = LogicJava.traceImplementation(callback, className, "$init");
                            } else {
                                clazz.$init.overloads[i].implementation = null;
                            }
                        }
                    }

                    let methods = clazz.class.getDeclaredMethods();
                    const parsedMethods = [];
                    methods.forEach(function(method) {
                        parsedMethods.push(
                            method
                                .toString()
                                .replace(className + ".", "TOKEN")
                                .match(/\sTOKEN(.*)\(/)[1]
                        );
                    });
                    methods = uniqueBy(parsedMethods);
                    methods.forEach(method => {
                        const oLen = clazz[method].overloads.length;
                        if (oLen > 0) {
                            for (let i = 0; i < oLen; i++) {
                                if (attach) {
                                    clazz[method].overloads[i].implementation = LogicJava.traceImplementation(callback, className, method);
                                } else {
                                    clazz[method].overloads[i].implementation = null;
                                }
                            }
                        }
                    });

                    clazz.$dispose();
                } catch (e) {
                    logErr("LogicJava.startTrace", e);
                }
            });
        });
    }

    static backtrace() {
        return Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
    }

    static getApplicationContext() {
        if (!LogicJava.available) {
            return;
        }

        const ActivityThread = Java.use("android.app.ActivityThread");
        const Context = Java.use("android.content.Context");

        const context = Java.cast(ActivityThread.currentApplication().getApplicationContext(), Context);

        ActivityThread.$dispose();
        Context.$dispose();

        return context;
    }

    static hook(className, method, implementation): boolean {
        if (!LogicJava.available) {
            return false;
        }

        Java.performNow(function() {
            LogicJava.hookInJVM(className, method, implementation);
        });

        return true;
    }

    static hookAllJavaMethods(className, implementation): boolean {
        if (!Java.available) {
            return false;
        }

        if (!isDefined(className)) {
            return false;
        }

        const that = this;

        Java.performNow(function() {
            const clazz = Java.use(className);
            const methods = clazz.class.getDeclaredMethods();

            const parsedMethods = [];
            methods.forEach(function(method) {
                parsedMethods.push(
                    method
                        .toString()
                        .replace(className + ".", "TOKEN")
                        .match(/\sTOKEN(.*)\(/)[1]
                );
            });
            const result = uniqueBy(parsedMethods);
            result.forEach(method => {
                LogicJava.hookInJVM(className, method, implementation);
            });
            clazz.$dispose();
        });
        return true;
    }

    static hookClassLoaderClassInitialization(clazz: string, callback?: fArgReturn): boolean {
        if (!isString(clazz) || isDefined(LogicJava.javaClassLoaderCallbacks[clazz])) {
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
                className = className + "." + method;
                method = "$init";
                handler = Java.use(className);
            } catch (err) {
                logErr("hookInJVM", err);
            }

            logErr("LogicJava.hook", err);
            if (handler === null) {
                return;
            }
        }

        try {
            if (handler == null || typeof handler[method] === "undefined") {
                return;
            }
        } catch (e) {
            // catching here not supported overload error from frida
            logErr("LogicJava.hook", e);
            return;
        }

        const overloadCount = handler[method].overloads.length;
        if (overloadCount > 0) {
            for (let i = 0; i < overloadCount; i++) {
                const overload = handler[method].overloads[i];
                if (isDefined(implementation)) {
                    overload.implementation = function() {
                        LogicJava.javaContexts[Process.getCurrentThreadId()] = this;
                        this.className = className;
                        this.method = method;
                        this.overload = overload;
                        const ret = implementation.apply(this, arguments);
                        if (typeof ret !== "undefined") {
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
    }

    static hookJavaMethod(targetClassMethod, implementation): boolean {
        if (isDefined(targetClassMethod)) {
            const delim = targetClassMethod.lastIndexOf(".");
            if (delim === -1) {
                return false;
            }

            const targetClass = targetClassMethod.slice(0, delim);
            const targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);
            LogicJava.hook(targetClass, targetMethod, implementation);
            return true;
        }
        return false;
    }

    static init(breakAtStart: boolean = false) {
        LogicJava.sdk = DwarfCore.getInstance().getAndroidApiLevel();
        Java.performNow(function() {
            logDebug("[" + Process.getCurrentThreadId() + "] " + "initializing logicJava with sdk: " + LogicJava.sdk);
        });
    }

    static jvmBreakpoint(className, method, args, types, condition?) {
        const classMethod = className + "." + method;
        const newArgs = {};
        for (let i = 0; i < args.length; i++) {
            let value = "";
            if (args[i] === null || typeof args[i] === "undefined") {
                value = "null";
            } else {
                if (typeof args[i] === "object") {
                    value = JSON.stringify(args[i]);
                    if (types[i].className === "[B") {
                        value += " (" + Java.use("java.lang.String").$new(args[i]) + ")";
                    }
                } else {
                    value = args[i].toString();
                }
            }
            newArgs[i] = {
                arg: value,
                name: types[i].name,
                handle: args[i],
                className: types[i].className
            };
        }

        // @ts-ignore
        DwarfCore.getInstance().onBreakpoint(0, Process.getCurrentThreadId(), DwarfHaltReason.BREAKPOINT, classMethod, newArgs, this, condition);
    }

    static jvmExplorer(what?: any) {
        let handle;
        if (typeof what === "undefined") {
            // flush handles
            LogicJava.javaHandles = {};

            handle = LogicJava.javaContexts[Process.getCurrentThreadId()];
            if (!isDefined(handle)) {
                console.log("jvm explorer outside context scope");
                return null;
            }
        } else if (typeof what === "object") {
            if (typeof what.handle_class !== "undefined") {
                const cl = Java.use(what.handle_class);
                handle = what.handle;
                if (typeof handle === "string") {
                    handle = LogicJava.javaHandles[handle];
                    if (typeof handle === "undefined") {
                        return null;
                    }
                } else if (typeof handle === "object") {
                    try {
                        handle = Java.cast(ptr(handle.$handle), cl);
                    } catch (e) {
                        logErr("jvmExplorer" + " | " + handle.$handle, e);
                        return null;
                    }
                } else {
                    try {
                        handle = Java.cast(ptr(handle), cl);
                    } catch (e) {
                        logErr("jvmExplorer" + " | " + handle, e);
                        return null;
                    }
                }
                cl.$dispose();
            } else {
                handle = what;
            }
        } else {
            console.log("Explorer handle not found");
            return {};
        }
        if (handle === null || typeof handle === "undefined") {
            console.log("Explorer handle null");
            return {};
        }
        let ol;
        try {
            ol = Object.getOwnPropertyNames(handle.__proto__);
        } catch (e) {
            logErr("jvmExplorer-1", e);
            return null;
        }
        let clazz = "";
        if (typeof handle.$className !== "undefined") {
            clazz = handle.$className;
        }
        const ret = {
            class: clazz,
            data: {}
        };
        // tslint:disable-next-line: forin
        for (const o in ol) {
            const name = ol[o];
            try {
                const overloads = [];
                let t = typeof handle[name];
                let value = "";
                let subHandle = null;
                let subHandleClass = "";

                if (t === "function") {
                    if (typeof handle[name].overloads !== "undefined") {
                        const overloadCount = handle[name].overloads.length;
                        if (overloadCount > 0) {
                            // tslint:disable-next-line: forin
                            for (const i in handle[name].overloads) {
                                overloads.push({
                                    args: handle[name].overloads[i].argumentTypes,
                                    return: handle[name].overloads[i].returnType
                                });
                            }
                        }
                    }
                } else if (t === "object") {
                    if (handle[name] !== null) {
                        subHandleClass = handle[name].$className;
                    }

                    if (typeof handle[name].$handle !== "undefined" && handle[name].$handle !== null) {
                        value = handle[name].$handle;
                        subHandle = handle[name].$handle;
                    } else {
                        if (handle[name] !== null && handle[name].value !== null) {
                            subHandleClass = handle[name].value.$className;
                        }

                        if (handle[name] !== null && handle[name].value !== null && typeof handle[name].value === "object") {
                            if (typeof handle[name].fieldReturnType !== "undefined") {
                                subHandle = handle[name].value;
                                if (typeof subHandle.$handle !== "undefined") {
                                    const pt = subHandle.$handle;
                                    LogicJava.javaHandles[pt] = subHandle;
                                    subHandle = pt;
                                    value = handle[name].fieldReturnType.className;
                                    subHandleClass = value;
                                } else {
                                    t = handle[name].fieldReturnType.type;
                                    subHandleClass = handle[name].fieldReturnType.className;

                                    if (handle[name].fieldReturnType.type !== "pointer") {
                                        value = subHandleClass;
                                    } else {
                                        if (handle[name].value !== null) {
                                            value = handle[name].value.toString();
                                            t = typeof value;
                                        }
                                    }
                                }
                            } else if (handle[name].value !== null) {
                                value = handle[name].value.toString();
                                t = typeof value;
                            }
                        } else if (handle[name].value !== null) {
                            t = typeof handle[name].value;
                            value = handle[name].value.toString();
                        }
                    }
                } else {
                    value = handle[name];
                }

                ret.data[name] = {
                    value,
                    handle: subHandle,
                    handle_class: subHandleClass,
                    type: t,
                    overloads
                };
            } catch (e) {
                logErr("jvmExplorer-2", e);
            }
        }
        return ret;
    }

    static restartApplication(): boolean {
        if (!LogicJava.available) {
            return false;
        }

        Java.performNow(function() {
            const Intent = Java.use("android.content.Intent");
            const ctx = LogicJava.getApplicationContext();
            const intent = ctx.getPackageManager().getLaunchIntentForPackage(ctx.getPackageName());
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP.value);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK.value);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK.value);
            ctx.startActivity(intent);
        });
        return true;
    }

    static startTrace(classes, callback): boolean {
        if (!LogicJava.available || LogicJava.tracing) {
            return false;
        }

        LogicJava.tracing = true;
        LogicJava.tracedClasses = classes;
        LogicJava.applyTracerImplementation(true, callback);

        return true;
    }

    static stopTrace(): boolean {
        if (!LogicJava.available || !LogicJava.tracing) {
            return false;
        }

        LogicJava.tracing = false;
        LogicJava.applyTracerImplementation(true);

        return true;
    }

    static traceImplementation(callback, className, method) {
        return function() {
            const uiCallback = !isDefined(callback);
            const classMethod = className + "." + method;

            if (uiCallback) {
                send("java_trace:::enter:::" + classMethod + ":::" + JSON.stringify(arguments));
            } else {
                if (isDefined(callback.onEnter)) {
                    callback.onEnter(arguments);
                }
            }

            let ret = this[method].apply(this, arguments);

            if (uiCallback) {
                let traceRet = ret;
                if (typeof traceRet === "object") {
                    traceRet = JSON.stringify(ret);
                } else if (typeof traceRet === "undefined") {
                    traceRet = "";
                }
                send("java_trace:::leave:::" + classMethod + ":::" + traceRet);
            } else {
                if (isDefined(callback.onLeave)) {
                    const tempRet = callback.onLeave(ret);
                    if (typeof tempRet !== "undefined") {
                        ret = tempRet;
                    }
                }
            }
            return ret;
        };
    }
}
