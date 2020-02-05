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

import { DwarfHaltReason } from "./consts";
import { JavaBreakpoint } from "./types/java_breakpoint";
import { DwarfBreakpointManager } from "./breakpoint_manager";

interface DwarfJavaClassInfo {
    className: string;
    clasMethods: Array<string>;
}

export class DwarfJavaHelper {
    private static instanceRef: DwarfJavaHelper;

    protected classCache: Array<string>;//{ [index: string]: DwarfJavaClassInfo };
    protected javaClassLoaderCallbacks: { [index: string]: ScriptInvocationListenerCallbacks | Function | string };
    protected libraryLoaderCallbacks: { [index: string]: ScriptInvocationListenerCallbacks | Function | string };
    protected oldOverloads: { [index: string]: Function | Array<Function> };
    protected sdk_version: number;
    protected initDone: boolean;
    protected breakpointsToHook: Array<JavaBreakpoint>;

    private constructor() {
        if (DwarfJavaHelper.instanceRef) {
            throw new Error("JavaHelper already exists! Use DwarfJavaHelper.getInstance()/Dwarf.getJavaHelper()");
        }
        trace('DwarfJavaHelper()');

        this.classCache = new Array<string>(); // = {};
        this.sdk_version = 0;
        this.javaClassLoaderCallbacks = {};
        this.libraryLoaderCallbacks = {};
        this.oldOverloads = {};
        this.breakpointsToHook = new Array<JavaBreakpoint>();
        this.initDone = false;

        this.initalize();
    }

    //Singleton
    static getInstance() {
        if (Java.available) {
            if (!DwarfJavaHelper.instanceRef) {
                DwarfJavaHelper.instanceRef = new DwarfJavaHelper();
            }
            return DwarfJavaHelper.instanceRef;
        } else {
            throw new Error('JavaHelper not available!');
        }
    }

    initalize = () => {
        if (this.initDone) {
            logDebug('DwarfJavaHelper => Init already done!');
        }
        trace('DwarfJavaHelper::initialize()');

        this.checkRequirements();

        this.sdk_version = Dwarf.getAndroidApiLevel();

        const self = this;

        Java.performNow(() => {
            logDebug('initializing logicJava with sdk: ' + this.sdk_version);

            //class loader
            const ClassLoader = Java.use('java.lang.ClassLoader');

            ClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function (className: string, resolve: boolean) {
                try {
                    if (self.classCache.indexOf(className) === -1) {
                        self.classCache.push(className);

                        if (self.breakpointsToHook.length > 0) {
                            self.breakpointsToHook.forEach(javaBreakpoint => {
                                if ((javaBreakpoint.getAddress() as string).indexOf(className) !== -1) {
                                    javaBreakpoint.setup();
                                    Dwarf.sync({ breakpoints: DwarfBreakpointManager.getInstance().getBreakpoints() });
                                }
                            });
                            self.breakpointsToHook = self.breakpointsToHook.filter((breakpoint) => {
                                return breakpoint.isHooked() == false;
                            });
                        }
                        //sync ui
                        Dwarf.sync({ java_class_loaded: className });
                    }

                    let userCallback: ScriptInvocationListenerCallbacks | Function | string = null;
                    if (self.javaClassLoaderCallbacks.hasOwnProperty(className)) {
                        userCallback = self.javaClassLoaderCallbacks[className];
                    } else if (isFunction(userCallback)) {
                        (userCallback as Function).apply(this, [className, resolve]);
                    }

                    if (isDefined(userCallback) && userCallback.hasOwnProperty('onEnter')) {
                        const userOnEnter = (userCallback as ScriptInvocationListenerCallbacks).onEnter;
                        if (isFunction(userOnEnter)) {
                            userOnEnter.apply(this, [className, resolve]);
                        }
                    } else if (isString(userCallback) && userCallback === 'breakpoint') {
                        Dwarf.onBreakpoint(DwarfHaltReason.BREAKPOINT, className, {}, this);
                    }

                    let result = this.loadClass(className, resolve);

                    if (isDefined(userCallback) && userCallback.hasOwnProperty('onLeave')) {
                        const userOnLeave = (userCallback as ScriptInvocationListenerCallbacks).onLeave;
                        if (isFunction(userOnLeave)) {
                            userOnLeave.apply(this, result);
                        }
                    }
                    return result;
                } catch (e) {
                    if (e.message.indexOf('java.lang.ClassNotFoundException') !== -1) {
                        throw e;
                    }
                    logDebug(e);
                }
            }

            /*
                TODO: check

            //Library loading
            const System = Java.use('java.lang.System');
            const Runtime = Java.use('java.lang.Runtime');
            const VMStack = Java.use('dalvik.system.VMStack');

            System.loadLibrary.implementation = function (library: string) {
                try {
                    let userCallback: ScriptInvocationListenerCallbacks | Function | string = null;

                    let libraryName = library;
                    if (libraryName.indexOf('/') != -1) {
                        libraryName = libraryName.substring(libraryName.lastIndexOf('/') + 1);
                    }

                    if (self.libraryLoaderCallbacks.hasOwnProperty(libraryName)) {
                        userCallback = self.libraryLoaderCallbacks[libraryName];
                    }

                    const callingClassLoader = VMStack.getCallingClassLoader();

                    if (isDefined(userCallback) && userCallback.hasOwnProperty('onEnter')) {
                        const userOnEnter = (userCallback as ScriptInvocationListenerCallbacks).onEnter;
                        if (isFunction(userOnEnter)) {
                            userOnEnter.apply(this, [callingClassLoader, library]);
                        }
                    } else if (isFunction(userCallback)) {
                        (userCallback as Function).apply(this, [callingClassLoader, library]);
                    }

                    const loaded = Runtime.getRuntime().loadLibrary0(callingClassLoader, library);

                    if (isDefined(userCallback) && userCallback.hasOwnProperty('onLeave')) {
                        const userOnLeave = (userCallback as ScriptInvocationListenerCallbacks).onLeave;
                        if (isFunction(userOnLeave)) {
                            userOnLeave.apply(this, loaded);
                        }
                    } else if (isString(userCallback) && userCallback === 'breakpoint') {
                        Dwarf.onBreakpoint(DwarfHaltReason.MODULE_LOADED, library, {}, this);
                    }

                    Dwarf.sync({ module_loaded: { name: library, caller: VMStack.getStackClass2().getName() } });

                    return loaded;
                } catch (e) {
                    logDebug(e.message);
                    throw e;
                }
            }

            System.load.implementation = function (library: string) {
                try {
                    let userCallback: ScriptInvocationListenerCallbacks | Function | string = null;
                    let libraryName = library;
                    if (libraryName.indexOf('/') != -1) {
                        libraryName = libraryName.substring(libraryName.lastIndexOf('/') + 1);
                    }
                    if (self.libraryLoaderCallbacks.hasOwnProperty(libraryName)) {
                        userCallback = self.libraryLoaderCallbacks[libraryName];
                    }

                    const callingClassLoader = VMStack.getCallingClassLoader();

                    if (isDefined(userCallback) && userCallback.hasOwnProperty('onEnter')) {
                        const userOnEnter = (userCallback as ScriptInvocationListenerCallbacks).onEnter;
                        if (isFunction(userOnEnter)) {
                            userOnEnter.apply(this, [callingClassLoader, library]);
                        }
                    } else if (isFunction(userCallback)) {
                        (userCallback as Function).apply(this, [callingClassLoader, library]);
                    }

                    const loaded = Runtime.getRuntime().load0(callingClassLoader, library);

                    if (isDefined(userCallback) && userCallback.hasOwnProperty('onLeave')) {
                        const userOnLeave = (userCallback as ScriptInvocationListenerCallbacks).onLeave;
                        if (isFunction(userOnLeave)) {
                            userOnLeave.apply(this, loaded);
                        }
                    } else if (isString(userCallback) && userCallback === 'breakpoint') {
                        Dwarf.onBreakpoint(DwarfHaltReason.MODULE_LOADED, library, {}, this);
                    }

                    Dwarf.sync({ module_loaded: { name: library, caller: VMStack.getStackClass2().getName() } });

                    return loaded;
                } catch (e) {
                    logDebug(e);
                    throw e;
                }
            }*/
        });
        this.initDone = true;
    }

    //add other stuff when needed
    checkRequirements = () => {
        if (!Java.available) {
            throw new Error('JavaHelper not available!');
        }
    }

    invalidateClassCache = () => {
        trace('JavaHelper::invalidateClassCache()');
        this.classCache = new Array<string>();
    }

    getClassMethods = (className: string, syncUi: boolean = false): Array<string> => {
        trace('DwarfJavaHelper::getClassMethods()');

        this.checkRequirements();

        const parsedMethods: Array<string> = new Array<string>();

        Java.performNow(() => {
            try {
                // 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
                const javaWrapper: Java.Wrapper = Java.use(className);
                const methods = javaWrapper.class.getDeclaredMethods();
                javaWrapper.$dispose();

                methods.forEach(function (method) {
                    parsedMethods.push(method.toString().replace(className + ".",
                        "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
                });
            } catch (e) {
                logDebug('DwarfJavaHelper::getClassMethods() Failed for : "' + className + '" !');
            }
        });
        if (parsedMethods.length > 0) {
            if (syncUi) {
                return Dwarf.sync({ class_methods: uniqueBy(parsedMethods) });
            } else {
                return new Array(uniqueBy(parsedMethods));
            }
        } else {
            if (syncUi) {
                return Dwarf.sync({ class_methods: [] });
            } else {
                return new Array();
            }
        }
    }

    enumerateLoadedClasses = (useCache: boolean = false) => {
        trace('JavaHelper::enumerateLoadedClasses()');

        this.checkRequirements();

        if (useCache && this.classCache.length) {
            //return this.classCache;
            Dwarf.sync({ java_classes: this.classCache, cached: useCache });
        } else {
            this.invalidateClassCache();

            Java.performNow(() => {
                try {
                    Java.enumerateLoadedClasses({
                        onMatch: (className) => {
                            this.classCache.push(className);
                        },
                        onComplete: () => {
                            Dwarf.sync({ java_classes: this.classCache, cached: useCache });
                        }
                    });
                } catch (e) {
                    logDebug('JavaHelper::enumerateLoadedClasses() => Error: ' + e);
                }
            });
        }
    }

    hookInJVM = (className: string, methodName: string = '$init', implementation: Function) => {
        trace('DwarfJavaHelper::hookInJVM()');

        this.checkRequirements();

        if (!isString(className)) {
            throw new Error('DwarfJavaHelper::hookInJVM() => Invalid arguments! -> className');
        }

        if (!isString(methodName)) {
            throw new Error('DwarfJavaHelper::hookInJVM() => Invalid arguments! -> methodName');
        }

        if (!isFunction(implementation)) {
            throw new Error('DwarfJavaHelper::hookInJVM() => Invalid arguments! -> implementation');
        }

        const self = this;
        Java.performNow(function () {
            try {
                const javaWrapper = Java.use(className);

                if (isDefined(javaWrapper) && isDefined(javaWrapper[methodName])) {
                    try {
                        const overloads = javaWrapper[methodName].overloads;
                        for (let i in overloads) {
                            if (overloads[i].hasOwnProperty('argumentTypes')) {
                                const overload = javaWrapper[methodName].overloads[i];
                                var parameters = [];
                                for (let j in overload.argumentTypes) {
                                    parameters.push(overloads[i].argumentTypes[j].className);
                                }

                                javaWrapper[methodName].overloads[i].implementation = function () {
                                    this.types = parameters;
                                    return implementation.apply(this, [arguments]);
                                };
                            }
                        }
                        /*const overloadCount = javaWrapper[methodName].overloads.length;
                        if (overloadCount > 0) {
                            if (!self.oldOverloads.hasOwnProperty(className + '.' + methodName)) {
                                self.oldOverloads[className + '.' + methodName] = new Array<Function>();
                            }
                            for (var i = 0; i < overloadCount; i++) {
                                (self.oldOverloads[className + '.' + methodName] as Function[]).push(javaWrapper[methodName].overloads[i].implementation);
                                javaWrapper[methodName].overloads[i].implementation = implementation;
                            }
                        } else {
                            javaWrapper[methodName].overload.implementation = implementation;
                        }*/
                    } catch (e) {
                        logDebug('DwarfJavaHelper::hookInJVM() => overload failed -> ' + e);
                    }
                } else {
                    throw new Error('DwarfJavaHelper::hookInJVM() => ' + (className + '.' + methodName) + ' not found!');
                }
            } catch (e) {
                logDebug('DwarfJavaHelper::hookInJVM() => Error: ' + e);
                throw new Error('DwarfJavaHelper::hookInJVM() => Unable to find class: ' + className);
            }
        });
    }

    replaceInJVM = (className: string, methodName: string = '$init', implementation: Function) => {

    }

    restoreInJVM = (className: string, methodName: string) => {
        trace('DwarfJavaHelper::restoreInJVM()');

        this.checkRequirements();

        if (!isString(className)) {
            throw new Error('DwarfJavaHelper::restoreInJVM() => Invalid arguments! -> className');
        }

        if (!isString(methodName)) {
            throw new Error('DwarfJavaHelper::restoreInJVM() => Invalid arguments! -> methodName');
        }

        Java.performNow(() => {
            try {
                const javaWrapper = Java.use(className);

                if (isDefined(javaWrapper) && isDefined(javaWrapper[methodName])) {
                    try {
                        const overloadCount = javaWrapper[methodName].overloads.length;
                        if (overloadCount > 0) {
                            for (var i = 0; i < overloadCount; i++) {
                                if (this.oldOverloads.hasOwnProperty(className + '.' + methodName)) {
                                    if (i < this.oldOverloads[className + '.' + methodName].length) {
                                        const oldImplementation = (this.oldOverloads[className + '.' + methodName] as Function[])[i];
                                        javaWrapper[methodName].overloads[i].implementation = oldImplementation;
                                    } else {
                                        javaWrapper[methodName].overloads[i].implementation = null;
                                    }
                                } else {
                                    javaWrapper[methodName].overloads[i].implementation = null;
                                }
                            }
                            if (this.oldOverloads.hasOwnProperty(className + '.' + methodName)) {
                                delete this.oldOverloads[className + '.' + methodName];
                            }
                        } else {
                            javaWrapper[methodName].overload.implementation = null;
                        }
                    } catch (e) {
                        logDebug('DwarfJavaHelper::restoreInJVM() => overload failed -> ' + e);
                    }
                } else {
                    throw new Error('DwarfJavaHelper::restoreInJVM() => ' + (className + '.' + methodName) + ' not found!');
                }
            } catch (e) {
                logDebug('DwarfJavaHelper::restoreInJVM() => Error: ' + e);
                throw new Error('DwarfJavaHelper::restoreInJVM() => Unable to find class: ' + className);
            }
        });
    }

    /**
     * @param  {string} className
     * @param  {Function} callback?
     * @param  {boolean=false} permanent when set to true removeClassLoaderHook wont delete hook
     * @returns boolean
     */
    public addClassLoaderHook = (className: string, callback: ScriptInvocationListenerCallbacks | Function | string, permanent: boolean = false): boolean => {
        trace('JavaHelper::addClassLoaderHook()');

        this.checkRequirements();

        if (!isString(className)) {
            throw new Error('DwarfJavaHelper::addClassLoaderHook() => Invalid arguments!');
        }

        if (this.javaClassLoaderCallbacks.hasOwnProperty(className)) {
            throw new Error('DwarfJavaHelper::addClassLoaderHook() => Already hooked!');
        }

        if (isFunction(callback)) {
            if (permanent) {
                Object.defineProperty(this.javaClassLoaderCallbacks, className, { value: callback, configurable: false, writable: false });
            } else {
                this.javaClassLoaderCallbacks[className] = callback;
            }
        } else {
            if (isString(callback)) {
                if (permanent) {
                    Object.defineProperty(this.javaClassLoaderCallbacks, className, { value: 'breakpoint', configurable: false, writable: false });
                } else {
                    this.javaClassLoaderCallbacks[className] = 'breakpoint';
                }
            } else {
                if (isDefined(callback)) {
                    if ((callback.hasOwnProperty('onEnter') && isFunction((callback as ScriptInvocationListenerCallbacks).onEnter)) ||
                        (callback.hasOwnProperty('onLeave') && isFunction((callback as ScriptInvocationListenerCallbacks).onLeave))) {
                        this.javaClassLoaderCallbacks[className] = callback;
                    }
                }
            }
        }
        return true;
    }

    public removeClassLoaderHook = (className: string): boolean => {
        trace('JavaHelper::removeClassLoaderHook()');

        this.checkRequirements();

        if (!isString(className)) {
            throw new Error('DwarfJavaHelper::removeClassLoaderHook() => Invalid arguments!');
        }

        if (!this.javaClassLoaderCallbacks.hasOwnProperty(className)) {
            throw new Error('DwarfJavaHelper::removeClassLoaderHook() => Not hooked!');
        }

        return delete this.javaClassLoaderCallbacks[className];
    }

    addBreakpointToHook = (javaBreakpoint: JavaBreakpoint) => {
        this.breakpointsToHook.push(javaBreakpoint);
    }

}