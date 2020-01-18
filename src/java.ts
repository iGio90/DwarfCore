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

interface DwarfJavaClassInfo {
    className: string;
    clasMethods: Array<string>;
}

export class DwarfJavaHelper {
    private static instanceRef: DwarfJavaHelper;

    protected classCache: { [index: string]: DwarfJavaClassInfo };
    protected javaClassLoaderCallbacks: { [index: string]: ScriptInvocationListenerCallbacks | Function | string };
    protected libraryLoaderCallbacks: { [index: string]: ScriptInvocationListenerCallbacks | Function | string };
    protected oldOverloads: { [index: string]: Function | Array<Function> };
    protected sdk_version: number;
    protected initDone: boolean;

    private constructor() {
        if (DwarfJavaHelper.instanceRef) {
            throw new Error("JavaHelper already exists! Use DwarfJavaHelper.getInstance()/Dwarf.getJavaHelper()");
        }
        trace('DwarfJavaHelper()');

        this.classCache = {};
        this.sdk_version = 0;
        this.javaClassLoaderCallbacks = {};
        this.libraryLoaderCallbacks = {};
        this.oldOverloads = {};
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
                    /*if (!self.classCache.hasOwnProperty(className)) {
                        const classInfo: DwarfJavaClassInfo = {
                            className: className,
                            clasMethods: self.getClassMethods(className)
                        }
                        self.classCache[className] = classInfo;

                        //sync ui
                        Dwarf.sync({ java_class_loaded: classInfo });
                    }*/

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
                        Dwarf.onBreakpoint(DwarfHaltReason.CLASS_LOADER, className, {}, this);
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

            //Library loading
            const System = Java.use('java.lang.System');
            const Runtime = Java.use('java.lang.Runtime');
            const VMStack = Java.use('dalvik.system.VMStack');

            System.loadLibrary.implementation = function (library: string) {
                try {
                    let userCallback: ScriptInvocationListenerCallbacks | Function | string = null;
                    //strip path
                    const libraryName = library.substr(library.lastIndexOf('/') + 1);
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

                    const procModule = Process.findModuleByName(libraryName);
                    if (isDefined(procModule)) {
                        let moduleInfo = Object.assign({ imports: [], exports: [], symbols: [] }, procModule);
                        moduleInfo.imports = procModule.enumerateImports();
                        moduleInfo.exports = procModule.enumerateExports();
                        moduleInfo.symbols = procModule.enumerateSymbols();
                        Dwarf.sync({ modules: moduleInfo });
                    }

                    return loaded;
                } catch (e) {
                    logDebug(e);
                    throw e;
                }
            }

            System.load.implementation = function (library: string) {
                try {
                    let userCallback: ScriptInvocationListenerCallbacks | Function | string = null;
                    //strip path
                    const libraryName = library.substr(library.lastIndexOf('/') + 1);
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

                    const procModule = Process.findModuleByName(libraryName);
                    if (isDefined(procModule)) {
                        let moduleInfo = Object.assign({ imports: [], exports: [], symbols: [] }, procModule);
                        moduleInfo.imports = procModule.enumerateImports();
                        moduleInfo.exports = procModule.enumerateExports();
                        moduleInfo.symbols = procModule.enumerateSymbols();
                        Dwarf.sync({ modules: moduleInfo });
                    }

                    return loaded;
                } catch (e) {
                    logDebug(e);
                    throw e;
                }
            }
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
        this.classCache = {};
    }

    getClassMethods = (className: string): Array<string> => {
        trace('DwarfJavaHelper::getClassMethods()');

        this.checkRequirements();

        Java.performNow(() => {
            try {
                // 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
                const javaWrapper: Java.Wrapper = Java.use(className);
                const methods = javaWrapper.class.getDeclaredMethods();
                javaWrapper.$dispose();

                const parsedMethods = [];
                methods.forEach(function (method) {
                    parsedMethods.push(method.toString().replace(className + ".",
                        "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
                });
                return new Array(uniqueBy(parsedMethods));
            } catch (e) {
                logDebug('DwarfJavaHelper::getClassMethods() Failed for : "' + className + '" !');
            }
        });
        return new Array<string>();
    }

    enumerateLoadedClasses = (useCache: boolean = false) => {
        trace('JavaHelper::enumerateLoadedClasses()');

        this.checkRequirements();

        if (useCache && this.classCache.length) {
            //return this.classCache;
            Dwarf.sync({ java_classes: this.classCache, cached: useCache });
        } else {
            this.invalidateClassCache();

            const self = this;

            const classList: Array<string> = new Array<string>();

            Java.performNow(() => {
                try {
                    Java.enumerateLoadedClasses({
                        onMatch: function (className) {
                            classList.push(className);
                        },
                        onComplete: function () {
                            classList.forEach(className => {
                                if (!self.classCache.hasOwnProperty(className)) {
                                    const classInfo: DwarfJavaClassInfo = {
                                        className: className,
                                        clasMethods: self.getClassMethods(className)
                                    }
                                    self.classCache[className] = classInfo;
                                }
                            });

                            Dwarf.sync({ java_classes: self.classCache, cached: useCache });
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

        Java.performNow(() => {
            try {
                const javaWrapper = Java.use(className);

                if (isDefined(javaWrapper) && isDefined(javaWrapper[methodName])) {
                    try {
                        const overloadCount = javaWrapper[methodName].overloads.length;
                        if (overloadCount > 0) {
                            if (!this.oldOverloads.hasOwnProperty(className + '.' + methodName)) {
                                this.oldOverloads[className + '.' + methodName] = new Array<Function>();
                            }
                            for (var i = 0; i < overloadCount; i++) {
                                (this.oldOverloads[className + '.' + methodName] as Function[]).push(javaWrapper[methodName].overloads[i].implementation);
                                javaWrapper[methodName].overloads[i].implementation = implementation;
                            }
                        } else {
                            javaWrapper[methodName].overload.implementation = implementation;
                        }
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

    public addLibraryLoaderHook = () => {

    }

}