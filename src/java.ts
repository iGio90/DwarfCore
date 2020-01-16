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

export class DwarfJavaHelper {
    private static instanceRef: DwarfJavaHelper;

    protected classCache: Array<string>;
    protected javaClassLoaderCallbacks: { [index: string]: Function | string };
    protected libraryLoaderCallbacks: { [index: string]: ScriptInvocationListenerCallbacks | Function | string };
    protected sdk_version: number;

    private constructor() {
        if (DwarfJavaHelper.instanceRef) {
            throw new Error("JavaHelper already exists! Use DwarfJavaHelper.getInstance()/Dwarf.getJavaHelper()");
        }
        trace('DwarfJavaHelper()');

        this.classCache = new Array<string>();
        this.sdk_version = 0;

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
        this.checkRequirements();

        this.sdk_version = Dwarf.getAndroidApiLevel();

        Java.performNow(() => {
            try {
                logDebug('initializing logicJava with sdk: ' + this.sdk_version);

                // attach to ClassLoader to notify for new loaded class
                const ClassLoader = Java.use('java.lang.ClassLoader');
                const overload = ClassLoader.loadClass.overload('java.lang.String', 'boolean');
                const self = this;

                overload.implementation = function (clazz, resolve) {
                    if (self.classCache.indexOf(clazz) === -1) {
                        self.classCache.push(clazz);

                        //sync ui
                        Dwarf.sync({ java_class_loaded: clazz });

                        //handle callback
                        //TODO: callback before overload.call??
                        // const bla = overload.call(this, clazz, resolve); // this allows onenter/onleave
                        if (self.javaClassLoaderCallbacks.hasOwnProperty(clazz)) {
                            const userCallback = self.javaClassLoaderCallbacks[clazz];
                            if (isFunction(userCallback)) {
                                (userCallback as Function).call(this);
                            } else {
                                if (isString(userCallback) && userCallback === 'breakpoint') {
                                    Dwarf.onBreakpoint(DwarfHaltReason.CLASS_LOADER, clazz, {}, this);
                                } else {
                                    logDebug('Invalid classLoaderCallback: ' + clazz + ' => ' + JSON.stringify(userCallback));
                                }
                            }
                        }
                        // return bla
                        return overload.call(this, clazz, resolve);
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
                        }

                        const loaded = Runtime.getRuntime().loadLibrary0(callingClassLoader, library);

                        if (isFunction(userCallback)) {
                            (userCallback as Function).apply(this, loaded);
                        } else if (isDefined(userCallback) && userCallback.hasOwnProperty('onLeave')) {
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
                        }

                        const loaded = Runtime.getRuntime().load0(callingClassLoader, library);

                        if (isFunction(userCallback)) {
                            (userCallback as Function).apply(this, loaded);
                        } else if (isDefined(userCallback) && userCallback.hasOwnProperty('onLeave')) {
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
                    }
                }
            } catch (e) {
                logDebug(e);
            }
        });
    }

    //add other stuff when needed
    checkRequirements = () => {
        if (!Java.available) {
            throw new Error('JavaHelper not available!');
        }
    }

    invalidateClassCache = () => {
        this.classCache = new Array<string>();
    }

    enumerateLoadedClasses = (useCache: boolean = false) => {
        trace('JavaHelper::enumerateLoadedClasses()');

        this.checkRequirements();

        if (useCache && this.classCache.length) {
            //TODO: whats the reason for the loop { send } and not doing send(classes)? or was it too big?
            /*Dwarf.loggedSend('enumerate_java_classes_start:::');
            for (let i = 0; i < LogicJava.javaClasses.length; i++) {
                send('enumerate_java_classes_match:::' + LogicJava.javaClasses[i]);
            }
            Dwarf.loggedSend('enumerate_java_classes_complete:::');*/
            return this.classCache;
        } else {
            /*Java.performNow(function () {
                Dwarf.loggedSend('enumerate_java_classes_start:::');
                try {
                    Java.enumerateLoadedClasses({
                        onMatch: function (className) {
                            if (LogicJava !== null) {
                                LogicJava.javaClasses.push(className);
                            }
                            send('enumerate_java_classes_match:::' + className);
                        },
                        onComplete: function () {
                            send('enumerate_java_classes_complete:::');
                        }
                    });
                } catch (e) {
                    logErr('enumerateJavaClasses', e);
                    Dwarf.loggedSend('enumerate_java_classes_complete:::');
                }
            });*/
            this.invalidateClassCache();

            Java.performNow(() => {
                try {
                    Java.enumerateLoadedClasses({
                        onMatch: (className) => {
                            this.classCache.push(className);
                        },
                        onComplete: () => {
                            return this.classCache;
                        }
                    });
                } catch (e) {
                    logDebug('JavaHelper::enumerateLoadedClasses() => Error: ' + e);
                    return null;
                }
            });
        }
    }


    /**
     * @param  {string} className
     * @param  {Function} callback?
     * @param  {boolean=false} permanent when set to true removeClassLoaderHook wont delete hook
     * @returns boolean
     */
    public addClassLoaderHook = (className: string, callback?: Function | string, permanent: boolean = false): boolean => {
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
            if (permanent) {
                Object.defineProperty(this.javaClassLoaderCallbacks, className, { value: 'breakpoint', configurable: false, writable: false });
            } else {
                this.javaClassLoaderCallbacks[className] = 'breakpoint';
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