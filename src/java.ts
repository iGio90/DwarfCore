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

import { DwarfHookType } from "./consts";
import { JavaHook } from "./types/java_hook";
import { DwarfHooksManager } from "./hooks_manager";

export class DwarfJavaHelper {
    private static instanceRef: DwarfJavaHelper;

    protected classCache: Array<string>;
    protected javaClassLoaderCallbacks: {
        [index: string]: ScriptInvocationListenerCallbacks | Function | string;
    };
    protected oldOverloads: { [index: string]: Function | Array<Function> };
    protected sdk_version: number;
    protected initDone: boolean;
    protected hooksToAttach: Array<JavaHook>;
    protected excludedClasses: Array<string>;

    private constructor() {
        if (DwarfJavaHelper.instanceRef) {
            throw new Error("JavaHelper already exists! Use DwarfJavaHelper.getInstance()/Dwarf.getJavaHelper()");
        }
        trace("DwarfJavaHelper()");

        this.classCache = new Array<string>();
        this.sdk_version = 0;
        this.javaClassLoaderCallbacks = {};
        this.oldOverloads = {};
        this.hooksToAttach = new Array<JavaHook>();
        this.initDone = false;
        this.excludedClasses = ["android.", "com.android", "java.lang", "java.io"];
    }

    //Singleton
    static getInstance() {
        if (!DwarfJavaHelper.instanceRef) {
            DwarfJavaHelper.instanceRef = new DwarfJavaHelper();
        }
        return DwarfJavaHelper.instanceRef;
    }

    /*public javaPerform = (fn: () => void) => {
        logDebug("Using performnow");
        return Java.performNow(function() { fn(); });
    };*/

    public initalize = () => {
        if (this.initDone) {
            logDebug("DwarfJavaHelper => Init already done!");
        }
        trace("DwarfJavaHelper::initialize()");

        this.checkRequirements();

        this.sdk_version = Dwarf.getAndroidApiLevel();

        const self = this;
        Java.performNow(function () {
            //class loader
            const ClassLoader = Java.use("java.lang.ClassLoader");

            ClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = function (className: string, resolve: boolean) {
                try {
                    let syncMsg = {};

                    if (self.classCache.indexOf(className) === -1) {
                        self.classCache.push(className);
                    }

                    syncMsg = Object.assign(syncMsg, {
                        javaClassLoaded: className,
                    });

                    //handle classLoadHooks enter
                    const dwarfHook = DwarfHooksManager.getInstance().getHookByAddress(className, true, DwarfHookType.CLASS_LOAD);

                    if (isDefined(dwarfHook)) {
                        dwarfHook.onEnterCallback(dwarfHook, this, arguments);
                    }

                    //load class
                    let result = this.loadClass(className, resolve);

                    //handle classLoadHooks leave
                    if (isDefined(dwarfHook)) {
                        dwarfHook.onLeaveCallback(dwarfHook, this, result);
                    }

                    try {
                        if (self.hooksToAttach.length > 0) {
                            self.hooksToAttach.forEach((javaHook) => {
                                if (!javaHook.isAttached()) {
                                    javaHook.setup();
                                    syncMsg = Object.assign(syncMsg, {
                                        dwarfHooks: DwarfHooksManager.getInstance().getHooks(),
                                    });
                                }
                            });
                            self.hooksToAttach = self.hooksToAttach.filter((dwarfHook) => !dwarfHook.isAttached());
                        }
                    } catch (e) {}

                    //sync ui
                    Dwarf.sync(syncMsg);

                    return result;
                } catch (e) {
                    if (e.message.indexOf("java.lang.ClassNotFoundException") !== -1) {
                        throw e;
                    }
                    logDebug(e);
                }
            };
        });

        this.initDone = true;
    };

    detach = () => {
        this.checkRequirements();
        Java.performNow(function () {
            const ClassLoader = Java.use("java.lang.ClassLoader");
            ClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = null;
        });
    };

    //add other stuff when needed
    checkRequirements = () => {
        if (!Java.available) {
            throw new Error("JavaHelper not available!");
        }
    };

    invalidateClassCache = () => {
        trace("JavaHelper::invalidateClassCache()");
        this.classCache = new Array<string>();
    };

    getApplicationContext = (): any => {
        trace("JavaHelper::getApplicationContext()");

        this.checkRequirements();

        const ActivityThread = Java.use("android.app.ActivityThread");
        return ActivityThread.currentApplication().getApplicationContext();
    };

    getClassMethods = (className: string, syncUi: boolean = false): Array<string> => {
        trace("DwarfJavaHelper::getClassMethods()");

        this.checkRequirements();

        const parsedMethods: Array<string> = new Array<string>();

        Java.performNow(() => {
            try {
                const clazz = Java.use(className);
                const methods: Array<Java.Method> = clazz.class.getDeclaredMethods();
                clazz.$dispose();

                for (const method of methods) {
                    const methodName = method.toString().replace(className + ".", "TOKEN");
                    const regexMatch = methodName.match(/\sTOKEN(.*)\(/);

                    if (regexMatch && regexMatch.length >= 2) {
                        parsedMethods.push(regexMatch[1]);
                    }
                }
            } catch (e) {
                logErr("DwarfJavaHelper::getClassMethods()", e);
            }
        });
        if (parsedMethods.length > 0) {
            if (syncUi) {
                return Dwarf.sync({ class_methods: uniqueBy(parsedMethods) });
            } else {
                return uniqueBy(parsedMethods);
            }
        } else {
            if (syncUi) {
                return Dwarf.sync({ class_methods: [] });
            } else {
                return new Array();
            }
        }
    };

    enumerateLoadedClasses = (useCache: boolean = false) => {
        trace("JavaHelper::enumerateLoadedClasses()");

        this.checkRequirements();

        const self = this;

        if (useCache && this.classCache.length) {
            //return this.classCache;
            Dwarf.sync({ java_classes: self.classCache, cached: useCache });
        } else {
            this.invalidateClassCache();

            Java.performNow(function () {
                try {
                    Java.enumerateLoadedClasses({
                        onMatch: (className) => {
                            self.classCache.push(className);
                        },
                        onComplete: () => {
                            let syncMsg = {
                                java_classes: self.classCache,
                                cached: useCache,
                            };
                            Dwarf.sync(syncMsg);
                        },
                    });
                } catch (e) {
                    logDebug("JavaHelper::enumerateLoadedClasses() => Error: " + e);
                }
            });
        }
    };

    enumerateDexClasses = () => {
        trace("DwarfJavaHelper::enumerateDexClasses()");
        const self = this;

        this.checkRequirements();

        const dexClasses = new Array<string>();

        Java.performNow(function () {
            try {
                const appContext = self.getApplicationContext();
                const apkPath = appContext.getPackageCodePath();
                const DexFile = Java.use("dalvik.system.DexFile");

                const dexFile = DexFile.$new(apkPath);
                const enumeration = dexFile.entries();

                while (enumeration.hasMoreElements()) {
                    const className = enumeration.nextElement();
                    dexClasses.push(className.toString());
                }
                dexFile.$dispose();
                DexFile.$dispose();

                Dwarf.sync({ dexClasses: dexClasses });
            } catch (e) {
                logErr("enumerateDexClasses() -> ", e);
            }
        });
        return dexClasses;
    };

    hookInJVM = (className: string, methodName: string = "$init", implementation: Function) => {
        trace("DwarfJavaHelper::hookInJVM()");

        this.checkRequirements();

        if (!isString(className)) {
            throw new Error("DwarfJavaHelper::hookInJVM() => Invalid arguments! -> className");
        }

        if (!isString(methodName)) {
            throw new Error("DwarfJavaHelper::hookInJVM() => Invalid arguments! -> methodName");
        }

        if (!isFunction(implementation)) {
            throw new Error("DwarfJavaHelper::hookInJVM() => Invalid arguments! -> implementation");
        }

        const self = this;
        Java.performNow(function () {
            try {
                const javaWrapper = Java.use(className);

                if (isDefined(javaWrapper) && isDefined(javaWrapper[methodName])) {
                    try {
                        const overloads = javaWrapper[methodName].overloads;
                        for (let i in overloads) {
                            const overload = overloads[i];
                            let parameters = [];
                            if (overload.hasOwnProperty("argumentTypes")) {
                                for (let j in overload.argumentTypes) {
                                    parameters.push(overload.argumentTypes[j].className);
                                }
                            }
                            overload.implementation = function () {
                                this.types = parameters;
                                var args = [].slice.call(arguments);
                                return implementation.apply(this, args);
                            };
                        }
                    } catch (e) {
                        logDebug("DwarfJavaHelper::hookInJVM() => overload failed -> " + e);
                    }
                } else {
                    throw new Error("DwarfJavaHelper::hookInJVM() => " + (className + "." + methodName) + " not found!");
                }
            } catch (e) {
                logDebug("DwarfJavaHelper::hookInJVM() => Error: " + e);
                throw new Error("DwarfJavaHelper::hookInJVM() => Unable to find class: " + className);
            }
        });
    };

    restoreInJVM = (className: string, methodName: string) => {
        trace("DwarfJavaHelper::restoreInJVM()");

        this.checkRequirements();

        if (!isString(className)) {
            throw new Error("DwarfJavaHelper::restoreInJVM() => Invalid arguments! -> className");
        }

        if (!isString(methodName)) {
            throw new Error("DwarfJavaHelper::restoreInJVM() => Invalid arguments! -> methodName");
        }

        const self = this;

        Java.performNow(function () {
            try {
                const javaWrapper = Java.use(className);

                if (isDefined(javaWrapper) && isDefined(javaWrapper[methodName])) {
                    try {
                        const overloadCount = javaWrapper[methodName].overloads.length;
                        if (overloadCount > 0) {
                            for (var i = 0; i < overloadCount; i++) {
                                javaWrapper[methodName].overloads[i].implementation = null;
                                if (self.oldOverloads.hasOwnProperty(className + "." + methodName)) {
                                    if (i < self.oldOverloads[className + "." + methodName].length) {
                                        const oldImplementation = self.oldOverloads[className + "." + methodName][i];
                                        javaWrapper[methodName].overloads[i].implementation = oldImplementation;
                                    } else {
                                        javaWrapper[methodName].overloads[i].implementation = null;
                                    }
                                } else {
                                    javaWrapper[methodName].overloads[i].implementation = null;
                                }
                            }
                            if (self.oldOverloads.hasOwnProperty(className + "." + methodName)) {
                                delete self.oldOverloads[className + "." + methodName];
                            }
                        } else {
                            javaWrapper[methodName].overload.implementation = null;
                        }
                    } catch (e) {
                        logDebug("DwarfJavaHelper::restoreInJVM() => overload failed -> " + e);
                    }
                } else {
                    throw new Error("DwarfJavaHelper::restoreInJVM() => " + (className + "." + methodName) + " not found!");
                }
            } catch (e) {
                logDebug("DwarfJavaHelper::restoreInJVM() => Error: " + e);
                throw new Error("DwarfJavaHelper::restoreInJVM() => Unable to find class: " + className);
            }
        });
    };

    addHookToAttach = (javaHook: JavaHook) => {
        trace("DwarfJavaHelper::addHookToAttach()");

        if (javaHook.getType() == DwarfHookType.JAVA) {
            this.hooksToAttach.push(javaHook);
        }
    };

    public jvmExplore = (what?: any) => {
        if (!isDefined(what)) {
        }
    };

    traceHandler = () => {
        /*let result = null;
        self.onEnterCallback(self, this, arguments);

        result = this[methodName].apply(this, arguments);

        self.onLeaveCallback(self, this, result);
        return result;*/
    };
}
