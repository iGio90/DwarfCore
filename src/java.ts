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

import { DwarfHaltReason, DwarfHookType } from "./consts";
import { JavaHook } from "./types/java_hook";
import { DwarfHooksManager } from "./hooks_manager";
import { ClassLoadHook } from "./types/class_load_hook";

export class DwarfJavaHelper {
    private static instanceRef: DwarfJavaHelper;

    protected classCache: Array<string>;
    protected javaClassLoaderCallbacks: { [index: string]: ScriptInvocationListenerCallbacks | Function | string };
    protected oldOverloads: { [index: string]: Function | Array<Function> };
    protected sdk_version: number;
    protected initDone: boolean;
    protected hooksToAttach: Array<JavaHook>;

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
    }

    //Singleton
    static getInstance() {
        if (Java.available) {
            if (!DwarfJavaHelper.instanceRef) {
                DwarfJavaHelper.instanceRef = new DwarfJavaHelper();
            }
            return DwarfJavaHelper.instanceRef;
        } else {
            throw new Error("JavaHelper not available!");
        }
    }

    public initalize = () => {
        if (this.initDone) {
            logDebug("DwarfJavaHelper => Init already done!");
        }
        trace("DwarfJavaHelper::initialize()");

        this.checkRequirements();

        this.sdk_version = Dwarf.getAndroidApiLevel();

        const self = this;

        Java.performNow(() => {
            logDebug("initializing logicJava with sdk: " + this.sdk_version);

            //class loader
            const ClassLoader = Java.use("java.lang.ClassLoader");

            ClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = function(
                className: string,
                resolve: boolean
            ) {
                try {
                    if (self.classCache.indexOf(className) === -1) {
                        self.classCache.push(className);

                        if (self.hooksToAttach.length > 0) {
                            self.hooksToAttach.forEach(javaHook => {
                                if ((javaHook.getAddress() as string).indexOf(className) !== -1) {
                                    javaHook.setup();
                                    Dwarf.sync({ dwarfHooks: DwarfHooksManager.getInstance().getHooks() });
                                }
                            });
                            self.hooksToAttach = self.hooksToAttach.filter(dwarfHook => !dwarfHook.isHooked());
                        }
                        //sync ui
                        Dwarf.sync({ java_class_loaded: className });
                    }

                    //handle classLoadHooks enter
                    for(const dwarfHook of DwarfHooksManager.getInstance().getHooks()) {
                        if(dwarfHook.getType() === DwarfHookType.CLASS_LOAD) {
                            if(dwarfHook.getAddress() === className) {
                                dwarfHook.onEnterCallback(this, arguments);
                            }
                        }
                    }

                    //load class
                    let result = this.loadClass(className, resolve);

                    //handle classLoadHooks leave
                    for(const dwarfHook of DwarfHooksManager.getInstance().getHooks()) {
                        if(dwarfHook.getType() === DwarfHookType.CLASS_LOAD) {
                            if(dwarfHook.getAddress() === className) {
                                dwarfHook.onLeaveCallback(this, result);
                            }
                        }
                    }
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

        if (useCache && this.classCache.length) {
            //return this.classCache;
            Dwarf.sync({ java_classes: this.classCache, cached: useCache });
        } else {
            this.invalidateClassCache();

            Java.performNow(() => {
                try {
                    Java.enumerateLoadedClasses({
                        onMatch: className => {
                            this.classCache.push(className);
                        },
                        onComplete: () => {
                            Dwarf.sync({ java_classes: this.classCache, cached: useCache });
                        },
                    });
                } catch (e) {
                    logDebug("JavaHelper::enumerateLoadedClasses() => Error: " + e);
                }
            });
        }
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
        Java.performNow(function() {
            try {
                const javaWrapper = Java.use(className);

                if (isDefined(javaWrapper) && isDefined(javaWrapper[methodName])) {
                    try {
                        const overloads = javaWrapper[methodName].overloads;
                        for (let i in overloads) {
                            if (overloads[i].hasOwnProperty("argumentTypes")) {
                                const overload = javaWrapper[methodName].overloads[i];
                                var parameters = [];
                                for (let j in overload.argumentTypes) {
                                    parameters.push(overloads[i].argumentTypes[j].className);
                                }

                                javaWrapper[methodName].overloads[i].implementation = function() {
                                    this.types = parameters;
                                    var args = [].slice.call(arguments);
                                    return implementation.apply(this, args);
                                };
                            }
                        }
                    } catch (e) {
                        logDebug("DwarfJavaHelper::hookInJVM() => overload failed -> " + e);
                    }
                } else {
                    throw new Error(
                        "DwarfJavaHelper::hookInJVM() => " + (className + "." + methodName) + " not found!"
                    );
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

        Java.performNow(() => {
            try {
                const javaWrapper = Java.use(className);

                if (isDefined(javaWrapper) && isDefined(javaWrapper[methodName])) {
                    try {
                        const overloadCount = javaWrapper[methodName].overloads.length;
                        if (overloadCount > 0) {
                            for (var i = 0; i < overloadCount; i++) {
                                if (this.oldOverloads.hasOwnProperty(className + "." + methodName)) {
                                    if (i < this.oldOverloads[className + "." + methodName].length) {
                                        const oldImplementation = (this.oldOverloads[
                                            className + "." + methodName
                                        ] as Function[])[i];
                                        javaWrapper[methodName].overloads[i].implementation = oldImplementation;
                                    } else {
                                        javaWrapper[methodName].overloads[i].implementation = null;
                                    }
                                } else {
                                    javaWrapper[methodName].overloads[i].implementation = null;
                                }
                            }
                            if (this.oldOverloads.hasOwnProperty(className + "." + methodName)) {
                                delete this.oldOverloads[className + "." + methodName];
                            }
                        } else {
                            javaWrapper[methodName].overload.implementation = null;
                        }
                    } catch (e) {
                        logDebug("DwarfJavaHelper::restoreInJVM() => overload failed -> " + e);
                    }
                } else {
                    throw new Error(
                        "DwarfJavaHelper::restoreInJVM() => " + (className + "." + methodName) + " not found!"
                    );
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
}
