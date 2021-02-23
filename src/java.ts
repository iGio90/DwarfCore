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

import { DwarfHookType } from "./consts";
import { JavaHook } from "./types/java_hook";
import { DwarfHooksManager } from "./DwarfHooksManager";
import { DwarfCore } from "./DwarfCore";

/**
 * @internal
 */
export class DwarfJavaHelper {

    protected classCache: string[];
    protected excludedClasses: string[];

    // Singleton
    static getInstance() {
        if (!DwarfJavaHelper.instanceRef) {
            DwarfJavaHelper.instanceRef = new DwarfJavaHelper();
        }
        return DwarfJavaHelper.instanceRef;
    }
    protected hooksToAttach: JavaHook[];
    protected initDone: boolean;
    /*protected javaClassLoaderCallbacks: {
        [index: string]: ScriptInvocationListenerCallbacks | fArgReturn | string;
    };*/
    protected oldOverloads: { [index: string]: fArgReturn | fArgReturn[] };
    protected sdkVersion: number;
    private static instanceRef: DwarfJavaHelper;

    private constructor() {
        if (DwarfJavaHelper.instanceRef) {
            throw new Error("JavaHelper already exists! Use DwarfJavaHelper.getInstance()/Dwarf.getJavaHelper()");
        }
        trace("DwarfJavaHelper()");

        this.classCache = new Array<string>();
        this.sdkVersion = 0;
        // this.javaClassLoaderCallbacks = {};
        this.oldOverloads = {};
        this.hooksToAttach = new Array<JavaHook>();
        this.initDone = false;
        this.excludedClasses = ["android.", "com.android", "java.lang", "java.io"];
    }

    addHookToAttach = (javaHook: JavaHook) => {
        trace("DwarfJavaHelper::addHookToAttach()");

        if (javaHook.getType() === DwarfHookType.JAVA && !javaHook.isAttached()) {
            this.hooksToAttach.push(javaHook);
        }
    };

    // add other stuff when needed
    checkRequirements = () => {
        if (!Java.available) {
            throw new Error("JavaHelper not available!");
        }
    };

    detach = () => {
        this.checkRequirements();
        Java.performNow(function () {
            const ClassLoader = Java.use("java.lang.ClassLoader");
            ClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = null;
        });
    };

    enumerateDexClasses = (packagePath?: string) => {
        trace("DwarfJavaHelper::enumerateDexClasses()");
        const self = this;

        this.checkRequirements();

        const dexClasses = new Array<string>();
        return dexClasses;

        Java.performNow(function () {
            try {
                if (!isString(packagePath)) {
                    const appContext = self.getApplicationContext();
                    const apkPath = appContext.getPackageCodePath();
                    packagePath = apkPath;
                }
                const ZipFile = Java.use("java.util.zip.ZipFile");
                const FileOutputStream = Java.use("java.io.FileOutputStream");
                const BufferedInputStream = Java.use("java.io.BufferedInputStream");
                const BufferedOutputStream = Java.use("java.io.BufferedOutputStream");
                const apkZip = ZipFile.$new(packagePath);
                const zipEntries = apkZip.entries();

                while (zipEntries.hasMoreElements()) {
                    const zipEntry = zipEntries.nextElement().toString();
                    if (zipEntry.indexOf(".dex") !== -1) {
                        const inputStream = BufferedInputStream.$new(apkZip.getInputStream(apkZip.getEntry(zipEntry)), 1024);
                        const outputStream = BufferedOutputStream.$new(
                            FileOutputStream.$new("/data/data/" + DwarfCore.getInstance().getProcessInfo().getName() + "/" + zipEntry),
                            1024
                        );
                        const read = 0;
                        while (true) {
                            const b = inputStream.read();
                            if (b === -1) {
                                break;
                            }
                            outputStream.write(b);
                        }
                        outputStream.flush();
                        inputStream.close();
                        outputStream.close();
                        console.log(Java.openClassFile("/data/data/" + DwarfCore.getInstance().getProcessInfo().getName() + "/" + zipEntry).getClassNames());
                    }
                }

                apkZip.close();

                /*console.log(Java.openClassFile(packagePath).getClassNames());
                const DexFile = Java.use("dalvik.system.DexFile");
                const dexFile = DexFile.$new(packagePath);
                const enumeration = dexFile.entries();

                while (enumeration.hasMoreElements()) {
                    const className = enumeration.nextElement();
                    dexClasses.push(className.toString());
                }
                dexFile.$dispose();
                DexFile.$dispose();*/
            } catch (e) {
                logErr("enumerateDexClasses() -> ", e);
            }
        });

        Java.performNow(function () {
            try {
                if (!isString(packagePath)) {
                    const appContext = self.getApplicationContext();
                    const apkPath = appContext.getPackageCodePath();
                    packagePath = apkPath;
                }
                console.log(Java.openClassFile(packagePath).getClassNames());
                const DexFile = Java.use("dalvik.system.DexFile");
                const dexFile = DexFile.$new(packagePath);
                const enumeration = dexFile.entries();

                while (enumeration.hasMoreElements()) {
                    const className = enumeration.nextElement();
                    dexClasses.push(className.toString());
                }
                dexFile.$dispose();
                DexFile.$dispose();
            } catch (e) {
                logErr("enumerateDexClasses() -> ", e);
            }
        });
        return dexClasses;
    };

    enumerateLoadedClassesUI = () => {
        trace("JavaHelper::enumerateLoadedClassesUI()");

        this.checkRequirements();
        this.invalidateClassCache();

        const self = this;

        Java.performNow(function () {
            try {
                Java.enumerateLoadedClasses({
                    onMatch: (className) => {
                        self.classCache.push(className);
                    },
                    onComplete: () => {
                        DwarfCore.getInstance().sync({ loadedJavaClasses: self.classCache });
                    },
                });
            } catch (e) {
                logDebug("JavaHelper::enumerateLoadedClassesUI() => Error: " + e);
            }
        });
    };

    getApplicationContext = (): any => {
        trace("JavaHelper::getApplicationContext()");

        this.checkRequirements();

        const ActivityThread = Java.use("android.app.ActivityThread");
        return ActivityThread.currentApplication().getApplicationContext();
    };

    getClassMethods = (className: string): string[] => {
        trace("DwarfJavaHelper::getClassMethods()");

        this.checkRequirements();

        const parsedMethods: string[] = new Array<string>();

        Java.performNow(() => {
            try {
                const clazz = Java.use(className);
                const methods: Java.Method[] = clazz.class.getDeclaredMethods();
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
            return uniqueBy(parsedMethods);
        } else {
            return new Array();
        }
    };

    getClassMethodsUI = (className: string) => {
        trace("DwarfJavaHelper::getClassMethodsUI()");

        this.checkRequirements();

        const parsedMethods: string[] = new Array<string>();

        Java.performNow(() => {
            try {
                const clazz = Java.use(className);
                const methods: Java.Method[] = clazz.class.getDeclaredMethods();
                clazz.$dispose();

                for (const method of methods) {
                    const methodStr = method.toString().replace(className + ".", "");
                    parsedMethods.push(methodStr.substring(0, methodStr.indexOf(")") + 1));
                }
            } catch (e) {
                logErr("DwarfJavaHelper::getClassMethodsUI()", e);
            }
        });
        return DwarfCore.getInstance().sync({ class_methods: parsedMethods });
    };

    hookInJVM = (className: string, methodName: string = "$init", implementation: fArgReturn) => {
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
                        for(const overload of overloads) {
                            const parameters = [];
                            let returnType;
                            if (overload.hasOwnProperty("argumentTypes")) {
                                for (const arg of overload.argumentTypes) {
                                    parameters.push(arg.className);
                                }
                            }
                            if (overload.hasOwnProperty("returnType")) {
                                returnType = overload.returnType.className;
                            }
                            overload.implementation = function () {
                                this.types = parameters;
                                this.retType = returnType;
                                const args = [].slice.call(arguments);
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

    /*public javaPerform = (fn: () => void) => {
        logDebug("Using performnow");
        return Java.performNow(function() { fn(); });
    };*/

    public initalize = (packagePath?: string) => {
        if (this.initDone) {
            logDebug("DwarfJavaHelper => Init already done!");
        }
        trace("DwarfJavaHelper::initialize()");

        this.checkRequirements();

        this.sdkVersion = DwarfCore.getInstance().getAndroidApiLevel();

        const self = this;
        Java.performNow(function () {
            // class loader
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

                    // handle classLoadHooks enter
                    const dwarfHook = DwarfHooksManager.getInstance().getHookByAddress(className, true, DwarfHookType.CLASS_LOAD);

                    if (isDefined(dwarfHook)) {
                        dwarfHook.onEnterCallback(dwarfHook, this, arguments);
                    }

                    // load class
                    const result = this.loadClass(className, resolve);

                    // handle classLoadHooks leave
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
                            self.hooksToAttach = self.hooksToAttach.filter((hook) => !hook.isAttached());
                        }
                    } catch (e) {
                        logErr("ClassLoader::loadClass", e);
                    }

                    // sync ui
                    DwarfCore.getInstance().sync(syncMsg);

                    return result;
                } catch (e) {
                    if (e.message.indexOf("java.lang.ClassNotFoundException") !== -1) {
                        throw e;
                    }
                    logDebug(e);
                }
            };
        });

        this.initClassCache(packagePath);
        this.initDone = true;
    };

    initClassCache = (packagePath?: string) => {
        trace("JavaHelper::initClassCache()");
        this.checkRequirements();
        this.invalidateClassCache();

        const self = this;

        const dexClasses = self.enumerateDexClasses(packagePath);
        self.updateClassCache(function (loadedClasses) {
            DwarfCore.getInstance().sync({ dexClasses, loadedClasses });
        });
    };

    invalidateClassCache = () => {
        trace("JavaHelper::invalidateClassCache()");
        this.classCache = new Array<string>();
    };

    public jvmExplore = (what?: any) => {
        if (!isDefined(what)) {
            // TODO: implement
        }
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
                            for (let i = 0; i < overloadCount; i++) {
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

    traceHandler = () => {
        /*let result = null;
        self.onEnterCallback(self, this, arguments);

        result = this[methodName].apply(this, arguments);

        self.onLeaveCallback(self, this, result);
        return result;*/
    };

    updateClassCache = (fnCallback: fArgVoid) => {
        trace("JavaHelper::updateClassCache()");
        this.checkRequirements();

        const self = this;
        Java.performNow(function () {
            try {
                Java.enumerateLoadedClasses({
                    onMatch: (className) => {
                        self.classCache.push(className);
                    },
                    onComplete: () => {
                        if (isFunction(fnCallback)) {
                            fnCallback(self.classCache);
                        }
                    },
                });
            } catch (e) {
                logDebug("JavaHelper::updateClassCache() => Error: " + e);
            }
        });
    };
}
