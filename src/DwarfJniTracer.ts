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

/*
    based on
    https://github.com/mapbox/jni.hpp/blob/master/test/openjdk/jni.h
    https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html
*/
import { DwarfCore } from "./DwarfCore";
import { JNI_FUNCDECLS } from "./_jni_funcs";

// TODO: remove templates and create handler at runtime > JNI_FUNCDECLS

export class DwarfJniTracer {
    private static instanceRef: DwarfJniTracer;
    private _listeners: InvocationListener[];

    /** @internal */
    static getInstance() {
        if (!DwarfJniTracer.instanceRef) {
            DwarfJniTracer.instanceRef = new this();
        }
        return DwarfJniTracer.instanceRef;
    }

    /** @internal */
    private constructor() {
        if (DwarfJniTracer.instanceRef) {
            throw new Error("DwarfJniTracer already exists! Use DwarfJniTracer.getInstance()/Dwarf.getJniTracer()");
        }

        trace("DwarfJniTracer()");

        this._listeners = new Array<InvocationListener>(Object.keys(JNI_FUNCDECLS).length);
        for (let i = 0; i < this._listeners.length; i++) {
            this._listeners[i] = null;
        }
    }

    removeAll = () => {
        trace("DwarfJniTracer::removeAll()");

        for (let i = 0; i < this._listeners.length; i++) {
            if (this._listeners[i] !== null) {
                this._listeners[i].detach();
                this._listeners[i] = null;
            }
        }

        Interceptor.flush();
        this._syncUI();
    };

    removeTrace = (funcs?: string | number | string[] | number[]) => {
        trace("DwarfJniTracer::removeTrace()");

        if (!isDefined(funcs) || (isString(funcs) && funcs === "all") || (isNumber(funcs) && funcs === -1)) {
            return this.removeAll();
        }

        let fnsToRemove = [];
        if (!Array.isArray(funcs)) {
            fnsToRemove.push(funcs);
        } else {
            fnsToRemove = funcs;
        }

        fnsToRemove
            .filter((fncIdx) => {
                if (isNumber(fncIdx)) {
                    if (fncIdx >= 0 || fncIdx < Object.keys(JNI_FUNCDECLS).length) {
                        return fncIdx;
                    } else {
                        console.log("Error: (JNITracer) -> Invalid function! > " + fncIdx);
                    }
                } else if (isString(fncIdx)) {
                    if (JNI_FUNCDECLS.hasOwnProperty(fncIdx)) {
                        fncIdx = Object.keys(JNI_FUNCDECLS).indexOf(fncIdx as string);
                        if (fncIdx >= 0 || fncIdx < Object.keys(JNI_FUNCDECLS).length) {
                            return fncIdx;
                        } else {
                            console.log("Error: (JNITracer) -> Invalid function! > " + fncIdx);
                        }
                    } else {
                        console.log("Error: (JNITracer) -> Invalid function! > " + fncIdx);
                    }
                }
            })
            .forEach((fncIdx) => {
                if (this._listeners[fncIdx] === null) {
                    console.log("Error: (JNITracer) -> Not tracing! > " + fncIdx);
                } else {
                    this._listeners[fncIdx].detach();
                    this._listeners[fncIdx] = null;
                }
            });

        if (fnsToRemove.length) {
            Interceptor.flush();
            this._syncUI();
        }
    };

    // TODO: allow custom callbacks?
    traceFunction = (funcs: number | string | number[] | string[]) => {
        trace("DwarfJniTracer::traceFunction()");

        let fnsToHook = [];
        if (!Array.isArray(funcs)) {
            fnsToHook.push(funcs);
        } else {
            fnsToHook = funcs;
        }

        fnsToHook
            .filter((fncIdx) => {
                if (isNumber(fncIdx)) {
                    if (fncIdx >= 0 || fncIdx < Object.keys(JNI_FUNCDECLS).length) {
                        if (this._listeners[fncIdx] === null) {
                            return fncIdx;
                        } else {
                            console.log("Error: (JNITracer) -> Already tracing: " + Object.entries(JNI_FUNCDECLS)[fncIdx][0]);
                        }
                    } else {
                        console.log("Error: (JNITracer) -> Invalid function! > " + fncIdx);
                    }
                } else if (isString(fncIdx)) {
                    if (JNI_FUNCDECLS.hasOwnProperty(fncIdx)) {
                        fncIdx = Object.keys(JNI_FUNCDECLS).indexOf(fncIdx as string);
                        if (fncIdx >= 0 || fncIdx < Object.keys(JNI_FUNCDECLS).length) {
                            if (this._listeners[fncIdx] === null) {
                                return fncIdx;
                            } else {
                                console.log("Error: (JNITracer) -> Already tracing: " + Object.entries(JNI_FUNCDECLS)[fncIdx][0]);
                            }
                        } else {
                            console.log("Error: (JNITracer) -> Invalid function! > " + fncIdx);
                        }
                    } else {
                        console.log("Error: (JNITracer) -> Invalid function! > " + fncIdx);
                    }
                }
            })
            .forEach((fncIdx: number) => {
                const jniFuncDef = Object.entries(JNI_FUNCDECLS)[fncIdx];

                if (this._listeners[fncIdx] === null) {
                    let jniFuncStr = "" + jniFuncDef[1].type + " " + jniFuncDef[0] + "(";

                    if (Array.isArray(jniFuncDef[1].args) && jniFuncDef[1].args.length) {
                        const fnArgs = jniFuncDef[1].args as { name: string; type: string }[];
                        jniFuncStr += fnArgs
                            .map((arg) => {
                                return arg.type + " " + arg.name;
                            })
                            .join(", ");
                    }

                    jniFuncStr += ")";

                    const rnd = Math.floor(Math.random() * Date.now());

                    this._listeners[fncIdx] = Interceptor.attach(getJNIFuncPtr(fncIdx as number), {
                        onEnter(args) {
                            const defArgs = jniFuncDef[1].args;
                            const inArgs = [];

                            this._cid = Date.now() + rnd;

                            for (const arg of defArgs) {
                                let tsValue = "";
                                if (arg.type.indexOf("char") !== -1) {
                                    tsValue = args[inArgs.length].readCString();
                                }
                                inArgs.push({
                                    type: arg.type,
                                    name: arg.name,
                                    value: args[inArgs.length],
                                    ts: tsValue,
                                });
                            }
                            DwarfCore.getInstance().sync({
                                JNITracer: {
                                    id: fncIdx,
                                    in: jniFuncStr,
                                    args: inArgs,
                                    time: Date.now(),
                                    cid: this._cid,
                                },
                            });
                        },
                        onLeave(retVal) {
                            const outVal = { type: jniFuncDef[1].type, value: retVal, ts: "" };
                            if (outVal.type.indexOf("char") !== -1) {
                                outVal.ts = retVal.readCString();
                            }
                            DwarfCore.getInstance().sync({
                                JNITracer: {
                                    id: fncIdx,
                                    out: jniFuncStr,
                                    return: outVal,
                                    time: Date.now(),
                                    cid: this._cid,
                                },
                            });
                        },
                    });
                }
            });

        if (fnsToHook.length) {
            Interceptor.flush();
            this._syncUI();
        }
    };

    private _syncUI = () => {
        DwarfCore.getInstance().sync({
            JNITracer: {
                enabled: this._listeners.map((val) => (val !== null ? 1 : 0)),
            },
        });
    };
}
