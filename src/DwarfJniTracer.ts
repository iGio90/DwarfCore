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
import { JNI_Functions } from "./consts";
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

        this._listeners = new Array<InvocationListener>(JNI_Functions.GetObjectRefType);
        for (let i = 0; i < this._listeners.length; i++) {
            this._listeners[i] = null;
        }

        // TODO: maxstack exceeded???
        /*DwarfCore.getInstance().sync({
            JNITracer: {
                available: Object.keys(JNI_FUNCDECLS),
            },
        });*/
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

    removeTrace = (fncIdx: JNI_Functions) => {
        trace("DwarfJniTracer::removeTrace()");

        if (fncIdx <= JNI_Functions.reserved3 || fncIdx > JNI_Functions.GetObjectRefType) {
            throw new Error("JNITracer: Invalid function!");
        }
        if (this._listeners[fncIdx] !== null) {
            this._listeners[fncIdx].detach();
            this._listeners[fncIdx] = null;
        }

        Interceptor.flush();
        this._syncUI();
    };

    traceFunction = (fncIdx: number | string, sync: boolean = true) => {
        trace("DwarfJniTracer::traceFunction()");

        if (isNumber(fncIdx)) {
            if (fncIdx < 0 || fncIdx > JNI_Functions.GetObjectRefType) {
                throw new Error("JNITracer: Invalid function!");
            }
        } else if (isString(fncIdx)) {
            if (!JNI_FUNCDECLS.hasOwnProperty(fncIdx)) {
                throw new Error("JNITracer: Invalid function!");
            }
            fncIdx = Object.keys(JNI_FUNCDECLS).indexOf(fncIdx as string);
            if (fncIdx < 0 || fncIdx > JNI_Functions.GetObjectRefType) {
                throw new Error("JNITracer: Invalid function!");
            }
        }

        if (this._listeners[fncIdx] !== null) {
            throw new Error("JNITracer: already tracing");
        }

        const jniFuncDef = Object.entries(JNI_FUNCDECLS)[fncIdx];

        let jniFuncStr = "" + jniFuncDef[1].type + " " + jniFuncDef[0] + "(";

        jniFuncDef[1].args.forEach((arg) => {
            jniFuncStr += arg.type + " " + arg.name + ", ";
        });

        jniFuncStr += ")";
        jniFuncStr = jniFuncStr.replace(", )", "");

        this._listeners[fncIdx] = Interceptor.attach(getJNIFuncPtr(fncIdx as number), {
            onEnter(args) {
                const defArgs = jniFuncDef[1].args;
                const inArgs = [];

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
                        in: jniFuncStr,
                        args: inArgs,
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
                        out: jniFuncStr,
                        return: outVal,
                    },
                });
            },
        });

        if (sync) {
            this._syncUI();
        }
    };

    traceFunctions = (funcs: number[] | string[]) => {
        trace("DwarfJniTracer::traceFunctions()");

        if (typeof funcs === "number") {
            return this.traceFunction(funcs);
        }

        if (typeof funcs === "string" && JNI_FUNCDECLS.hasOwnProperty(funcs)) {
            return this.traceFunction(funcs);
        }

        for (const func of funcs) {
            this.traceFunction(func, false);
        }

        this._syncUI();
    };

    private _syncUI = () => {
        DwarfCore.getInstance().sync({
            JNITracer: {
                enabled: this._listeners.map((val) => (val !== null ? 1 : 0)),
            },
        });
    };
}
