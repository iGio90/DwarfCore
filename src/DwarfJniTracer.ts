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
import { JNI_TEMPLATES } from "./_jni_templates";

export class DwarfJniTracer {
    private _listeners: InvocationListener[];

    constructor() {
        trace("DwarfJniTracer()");

        this._listeners = new Array<InvocationListener>(JNI_Functions.GetObjectRefType);
        for (let i = 0; i < this._listeners.length; i++) {
            this._listeners[i] = null;
        }

        DwarfCore.getInstance().sync({
            JNITracer: {
                available: Object.keys(JNI_TEMPLATES),
            },
        });
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

    traceFunction = (fncIdx: JNI_Functions, sync: boolean = true) => {
        trace("DwarfJniTracer::traceFunction()");

        if (fncIdx <= JNI_Functions.reserved3 || fncIdx > JNI_Functions.GetObjectRefType) {
            throw new Error("JNITracer: Invalid function!");
        }

        if (this._listeners[fncIdx] !== null) {
            throw new Error("JNITracer: already tracing");
        }

        this._listeners[fncIdx] = Interceptor.attach(getJNIFuncPtr(fncIdx), Object.values(JNI_TEMPLATES)[fncIdx]);

        if (sync) {
            this._syncUI();
        }
    };

    traceFunctions = (funcs: JNI_Functions[]) => {
        trace("DwarfJniTracer::traceFunctions()");

        if (typeof funcs === "number") {
            return this.traceFunction(funcs);
        }

        for(const func of funcs) {
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
