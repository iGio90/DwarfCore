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

//based on
//https://github.com/mapbox/jni.hpp/blob/master/test/openjdk/jni.h
//https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html
import { JNI_Functions } from "./consts";
import { JNI_TEMPLATES } from "./_jni_templates";

export class DwarfJniTracer {
    protected _vm_env;
    private _listeners: Array<InvocationListener>;

    constructor() {
        if (!this._vm_env) {
            this._vm_env = Java.vm.getEnv();
        }
        this._listeners = new Array<InvocationListener>(JNI_Functions.GetObjectRefType);
        for (let i = 0; i < this._listeners.length; i++) {
            this._listeners[i] = null;
        }
    }

    private _getNativeFuncPtr = (index: number): NativePointer => {
        if (index <= JNI_Functions.reserved3 || index > JNI_Functions.GetObjectRefType) {
            throw new Error("JNITracer: Invalid function!");
        }
        return this._vm_env.handle
            .readPointer()
            .add(index * Process.pointerSize)
            .readPointer();
    };

    disableTracer = () => {
        for (let i = 0; i < this._listeners.length; i++) {
            if (this._listeners[i] !== null) {
                this._listeners[i].detach();
                this._listeners[i] = null;
            }
        }
        Interceptor.flush();
    };

    traceFunction = (fncIdx: JNI_Functions) => {
        if (fncIdx <= JNI_Functions.reserved3 || fncIdx > JNI_Functions.GetObjectRefType) {
            throw new Error("JNITracer: Invalid function!");
        }

        if (this._listeners[fncIdx] !== null) {
            throw new Error("JNITracer: already tracing");
        }

        this._listeners[fncIdx] = Interceptor.attach(this._getNativeFuncPtr(fncIdx), Object.values(JNI_TEMPLATES)[fncIdx]);
    };

    removeTrace = (fncIdx: JNI_Functions) => {
        if (fncIdx <= JNI_Functions.reserved3 || fncIdx > JNI_Functions.GetObjectRefType) {
            throw new Error("JNITracer: Invalid function!");
        }
        if (this._listeners[fncIdx] !== null) {
            this._listeners[fncIdx].detach();
            this._listeners[fncIdx] = null;
        }
    };
}
