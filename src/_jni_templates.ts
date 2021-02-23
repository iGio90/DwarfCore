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

import { DwarfCore } from "./DwarfCore";

/*
    based on
    https://github.com/mapbox/jni.hpp/blob/master/test/openjdk/jni.h
    https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html
*/

// TODO: autoparse header

export const JNI_TEMPLATES = {
    reserved0: {},
    reserved1: {},
    reserved2: {},
    reserved3: {},

    GetVersion: {
        onEnter (args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    func: "jint GetVersion(JNIEnv*)",
                    args: { 0: args[0] },
                },
            });
        },
        onLeave (retval) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    func: "jint GetVersion(JNIEnv*)",
                    return: retval,
                },
            });
        },
    },

    DefineClass: {
        onEnter (args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    func: "jclass DefineClass(JNIEnv *env, const char *name, jobject loader, const jbyte *buf, jsize len)",
                    args: { 0: args[0], 1: args[1].readCString(), 2: args[2], 3: args[3], 4: args[4], 5: args[5] },
                },
            });
        },
        onLeave (retval) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    func: "jclass DefineClass(JNIEnv *env, const char *name, jobject loader, const jbyte *buf, jsize len)",
                    return: retval,
                },
            });
        },
    },

    findClass: {
        onEnter (args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    func: "jclass FindClass(JNIEnv*, const char*)",
                    args: { 0: args[0], 1: args[1].readCString() },
                },
            });
        },
        onLeave (retval) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    func: "jclass FindClass(JNIEnv*, const char*)",
                    return: retval,
                },
            });
        },
    },
};
