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

export const JNI_FUNCDECLS = {
    reserved0: { type: "void*", args: [] },
    reserved1: { type: "void*", args: [] },
    reserved2: { type: "void*", args: [] },
    reserved3: { type: "void*", args: [] },
    GetVersion: { type: "jint", args: [{ type: "JNIEnv*", name: "env" }] },
    DefineClass: {
        type: "jclass",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "char*", name: "name" },
            { type: "jobject", name: "loader" },
            { type: "jbyte*", name: "buf" },
            { type: "jsize", name: "len" },
        ],
    },
    FindClass: {
        type: "jclass",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "char*", name: "name" },
        ],
    },
    FromReflectedMethod: {
        type: "jmethodID",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "method" },
        ],
    },
    FromReflectedField: {
        type: "jfieldID",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "field" },
        ],
    },
    ToReflectedMethod: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "cls" },
            { type: "jmethodID", name: "methodID" },
            { type: "jboolean", name: "isStatic" },
        ],
    },
    GetSuperclass: {
        type: "jclass",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "sub" },
        ],
    },
    IsAssignableFrom: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "sub" },
            { type: "jclass", name: "sup" },
        ],
    },
    ToReflectedField: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "cls" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jboolean", name: "isStatic" },
        ],
    },
    Throw: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jthrowable", name: "obj" },
        ],
    },
    ThrowNew: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "char*", name: "msg" },
        ],
    },
    ExceptionOccurred: { type: "jthrowable", args: [{ type: "JNIEnv*", name: "env" }] },
    ExceptionDescribe: { type: "void", args: [{ type: "JNIEnv*", name: "env" }] },
    ExceptionClear: { type: "void", args: [{ type: "JNIEnv*", name: "env" }] },
    FatalError: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "char*", name: "msg" },
        ],
    },
    PushLocalFrame: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jint", name: "capacity" },
        ],
    },
    PopLocalFrame: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "result" },
        ],
    },
    NewGlobalRef: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "lobj" },
        ],
    },
    DeleteGlobalRef: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "gref" },
        ],
    },
    DeleteLocalRef: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
        ],
    },
    IsSameObject: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj1" },
            { type: "jobject", name: "obj2" },
        ],
    },
    NewLocalRef: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "ref" },
        ],
    },
    EnsureLocalCapacity: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jint", name: "capacity" },
        ],
    },
    AllocObject: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
        ],
    },
    NewObject: {
        type: "jobject",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    NewObjectV: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    NewObjectA: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    GetObjectClass: {
        type: "jclass",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
        ],
    },
    IsInstanceOf: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
        ],
    },
    GetMethodID: {
        type: "jmethodID",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "char*", name: "name" },
            { type: "char*", name: "sig" },
        ],
    },
    CallObjectMethod: {
        type: "jobject",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallObjectMethodV: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallObjectMethodA: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallBooleanMethod: {
        type: "jboolean",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallBooleanMethodV: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallBooleanMethodA: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallByteMethod: {
        type: "jbyte",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallByteMethodV: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallByteMethodA: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallCharMethod: {
        type: "jchar",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallCharMethodV: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallCharMethodA: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallShortMethod: {
        type: "jshort",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallShortMethodV: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallShortMethodA: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallIntMethod: {
        type: "jint",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallIntMethodV: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallIntMethodA: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallLongMethod: {
        type: "jlong",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallLongMethodV: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallLongMethodA: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallFloatMethod: {
        type: "jfloat",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallFloatMethodV: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallFloatMethodA: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallDoubleMethod: {
        type: "jdouble",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallDoubleMethodV: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallDoubleMethodA: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallVoidMethod: {
        type: "void",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jobject", name: "obj" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallVoidMethodV: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallVoidMethodA: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualObjectMethod: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualObjectMethodV: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualObjectMethodA: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualBooleanMethod: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualBooleanMethodV: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualBooleanMethodA: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualByteMethod: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualByteMethodV: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualByteMethodA: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualCharMethod: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualCharMethodV: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualCharMethodA: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualShortMethod: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualShortMethodV: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualShortMethodA: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualIntMethod: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualIntMethodV: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualIntMethodA: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualLongMethod: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualLongMethodV: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualLongMethodA: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualFloatMethod: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualFloatMethodV: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualFloatMethodA: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualDoubleMethod: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualDoubleMethodV: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualDoubleMethodA: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallNonvirtualVoidMethod: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue[]", name: "params" },
        ],
    },
    CallNonvirtualVoidMethodV: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallNonvirtualVoidMethodA: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    GetFieldID: {
        type: "jfieldID",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "char*", name: "name" },
            { type: "char*", name: "sig" },
        ],
    },
    GetObjectField: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetBooleanField: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetByteField: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetCharField: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetShortField: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetIntField: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetLongField: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetFloatField: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetDoubleField: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    SetObjectField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jobject", name: "val" },
        ],
    },
    SetBooleanField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jboolean", name: "val" },
        ],
    },
    SetByteField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jbyte", name: "val" },
        ],
    },
    SetCharField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jchar", name: "val" },
        ],
    },
    SetShortField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jshort", name: "val" },
        ],
    },
    SetIntField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jint", name: "val" },
        ],
    },
    SetLongField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jlong", name: "val" },
        ],
    },
    SetFloatField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jfloat", name: "val" },
        ],
    },
    SetDoubleField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jdouble", name: "val" },
        ],
    },
    GetStaticMethodID: {
        type: "jmethodID",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "char*", name: "name" },
            { type: "char*", name: "sig" },
        ],
    },
    CallStaticObjectMethod: {
        type: "jobject",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticObjectMethodV: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticObjectMethodA: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticBooleanMethod: {
        type: "jboolean",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticBooleanMethodV: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticBooleanMethodA: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticByteMethod: {
        type: "jbyte",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticByteMethodV: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticByteMethodA: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticCharMethod: {
        type: "jchar",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticCharMethodV: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticCharMethodA: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticShortMethod: {
        type: "jshort",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticShortMethodV: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticShortMethodA: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticIntMethod: {
        type: "jint",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticIntMethodV: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticIntMethodA: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticLongMethod: {
        type: "jlong",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticLongMethodV: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticLongMethodA: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticFloatMethod: {
        type: "jfloat",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticFloatMethodV: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticFloatMethodA: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticDoubleMethod: {
        type: "jdouble",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "clazz" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticDoubleMethodV: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticDoubleMethodA: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    CallStaticVoidMethod: {
        type: "void",
        args: [{ type: "JNIEnv*", name: "env" }, { type: "jclass", name: "cls" }, { type: "jmethodID", name: "methodID" }, { type: "jvalue[]", name: "params" }],
    },
    CallStaticVoidMethodV: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "cls" },
            { type: "jmethodID", name: "methodID" },
            { type: "va_list", name: "args" },
        ],
    },
    CallStaticVoidMethodA: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "cls" },
            { type: "jmethodID", name: "methodID" },
            { type: "jvalue*", name: "args" },
        ],
    },
    GetStaticFieldID: {
        type: "jfieldID",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "char*", name: "name" },
            { type: "char*", name: "sig" },
        ],
    },
    GetStaticObjectField: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetStaticBooleanField: {
        type: "jboolean",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetStaticByteField: {
        type: "jbyte",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetStaticCharField: {
        type: "jchar",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetStaticShortField: {
        type: "jshort",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetStaticIntField: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetStaticLongField: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetStaticFloatField: {
        type: "jfloat",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    GetStaticDoubleField: {
        type: "jdouble",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
        ],
    },
    SetStaticObjectField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jobject", name: "value" },
        ],
    },
    SetStaticBooleanField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jboolean", name: "value" },
        ],
    },
    SetStaticByteField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jbyte", name: "value" },
        ],
    },
    SetStaticCharField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jchar", name: "value" },
        ],
    },
    SetStaticShortField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jshort", name: "value" },
        ],
    },
    SetStaticIntField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jint", name: "value" },
        ],
    },
    SetStaticLongField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jlong", name: "value" },
        ],
    },
    SetStaticFloatField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jfloat", name: "value" },
        ],
    },
    SetStaticDoubleField: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "jfieldID", name: "fieldID" },
            { type: "jdouble", name: "value" },
        ],
    },
    NewString: {
        type: "jstring",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jchar*", name: "unicode" },
            { type: "jsize", name: "len" },
        ],
    },
    GetStringLength: {
        type: "jsize",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "str" },
        ],
    },
    GetStringChars: {
        type: "jchar*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "str" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    ReleaseStringChars: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "str" },
            { type: "jchar*", name: "chars" },
        ],
    },
    NewStringUTF: {
        type: "jstring",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "char*", name: "utf" },
        ],
    },
    GetStringUTFLength: {
        type: "jsize",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "str" },
        ],
    },
    GetStringUTFChars: {
        type: "char*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "str" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    ReleaseStringUTFChars: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "str" },
            { type: "char*", name: "chars" },
        ],
    },
    GetArrayLength: {
        type: "jsize",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jarray", name: "array" },
        ],
    },
    NewObjectArray: {
        type: "jobjectArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
            { type: "jclass", name: "clazz" },
            { type: "jobject", name: "init" },
        ],
    },
    GetObjectArrayElement: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobjectArray", name: "array" },
            { type: "jsize", name: "index" },
        ],
    },
    SetObjectArrayElement: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobjectArray", name: "array" },
            { type: "jsize", name: "index" },
            { type: "jobject", name: "val" },
        ],
    },
    NewBooleanArray: {
        type: "jbooleanArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
        ],
    },
    NewByteArray: {
        type: "jbyteArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
        ],
    },
    NewCharArray: {
        type: "jcharArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
        ],
    },
    NewShortArray: {
        type: "jshortArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
        ],
    },
    NewIntArray: {
        type: "jintArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
        ],
    },
    NewLongArray: {
        type: "jlongArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
        ],
    },
    NewFloatArray: {
        type: "jfloatArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
        ],
    },
    NewDoubleArray: {
        type: "jdoubleArray",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jsize", name: "len" },
        ],
    },
    GetBooleanArrayElements: {
        type: "jboolean*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jbooleanArray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    GetByteArrayElements: {
        type: "jbyte*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jbyteArray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    GetCharArrayElements: {
        type: "jchar*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jcharArray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    GetShortArrayElements: {
        type: "jshort*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jshortArray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    GetIntArrayElements: {
        type: "jint*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jintArray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    GetLongArrayElements: {
        type: "jlong*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jlongArray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    GetFloatArrayElements: {
        type: "jfloat*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jfloatArray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    GetDoubleArrayElements: {
        type: "jdouble*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jdoubleArray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    ReleaseBooleanArrayElements: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jbooleanArray", name: "array" },
            { type: "jboolean*", name: "elems" },
            { type: "jint", name: "mode" },
        ],
    },
    ReleaseByteArrayElements: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jbyteArray", name: "array" },
            { type: "jbyte*", name: "elems" },
            { type: "jint", name: "mode" },
        ],
    },
    ReleaseCharArrayElements: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jcharArray", name: "array" },
            { type: "jchar*", name: "elems" },
            { type: "jint", name: "mode" },
        ],
    },
    ReleaseShortArrayElements: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jshortArray", name: "array" },
            { type: "jshort*", name: "elems" },
            { type: "jint", name: "mode" },
        ],
    },
    ReleaseIntArrayElements: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jintArray", name: "array" },
            { type: "jint*", name: "elems" },
            { type: "jint", name: "mode" },
        ],
    },
    ReleaseLongArrayElements: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jlongArray", name: "array" },
            { type: "jlong*", name: "elems" },
            { type: "jint", name: "mode" },
        ],
    },
    ReleaseFloatArrayElements: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jfloatArray", name: "array" },
            { type: "jfloat*", name: "elems" },
            { type: "jint", name: "mode" },
        ],
    },
    ReleaseDoubleArrayElements: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jdoubleArray", name: "array" },
            { type: "jdouble*", name: "elems" },
            { type: "jint", name: "mode" },
        ],
    },
    GetBooleanArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jbooleanArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "l" },
            { type: "jboolean*", name: "buf" },
        ],
    },
    GetByteArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jbyteArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jbyte*", name: "buf" },
        ],
    },
    GetCharArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jcharArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jchar*", name: "buf" },
        ],
    },
    GetShortArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jshortArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jshort*", name: "buf" },
        ],
    },
    GetIntArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jintArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jint*", name: "buf" },
        ],
    },
    GetLongArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jlongArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jlong*", name: "buf" },
        ],
    },
    GetFloatArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jfloatArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jfloat*", name: "buf" },
        ],
    },
    GetDoubleArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jdoubleArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jdouble*", name: "buf" },
        ],
    },
    SetBooleanArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jbooleanArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "l" },
            { type: "jboolean*", name: "buf" },
        ],
    },
    SetByteArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jbyteArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jbyte*", name: "buf" },
        ],
    },
    SetCharArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jcharArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jchar*", name: "buf" },
        ],
    },
    SetShortArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jshortArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jshort*", name: "buf" },
        ],
    },
    SetIntArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jintArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jint*", name: "buf" },
        ],
    },
    SetLongArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jlongArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jlong*", name: "buf" },
        ],
    },
    SetFloatArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jfloatArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jfloat*", name: "buf" },
        ],
    },
    SetDoubleArrayRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jdoubleArray", name: "array" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jdouble*", name: "buf" },
        ],
    },
    RegisterNatives: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
            { type: "JNINativeMethod*", name: "methods" },
            { type: "jint", name: "nMethods" },
        ],
    },
    UnregisterNatives: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jclass", name: "clazz" },
        ],
    },
    MonitorEnter: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
        ],
    },
    MonitorExit: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
        ],
    },
    GetJavaVM: {
        type: "jint",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "JavaVM**", name: "vm" },
        ],
    },
    GetStringRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "str" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "jchar*", name: "buf" },
        ],
    },
    GetStringUTFRegion: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "str" },
            { type: "jsize", name: "start" },
            { type: "jsize", name: "len" },
            { type: "char*", name: "buf" },
        ],
    },
    GetPrimitiveArrayCritical: {
        type: "void*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jarray", name: "array" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    ReleasePrimitiveArrayCritical: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jarray", name: "array" },
            { type: "void*", name: "carray" },
            { type: "jint", name: "mode" },
        ],
    },
    GetStringCritical: {
        type: "jchar*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "string" },
            { type: "jboolean*", name: "isCopy" },
        ],
    },
    ReleaseStringCritical: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jstring", name: "string" },
            { type: "jchar*", name: "cstring" },
        ],
    },
    NewWeakGlobalRef: {
        type: "jweak",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
        ],
    },
    DeleteWeakGlobalRef: {
        type: "void",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jweak", name: "ref" },
        ],
    },
    ExceptionCheck: { type: "jboolean", args: [{ type: "JNIEnv*", name: "env" }] },
    NewDirectByteBuffer: {
        type: "jobject",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "void*", name: "address" },
            { type: "jlong", name: "capacity" },
        ],
    },
    GetDirectBufferAddress: {
        type: "void*",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "buf" },
        ],
    },
    GetDirectBufferCapacity: {
        type: "jlong",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "buf" },
        ],
    },
    GetObjectRefType: {
        type: "jobjectRefType",
        args: [
            { type: "JNIEnv*", name: "env" },
            { type: "jobject", name: "obj" },
        ],
    },
};
