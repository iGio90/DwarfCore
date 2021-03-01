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

export const JNI_FUNCDECLS = [
    "void reserved0()",
    "void reserved1()",
    "void reserved2()",
    "void reserved3()",
    "jint GetVersion(JNIEnv*)",
    "jclass DefineClass(JNIEnv*, char*, jobject, jbyte*, jsize)",
    "jclass FindClass(JNIEnv*, char*)",
    "jmethodID FromReflectedMethod(JNIEnv*, jobject)",
    "jfieldID FromReflectedField(JNIEnv*, jobject)",
    "jobject ToReflectedMethod(JNIEnv*, jclass, jmethodID, jboolean)",
    "jclass GetSuperclass(JNIEnv*, jclass)",
    "jboolean IsAssignableFrom(JNIEnv*, jclass, jclass)",
    "jobject ToReflectedField(JNIEnv*, jclass, jfieldID, jboolean)",
    "jint Throw(JNIEnv*, jthrowable)",
    "jint ThrowNew(JNIEnv*, jclass, char*)",
    "jthrowable ExceptionOccurred(JNIEnv*)",
    "void ExceptionDescribe(JNIEnv*)",
    "void ExceptionClear(JNIEnv*)",
    "void FatalError(JNIEnv*, char*)",
    "jint PushLocalFrame(JNIEnv*, jint)",
    "jobject PopLocalFrame(JNIEnv*, jobject)",
    "jobject NewGlobalRef(JNIEnv*, jobject)",
    "void DeleteGlobalRef(JNIEnv*, jobject)",
    "void DeleteLocalRef(JNIEnv*, jobject)",
    "jboolean IsSameObject(JNIEnv*, jobject, jobject)",
    "jobject NewLocalRef(JNIEnv*, jobject)",
    "jint EnsureLocalCapacity(JNIEnv*, jint)",
    "jobject AllocObject(JNIEnv*, jclass)",
    "jobject NewObject(JNIEnv*, jclass, jmethodID, ...)",
    "jobject NewObjectV(JNIEnv*, jclass, jmethodID, va_list)",
    "jobject NewObjectA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jclass GetObjectClass(JNIEnv*, jobject)",
    "jboolean IsInstanceOf(JNIEnv*, jobject, jclass)",
    "jmethodID GetMethodID(JNIEnv*, jclass, char*, char*)",
    "jobject CallObjectMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jobject CallObjectMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jobject CallObjectMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jboolean CallBooleanMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jboolean CallBooleanMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jboolean CallBooleanMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jbyte CallByteMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jbyte CallByteMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jbyte CallByteMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jchar CallCharMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jchar CallCharMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jchar CallCharMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jshort CallShortMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jshort CallShortMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jshort CallShortMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jint CallIntMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jint CallIntMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jint CallIntMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jlong CallLongMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jlong CallLongMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jlong CallLongMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jfloat CallFloatMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jfloat CallFloatMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jfloat CallFloatMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jdouble CallDoubleMethod(JNIEnv*, jobject, jmethodID, ...)",
    "jdouble CallDoubleMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "jdouble CallDoubleMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "void CallVoidMethod(JNIEnv*, jobject, jmethodID, ...)",
    "void CallVoidMethodV(JNIEnv*, jobject, jmethodID, va_list)",
    "void CallVoidMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
    "jobject CallNonvirtualObjectMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jobject CallNonvirtualObjectMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jobject CallNonvirtualObjectMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jboolean CallNonvirtualBooleanMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jboolean CallNonvirtualBooleanMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jboolean CallNonvirtualBooleanMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jbyte CallNonvirtualByteMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jbyte CallNonvirtualByteMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jbyte CallNonvirtualByteMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jchar CallNonvirtualCharMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jchar CallNonvirtualCharMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jchar CallNonvirtualCharMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jshort CallNonvirtualShortMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jshort CallNonvirtualShortMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jshort CallNonvirtualShortMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jint CallNonvirtualIntMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jint CallNonvirtualIntMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jint CallNonvirtualIntMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jlong CallNonvirtualLongMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jlong CallNonvirtualLongMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jlong CallNonvirtualLongMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jfloat CallNonvirtualFloatMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jfloat CallNonvirtualFloatMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jfloat CallNonvirtualFloatMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jdouble CallNonvirtualDoubleMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "jdouble CallNonvirtualDoubleMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "jdouble CallNonvirtualDoubleMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "void CallNonvirtualVoidMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
    "void CallNonvirtualVoidMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
    "void CallNonvirtualVoidMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
    "jfieldID GetFieldID(JNIEnv*, jclass, char*, char*)",
    "jobject GetObjectField(JNIEnv*, jobject, jfieldID)",
    "jboolean GetBooleanField(JNIEnv*, jobject, jfieldID)",
    "jbyte GetByteField(JNIEnv*, jobject, jfieldID)",
    "jchar GetCharField(JNIEnv*, jobject, jfieldID)",
    "jshort GetShortField(JNIEnv*, jobject, jfieldID)",
    "jint GetIntField(JNIEnv*, jobject, jfieldID)",
    "jlong GetLongField(JNIEnv*, jobject, jfieldID)",
    "jfloat GetFloatField(JNIEnv*, jobject, jfieldID)",
    "jdouble GetDoubleField(JNIEnv*, jobject, jfieldID)",
    "void SetObjectField(JNIEnv*, jobject, jfieldID, jobject)",
    "void SetBooleanField(JNIEnv*, jobject, jfieldID, jboolean)",
    "void SetByteField(JNIEnv*, jobject, jfieldID, jbyte)",
    "void SetCharField(JNIEnv*, jobject, jfieldID, jchar)",
    "void SetShortField(JNIEnv*, jobject, jfieldID, jshort)",
    "void SetIntField(JNIEnv*, jobject, jfieldID, jint)",
    "void SetLongField(JNIEnv*, jobject, jfieldID, jlong)",
    "void SetFloatField(JNIEnv*, jobject, jfieldID, jfloat)",
    "void SetDoubleField(JNIEnv*, jobject, jfieldID, jdouble)",
    "jmethodID GetStaticMethodID(JNIEnv*, jclass, char*, char*)",
    "jobject CallStaticObjectMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jobject CallStaticObjectMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jobject CallStaticObjectMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jboolean CallStaticBooleanMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jboolean CallStaticBooleanMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jboolean CallStaticBooleanMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jbyte CallStaticByteMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jbyte CallStaticByteMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jbyte CallStaticByteMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jchar CallStaticCharMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jchar CallStaticCharMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jchar CallStaticCharMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jshort CallStaticShortMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jshort CallStaticShortMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jshort CallStaticShortMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jint CallStaticIntMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jint CallStaticIntMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jint CallStaticIntMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jlong CallStaticLongMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jlong CallStaticLongMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jlong CallStaticLongMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jfloat CallStaticFloatMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jfloat CallStaticFloatMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jfloat CallStaticFloatMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jdouble CallStaticDoubleMethod(JNIEnv*, jclass, jmethodID, ...)",
    "jdouble CallStaticDoubleMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "jdouble CallStaticDoubleMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "void CallStaticVoidMethod(JNIEnv*, jclass, jmethodID, ...)",
    "void CallStaticVoidMethodV(JNIEnv*, jclass, jmethodID, va_list)",
    "void CallStaticVoidMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
    "jfieldID GetStaticFieldID(JNIEnv*, jclass, char*, char*)",
    "jobject GetStaticObjectField(JNIEnv*, jclass, jfieldID)",
    "jboolean GetStaticBooleanField(JNIEnv*, jclass, jfieldID)",
    "jbyte GetStaticByteField(JNIEnv*, jclass, jfieldID)",
    "jchar GetStaticCharField(JNIEnv*, jclass, jfieldID)",
    "jshort GetStaticShortField(JNIEnv*, jclass, jfieldID)",
    "jint GetStaticIntField(JNIEnv*, jclass, jfieldID)",
    "jlong GetStaticLongField(JNIEnv*, jclass, jfieldID)",
    "jfloat GetStaticFloatField(JNIEnv*, jclass, jfieldID)",
    "jdouble GetStaticDoubleField(JNIEnv*, jclass, jfieldID)",
    "void SetStaticObjectField(JNIEnv*, jclass, jfieldID, jobject)",
    "void SetStaticBooleanField(JNIEnv*, jclass, jfieldID, jboolean)",
    "void SetStaticByteField(JNIEnv*, jclass, jfieldID, jbyte)",
    "void SetStaticCharField(JNIEnv*, jclass, jfieldID, jchar)",
    "void SetStaticShortField(JNIEnv*, jclass, jfieldID, jshort)",
    "void SetStaticIntField(JNIEnv*, jclass, jfieldID, jint)",
    "void SetStaticLongField(JNIEnv*, jclass, jfieldID, jlong)",
    "void SetStaticFloatField(JNIEnv*, jclass, jfieldID, jfloat)",
    "void SetStaticDoubleField(JNIEnv*, jclass, jfieldID, jdouble)",
    "jstring NewString(JNIEnv*, jchar*, jsize)",
    "jsize GetStringLength(JNIEnv*, jstring)",
    "jchar* GetStringChars(JNIEnv*, jstring, jboolean*)",
    "void ReleaseStringChars(JNIEnv*, jstring, jchar*)",
    "jstring NewStringUTF(JNIEnv*, char*)",
    "jsize GetStringUTFLength(JNIEnv*, jstring)",
    "char* GetStringUTFChars(JNIEnv*, jstring, jboolean*)",
    "void ReleaseStringUTFChars(JNIEnv*, jstring, char*)",
    "jsize GetArrayLength(JNIEnv*, jarray)",
    "jobjectArray NewObjectArray(JNIEnv*, jsize, jclass, jobject)",
    "jobject GetObjectArrayElement(JNIEnv*, jobjectArray, jsize)",
    "void SetObjectArrayElement(JNIEnv*, jobjectArray, jsize, jobject)",
    "jbooleanArray NewBooleanArray(JNIEnv*, jsize)",
    "jbyteArray NewByteArray(JNIEnv*, jsize)",
    "jcharArray NewCharArray(JNIEnv*, jsize)",
    "jshortArray NewShortArray(JNIEnv*, jsize)",
    "jintArray NewIntArray(JNIEnv*, jsize)",
    "jlongArray NewLongArray(JNIEnv*, jsize)",
    "jfloatArray NewFloatArray(JNIEnv*, jsize)",
    "jdoubleArray NewDoubleArray(JNIEnv*, jsize)",
    "jboolean* GetBooleanArrayElements(JNIEnv*, jbooleanArray, jboolean*)",
    "jbyte* GetByteArrayElements(JNIEnv*, jbyteArray, jboolean*)",
    "jchar* GetCharArrayElements(JNIEnv*, jcharArray, jboolean*)",
    "jshort* GetShortArrayElements(JNIEnv*, jshortArray, jboolean*)",
    "jint* GetIntArrayElements(JNIEnv*, jintArray, jboolean*)",
    "jlong* GetLongArrayElements(JNIEnv*, jlongArray, jboolean*)",
    "jfloat* GetFloatArrayElements(JNIEnv*, jfloatArray, jboolean*)",
    "jdouble* GetDoubleArrayElements(JNIEnv*, jdoubleArray, jboolean*)",
    "void ReleaseBooleanArrayElements(JNIEnv*, jbooleanArray, jboolean*, jint)",
    "void ReleaseByteArrayElements(JNIEnv*, jbyteArray, jbyte*, jint)",
    "void ReleaseCharArrayElements(JNIEnv*, jcharArray, jchar*, jint)",
    "void ReleaseShortArrayElements(JNIEnv*, jshortArray, jshort*, jint)",
    "void ReleaseIntArrayElements(JNIEnv*, jintArray, jint*, jint)",
    "void ReleaseLongArrayElements(JNIEnv*, jlongArray, jlong*, jint)",
    "void ReleaseFloatArrayElements(JNIEnv*, jfloatArray, jfloat*, jint)",
    "void ReleaseDoubleArrayElements(JNIEnv*, jdoubleArray, jdouble*, jint)",
    "void GetBooleanArrayRegion(JNIEnv*, jbooleanArray, jsize, jsize, jboolean*)",
    "void GetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, jbyte*)",
    "void GetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, jchar*)",
    "void GetShortArrayRegion(JNIEnv*, jshortArray, jsize, jsize, jshort*)",
    "void GetIntArrayRegion(JNIEnv*, jintArray, jsize, jsize, jint*)",
    "void GetLongArrayRegion(JNIEnv*, jlongArray, jsize, jsize, jlong*)",
    "void GetFloatArrayRegion(JNIEnv*, jfloatArray, jsize, jsize, jfloat*)",
    "void GetDoubleArrayRegion(JNIEnv*, jdoubleArray, jsize, jsize, jdouble*)",
    "void SetBooleanArrayRegion(JNIEnv*, jbooleanArray, jsize, jsize, jboolean*)",
    "void SetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, jbyte*)",
    "void SetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, jchar*)",
    "void SetShortArrayRegion(JNIEnv*, jshortArray, jsize, jsize, jshort*)",
    "void SetIntArrayRegion(JNIEnv*, jintArray, jsize, jsize, jint*)",
    "void SetLongArrayRegion(JNIEnv*, jlongArray, jsize, jsize, jlong*)",
    "void SetFloatArrayRegion(JNIEnv*, jfloatArray, jsize, jsize, jfloat*)",
    "void SetDoubleArrayRegion(JNIEnv*, jdoubleArray, jsize, jsize, jdouble*)",
    "jint RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)",
    "jint UnregisterNatives(JNIEnv*, jclass)",
    "jint MonitorEnter(JNIEnv*, jobject)",
    "jint MonitorExit(JNIEnv*, jobject)",
    "jint GetJavaVM(JNIEnv*, JavaVM**)",
    "void GetStringRegion(JNIEnv*, jstring, jsize, jsize, jchar*)",
    "void GetStringUTFRegion(JNIEnv*, jstring, jsize, jsize, char*)",
    "void GetPrimitiveArrayCritical(JNIEnv*, jarray, jboolean*)",
    "void ReleasePrimitiveArrayCritical(JNIEnv*, jarray, void*, jint)",
    "jchar GetStringCritical(JNIEnv*, jstring, jboolean*)",
    "void ReleaseStringCritical(JNIEnv*, jstring, jchar*)",
    "jweak NewWeakGlobalRef(JNIEnv*, jobject)",
    "void DeleteWeakGlobalRef(JNIEnv*, jweak)",
    "jboolean ExceptionCheck(JNIEnv*)",
    "jobject NewDirectByteBuffer(JNIEnv*, void*, jlong)",
    "void GetDirectBufferAddress(JNIEnv*, jobject)",
    "jlong GetDirectBufferCapacity(JNIEnv*, jobject)",
    "jobjectRefType GetObjectRefType(JNIEnv*, jobject)",
];


export const JNI_TEMPLATES = {
    reserved0: {
        onEnter() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void reserved0()",
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void reserved0()",
                },
            });
        },
    },
    reserved1: {
        onEnter() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void reserved1()",
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void reserved1()",
                },
            });
        },
    },
    reserved2: {
        onEnter() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void reserved2()",
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void reserved2()",
                },
            });
        },
    },
    reserved3: {
        onEnter() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void reserved3()",
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void reserved3()",
                },
            });
        },
    },
    GetVersion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint GetVersion(JNIEnv*)",
                    args,
                    argTypes: ["JNIEnv*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint GetVersion(JNIEnv*)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    DefineClass: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jclass DefineClass(JNIEnv*, char*, jobject, jbyte*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "char*", "jobject", "jbyte*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jclass DefineClass(JNIEnv*, char*, jobject, jbyte*, jsize)",
                    return: retVal,
                    retType: "jclass",
                },
            });
        },
    },
    FindClass: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jclass FindClass(JNIEnv*, char*)",
                    args,
                    argTypes: ["JNIEnv*", "char*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jclass FindClass(JNIEnv*, char*)",
                    return: retVal,
                    retType: "jclass",
                },
            });
        },
    },
    FromReflectedMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jmethodID FromReflectedMethod(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jmethodID FromReflectedMethod(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jmethodID",
                },
            });
        },
    },
    FromReflectedField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfieldID FromReflectedField(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfieldID FromReflectedField(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jfieldID",
                },
            });
        },
    },
    ToReflectedMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject ToReflectedMethod(JNIEnv*, jclass, jmethodID, jboolean)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jboolean"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject ToReflectedMethod(JNIEnv*, jclass, jmethodID, jboolean)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    GetSuperclass: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jclass GetSuperclass(JNIEnv*, jclass)",
                    args,
                    argTypes: ["JNIEnv*", "jclass"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jclass GetSuperclass(JNIEnv*, jclass)",
                    return: retVal,
                    retType: "jclass",
                },
            });
        },
    },
    IsAssignableFrom: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean IsAssignableFrom(JNIEnv*, jclass, jclass)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jclass"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean IsAssignableFrom(JNIEnv*, jclass, jclass)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    ToReflectedField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject ToReflectedField(JNIEnv*, jclass, jfieldID, jboolean)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jboolean"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject ToReflectedField(JNIEnv*, jclass, jfieldID, jboolean)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    Throw: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint Throw(JNIEnv*, jthrowable)",
                    args,
                    argTypes: ["JNIEnv*", "jthrowable"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint Throw(JNIEnv*, jthrowable)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    ThrowNew: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint ThrowNew(JNIEnv*, jclass, char*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "char*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint ThrowNew(JNIEnv*, jclass, char*)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    ExceptionOccurred: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jthrowable ExceptionOccurred(JNIEnv*)",
                    args,
                    argTypes: ["JNIEnv*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jthrowable ExceptionOccurred(JNIEnv*)",
                    return: retVal,
                    retType: "jthrowable",
                },
            });
        },
    },
    ExceptionDescribe: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ExceptionDescribe(JNIEnv*)",
                    args,
                    argTypes: ["JNIEnv*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ExceptionDescribe(JNIEnv*)",
                },
            });
        },
    },
    ExceptionClear: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ExceptionClear(JNIEnv*)",
                    args,
                    argTypes: ["JNIEnv*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ExceptionClear(JNIEnv*)",
                },
            });
        },
    },
    FatalError: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void FatalError(JNIEnv*, char*)",
                    args,
                    argTypes: ["JNIEnv*", "char*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void FatalError(JNIEnv*, char*)",
                },
            });
        },
    },
    PushLocalFrame: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint PushLocalFrame(JNIEnv*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jint"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint PushLocalFrame(JNIEnv*, jint)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    PopLocalFrame: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject PopLocalFrame(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject PopLocalFrame(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    NewGlobalRef: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject NewGlobalRef(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject NewGlobalRef(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    DeleteGlobalRef: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void DeleteGlobalRef(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void DeleteGlobalRef(JNIEnv*, jobject)",
                },
            });
        },
    },
    DeleteLocalRef: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void DeleteLocalRef(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void DeleteLocalRef(JNIEnv*, jobject)",
                },
            });
        },
    },
    IsSameObject: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean IsSameObject(JNIEnv*, jobject, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean IsSameObject(JNIEnv*, jobject, jobject)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    NewLocalRef: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject NewLocalRef(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject NewLocalRef(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    EnsureLocalCapacity: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint EnsureLocalCapacity(JNIEnv*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jint"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint EnsureLocalCapacity(JNIEnv*, jint)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    AllocObject: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject AllocObject(JNIEnv*, jclass)",
                    args,
                    argTypes: ["JNIEnv*", "jclass"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject AllocObject(JNIEnv*, jclass)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    NewObject: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject NewObject(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject NewObject(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    NewObjectV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject NewObjectV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject NewObjectV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    NewObjectA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject NewObjectA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject NewObjectA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    GetObjectClass: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jclass GetObjectClass(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jclass GetObjectClass(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jclass",
                },
            });
        },
    },
    IsInstanceOf: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean IsInstanceOf(JNIEnv*, jobject, jclass)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean IsInstanceOf(JNIEnv*, jobject, jclass)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    GetMethodID: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jmethodID GetMethodID(JNIEnv*, jclass, char*, char*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "char*", "char*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jmethodID GetMethodID(JNIEnv*, jclass, char*, char*)",
                    return: retVal,
                    retType: "jmethodID",
                },
            });
        },
    },
    CallObjectMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallObjectMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallObjectMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallObjectMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallObjectMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallObjectMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallObjectMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallObjectMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallObjectMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallBooleanMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallBooleanMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallBooleanMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallBooleanMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallBooleanMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallBooleanMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallBooleanMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallBooleanMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallBooleanMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallByteMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallByteMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallByteMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallByteMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallByteMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallByteMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallByteMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallByteMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallByteMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallCharMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallCharMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallCharMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallCharMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallCharMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallCharMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallCharMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallCharMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallCharMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallShortMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallShortMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallShortMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallShortMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallShortMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallShortMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallShortMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallShortMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallShortMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallIntMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallIntMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallIntMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallIntMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallIntMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallIntMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallIntMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallIntMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallIntMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallLongMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallLongMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallLongMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallLongMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallLongMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallLongMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallLongMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallLongMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallLongMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallFloatMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallFloatMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallFloatMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallFloatMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallFloatMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallFloatMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallFloatMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallFloatMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallFloatMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallDoubleMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallDoubleMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallDoubleMethod(JNIEnv*, jobject, jmethodID, ...)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallDoubleMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallDoubleMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallDoubleMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallDoubleMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallDoubleMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallDoubleMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallVoidMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallVoidMethod(JNIEnv*, jobject, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "..."],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallVoidMethod(JNIEnv*, jobject, jmethodID, ...)",
                },
            });
        },
    },
    CallVoidMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallVoidMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "va_list"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallVoidMethodV(JNIEnv*, jobject, jmethodID, va_list)",
                },
            });
        },
    },
    CallVoidMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallVoidMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallVoidMethodA(JNIEnv*, jobject, jmethodID, jvalue*)",
                },
            });
        },
    },
    CallNonvirtualObjectMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallNonvirtualObjectMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallNonvirtualObjectMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallNonvirtualObjectMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallNonvirtualObjectMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallNonvirtualObjectMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallNonvirtualObjectMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallNonvirtualObjectMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallNonvirtualObjectMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallNonvirtualBooleanMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallNonvirtualBooleanMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallNonvirtualBooleanMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallNonvirtualBooleanMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallNonvirtualBooleanMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallNonvirtualBooleanMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallNonvirtualBooleanMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallNonvirtualBooleanMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallNonvirtualBooleanMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallNonvirtualByteMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallNonvirtualByteMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallNonvirtualByteMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallNonvirtualByteMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallNonvirtualByteMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallNonvirtualByteMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallNonvirtualByteMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallNonvirtualByteMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallNonvirtualByteMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallNonvirtualCharMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallNonvirtualCharMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallNonvirtualCharMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallNonvirtualCharMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallNonvirtualCharMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallNonvirtualCharMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallNonvirtualCharMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallNonvirtualCharMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallNonvirtualCharMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallNonvirtualShortMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallNonvirtualShortMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallNonvirtualShortMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallNonvirtualShortMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallNonvirtualShortMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallNonvirtualShortMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallNonvirtualShortMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallNonvirtualShortMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallNonvirtualShortMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallNonvirtualIntMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallNonvirtualIntMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallNonvirtualIntMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallNonvirtualIntMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallNonvirtualIntMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallNonvirtualIntMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallNonvirtualIntMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallNonvirtualIntMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallNonvirtualIntMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallNonvirtualLongMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallNonvirtualLongMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallNonvirtualLongMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallNonvirtualLongMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallNonvirtualLongMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallNonvirtualLongMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallNonvirtualLongMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallNonvirtualLongMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallNonvirtualLongMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallNonvirtualFloatMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallNonvirtualFloatMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallNonvirtualFloatMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallNonvirtualFloatMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallNonvirtualFloatMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallNonvirtualFloatMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallNonvirtualFloatMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallNonvirtualFloatMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallNonvirtualFloatMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallNonvirtualDoubleMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallNonvirtualDoubleMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallNonvirtualDoubleMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallNonvirtualDoubleMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallNonvirtualDoubleMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallNonvirtualDoubleMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallNonvirtualDoubleMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallNonvirtualDoubleMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallNonvirtualDoubleMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallNonvirtualVoidMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallNonvirtualVoidMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallNonvirtualVoidMethod(JNIEnv*, jobject, jclass, jmethodID, ...)",
                },
            });
        },
    },
    CallNonvirtualVoidMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallNonvirtualVoidMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallNonvirtualVoidMethodV(JNIEnv*, jobject, jclass, jmethodID, va_list)",
                },
            });
        },
    },
    CallNonvirtualVoidMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallNonvirtualVoidMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallNonvirtualVoidMethodA(JNIEnv*, jobject, jclass, jmethodID, jvalue*)",
                },
            });
        },
    },
    GetFieldID: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfieldID GetFieldID(JNIEnv*, jclass, char*, char*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "char*", "char*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfieldID GetFieldID(JNIEnv*, jclass, char*, char*)",
                    return: retVal,
                    retType: "jfieldID",
                },
            });
        },
    },
    GetObjectField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject GetObjectField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject GetObjectField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    GetBooleanField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean GetBooleanField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean GetBooleanField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    GetByteField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte GetByteField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte GetByteField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    GetCharField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar GetCharField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar GetCharField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    GetShortField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort GetShortField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort GetShortField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    GetIntField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint GetIntField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint GetIntField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    GetLongField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong GetLongField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong GetLongField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    GetFloatField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat GetFloatField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat GetFloatField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    GetDoubleField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble GetDoubleField(JNIEnv*, jobject, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble GetDoubleField(JNIEnv*, jobject, jfieldID)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    SetObjectField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetObjectField(JNIEnv*, jobject, jfieldID, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jobject"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetObjectField(JNIEnv*, jobject, jfieldID, jobject)",
                },
            });
        },
    },
    SetBooleanField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetBooleanField(JNIEnv*, jobject, jfieldID, jboolean)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jboolean"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetBooleanField(JNIEnv*, jobject, jfieldID, jboolean)",
                },
            });
        },
    },
    SetByteField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetByteField(JNIEnv*, jobject, jfieldID, jbyte)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jbyte"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetByteField(JNIEnv*, jobject, jfieldID, jbyte)",
                },
            });
        },
    },
    SetCharField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetCharField(JNIEnv*, jobject, jfieldID, jchar)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jchar"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetCharField(JNIEnv*, jobject, jfieldID, jchar)",
                },
            });
        },
    },
    SetShortField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetShortField(JNIEnv*, jobject, jfieldID, jshort)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jshort"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetShortField(JNIEnv*, jobject, jfieldID, jshort)",
                },
            });
        },
    },
    SetIntField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetIntField(JNIEnv*, jobject, jfieldID, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetIntField(JNIEnv*, jobject, jfieldID, jint)",
                },
            });
        },
    },
    SetLongField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetLongField(JNIEnv*, jobject, jfieldID, jlong)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jlong"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetLongField(JNIEnv*, jobject, jfieldID, jlong)",
                },
            });
        },
    },
    SetFloatField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetFloatField(JNIEnv*, jobject, jfieldID, jfloat)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jfloat"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetFloatField(JNIEnv*, jobject, jfieldID, jfloat)",
                },
            });
        },
    },
    SetDoubleField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetDoubleField(JNIEnv*, jobject, jfieldID, jdouble)",
                    args,
                    argTypes: ["JNIEnv*", "jobject", "jfieldID", "jdouble"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetDoubleField(JNIEnv*, jobject, jfieldID, jdouble)",
                },
            });
        },
    },
    GetStaticMethodID: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jmethodID GetStaticMethodID(JNIEnv*, jclass, char*, char*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "char*", "char*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jmethodID GetStaticMethodID(JNIEnv*, jclass, char*, char*)",
                    return: retVal,
                    retType: "jmethodID",
                },
            });
        },
    },
    CallStaticObjectMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallStaticObjectMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallStaticObjectMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallStaticObjectMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallStaticObjectMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallStaticObjectMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallStaticObjectMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject CallStaticObjectMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject CallStaticObjectMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    CallStaticBooleanMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallStaticBooleanMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallStaticBooleanMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallStaticBooleanMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallStaticBooleanMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallStaticBooleanMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallStaticBooleanMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean CallStaticBooleanMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean CallStaticBooleanMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    CallStaticByteMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallStaticByteMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallStaticByteMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallStaticByteMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallStaticByteMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallStaticByteMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallStaticByteMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte CallStaticByteMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte CallStaticByteMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    CallStaticCharMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallStaticCharMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallStaticCharMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallStaticCharMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallStaticCharMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallStaticCharMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallStaticCharMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar CallStaticCharMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar CallStaticCharMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    CallStaticShortMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallStaticShortMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallStaticShortMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallStaticShortMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallStaticShortMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallStaticShortMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallStaticShortMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort CallStaticShortMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort CallStaticShortMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    CallStaticIntMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallStaticIntMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallStaticIntMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallStaticIntMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallStaticIntMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallStaticIntMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallStaticIntMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint CallStaticIntMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint CallStaticIntMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    CallStaticLongMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallStaticLongMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallStaticLongMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallStaticLongMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallStaticLongMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallStaticLongMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallStaticLongMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong CallStaticLongMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong CallStaticLongMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    CallStaticFloatMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallStaticFloatMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallStaticFloatMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallStaticFloatMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallStaticFloatMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallStaticFloatMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallStaticFloatMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat CallStaticFloatMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat CallStaticFloatMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    CallStaticDoubleMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallStaticDoubleMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallStaticDoubleMethod(JNIEnv*, jclass, jmethodID, ...)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallStaticDoubleMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallStaticDoubleMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallStaticDoubleMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallStaticDoubleMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble CallStaticDoubleMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble CallStaticDoubleMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    CallStaticVoidMethod: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallStaticVoidMethod(JNIEnv*, jclass, jmethodID, ...)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "..."],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallStaticVoidMethod(JNIEnv*, jclass, jmethodID, ...)",
                },
            });
        },
    },
    CallStaticVoidMethodV: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallStaticVoidMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "va_list"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallStaticVoidMethodV(JNIEnv*, jclass, jmethodID, va_list)",
                },
            });
        },
    },
    CallStaticVoidMethodA: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void CallStaticVoidMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jmethodID", "jvalue*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void CallStaticVoidMethodA(JNIEnv*, jclass, jmethodID, jvalue*)",
                },
            });
        },
    },
    GetStaticFieldID: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfieldID GetStaticFieldID(JNIEnv*, jclass, char*, char*)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "char*", "char*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfieldID GetStaticFieldID(JNIEnv*, jclass, char*, char*)",
                    return: retVal,
                    retType: "jfieldID",
                },
            });
        },
    },
    GetStaticObjectField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject GetStaticObjectField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject GetStaticObjectField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    GetStaticBooleanField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean GetStaticBooleanField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean GetStaticBooleanField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    GetStaticByteField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte GetStaticByteField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte GetStaticByteField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jbyte",
                },
            });
        },
    },
    GetStaticCharField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar GetStaticCharField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar GetStaticCharField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    GetStaticShortField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort GetStaticShortField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort GetStaticShortField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jshort",
                },
            });
        },
    },
    GetStaticIntField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint GetStaticIntField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint GetStaticIntField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    GetStaticLongField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong GetStaticLongField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong GetStaticLongField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    GetStaticFloatField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat GetStaticFloatField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat GetStaticFloatField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jfloat",
                },
            });
        },
    },
    GetStaticDoubleField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble GetStaticDoubleField(JNIEnv*, jclass, jfieldID)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble GetStaticDoubleField(JNIEnv*, jclass, jfieldID)",
                    return: retVal,
                    retType: "jdouble",
                },
            });
        },
    },
    SetStaticObjectField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticObjectField(JNIEnv*, jclass, jfieldID, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jobject"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticObjectField(JNIEnv*, jclass, jfieldID, jobject)",
                },
            });
        },
    },
    SetStaticBooleanField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticBooleanField(JNIEnv*, jclass, jfieldID, jboolean)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jboolean"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticBooleanField(JNIEnv*, jclass, jfieldID, jboolean)",
                },
            });
        },
    },
    SetStaticByteField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticByteField(JNIEnv*, jclass, jfieldID, jbyte)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jbyte"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticByteField(JNIEnv*, jclass, jfieldID, jbyte)",
                },
            });
        },
    },
    SetStaticCharField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticCharField(JNIEnv*, jclass, jfieldID, jchar)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jchar"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticCharField(JNIEnv*, jclass, jfieldID, jchar)",
                },
            });
        },
    },
    SetStaticShortField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticShortField(JNIEnv*, jclass, jfieldID, jshort)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jshort"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticShortField(JNIEnv*, jclass, jfieldID, jshort)",
                },
            });
        },
    },
    SetStaticIntField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticIntField(JNIEnv*, jclass, jfieldID, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticIntField(JNIEnv*, jclass, jfieldID, jint)",
                },
            });
        },
    },
    SetStaticLongField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticLongField(JNIEnv*, jclass, jfieldID, jlong)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jlong"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticLongField(JNIEnv*, jclass, jfieldID, jlong)",
                },
            });
        },
    },
    SetStaticFloatField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticFloatField(JNIEnv*, jclass, jfieldID, jfloat)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jfloat"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticFloatField(JNIEnv*, jclass, jfieldID, jfloat)",
                },
            });
        },
    },
    SetStaticDoubleField: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetStaticDoubleField(JNIEnv*, jclass, jfieldID, jdouble)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "jfieldID", "jdouble"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetStaticDoubleField(JNIEnv*, jclass, jfieldID, jdouble)",
                },
            });
        },
    },
    NewString: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jstring NewString(JNIEnv*, jchar*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jchar*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jstring NewString(JNIEnv*, jchar*, jsize)",
                    return: retVal,
                    retType: "jstring",
                },
            });
        },
    },
    GetStringLength: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jsize GetStringLength(JNIEnv*, jstring)",
                    args,
                    argTypes: ["JNIEnv*", "jstring"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jsize GetStringLength(JNIEnv*, jstring)",
                    return: retVal,
                    retType: "jsize",
                },
            });
        },
    },
    GetStringChars: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar* GetStringChars(JNIEnv*, jstring, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jstring", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar* GetStringChars(JNIEnv*, jstring, jboolean*)",
                    return: retVal,
                    retType: "jchar*",
                },
            });
        },
    },
    ReleaseStringChars: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseStringChars(JNIEnv*, jstring, jchar*)",
                    args,
                    argTypes: ["JNIEnv*", "jstring", "jchar*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseStringChars(JNIEnv*, jstring, jchar*)",
                },
            });
        },
    },
    NewStringUTF: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jstring NewStringUTF(JNIEnv*, char*)",
                    args,
                    argTypes: ["JNIEnv*", "char*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jstring NewStringUTF(JNIEnv*, char*)",
                    return: retVal,
                    retType: "jstring",
                },
            });
        },
    },
    GetStringUTFLength: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jsize GetStringUTFLength(JNIEnv*, jstring)",
                    args,
                    argTypes: ["JNIEnv*", "jstring"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jsize GetStringUTFLength(JNIEnv*, jstring)",
                    return: retVal,
                    retType: "jsize",
                },
            });
        },
    },
    GetStringUTFChars: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "char* GetStringUTFChars(JNIEnv*, jstring, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jstring", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "char* GetStringUTFChars(JNIEnv*, jstring, jboolean*)",
                    return: retVal,
                    retType: "char*",
                },
            });
        },
    },
    ReleaseStringUTFChars: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseStringUTFChars(JNIEnv*, jstring, char*)",
                    args,
                    argTypes: ["JNIEnv*", "jstring", "char*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseStringUTFChars(JNIEnv*, jstring, char*)",
                },
            });
        },
    },
    GetArrayLength: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jsize GetArrayLength(JNIEnv*, jarray)",
                    args,
                    argTypes: ["JNIEnv*", "jarray"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jsize GetArrayLength(JNIEnv*, jarray)",
                    return: retVal,
                    retType: "jsize",
                },
            });
        },
    },
    NewObjectArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobjectArray NewObjectArray(JNIEnv*, jsize, jclass, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jsize", "jclass", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobjectArray NewObjectArray(JNIEnv*, jsize, jclass, jobject)",
                    return: retVal,
                    retType: "jobjectArray",
                },
            });
        },
    },
    GetObjectArrayElement: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject GetObjectArrayElement(JNIEnv*, jobjectArray, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jobjectArray", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject GetObjectArrayElement(JNIEnv*, jobjectArray, jsize)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    SetObjectArrayElement: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetObjectArrayElement(JNIEnv*, jobjectArray, jsize, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobjectArray", "jsize", "jobject"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetObjectArrayElement(JNIEnv*, jobjectArray, jsize, jobject)",
                },
            });
        },
    },
    NewBooleanArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbooleanArray NewBooleanArray(JNIEnv*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbooleanArray NewBooleanArray(JNIEnv*, jsize)",
                    return: retVal,
                    retType: "jbooleanArray",
                },
            });
        },
    },
    NewByteArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyteArray NewByteArray(JNIEnv*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyteArray NewByteArray(JNIEnv*, jsize)",
                    return: retVal,
                    retType: "jbyteArray",
                },
            });
        },
    },
    NewCharArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jcharArray NewCharArray(JNIEnv*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jcharArray NewCharArray(JNIEnv*, jsize)",
                    return: retVal,
                    retType: "jcharArray",
                },
            });
        },
    },
    NewShortArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshortArray NewShortArray(JNIEnv*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshortArray NewShortArray(JNIEnv*, jsize)",
                    return: retVal,
                    retType: "jshortArray",
                },
            });
        },
    },
    NewIntArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jintArray NewIntArray(JNIEnv*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jintArray NewIntArray(JNIEnv*, jsize)",
                    return: retVal,
                    retType: "jintArray",
                },
            });
        },
    },
    NewLongArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlongArray NewLongArray(JNIEnv*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlongArray NewLongArray(JNIEnv*, jsize)",
                    return: retVal,
                    retType: "jlongArray",
                },
            });
        },
    },
    NewFloatArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloatArray NewFloatArray(JNIEnv*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloatArray NewFloatArray(JNIEnv*, jsize)",
                    return: retVal,
                    retType: "jfloatArray",
                },
            });
        },
    },
    NewDoubleArray: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdoubleArray NewDoubleArray(JNIEnv*, jsize)",
                    args,
                    argTypes: ["JNIEnv*", "jsize"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdoubleArray NewDoubleArray(JNIEnv*, jsize)",
                    return: retVal,
                    retType: "jdoubleArray",
                },
            });
        },
    },
    GetBooleanArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean* GetBooleanArrayElements(JNIEnv*, jbooleanArray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jbooleanArray", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean* GetBooleanArrayElements(JNIEnv*, jbooleanArray, jboolean*)",
                    return: retVal,
                    retType: "jboolean*",
                },
            });
        },
    },
    GetByteArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jbyte* GetByteArrayElements(JNIEnv*, jbyteArray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jbyteArray", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jbyte* GetByteArrayElements(JNIEnv*, jbyteArray, jboolean*)",
                    return: retVal,
                    retType: "jbyte*",
                },
            });
        },
    },
    GetCharArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar* GetCharArrayElements(JNIEnv*, jcharArray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jcharArray", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar* GetCharArrayElements(JNIEnv*, jcharArray, jboolean*)",
                    return: retVal,
                    retType: "jchar*",
                },
            });
        },
    },
    GetShortArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jshort* GetShortArrayElements(JNIEnv*, jshortArray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jshortArray", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jshort* GetShortArrayElements(JNIEnv*, jshortArray, jboolean*)",
                    return: retVal,
                    retType: "jshort*",
                },
            });
        },
    },
    GetIntArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint* GetIntArrayElements(JNIEnv*, jintArray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jintArray", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint* GetIntArrayElements(JNIEnv*, jintArray, jboolean*)",
                    return: retVal,
                    retType: "jint*",
                },
            });
        },
    },
    GetLongArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong* GetLongArrayElements(JNIEnv*, jlongArray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jlongArray", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong* GetLongArrayElements(JNIEnv*, jlongArray, jboolean*)",
                    return: retVal,
                    retType: "jlong*",
                },
            });
        },
    },
    GetFloatArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jfloat* GetFloatArrayElements(JNIEnv*, jfloatArray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jfloatArray", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jfloat* GetFloatArrayElements(JNIEnv*, jfloatArray, jboolean*)",
                    return: retVal,
                    retType: "jfloat*",
                },
            });
        },
    },
    GetDoubleArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jdouble* GetDoubleArrayElements(JNIEnv*, jdoubleArray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jdoubleArray", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jdouble* GetDoubleArrayElements(JNIEnv*, jdoubleArray, jboolean*)",
                    return: retVal,
                    retType: "jdouble*",
                },
            });
        },
    },
    ReleaseBooleanArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseBooleanArrayElements(JNIEnv*, jbooleanArray, jboolean*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jbooleanArray", "jboolean*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseBooleanArrayElements(JNIEnv*, jbooleanArray, jboolean*, jint)",
                },
            });
        },
    },
    ReleaseByteArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseByteArrayElements(JNIEnv*, jbyteArray, jbyte*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jbyteArray", "jbyte*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseByteArrayElements(JNIEnv*, jbyteArray, jbyte*, jint)",
                },
            });
        },
    },
    ReleaseCharArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseCharArrayElements(JNIEnv*, jcharArray, jchar*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jcharArray", "jchar*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseCharArrayElements(JNIEnv*, jcharArray, jchar*, jint)",
                },
            });
        },
    },
    ReleaseShortArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseShortArrayElements(JNIEnv*, jshortArray, jshort*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jshortArray", "jshort*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseShortArrayElements(JNIEnv*, jshortArray, jshort*, jint)",
                },
            });
        },
    },
    ReleaseIntArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseIntArrayElements(JNIEnv*, jintArray, jint*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jintArray", "jint*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseIntArrayElements(JNIEnv*, jintArray, jint*, jint)",
                },
            });
        },
    },
    ReleaseLongArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseLongArrayElements(JNIEnv*, jlongArray, jlong*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jlongArray", "jlong*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseLongArrayElements(JNIEnv*, jlongArray, jlong*, jint)",
                },
            });
        },
    },
    ReleaseFloatArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseFloatArrayElements(JNIEnv*, jfloatArray, jfloat*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jfloatArray", "jfloat*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseFloatArrayElements(JNIEnv*, jfloatArray, jfloat*, jint)",
                },
            });
        },
    },
    ReleaseDoubleArrayElements: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseDoubleArrayElements(JNIEnv*, jdoubleArray, jdouble*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jdoubleArray", "jdouble*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseDoubleArrayElements(JNIEnv*, jdoubleArray, jdouble*, jint)",
                },
            });
        },
    },
    GetBooleanArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetBooleanArrayRegion(JNIEnv*, jbooleanArray, jsize, jsize, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jbooleanArray", "jsize", "jsize", "jboolean*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetBooleanArrayRegion(JNIEnv*, jbooleanArray, jsize, jsize, jboolean*)",
                },
            });
        },
    },
    GetByteArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, jbyte*)",
                    args,
                    argTypes: ["JNIEnv*", "jbyteArray", "jsize", "jsize", "jbyte*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, jbyte*)",
                },
            });
        },
    },
    GetCharArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, jchar*)",
                    args,
                    argTypes: ["JNIEnv*", "jcharArray", "jsize", "jsize", "jchar*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, jchar*)",
                },
            });
        },
    },
    GetShortArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetShortArrayRegion(JNIEnv*, jshortArray, jsize, jsize, jshort*)",
                    args,
                    argTypes: ["JNIEnv*", "jshortArray", "jsize", "jsize", "jshort*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetShortArrayRegion(JNIEnv*, jshortArray, jsize, jsize, jshort*)",
                },
            });
        },
    },
    GetIntArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetIntArrayRegion(JNIEnv*, jintArray, jsize, jsize, jint*)",
                    args,
                    argTypes: ["JNIEnv*", "jintArray", "jsize", "jsize", "jint*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetIntArrayRegion(JNIEnv*, jintArray, jsize, jsize, jint*)",
                },
            });
        },
    },
    GetLongArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetLongArrayRegion(JNIEnv*, jlongArray, jsize, jsize, jlong*)",
                    args,
                    argTypes: ["JNIEnv*", "jlongArray", "jsize", "jsize", "jlong*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetLongArrayRegion(JNIEnv*, jlongArray, jsize, jsize, jlong*)",
                },
            });
        },
    },
    GetFloatArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetFloatArrayRegion(JNIEnv*, jfloatArray, jsize, jsize, jfloat*)",
                    args,
                    argTypes: ["JNIEnv*", "jfloatArray", "jsize", "jsize", "jfloat*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetFloatArrayRegion(JNIEnv*, jfloatArray, jsize, jsize, jfloat*)",
                },
            });
        },
    },
    GetDoubleArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetDoubleArrayRegion(JNIEnv*, jdoubleArray, jsize, jsize, jdouble*)",
                    args,
                    argTypes: ["JNIEnv*", "jdoubleArray", "jsize", "jsize", "jdouble*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetDoubleArrayRegion(JNIEnv*, jdoubleArray, jsize, jsize, jdouble*)",
                },
            });
        },
    },
    SetBooleanArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetBooleanArrayRegion(JNIEnv*, jbooleanArray, jsize, jsize, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jbooleanArray", "jsize", "jsize", "jboolean*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetBooleanArrayRegion(JNIEnv*, jbooleanArray, jsize, jsize, jboolean*)",
                },
            });
        },
    },
    SetByteArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, jbyte*)",
                    args,
                    argTypes: ["JNIEnv*", "jbyteArray", "jsize", "jsize", "jbyte*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetByteArrayRegion(JNIEnv*, jbyteArray, jsize, jsize, jbyte*)",
                },
            });
        },
    },
    SetCharArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, jchar*)",
                    args,
                    argTypes: ["JNIEnv*", "jcharArray", "jsize", "jsize", "jchar*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetCharArrayRegion(JNIEnv*, jcharArray, jsize, jsize, jchar*)",
                },
            });
        },
    },
    SetShortArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetShortArrayRegion(JNIEnv*, jshortArray, jsize, jsize, jshort*)",
                    args,
                    argTypes: ["JNIEnv*", "jshortArray", "jsize", "jsize", "jshort*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetShortArrayRegion(JNIEnv*, jshortArray, jsize, jsize, jshort*)",
                },
            });
        },
    },
    SetIntArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetIntArrayRegion(JNIEnv*, jintArray, jsize, jsize, jint*)",
                    args,
                    argTypes: ["JNIEnv*", "jintArray", "jsize", "jsize", "jint*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetIntArrayRegion(JNIEnv*, jintArray, jsize, jsize, jint*)",
                },
            });
        },
    },
    SetLongArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetLongArrayRegion(JNIEnv*, jlongArray, jsize, jsize, jlong*)",
                    args,
                    argTypes: ["JNIEnv*", "jlongArray", "jsize", "jsize", "jlong*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetLongArrayRegion(JNIEnv*, jlongArray, jsize, jsize, jlong*)",
                },
            });
        },
    },
    SetFloatArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetFloatArrayRegion(JNIEnv*, jfloatArray, jsize, jsize, jfloat*)",
                    args,
                    argTypes: ["JNIEnv*", "jfloatArray", "jsize", "jsize", "jfloat*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetFloatArrayRegion(JNIEnv*, jfloatArray, jsize, jsize, jfloat*)",
                },
            });
        },
    },
    SetDoubleArrayRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void SetDoubleArrayRegion(JNIEnv*, jdoubleArray, jsize, jsize, jdouble*)",
                    args,
                    argTypes: ["JNIEnv*", "jdoubleArray", "jsize", "jsize", "jdouble*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void SetDoubleArrayRegion(JNIEnv*, jdoubleArray, jsize, jsize, jdouble*)",
                },
            });
        },
    },
    RegisterNatives: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jclass", "JNINativeMethod*", "jint"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint RegisterNatives(JNIEnv*, jclass, JNINativeMethod*, jint)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    UnregisterNatives: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint UnregisterNatives(JNIEnv*, jclass)",
                    args,
                    argTypes: ["JNIEnv*", "jclass"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint UnregisterNatives(JNIEnv*, jclass)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    MonitorEnter: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint MonitorEnter(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint MonitorEnter(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    MonitorExit: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint MonitorExit(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint MonitorExit(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    GetJavaVM: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jint GetJavaVM(JNIEnv*, JavaVM**)",
                    args,
                    argTypes: ["JNIEnv*", "JavaVM**"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jint GetJavaVM(JNIEnv*, JavaVM**)",
                    return: retVal,
                    retType: "jint",
                },
            });
        },
    },
    GetStringRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetStringRegion(JNIEnv*, jstring, jsize, jsize, jchar*)",
                    args,
                    argTypes: ["JNIEnv*", "jstring", "jsize", "jsize", "jchar*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetStringRegion(JNIEnv*, jstring, jsize, jsize, jchar*)",
                },
            });
        },
    },
    GetStringUTFRegion: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetStringUTFRegion(JNIEnv*, jstring, jsize, jsize, char*)",
                    args,
                    argTypes: ["JNIEnv*", "jstring", "jsize", "jsize", "char*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetStringUTFRegion(JNIEnv*, jstring, jsize, jsize, char*)",
                },
            });
        },
    },
    GetPrimitiveArrayCritical: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetPrimitiveArrayCritical(JNIEnv*, jarray, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jarray", "jboolean*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetPrimitiveArrayCritical(JNIEnv*, jarray, jboolean*)",
                },
            });
        },
    },
    ReleasePrimitiveArrayCritical: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleasePrimitiveArrayCritical(JNIEnv*, jarray, void*, jint)",
                    args,
                    argTypes: ["JNIEnv*", "jarray", "void*", "jint"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleasePrimitiveArrayCritical(JNIEnv*, jarray, void*, jint)",
                },
            });
        },
    },
    GetStringCritical: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jchar GetStringCritical(JNIEnv*, jstring, jboolean*)",
                    args,
                    argTypes: ["JNIEnv*", "jstring", "jboolean*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jchar GetStringCritical(JNIEnv*, jstring, jboolean*)",
                    return: retVal,
                    retType: "jchar",
                },
            });
        },
    },
    ReleaseStringCritical: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void ReleaseStringCritical(JNIEnv*, jstring, jchar*)",
                    args,
                    argTypes: ["JNIEnv*", "jstring", "jchar*"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void ReleaseStringCritical(JNIEnv*, jstring, jchar*)",
                },
            });
        },
    },
    NewWeakGlobalRef: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jweak NewWeakGlobalRef(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jweak NewWeakGlobalRef(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jweak",
                },
            });
        },
    },
    DeleteWeakGlobalRef: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void DeleteWeakGlobalRef(JNIEnv*, jweak)",
                    args,
                    argTypes: ["JNIEnv*", "jweak"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void DeleteWeakGlobalRef(JNIEnv*, jweak)",
                },
            });
        },
    },
    ExceptionCheck: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jboolean ExceptionCheck(JNIEnv*)",
                    args,
                    argTypes: ["JNIEnv*"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jboolean ExceptionCheck(JNIEnv*)",
                    return: retVal,
                    retType: "jboolean",
                },
            });
        },
    },
    NewDirectByteBuffer: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobject NewDirectByteBuffer(JNIEnv*, void*, jlong)",
                    args,
                    argTypes: ["JNIEnv*", "void*", "jlong"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobject NewDirectByteBuffer(JNIEnv*, void*, jlong)",
                    return: retVal,
                    retType: "jobject",
                },
            });
        },
    },
    GetDirectBufferAddress: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "void GetDirectBufferAddress(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave() {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "void GetDirectBufferAddress(JNIEnv*, jobject)",
                },
            });
        },
    },
    GetDirectBufferCapacity: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jlong GetDirectBufferCapacity(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jlong GetDirectBufferCapacity(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jlong",
                },
            });
        },
    },
    GetObjectRefType: {
        onEnter(args) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    in: "jobjectRefType GetObjectRefType(JNIEnv*, jobject)",
                    args,
                    argTypes: ["JNIEnv*", "jobject"],
                },
            });
        },
        onLeave(retVal) {
            DwarfCore.getInstance().sync({
                JNITracer: {
                    out: "jobjectRefType GetObjectRefType(JNIEnv*, jobject)",
                    return: retVal,
                    retType: "jobjectRefType",
                },
            });
        },
    },
};
