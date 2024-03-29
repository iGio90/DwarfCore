/**
 * Dwarf - Copyright (C) 2018-2023 Giovanni Rocca (iGio90), PinkiePieStyle
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import {DwarfCore} from "./DwarfCore";

export class ThreadWrapper {
    static handler: NativePointer = NULL;
    static handlerFunction: fArgReturn | null = null;
    static onCreateCallback = null;
    static pthreadCreateAddress: NativePointer | null = null;
    static pthreadCreateImplementation: NativeFunction<number, [NativePointerValue, NativePointerValue, NativePointerValue, NativePointerValue]> | null = null;

    private static init() {
        // attempt to retrieve pthread_create
        ThreadWrapper.pthreadCreateAddress = Module.findExportByName(null, "pthread_create");
        if (ThreadWrapper.pthreadCreateAddress != null && !ThreadWrapper.pthreadCreateAddress.isNull()) {
            ThreadWrapper.pthreadCreateImplementation = new NativeFunction(ThreadWrapper.pthreadCreateAddress, "int", ["pointer", "pointer", "pointer", "pointer"]);

            // allocate space for a fake handler which we intercept to run the callback
            ThreadWrapper.handler = Memory.alloc(Process.pointerSize);
            // set permissions
            Memory.protect(ThreadWrapper.handler, Process.pointerSize, "rwx");
            if (Process.arch === "arm64") {
                // arm64 require some fake code to get a trampoline from frida
                ThreadWrapper.handler.writeByteArray([0xe1, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
            }
            // hook the fake handler
            Interceptor.replace(
                ThreadWrapper.handler,
                new NativeCallback(
                    function () {
                        // null check for handler function
                        if (ThreadWrapper.handlerFunction !== null) {
                            // invoke callback
                            const ret = ThreadWrapper.handlerFunction.apply(this);
                            // reset callback (unsafe asf... but we don't care)
                            ThreadWrapper.handlerFunction = null;
                            // return result
                            return ret;
                        }
                        return 0;
                    },
                    "int",
                    []
                )
            );
            // replace pthread_create for fun and profit
            Interceptor.attach(ThreadWrapper.pthreadCreateAddress, function (args) {
                send("new_thread:::" + Process.getCurrentThreadId() + ":::" + args[2]);
                if (ThreadWrapper.onCreateCallback !== null && typeof ThreadWrapper.onCreateCallback === "function") {
                    ThreadWrapper.onCreateCallback(args[2]);
                }
            });
        }
    }

    static backtrace(context, backtracer) {
        return Thread.backtrace(context, backtracer);
    }

    static new(fn: fArgReturn) {
        // check if pthread_create is defined
        if (ThreadWrapper.pthreadCreateAddress !== null) {
            return 1;
        }

        // check if fn is a valid function
        if (typeof fn !== "function") {
            return 2;
        }

        // alocate space for struct pthread_t
        // tslint:disable-next-line: variable-name
        const pthread_t = Memory.alloc(Process.pointerSize);
        // set necessary permissions
        Memory.protect(pthread_t, Process.pointerSize, "rwx");
        // store the function into thread object
        ThreadWrapper.handlerFunction = fn;
        // spawn the thread
        return ThreadWrapper.pthreadCreateImplementation(pthread_t, ptr(0), ThreadWrapper.handler, ptr(0));
    }

    static sleep(delay) {
        Thread.sleep(delay);
    }

    // set a callback for thread creation
    static onCreate(callback) {
        ThreadWrapper.onCreateCallback = callback;
    }
}
