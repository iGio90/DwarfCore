import {Dwarf} from "./dwarf";

export class ThreadWrapper {
    static onCreateCallback = null;

    static pthreadCreateAddress: NativePointer | null = null;
    static pthreadCreateImplementation: NativeFunction;

    static handler: NativePointer = NULL;
    static handlerFunction: Function | null = null;
    
    private static init() {
        // attempt to retrieve pthread_create
        ThreadWrapper.pthreadCreateAddress = Module.findExportByName(null, 'pthread_create');
        if (ThreadWrapper.pthreadCreateAddress != null && !ThreadWrapper.pthreadCreateAddress.isNull()) {
            ThreadWrapper.pthreadCreateImplementation = new NativeFunction(ThreadWrapper.pthreadCreateAddress,
                'int', ['pointer', 'pointer', 'pointer', 'pointer']);

            // allocate space for a fake handler which we intercept to run the callback
            ThreadWrapper.handler = Memory.alloc(Process.pointerSize);
            // set permissions
            Memory.protect(ThreadWrapper.handler, Process.pointerSize, 'rwx');
            if (Process.arch === 'arm64') {
                // arm64 require some fake code to get a trampoline from frida
                ThreadWrapper.handler.writeByteArray([0xE1, 0x03, 0x01, 0xAA, 0xC0, 0x03, 0x5F, 0xD6]);
            }
            // hook the fake handler
            Interceptor.replace(ThreadWrapper.handler, new NativeCallback(function () {
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
            }, 'int', []));
            // replace pthread_create for fun and profit
            Interceptor.attach(ThreadWrapper.pthreadCreateAddress, function (args) {
                Dwarf.loggedSend('new_thread:::' + Process.getCurrentThreadId() + ':::' + args[2]);
                if (ThreadWrapper.onCreateCallback !== null && typeof ThreadWrapper.onCreateCallback === 'function') {
                    ThreadWrapper.onCreateCallback(args[2]);
                }
            });
        }
    }
    
    static backtrace(context, backtracer) {
        return Thread.backtrace(context, backtracer);
    }

    static new(fn: Function) {
        // check if pthread_create is defined
        if (ThreadWrapper.pthreadCreateAddress !== null) {
            return 1;
        }
    
        // check if fn is a valid function
        if (typeof fn !== 'function') {
            return 2;
        }
    
        // alocate space for struct pthread_t
        const pthread_t = Memory.alloc(Process.pointerSize);
        // set necessary permissions
        Memory.protect(pthread_t, Process.pointerSize, 'rwx');
        // store the function into thread object
        ThreadWrapper.handlerFunction = fn;
        // spawn the thread
        return ThreadWrapper.pthreadCreateImplementation(pthread_t, ptr(0), ThreadWrapper.handler, ptr(0));
    };
    
    static sleep(delay) {
        Thread.sleep(delay);
    };
    
    // set a callback for thread creation
    static onCreate(callback) {
        ThreadWrapper.onCreateCallback = callback;
    }
}