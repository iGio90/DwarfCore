export class ThreadContext {
    tid: number;
    context = null;
    javaHandle = null;

    apiQueue = [];
    preventSleep = false;

    constructor(tid) {
        this.tid = tid;
    }
}