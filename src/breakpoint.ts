export class Breakpoint {
    target: NativePointer | string;
    interceptor?: InvocationListener;
    condition?: string | Function;

    constructor(target: NativePointer | string) {
        this.target = target;
    }
}