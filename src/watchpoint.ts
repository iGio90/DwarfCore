export const MEMORY_ACCESS_READ = 1;
export const MEMORY_ACCESS_WRITE = 2;
export const MEMORY_ACCESS_EXECUTE = 4;
export const MEMORY_WATCH_SINGLE_SHOT = 8;


export class Watchpoint {
    address: NativePointer;
    flags: number;
    originalPermissions: string;
    debugSymbol: DebugSymbol;
    callback: Function | null;

    constructor(address: NativePointer, flags: number, perm: string, callback: Function | null) {
        this.address = address;
        this.debugSymbol = DebugSymbol.fromAddress(address);
        this.flags = flags;
        this.originalPermissions = perm;
        this.callback = callback;
    }

    watch() {
        let perm = '';
        if (this.flags & MEMORY_ACCESS_READ) {
            perm += '-';
        } else {
            perm += this.originalPermissions[0];
        }
        if (this.flags & MEMORY_ACCESS_WRITE) {
            perm += '-';
        } else {
            perm += this.originalPermissions[1];
        }
        if (this.flags & MEMORY_ACCESS_EXECUTE) {
            perm += '-';
        } else {
            if (this.originalPermissions[2] === 'x') {
                perm += 'x';
            } else {
                perm += '-';
            }
        }
        Memory.protect(this.address, 1, perm);
    };

    restore() {
        Memory.protect(this.address, 1, this.originalPermissions)
    };
}