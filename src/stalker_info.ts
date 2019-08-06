export class StalkerInfo {
    tid: number;
    context = null;
    initialContextAddress = NULL;
    lastContextAddress = NULL;
    didFistJumpOut = false;
    terminated = false;
    currentMode = null;
    lastBlockInstruction = null;
    lastCallJumpInstruction = null;

    constructor(tid) {
        this.tid = tid;
    }
}