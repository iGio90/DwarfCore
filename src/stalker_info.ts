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
    instructionsFilter: string[] = [];

    constructor(tid) {
        this.tid = tid;
    }
}