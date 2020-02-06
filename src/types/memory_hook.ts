/**
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

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
**/

import { DwarfHook } from "./dwarf_hook";
import { DwarfCore } from "../dwarf";
import { DwarfMemoryAccessType, DwarfHookType, DwarfHaltReason } from "../consts";

export class MemoryHook extends DwarfHook {
    protected bpFlags: number;
    protected memOrgPermissions: string;
    protected callBackFunc: Function | null;

    /**
     * @param  {DwarfHookType} bpType
     * @param  {NativePointer|string} bpAddress
     * @param  {number} bpFlags
     */
    public constructor(
        bpAddress: NativePointer | string,
        bpFlags: number = DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) {
        trace("MemoryHook()");
        let memPtr: NativePointer = makeNativePointer(bpAddress);

        if (memPtr === null || memPtr.isNull()) {
            throw new Error("MemoryHook() -> Invalid Address!");
        }

        try {
            memPtr.readU8();
        } catch (error) {
            logErr("MemoryHook()", error);
            throw new Error("MemoryHook() -> Invalid Address!");
        }

        const rangeDetails = Process.findRangeByAddress(memPtr);
        if (rangeDetails === null) {
            throw new Error("MemoryHook() -> Unable to find MemoryRange!");
        }

        super(DwarfHookType.MEMORY, memPtr, userCallback, isSingleShot, isEnabled);

        this.bpFlags = bpFlags;
        this.memOrgPermissions = rangeDetails.protection;

        //Enable MemBP
        if (this.isEnabled()) {
            this.enable();
        }
    }

    /**
     * Change MemoryHook flags
     *
     * @param  {number} bpFlags - DwarfMemoryAccessType
     */
    public setFlags(bpFlags: number): void {
        trace("MemoryHook::setFlags()");
        let wasEnabled = false;
        if (this.isEnabled()) {
            this.disable();
            wasEnabled = true;
        }

        this.bpFlags = bpFlags;

        if (wasEnabled) {
            this.enable();
        }
    }

    public getFlags() {
        trace("MemoryHook::getFlags()");
        return this.bpFlags;
    }

    public setCallback(callbackFunction: Function): void {
        trace("MemoryHook::setCallback()");
        if (typeof callbackFunction === "function") {
            this.callBackFunc = callbackFunction;
        }
    }

    public getCallback(): Function | null {
        trace("MemoryHook::getCallback()");
        return this.callBackFunc;
    }

    public removeCallback(): void {
        trace("MemoryHook::removeCallback()");
        this.callBackFunc = null;
    }

    /**
     * Enables dwarf breakpoint
     */
    public enable(): void {
        trace("MemoryHook::enable()");

        //MemoryAccessMonitor is available on all platforms with >12.7.10
        super.enable();
        DwarfCore.getInstance()
            .getHooksManager()
            .updateMemoryHooks();
        return;
        if (Process.platform === "windows") {
            super.enable();
            DwarfCore.getInstance()
                .getHooksManager()
                .updateMemoryHooks();
            return;
        }

        let perm = "";
        if (this.bpFlags & DwarfMemoryAccessType.READ) {
            perm += "-";
        } else {
            perm += this.memOrgPermissions[0];
        }
        if (this.bpFlags & DwarfMemoryAccessType.WRITE) {
            perm += "-";
        } else {
            perm += this.memOrgPermissions[1];
        }
        if (this.bpFlags & DwarfMemoryAccessType.EXECUTE) {
            perm += "-";
        } else {
            if (this.memOrgPermissions[2] === "x") {
                perm += "x";
            } else {
                perm += "-";
            }
        }
        if (Memory.protect(this.hookAddress as NativePointer, 1, perm)) {
            super.enable();
        } else {
            throw new Error("MemoryHook::enable() -> Memory::protect failed!");
        }
    }

    /**
     * Disables dwarf breakpoint
     */
    public disable(): void {
        trace("MemoryHook::disable()");
        //MemoryAccessMonitor is available on all platforms with >12.7.10
        super.disable();
        DwarfCore.getInstance()
            .getHooksManager()
            .updateMemoryHooks();
        return;
        if (Process.platform === "windows") {
            super.disable();
            DwarfCore.getInstance()
                .getHooksManager()
                .updateMemoryHooks();
            return;
        }
        if (Memory.protect(this.hookAddress as NativePointer, 1, this.memOrgPermissions)) {
            super.disable();
        } else {
            throw new Error("MemoryHook::disable() -> Memory::protect failed!");
        }
    }

    /**
     * Toggles active
     * @returns true if active
     */
    public toggleActive(): boolean {
        trace("MemoryHook::toggleActive()");
        if (this.isEnabled()) {
            this.disable();
        } else {
            this.enable();
        }
        return this.isEnabled();
    }

    public onHit(details: ExceptionDetails | MemoryAccessDetails): boolean {
        trace("MemoryHook::onHit()");
        const _self = this;
        const tid = Process.getCurrentThreadId();
        let memOperation: MemoryOperation;
        let fromPtr: NativePointer;
        let memAddress: NativePointer;

        if (Process.platform === "windows") {
            memOperation = (details as MemoryAccessDetails).operation;
            fromPtr = (details as MemoryAccessDetails).from;
            memAddress = (details as MemoryAccessDetails).address;
        } else {
            memOperation = (details as ExceptionDetails).memory.operation;
            fromPtr = (details as ExceptionDetails).address;
            memAddress = (details as ExceptionDetails).memory.address;
        }

        let handleBp = false;

        switch (memOperation) {
            case "read":
                if (this.bpFlags & DwarfMemoryAccessType.READ) {
                    handleBp = true;
                }
                break;
            case "write":
                if (this.bpFlags & DwarfMemoryAccessType.WRITE) {
                    handleBp = true;
                }
                break;
            case "execute":
                if (this.bpFlags & DwarfMemoryAccessType.EXECUTE) {
                    handleBp = true;
                }
                break;
            default:
                logDebug("MemoryHook::onHit() -> Unknown Operation or Invalid Flags! (OP: " + memOperation + ", FLAGS: " + this.bpFlags.toString() + ")");
        }

        if (!handleBp) {
            return false;
        }

        //send infos to ui
        const returnval = { memory: { operation: memOperation, address: memAddress, from: fromPtr } };
        DwarfCore.getInstance().loggedSend("membp:::" + JSON.stringify(returnval) + ":::" + tid);

        //Disable to allow access to mem
        this.disable();
        this.bpHits++;

        const self = this;

        const invocationListener = Interceptor.attach(fromPtr, function(args) {
            const invocationContext: InvocationContext = this;
            invocationListener.detach();
            Interceptor.flush();

            const memoryCallback = _self.callBackFunc;
            if (memoryCallback !== null) {
                try {
                    memoryCallback.call(invocationContext, args);
                } catch (error) {
                    logErr("MemoryHook::callback()", error);
                }
            } else {
                //TODO: it halts only when no callback?
                DwarfCore.getInstance().onBreakpoint(
                    self.hookID,
                    Process.getCurrentThreadId(),
                    DwarfHaltReason.BREAKPOINT,
                    invocationContext.context.pc,
                    invocationContext.context
                );
            }

            //reattach if not singleshot
            if (!_self.isSingleShot()) {
                _self.enable();
            }
        });
        return true;
    }
}
