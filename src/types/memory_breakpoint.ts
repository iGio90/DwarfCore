/**
    Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

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

import { DwarfBreakpoint } from "./dwarf_breakpoint";
import { DwarfCore } from "../dwarf";
import { DwarfMemoryAccessType, DwarfBreakpointType, DwarfHaltReason } from "../consts";

export class MemoryBreakpoint extends DwarfBreakpoint {
    protected bpFlags: number;
    protected memOrgPermissions: string;
    protected callBackFunc:Function | null;

    /**
     * @param  {DwarfBreakpointType} bpType
     * @param  {NativePointer|string} bpAddress
     * @param  {number} bpFlags
     */
    public constructor(bpAddress: NativePointer | string, bpFlags: number = (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled?: boolean, bpCallback?:Function) {
        let memPtr: NativePointer;
        if (typeof bpAddress === 'string') {
            memPtr = ptr(bpAddress);
        } else {
            memPtr = bpAddress;
        }

        if (memPtr.isNull()) {
            throw new Error('MemoryBreakpoint() -> Invalid Address!');
        }

        try {
            memPtr.readU8();
        } catch (error) {
            logErr('MemoryBreakpoint()', error);
            throw new Error('MemoryBreakpoint() -> Invalid Address!');
        }

        const rangeDetails = Process.findRangeByAddress(memPtr);
        if (rangeDetails === null) {
            throw new Error('MemoryBreakpoint() -> Unable to find MemoryRange!');
        }

        super(DwarfBreakpointType.MEMORY, memPtr, bpEnabled);

        this.bpFlags = bpFlags;
        this.memOrgPermissions = rangeDetails.protection;
        this.callBackFunc = bpCallback || null;

        //Enable MemBP
        if(this.isEnabled()) {
            this.enable();
        }
    }

    /**
     * Change MemoryBreakpoint flags
     *
     * @param  {number} bpFlags - DwarfMemoryAccessType
     */
    public setFlags(bpFlags: number):void {
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
        return this.bpFlags;
    }

    public setCallback(callbackFunction:Function):void {
        if(typeof callbackFunction === 'function') {
            this.callBackFunc = callbackFunction;
        }
    }

    public getCallback():Function|null {
        return this.callBackFunc;
    }

    public removeCallback():void {
        this.callBackFunc = null;
    }

    /**
     * Enables dwarf breakpoint
     */
    public enable(): void {
        if(Process.platform === 'windows') {
            super.enable();
            DwarfCore.getInstance().getBreakpointManager().updateMemoryBreakpoints();
            return;
        }

        let perm = '';
        if (this.bpFlags & DwarfMemoryAccessType.READ) {
            perm += '-';
        } else {
            perm += this.memOrgPermissions[0];
        }
        if (this.bpFlags & DwarfMemoryAccessType.WRITE) {
            perm += '-';
        } else {
            perm += this.memOrgPermissions[1];
        }
        if (this.bpFlags & DwarfMemoryAccessType.EXECUTE) {
            perm += '-';
        } else {
            if (this.memOrgPermissions[2] === 'x') {
                perm += 'x';
            } else {
                perm += '-';
            }
        }
        if (Memory.protect(this.bpAddress as NativePointer, 1, perm)) {
            super.enable();
        } else {
            throw new Error('MemoryBreakpoint::enable() -> Memory::protect failed!');
        }
    }

    /**
     * Disables dwarf breakpoint
     */
    public disable(): void {
        if(Process.platform === 'windows') {
            super.disable();
            DwarfCore.getInstance().getBreakpointManager().updateMemoryBreakpoints();
            return;
        }
        if (Memory.protect(this.bpAddress as NativePointer, 1, this.memOrgPermissions)) {
            super.disable();
        } else {
            throw new Error('MemoryBreakpoint::disable() -> Memory::protect failed!');
        }
    }

    /**
     * Toggles active
     * @returns true if active
     */
    public toggleActive(): boolean {
        if (this.isEnabled()) {
            this.disable();
        } else {
            this.enable();
        }
        return this.isEnabled();
    }

    public onHit(details:ExceptionDetails | MemoryAccessDetails) {
        const _self = this;
        const tid = Process.getCurrentThreadId();
        let memOperation:MemoryOperation;
        let fromPtr:NativePointer;
        let memAddress:NativePointer;

        this.disable();
        this.updateHitsCounter();

        if(Process.platform === 'windows') {
            memOperation = (details as MemoryAccessDetails).operation;
            fromPtr = (details as MemoryAccessDetails).from;
            memAddress = (details as MemoryAccessDetails).address;
        } else {
            memOperation = (details as ExceptionDetails).memory.operation;
            fromPtr = (details as ExceptionDetails).address;
            memAddress = (details as ExceptionDetails).memory.address;
        }

        const returnval = { 'memory': { 'operation': memOperation, 'address': memAddress, 'from': fromPtr } };
        if ((this.bpFlags & DwarfMemoryAccessType.READ) && (memOperation === 'read')) {
            DwarfCore.getInstance().loggedSend('membp:::' + JSON.stringify(returnval) + ':::' + tid);
        } else if ((this.bpFlags & DwarfMemoryAccessType.WRITE) && (memOperation === 'write')) {
            DwarfCore.getInstance().loggedSend('membp:::' + JSON.stringify(returnval) + ':::' + tid);
        } else if ((this.bpFlags & DwarfMemoryAccessType.EXECUTE) && (memOperation === 'execute')) {
            DwarfCore.getInstance().loggedSend('membp:::' + JSON.stringify(returnval) + ':::' + tid);
        }

        const invocationListener = Interceptor.attach(fromPtr, function (args) {
            const invocationContext:InvocationContext = this;
            invocationListener.detach();
            Interceptor.flush();

            const memoryCallback = _self.callBackFunc;
            if (memoryCallback !== null) {
                try {
                    memoryCallback.call(invocationContext, args);
                } catch(error) {
                    logErr('MemoryBreakpoint::callback()', error);
                }
            } else {
                //TODO: it halts only when no callback?
                DwarfCore.getInstance().onBreakpoint(DwarfHaltReason.BREAKPOINT, invocationContext.context.pc, invocationContext.context);
            }

            //reattach when enabled and not singleshot
            if (!_self.isSingleShot()) {
                _self.enable();
            }
        });
    }
}
