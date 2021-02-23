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

import { DwarfHook } from "./dwarf_hook";
import { DwarfCore } from "../DwarfCore";
import { DwarfMemoryAccessType, DwarfHookType, DwarfHaltReason } from "../consts";

export class MemoryHook extends DwarfHook {
    protected bpFlags: number;
    protected memOrgPermissions: string;

    /**
     * @param  {DwarfHookType} bpType
     * @param  {NativePointer|string} bpAddress
     * @param  {number} bpFlags
     */
    public constructor(
        bpAddress: NativePointer | string,
        // tslint:disable-next-line: no-bitwise
        bpFlags: number = DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE,
        userCallback: DwarfCallback,
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) {
        trace("MemoryHook()");
        const memPtr: NativePointer = makeNativePointer(bpAddress);

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

        // no onEnter/onLeave
        if(!isString(userCallback) && !isFunction(userCallback)) {
            throw new Error('MemoryHook() -> Invalid Callback!');
        }

        super(DwarfHookType.MEMORY, memPtr, userCallback, isSingleShot, isEnabled);

        this.bpFlags = bpFlags;
        this.memOrgPermissions = rangeDetails.protection;

        // Enable MemBP
        if (this.isEnabled()) {
            this.enable();
        }
    }

    /**
     * Disables dwarf breakpoint
     */
    public disable(): void {
        trace("MemoryHook::disable()");
        // MemoryAccessMonitor is available on all platforms with >12.7.10
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
     * Enables dwarf breakpoint
     */
    public enable(): void {
        trace("MemoryHook::enable()");

        // MemoryAccessMonitor is available on all platforms with >12.7.10
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
        // tslint:disable-next-line: no-bitwise
        if (this.bpFlags & DwarfMemoryAccessType.READ) {
            perm += "-";
        } else {
            perm += this.memOrgPermissions[0];
        }
        // tslint:disable-next-line: no-bitwise
        if (this.bpFlags & DwarfMemoryAccessType.WRITE) {
            perm += "-";
        } else {
            perm += this.memOrgPermissions[1];
        }
        // tslint:disable-next-line: no-bitwise
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

    public getFlags() {
        trace("MemoryHook::getFlags()");
        return this.bpFlags;
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
}
