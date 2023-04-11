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

import {DwarfHook} from "./DwarfHook";
import {DwarfCore} from "../DwarfCore";
import {DwarfMemoryAccessType, DwarfHookType} from "../consts";

export class MemoryHook extends DwarfHook {
    public isInternal?: boolean;
    protected bpFlags: number;
    protected memOrgPermissions: string;

    /**
     * Creates an instance of DwarfHook.
     *
     * @param  {NativePointer|string} bpAddress
     * @param  {number} bpFlags
     * @param userCallback
     * @param isSingleShot
     * @param isEnabled
     */
    public constructor(
        bpAddress: NativePointer | string,
        // eslint-disable-next-line no-bitwise
        bpFlags: number = DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE,
        userCallback: DwarfCallback,
        isSingleShot = false,
        isEnabled = true
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
        if (!isString(userCallback) && !isFunction(userCallback)) {
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

        return DwarfCore.getInstance().getHooksManager().updateMemoryHooks();
    }

    /**
     * Enables dwarf breakpoint
     */
    public enable(): void {
        trace("MemoryHook::enable()");

        // MemoryAccessMonitor is available on all platforms with >12.7.10
        super.enable();
        return DwarfCore.getInstance().getHooksManager().updateMemoryHooks();
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
