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

import { DwarfBreakpoint } from "./types/dwarf_breakpoint"
import { NativeBreakpoint } from "./types/native_breakpoint";
import { JavaBreakpoint } from "./types/java_breakpoint";
import { MemoryBreakpoint } from "./types/memory_breakpoint";
import { DwarfCore } from "./dwarf";
import { DwarfBreakpointType, DwarfMemoryAccessType, DwarfHaltReason } from "./consts";

/**
 * DwarfBreakpointManager Singleton
 *
 * use Dwarf.getBreakpointManager() or DwarfBreakpointManager.getInstance()
 */
export class DwarfBreakpointManager {
    private static instanceRef: DwarfBreakpointManager;
    protected dwarfBreakpoints: Array<DwarfBreakpoint>;

    private constructor() {
        if (DwarfBreakpointManager.instanceRef) {
            throw new Error("DwarfBreakpointManager already exists! Use DwarfBreakpointManager.getInstance()/Dwarf.getBreakpointManager()");
        }
        logDebug('DwarfBreakpointManager()');
        this.dwarfBreakpoints = new Array<DwarfBreakpoint>();
    }

    static getInstance() {
        if (!DwarfBreakpointManager.instanceRef) {
            DwarfBreakpointManager.instanceRef = new this();
        }
        return DwarfBreakpointManager.instanceRef;
    }

    /**
     * @param  {DwarfBreakpointType} bpType
     * @param  {NativePointer|string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addBreakpoint = (bpType: DwarfBreakpointType, bpAddress: NativePointer | string, bpEnabled?: boolean) => {
        switch (bpType) {
            case DwarfBreakpointType.NATIVE:
                return this.addNativeBreakpoint(bpAddress, bpEnabled);
            case DwarfBreakpointType.JAVA:
                return this.addJavaBreakpoint(bpAddress as string, bpEnabled);
            case DwarfBreakpointType.OBJC:
                return this.addObjCBreakpoint(bpAddress as string, bpEnabled);
            case DwarfBreakpointType.MEMORY:
                return this.addMemoryBreakpoint(bpAddress, (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled);
        }
        throw new Error('DwarfBreakpointManager::addBreakpoint() -> Unknown BreakpointType!');
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addNativeBreakpoint = (bpAddress: NativePointer | string, bpEnabled?: boolean) => {
        try {
            const nativeBreakpoint = new NativeBreakpoint(bpAddress, bpEnabled);
            this.dwarfBreakpoints.push(nativeBreakpoint);
            return nativeBreakpoint;
        } catch (error) {

        }
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @param  {number=(DwarfMemoryAccessType.READ|DwarfMemoryAccessType.WRITE} bpFlags
     */
    public addMemoryBreakpoint = (bpAddress: NativePointer | string, bpFlags: number = (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled?: boolean) => {
        try {
            const memBreakpoint = new MemoryBreakpoint(bpAddress, (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled);
            this.dwarfBreakpoints.push(memBreakpoint);
            this.updateMemoryBreakpoints();
            return memBreakpoint;
        } catch (error) {

        }
    }

    /**
     * @param  {string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addJavaBreakpoint = (bpAddress: string, bpEnabled?: boolean) => {
        try {
            const javaBreakpoint = new JavaBreakpoint(bpAddress, bpEnabled);
            this.dwarfBreakpoints.push(javaBreakpoint);
            return javaBreakpoint;
        } catch (error) {

        }
    }

    /**
     * @param  {string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addObjCBreakpoint = (bpAddress: string, bpEnabled?: boolean) => {
        throw new Error('DwarfBreakpointManager::addObjCBreakpoint() -> Not implemented');
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns DwarfBreakpoint
     */
    public getBreakpointByAddress = (bpAddress: NativePointer | string, checkEnabled: boolean = false, checkForType?: DwarfBreakpointType): DwarfBreakpoint | null => {
        let bpFindAddress;
        if (typeof bpAddress === 'string') {
            bpFindAddress = bpAddress;
        } else {
            if (bpAddress.isNull()) {
                throw new Error('DwarfBreakpointManager::getBreakpointByAddress() -> Invalid Address!');
            }
            bpFindAddress = bpAddress.toString();
        }
        let dwarfBreakpoint = null;
        for (let bp of this.dwarfBreakpoints) {
            if (bp.getAddress() === bpFindAddress) {
                if (checkEnabled && !bp.isEnabled()) {
                    continue;
                }
                if (checkForType && bp.getType() !== checkForType) {
                    continue;
                }
                dwarfBreakpoint = bp;
                break;
            }
        }

        return dwarfBreakpoint;
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public toggleBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.toggleActive();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public enableBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.enable();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public disableBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.disable();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * Windows related stuff to handle MemoryBreakpoints
     * Call it after something MemoryBreakpoint related changes
     */
    public updateMemoryBreakpoints(): void {
        if (Process.platform === 'windows') {
            MemoryAccessMonitor.disable();
            let memoryBreakpoints;
            for (let memBreakpoint of this.dwarfBreakpoints) {
                if (memBreakpoint.getType() === DwarfBreakpointType.MEMORY) {
                    if (memBreakpoint.isEnabled()) {
                        memoryBreakpoints.push(memBreakpoint);
                    }
                }
            }
            if (memoryBreakpoints.length > 0) {
                MemoryAccessMonitor.enable(memoryBreakpoints, { onAccess: this.handleMemoryBreakpoints });
            }
        }
    }

    public handleMemoryBreakpoints = (details: ExceptionDetails | MemoryAccessDetails) => {
        let memoryAddress;
        if(Process.platform === 'windows') {
            memoryAddress = (details as MemoryAccessDetails).address;
        } else {
            memoryAddress = (details as ExceptionDetails).memory.address;
        }

        const dwarfBreakpoint = this.getBreakpointByAddress(memoryAddress, true, DwarfBreakpointType.MEMORY);

        if (dwarfBreakpoint === null) {
            return false;
        }

        const memoryBreakpoint = dwarfBreakpoint as MemoryBreakpoint;

        memoryBreakpoint.onHit(details);

        return true;
    }
}