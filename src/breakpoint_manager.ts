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
import { NOTIMP } from "dns";

export class DwarfBreakpointManager {
    protected dwarfBreakpoints: Array<DwarfBreakpoint>;

    addBreakpoint = (bpType: DwarfBreakpointType, bpAddress: NativePointer | string) => {
        switch (bpType) {
            case DwarfBreakpointType.NATIVE:
                return this.addNativeBreakpoint(bpAddress);
            case DwarfBreakpointType.JAVA:
                return this.addJavaBreakpoint(bpAddress as string);
            case DwarfBreakpointType.OBJC:
                return this.addObjCBreakpoint(bpAddress as string);
        }

    }

    addNativeBreakpoint = (bpAddress: NativePointer | string) => {
        try {
            const nativeBreakpoint = new NativeBreakpoint(bpAddress);
            this.dwarfBreakpoints.push(nativeBreakpoint);
            return nativeBreakpoint;
        } catch (error) {

        }
    }

    addJavaBreakpoint = (bpAddress: string) => {
        try {
            const javaBreakpoint = new JavaBreakpoint(bpAddress);
            this.dwarfBreakpoints.push(javaBreakpoint);
            return javaBreakpoint;
        } catch (error) {

        }
    }

    addObjCBreakpoint = (bpAddress:string) => {
        throw new Error('addObjCBreakpoint() -> Not implemented');
    }

    getBreakpointByAddress = (bpAddress: NativePointer | string): DwarfBreakpoint | null => {
        let bpFindAddress;
        if (typeof bpAddress === 'string') {
            bpFindAddress = bpAddress;
        } else {
            if (bpAddress.isNull()) {
                throw new Error('getBreakpointByAddress() -> Invalid Address!');
            }
            bpFindAddress = bpAddress.toString();
        }
        let dwarfBreakpoint = null;
        for (let bp of this.dwarfBreakpoints) {
            if (bp.getAddress() === bpFindAddress) {
                dwarfBreakpoint = bp;
                break;
            }
        }

        return dwarfBreakpoint;
    }

    toggleBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if(dwarfBreakpoint !== null) {
            dwarfBreakpoint.toggleActive();
            return dwarfBreakpoint.isEnabled();
        }
    }

    enableBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if(dwarfBreakpoint !== null) {
            dwarfBreakpoint.enable();
            return dwarfBreakpoint.isEnabled();
        }
    }

    disableBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if(dwarfBreakpoint !== null) {
            dwarfBreakpoint.disable();
            return dwarfBreakpoint.isEnabled();
        }
    }
}