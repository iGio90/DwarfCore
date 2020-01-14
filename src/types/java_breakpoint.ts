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

import { DwarfBreakpoint } from "./dwarf_breakpoint";
import { DwarfBreakpointType } from "../consts";


export class JavaBreakpoint extends DwarfBreakpoint {
    protected bpCallbacks: InvocationListenerCallbacks | Function | null;

    constructor(bpAddress: string, bpEnabled?: boolean) {
        if (typeof bpAddress !== 'string') {
            throw new Error('Invalid BreakpointAddress');
        }
        super(DwarfBreakpointType.JAVA, bpAddress, bpEnabled);
    }

    public setCallback(bpCallback: InvocationListenerCallbacks | Function | null): void {
        this.bpCallbacks = bpCallback;
    }

    public removeCallback(): void {
        this.bpCallbacks = null;
    }
}
