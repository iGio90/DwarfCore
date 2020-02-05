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


export class ClassLoadBreakpoint extends DwarfBreakpoint {
    /**
     * Creates an instance of DwarfBreakpoint.
     *
     * @param  {DwarfBreakpointType} bpType
     * @param  {NativePointer|string} bpAddress
     */
    constructor(className: string, bpEnabled?: boolean, bpCallback: ScriptInvocationListenerCallbacks | Function | string  = 'breakpoint') {
        if (!isString(className)) {
            throw new Error('ClassLoadBreakpoint() -> Invalid Arguments!');
        }

        super(DwarfBreakpointType.CLASS_LOAD, className, bpEnabled);
        this.bpCallbacks = bpCallback;
    }

    public getCallback() {
        return this.bpCallbacks;
    }

    public onHit() {
        this.bpActive = true;
        this.bpHits++;
    }
}
