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
import { DwarfBreakpointType } from "../consts";


export class NativeBreakpoint extends DwarfBreakpoint {
    protected bpCallbacks: InvocationListenerCallbacks | Function | null;
    protected bpDebugSymbol:DebugSymbol;
    protected bpCondition:Function;

    /**
     * Creates an instance of DwarfBreakpoint.
     *
     * @param  {DwarfBreakpointType} bpType
     * @param  {NativePointer|string} bpAddress
     */
    constructor(bpAddress: NativePointer | string, bpEnabled?: boolean, bpCallback?: InvocationListenerCallbacks | Function) {
        let natPtr;
        if (typeof bpAddress === 'string') {
            natPtr = ptr(bpAddress);
        } else {
            natPtr = bpAddress;
        }

        if (natPtr.isNull()) {
            throw new Error('NativeBreakpoint() -> Invalid Address!');
        }

        try {
            natPtr.readU8();
        } catch (error) {
            logErr('NativeBreakpoint()', error);
            throw new Error('NativeBreakpoint() -> Invalid Address!');
        }

        super(DwarfBreakpointType.NATIVE, natPtr, bpEnabled);

        this.bpDebugSymbol = DebugSymbol.fromAddress(natPtr);
        this.bpCallbacks = bpCallback || null;
    }

    public setCallback(bpCallback: InvocationListenerCallbacks | Function | null): void {
        this.bpCallbacks = bpCallback;
    }

    public removeCallback(): void {
        this.bpCallbacks = null;
    }

    public setCondition(bpCondition: string | Function): void {
        if(typeof bpCondition === 'string') {
            this.bpCondition = new Function(bpCondition);
        } else {
            if(typeof bpCondition === 'function') {
                this.bpCondition = bpCondition;
            } else {
                logDebug('NativeBreakpoint::setCondition() -> Unknown bpCondition!');
            }
        }
    }

    public getCondition():Function {
        return this.bpCondition;
    }

    public removeCondition():void {
        this.bpCondition = null;
    }
}
