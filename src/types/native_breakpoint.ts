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
import { DwarfBreakpointType, DwarfHaltReason } from "../consts";
import { DwarfCore } from "../dwarf";


export class NativeBreakpoint extends DwarfBreakpoint {
    protected bpCallbacks: InvocationListenerCallbacks | Function | null;
    protected bpDebugSymbol: DebugSymbol;
    protected bpCondition: Function;

    /**
     * Creates an instance of DwarfBreakpoint.
     *
     * @param  {DwarfBreakpointType} bpType
     * @param  {NativePointer|string} bpAddress
     */
    constructor(bpAddress: NativePointer | string, bpEnabled?: boolean, bpCallback?: ScriptInvocationListenerCallbacks | Function) {
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

        const self = this;

        if (!isDefined(this.bpCallbacks) || (isString(this.bpCallbacks) && this.bpCallbacks === 'breakpoint')) {
            const invocationListener = Interceptor.attach(natPtr, function () {
                const invocationContext = this;

                self.bpActive = true;
                self.bpHits++;

                DwarfCore.getInstance().onBreakpoint(self.bpID, self.threadId, DwarfHaltReason.BREAKPOINT, invocationContext.context.pc,
                    invocationContext.context, null, self.bpCondition);

                self.bpActive = false;
                if (self.isSingleShot()) {
                    invocationListener.detach();
                    Interceptor.flush();
                    DwarfCore.getInstance().getBreakpointManager().update();
                }
            });
        } else if (isDefined(this.bpCallbacks) && isFunction(this.bpCallbacks)) {
            const invocationListener = Interceptor.attach(natPtr, function () {
                const invocationContext = this;
                let breakExecution = false;

                self.bpActive = true;
                self.bpHits++;

                if (isDefined(self.bpCallbacks)) {
                    const userReturn = (self.bpCallbacks as Function).apply(this, arguments);
                    if (isDefined(userReturn) && userReturn == 1) {
                        breakExecution = true;
                    }
                }

                if (breakExecution) {
                    DwarfCore.getInstance().onBreakpoint(self.bpID, self.threadId, DwarfHaltReason.BREAKPOINT, invocationContext.context.pc,
                        invocationContext.context, null, self.bpCondition);
                }

                self.bpActive = false;
                if (self.isSingleShot()) {
                    invocationListener.detach();
                    Interceptor.flush();
                    DwarfCore.getInstance().getBreakpointManager().update();
                }
            });
        } else if (isDefined(this.bpCallbacks) && (this.bpCallbacks.hasOwnProperty('onEnter') || this.bpCallbacks.hasOwnProperty('onLeave'))) {
            const invocationListener = Interceptor.attach(natPtr, {
                onEnter: function () {
                    const invocationContext = this;
                    let breakExecution = false;

                    self.bpActive = true;
                    self.bpHits++;

                    if (isDefined(self.bpCallbacks) && self.bpCallbacks.hasOwnProperty('onEnter')) {
                        const userOnEnter = (self.bpCallbacks as ScriptInvocationListenerCallbacks).onEnter;
                        if (isFunction(userOnEnter)) {
                            let userReturn = userOnEnter.apply(this, arguments);
                            if (isDefined(userReturn) && userReturn == 1) {
                                breakExecution = true;
                            }
                        }
                    }

                    if (breakExecution) {
                        DwarfCore.getInstance().onBreakpoint(self.bpID, self.threadId, DwarfHaltReason.BREAKPOINT, invocationContext.context.pc,
                            invocationContext.context, null, self.bpCondition);
                    }
                },
                onLeave: function (result) {
                    const invocationContext = this;
                    let breakExecution = false;

                    if (isDefined(self.bpCallbacks) && self.bpCallbacks.hasOwnProperty('onLeave')) {
                        const userOnLeave = (self.bpCallbacks as ScriptInvocationListenerCallbacks).onLeave;
                        if (isFunction(userOnLeave)) {
                            let userReturn = userOnLeave.apply(this, result);
                            if (isDefined(userReturn) && userReturn == 1) {
                                breakExecution = true;
                            }
                        }
                    }

                    if (breakExecution) {
                        DwarfCore.getInstance().onBreakpoint(self.bpID, self.threadId, DwarfHaltReason.BREAKPOINT, invocationContext.context.pc,
                            invocationContext.context, null, self.bpCondition);
                    }

                    self.bpActive = false;
                    if (self.isSingleShot()) {
                        invocationListener.detach();
                        Interceptor.flush();
                        DwarfCore.getInstance().getBreakpointManager().update();
                    }
                    return result;
                }
            });
        }
    }

    public setCallback(bpCallback: InvocationListenerCallbacks | Function | null): void {
        this.bpCallbacks = bpCallback;
    }

    public removeCallback(): void {
        this.bpCallbacks = null;
    }

    public setCondition(bpCondition: string | Function): void {
        if (typeof bpCondition === 'string') {
            this.bpCondition = new Function(bpCondition);
        } else {
            if (typeof bpCondition === 'function') {
                this.bpCondition = bpCondition;
            } else {
                logDebug('NativeBreakpoint::setCondition() -> Unknown bpCondition!');
            }
        }
    }

    public getCondition(): Function {
        return this.bpCondition;
    }

    public removeCondition(): void {
        this.bpCondition = null;
    }
}
