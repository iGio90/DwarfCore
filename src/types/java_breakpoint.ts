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
import { LogicJava } from "../logic_java";


export class JavaBreakpoint extends DwarfBreakpoint {
    protected bpCallbacks: InvocationListenerCallbacks | Function | null;

    constructor(bpFunction: string, bpEnabled?: boolean) {
        if (typeof bpFunction !== 'string') {
            throw new Error('Invalid BreakpointAddress');
        }
        super(DwarfBreakpointType.JAVA, bpFunction, bpEnabled);

        //add check for () in bpFunction
        const className = bpFunction.substr(0, bpFunction.lastIndexOf('.'));
        const methodName = bpFunction.substr(bpFunction.lastIndexOf('.') + 1);

        const self = this;
        Java.performNow(function () {
            LogicJava.hookInJVM(className, methodName, function () {

                if(isDefined(self.bpCallbacks)) {
                    if(isValidFridaListener(self.bpCallbacks) && self.bpCallbacks.hasOwnProperty('onEnter')) {
                        const bpOnEnter = self.bpCallbacks['onEnter'];
                        if(isFunction(bpOnEnter)) {
                            //TODO:
                        }
                    }
                }
                //TODO: handle breakpoint callback when isfunction
                //TODO: remove LogicJava.jvmbreakpoint call and do it here
                LogicJava.jvmBreakpoint.call(this, className,
                    methodName, arguments, this.overload.argumentTypes);

                if(isDefined(self.bpCallbacks)) {
                    if(isValidFridaListener(self.bpCallbacks) && self.bpCallbacks.hasOwnProperty('onLeave')) {
                        const bpOnLeave = self.bpCallbacks['onLeave'];
                        if(isFunction(bpOnLeave)) {
                            //TODO:
                        }
                    }
                }
                //remove singleshots
                if (self.isSingleShot()) {
                    Dwarf.getBreakpointManager().update();
                }
            });
        });
    }

    public setCallback(bpCallback: InvocationListenerCallbacks | Function | null): void {
        this.bpCallbacks = bpCallback;
    }

    public removeCallback(): void {
        this.bpCallbacks = null;
    }
}
