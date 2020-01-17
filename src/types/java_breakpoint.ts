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
import { LogicJava } from "../logic_java";


export class JavaBreakpoint extends DwarfBreakpoint {
    protected bpCallbacks: ScriptInvocationListenerCallbacks | Function | string;

    constructor(bpFunction: string, bpEnabled?: boolean, bpCallbacks?) {
        if (typeof bpFunction !== 'string') {
            throw new Error('Invalid BreakpointAddress');
        }
        super(DwarfBreakpointType.JAVA, bpFunction, bpEnabled);

        if(isDefined(bpCallbacks)) {
            this.setCallback(bpCallbacks);
        } else {
            this.setCallback('breakpoint');
        }

        //add check for () in bpFunction
        const className = bpFunction.substr(0, bpFunction.lastIndexOf('.'));
        const methodName = bpFunction.substr(bpFunction.lastIndexOf('.') + 1);

        const self = this;
        Java.performNow(function () {
            Dwarf.getJavaHelper().hookInJVM(className, methodName, function () {
                try {
                    let userCallback: ScriptInvocationListenerCallbacks | Function | string = self.bpCallbacks;

                    if (isFunction(userCallback)) {
                        (userCallback as Function).apply(this, arguments);
                    } else if (isDefined(userCallback) && userCallback.hasOwnProperty('onEnter')) {
                        const userOnEnter = (userCallback as ScriptInvocationListenerCallbacks).onEnter;
                        if (isFunction(userOnEnter)) {
                            userOnEnter.apply(this, arguments);
                        }
                    }

                    if (!isDefined(userCallback) || (isString(userCallback) && userCallback === 'breakpoint')) {
                        Dwarf.onBreakpoint(DwarfHaltReason.BREAKPOINT, bpFunction, {}, this);
                    }

                    let result = this.methodName(arguments);

                    if (isDefined(userCallback) && userCallback.hasOwnProperty('onLeave')) {
                        const userOnLeave = (userCallback as ScriptInvocationListenerCallbacks).onLeave;
                        if (isFunction(userOnLeave)) {
                            userOnLeave.apply(this, result);
                        }
                    }

                    return result;
                } catch (e) {
                    console.log(e);
                }

                //remove singleshots
                if (self.isSingleShot()) {
                    Dwarf.getBreakpointManager().update();
                }
            });
        });
    }

    public setCallback(bpCallback: ScriptInvocationListenerCallbacks | Function | string): void {
        this.bpCallbacks = bpCallback;
    }

    public removeCallback(): void {
        this.bpCallbacks = null;
    }
}
