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

    constructor(className:string, methodName: string = '$init', bpEnabled: boolean = true, bpCallbacks:ScriptInvocationListenerCallbacks | Function | string = 'breakpoint') {
        trace('JavaBreakpoint()');

        if (!Java.available) {
            throw new Error('Java not available!');
        }

        if (!isString(className)) {
            throw new Error('Invalid className!');
        }

        if (!isString(methodName)) {
            throw new Error('Invalid methodName!');
        }

        Java.performNow(() => {
            try {
                const testWrapper = Java.use(className);
                if(isDefined(testWrapper) && !isDefined(testWrapper[methodName])) {
                    throw new Error('JavaBreakpoint() => Method: "' + methodName + '" not in "' + className + '"!');
                }
            } catch(e) {
                throw new Error('JavaBreakpoint() => ClassNotFound: "' + className + '" !');
            }
        });

        super(DwarfBreakpointType.JAVA, className + '.' + methodName, bpEnabled);

        if(isDefined) {
            this.bpCallbacks = bpCallbacks;
        } else {
            throw Error('JavaBreakpoint() callback missing');
        }

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

                    const classMethod = className + '.' + methodName;
                    const newArgs = {};
                    for (let i = 0; i < arguments.length; i++) {
                        let value = '';
                        if (arguments[i] === null || typeof arguments[i] === 'undefined') {
                            value = 'null';
                        } else {
                            if (typeof arguments[i] === 'object') {
                                value = JSON.stringify(arguments[i]);
                                if (arguments[i]['className'] === '[B') {
                                    value += ' (' + Java.use('java.lang.String').$new(arguments[i]) + ")";
                                }
                            } else {
                                value = arguments[i].toString();
                            }
                        }
                        newArgs[i] = {
                            arg: value,
                            name: this.overload.argumentTypes[i]['name'],
                            handle: arguments[i],
                            className: this.overload.argumentTypes[i]['className'],
                        }
                    }

                    if (!isDefined(userCallback) || (isString(userCallback) && userCallback === 'breakpoint')) {
                        Dwarf.onBreakpoint(Process.getCurrentThreadId(), DwarfHaltReason.BREAKPOINT, classMethod, newArgs, this);
                    }

                    let result = this[methodName].apply(this, arguments);

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
