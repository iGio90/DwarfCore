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
import { DwarfJavaHelper } from "../java";


export class JavaBreakpoint extends DwarfBreakpoint {
    protected bpCallbacks: ScriptInvocationListenerCallbacks | Function | string;
    private isSetupDone: boolean;

    constructor(className: string, methodName: string = '$init', bpEnabled: boolean = true, bpCallbacks: ScriptInvocationListenerCallbacks | Function | string = 'breakpoint') {
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

        super(DwarfBreakpointType.JAVA, className + '.' + methodName, bpEnabled);

        if (isDefined) {
            this.bpCallbacks = bpCallbacks;
        } else {
            throw Error('JavaBreakpoint() callback missing');
        }

        this.isSetupDone = false;

        Java.performNow(() => {
            try {
                const testWrapper = Java.use(className);
                if (isDefined(testWrapper) && isDefined(testWrapper[methodName])) {
                    this.setup();
                }
            } catch (e) {
                //this is used in classloader wich setups the bp later when class is loaded
                DwarfJavaHelper.getInstance().addBreakpointToHook(this);
            }
        });
    }

    setup(): void {
        const self = this;
        Java.performNow(function () {
            const className = (self.bpAddress as string).substr(0, (self.bpAddress as string).lastIndexOf('.'));
            const methodName = (self.bpAddress as string).substr((self.bpAddress as string).lastIndexOf('.') + 1);
            try {
                Dwarf.getJavaHelper().hookInJVM(className, methodName, function () {
                    try {
                        let result = null;
                        self.onEnterCallback(this, arguments);

                        result = this[methodName].apply(this, arguments);

                        self.onLeaveCallback(this, result);
                        return result;
                    } catch (e) {
                        console.log(e);
                    }
                });
            } catch (e) {
                this.isSetupDone = false;
            }
        });
        this.isSetupDone = true;
    }

    public setCallback(bpCallback: ScriptInvocationListenerCallbacks | Function | string): void {
        this.bpCallbacks = bpCallback;
    }

    public removeCallback(): void {
        this.bpCallbacks = null;
    }

    public isHooked(): boolean {
        return this.isSetupDone;
    }
}
