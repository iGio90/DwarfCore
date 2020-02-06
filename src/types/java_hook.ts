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

import { DwarfHook } from "./dwarf_hook";
import { DwarfHookType } from "../consts";
import { DwarfJavaHelper } from "../java";

export class JavaHook extends DwarfHook {
    private isSetupDone: boolean;

    constructor(className: string, methodName: string = "$init", userCallback: DwarfCallback = "breakpoint", isEnabled: boolean = true, isSingleShot: boolean = false) {
        trace("JavaHook()");

        if (!Java.available) {
            throw new Error("Java not available!");
        }

        if (!isString(className)) {
            throw new Error("Invalid className!");
        }

        if (!isString(methodName)) {
            throw new Error("Invalid methodName!");
        }

        super(DwarfHookType.JAVA, className + "." + methodName, userCallback, isEnabled, isSingleShot);

        this.isSetupDone = false;

        //try to attach or add to classLoaderHook wich calls setup when class is loaded
        Java.performNow(() => {
            try {
                const testWrapper = Java.use(className);
                if (isDefined(testWrapper) && isDefined(testWrapper[methodName])) {
                    this.setup();
                }
            } catch (e) {
                //this is used in classloader wich setups the bp later when class is loaded
                DwarfJavaHelper.getInstance().addHookToHook(this);
            }
        });
    }

    public setup(): void {
        const self = this;
        Java.performNow(function() {
            const className = (self.hookAddress as string).substr(0, (self.hookAddress as string).lastIndexOf("."));
            const methodName = (self.hookAddress as string).substr((self.hookAddress as string).lastIndexOf(".") + 1);
            try {
                Dwarf.getJavaHelper().hookInJVM(className, methodName, function() {
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

    /**
     * Returns true if hook is placed
     *
     * @returns boolean
     */
    public isHooked(): boolean {
        return this.isSetupDone;
    }
}
