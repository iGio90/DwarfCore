/*
    Dwarf - Copyright (C) 2018-2021 Giovanni Rocca (iGio90)

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
*/

import { DwarfHook } from "./DwarfHook";
import { DwarfHookType } from "../consts";
import { DwarfJavaHelper } from "../DwarfJavaHelper";
import { DwarfCore } from "../DwarfCore";

export class JavaHook extends DwarfHook {
    protected warningShown: boolean;

    constructor(
        className: string,
        methodName: string = "$init",
        userCallback: DwarfCallback = "breakpoint",
        isEnabled: boolean = true,
        isSingleShot: boolean = false
    ) {
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

        if (!isFunction(userCallback) && !isString(userCallback) && !isValidFridaListener(userCallback)) {
            throw new Error("JavaHook() -> Invalid Callback!");
        }

        super(DwarfHookType.JAVA, className + "." + methodName, userCallback, isSingleShot, isEnabled);

        this.bAttached = false;
        this.warningShown = false;

        // try to attach or add to classLoaderHook wich calls setup when class is loaded
        Java.performNow(() => {
            try {
                const testWrapper = Java.use(className);
                if (isDefined(testWrapper) && isDefined(testWrapper[methodName])) {
                    this.setup();
                } else {
                    console.log("Warning: Class or Method not found! (" + className + "." + methodName + ")");
                    this.warningShown = true;
                }
            } catch (e) {
                // this is used in classloader wich setups the bp later when class is loaded
                DwarfJavaHelper.getInstance().addHookToAttach(this);
            }
        });
    }

    public remove(syncUi: boolean = true): void {
        trace("JavaHook::remove()");

        if (this.bAttached) {
            const hookAddress = this.hookAddress as string;
            const className = hookAddress.substring(0, hookAddress.lastIndexOf("."));
            const methodName = hookAddress.substring(hookAddress.lastIndexOf(".") + 1);
            DwarfJavaHelper.getInstance().restoreInJVM(className, methodName);
        }
        return super.remove(syncUi);
    }

    public setup(): void {
        const self = this;
        if (self.bAttached) {
            return;
        }
        Java.performNow(function () {
            const className = (self.hookAddress as string).substr(0, (self.hookAddress as string).lastIndexOf("."));
            const methodName = (self.hookAddress as string).substr((self.hookAddress as string).lastIndexOf(".") + 1);
            const testWrapper = Java.use(className);
            if (!isDefined(testWrapper) || !isDefined(testWrapper[methodName])) {
                if (!self.warningShown) {
                    console.log("Warning: Class or Method not found! (" + self.hookAddress + ")");
                    self.warningShown = true;
                }
                return;
            }
            try {
                DwarfJavaHelper.getInstance().hookInJVM(className, methodName, function () {
                    try {
                        let result = null;
                        self.onEnterCallback(self, this, arguments);

                        result = this[methodName].apply(this, arguments);

                        self.onLeaveCallback(self, this, result);
                        return result;
                    } catch (e) {
                        console.log(e);
                    }
                });
                self.bAttached = true;
            } catch (e) {
                logErr("javahook", e);
                self.bAttached = false;
            }
        });
    }
}
