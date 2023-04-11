/**
 * Dwarf - Copyright (C) 2018-2023 Giovanni Rocca (iGio90), PinkiePieStyle
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import {DwarfHook} from "./DwarfHook";
import {DwarfHookType} from "../consts";
import {DwarfJavaHelper} from "../DwarfJavaHelper";

export class JavaHook extends DwarfHook {
    protected warningShown: boolean;
    protected _className: string;
    protected _methodName: string;

    constructor(
        className: string,
        methodName = "$init",
        userCallback: DwarfCallback = "breakpoint",
        isEnabled = true,
        isSingleShot = false
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
                    this._className = className;
                    this._methodName = methodName;
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

    public remove(syncUi = true): void {
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
        if (this.bAttached) {
            return;
        }

        const self = this; //eslint-disable-line
        Java.performNow(() => {
            try {
                DwarfJavaHelper.getInstance().hookInJVM(this._className, this._methodName, function () {
                    try {
                        let result = null;

                        self.onEnterCallback(self, this, arguments);

                        result = this[self._methodName].apply(this, arguments);

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
