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

import { DwarfHook } from "./DwarfHook";
import { DwarfHookType } from "../consts";

export class ClassLoadHook extends DwarfHook {

    /**
     * Creates an instance of DwarfHook.
     *
     * @param className
     * @param userCallback
     * @param isEnabled
     * @param isSingleShot
     */
    constructor(className: string, userCallback: DwarfCallback = "breakpoint", isEnabled: boolean = true, isSingleShot: boolean = false) {
        trace("ClassLoadHook()");

        if (!Java.available) {
            throw new Error("Java not available!");
        }

        if (!isString(className)) {
            throw new Error("ClassLoadHook() -> Invalid Arguments!");
        }

        super(DwarfHookType.CLASS_LOAD, className, userCallback, isEnabled, isSingleShot);
        this.bAttached = true;
    }
}
