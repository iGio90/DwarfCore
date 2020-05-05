/**
 * @hidden
 * @ignore
 * @internal
 */

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

export class ModuleLoadHook extends DwarfHook {
    /**
     * Creates an instance of DwarfHook.
     *
     * @param  {DwarfHookType} bpType
     * @param  {NativePointer|string} bpAddress
     */
    constructor(moduleName: string, userCallback: DwarfCallback = "breakpoint", isSingleShot: boolean = false, isEnabled: boolean = true) {
        if (!isString(moduleName)) {
            throw new Error("ModuleLoadHook() -> Invalid Arguments!");
        }

        if(!isFunction(userCallback) && !isString(userCallback) && !isValidFridaListener(userCallback)) {
            throw new Error('ModuleLoadHook() -> Invalid Callback!');
        }

        super(DwarfHookType.MODULE_LOAD, moduleName, userCallback, isSingleShot, isEnabled);
        this.bAttached = true;
    }
}
