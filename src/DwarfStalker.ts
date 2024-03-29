/**
 * @hidden
 * @ignore
 * @internal
 */

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

import { DwarfCore } from "./DwarfCore";
import { DwarfHaltReason } from "./consts";
import { StalkerInfo } from "./stalker_info";

export class DwarfStalker {
    private static instanceRef: DwarfStalker;

    private constructor() {
        if (DwarfStalker.instanceRef) {
            throw new Error("DwarfStalker already exists! Use DwarfStalker.getInstance()");
        }
        trace("DwarfStalker()");
    }

    /** @internal */
    static getInstance() {
        if (!DwarfStalker.instanceRef) {
            DwarfStalker.instanceRef = new DwarfStalker();
        }
        return DwarfStalker.instanceRef;
    }

    _hitPreventRelease = (threadId:number) => {
        const context = DwarfCore.getInstance().getThreadContext(threadId);
        if(isDefined(context)) {
            context.preventSleep = true;
        }
    }

    stalk = (threadId?:number) => {
        if(!isDefined(threadId)) {
            threadId = Process.getCurrentThreadId();
        }
        this._hitPreventRelease(threadId);


    };
}
