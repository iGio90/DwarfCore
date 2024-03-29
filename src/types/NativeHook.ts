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

export class NativeHook extends DwarfHook {
    protected bpDebugSymbol: DebugSymbol;
    // protected bpCondition: fEmptyVoid;
    protected orgMem: string;
    protected invocationListener: InvocationListener;

    /**
     * Creates an instance of DwarfHook.
     *
     * @param  {NativePointer|string} bpAddress
     * @param userCallback
     * @param isSingleShot
     * @param isEnabled
     */
    constructor(bpAddress: NativePointer | string, userCallback: DwarfCallback = "breakpoint", isSingleShot = false, isEnabled = true) {
        const nativePtr = makeNativePointer(bpAddress);

        if (nativePtr.isNull()) {
            throw new Error("NativeHook() -> Invalid Address!");
        }

        try {
            nativePtr.readU8();
        } catch (error) {
            logErr("NativeHook()", error);
            throw new Error("NativeHook() -> Invalid Address!");
        }

        if (!isFunction(userCallback) && !isString(userCallback) && !isValidFridaListener(userCallback)) {
            throw new Error("NativeHook() -> Invalid Callback!");
        }

        super(DwarfHookType.NATIVE, nativePtr, userCallback, isSingleShot, isEnabled);

        this.bAttached = false;
        this.bpDebugSymbol = DebugSymbol.fromAddress(nativePtr);
        this.orgMem = ba2hex(nativePtr.readByteArray(Process.pointerSize * 2));

        const self = this;
        try {
            self.invocationListener = Interceptor.attach(nativePtr, {
                onEnter (args) {
                    self.onEnterCallback(self, this, args);
                },
                onLeave (returnVal) {
                    self.onLeaveCallback(self, this, returnVal);
                },
            });
            self.bAttached = true;
        } catch (e) {
            logErr("NativeHook()", e);
        }
    }

    /* public setCondition(bpCondition: string | fEmptyVoid ): void {
        if (typeof bpCondition === "string") {
            this.bpCondition = new Function(bpCondition);
        } else {
            if (typeof bpCondition === "function") {
                this.bpCondition = bpCondition;
            } else {
                logDebug("NativeHook::setCondition() -> Unknown bpCondition!");
            }
        }
    }

    public getCondition(): fEmptyVoid {
        return this.bpCondition;
    }

    public removeCondition(): void {
        this.bpCondition = null;
    }*/

    public detach(): void {
        if (isDefined(this.invocationListener)) {
            this.invocationListener.detach();
            this.bActive = false;
            this.bAttached = false;
            this.bEnabled = false;
            this.orgMem = "";
        }
    }

    public remove(syncUi = true): void {
        trace("NativeHook::remove()");

        if (this.bAttached && isDefined(this.invocationListener)) {
            this.detach();
        }
        return super.remove(syncUi);
    }
}
