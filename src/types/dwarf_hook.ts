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

import { DwarfHookType, DwarfHaltReason } from "../consts";
import { DwarfCore } from "../dwarf";
import { DwarfHooksManager } from "../hooks_manager";

/**
 * DwarfHook
 */
export class DwarfHook {
    protected threadId: number;
    protected hookID: number;
    protected bpHits: number;
    protected bEnabled: boolean;
    protected hookType: DwarfHookType;
    protected hookAddress: NativePointer | string;
    protected bSingleShot: boolean;
    protected bActive: boolean;
    protected userCallback: ScriptInvocationListenerCallbacks | Function | string;

    /**
     * Creates an instance of DwarfHook.
     *
     * @param  {DwarfHookType} dwarfHookType
     * @param  {NativePointer|string} hookAddress
     * @param  {ScriptInvocationListenerCallbacks|Function|string='breakpoint'} userCallback
     * @param  {boolean=true} isEnabled
     * @param  {boolean=false} isSingleShot
     */
    public constructor(
        dwarfHookType: DwarfHookType,
        hookAddress: DwarfHookAddress,
        userCallback: DwarfCallback = "breakpoint",
        isSingleShot: boolean = false,
        isEnabled: boolean = true
    ) {
        trace("DwarfHook()");

        if (dwarfHookType < DwarfHookType.NATIVE || dwarfHookType > DwarfHookType.CLASS_LOAD) {
            throw new Error("Invalid HookType");
        }

        if(!isFunction(userCallback) && !isString(userCallback) && !isValidFridaListener(userCallback)) {
            throw new Error('DwarfHook() -> Invalid Callback!');
        }

        if(dwarfHookType === DwarfHookType.MEMORY) {
            if(isValidFridaListener(userCallback)) {
                throw new Error('DwarfHook() -> Invalid Callback!');
            }
        }

        this.hookType = dwarfHookType;
        this.hookAddress = hookAddress;
        this.userCallback = userCallback;
        this.bEnabled = isEnabled;
        this.bSingleShot = isSingleShot;

        this.bpHits = 0;
        this.threadId = Process.getCurrentThreadId();
        this.hookID = DwarfCore.getInstance()
            .getHooksManager()
            .getNextHookID();
        this.bActive = false;
    }

    /**
     * Gets id of Hook
     *
     * @returns number
     */
    public getHookId(): number {
        trace("DwarfHook::getHookId()");
        return this.hookID;
    }

    /**
     * Gets type of Hook
     *
     * (see consts.ts)
     *
     * @returns DwarfHookType
     */
    public getType(): DwarfHookType {
        trace("DwarfHook::getType()");
        return this.hookType;
    }

    /**
     * Gets Address of Hook
     *
     * @returns NativePointer | string
     */
    public getAddress(): NativePointer | string {
        trace("DwarfHook::getAddress()");
        switch (this.hookType) {
            case DwarfHookType.MEMORY:
            case DwarfHookType.NATIVE:
                return this.hookAddress;
            case DwarfHookType.JAVA:
            case DwarfHookType.OBJC:
            case DwarfHookType.MODULE_LOAD:
            case DwarfHookType.CLASS_LOAD:
                return this.hookAddress as string;
            default:
                break;
        }
        throw new Error("Something is wrong!");
    }

    /**
     * Gets number of Hits
     *
     * @returns number
     */
    public getHits(): number {
        trace("DwarfHook::getHits()");
        return this.bpHits;
    }

    /**
     * Enables dwarf breakpoint
     */
    public enable(): void {
        trace("DwarfHook::enable()");
        this.bEnabled = true;
    }

    /**
     * Disables dwarf breakpoint
     */
    public disable(): void {
        trace("DwarfHook::disable()");
        this.bEnabled = false;
    }

    public isEnabled(): boolean {
        trace("DwarfHook::isEnabled()");
        return this.bEnabled == true;
    }

    public isActive(): boolean {
        trace("DwarfHook::isActive()");
        return this.bActive == true;
    }

    /**
     * @returns boolean
     */
    public isSingleShot(): boolean {
        trace("DwarfHook::isSingleShot()");
        return this.bSingleShot;
    }

    /**
     * @param  {boolean=true} singleShot
     */
    public setSingleShot(singleShot: boolean = true) {
        trace("DwarfHook::setSingleShot()");
        this.bSingleShot = singleShot;
    }

    public resetHitsCounter() {
        trace("DwarfHook::resetHitsCounter()");
        this.bpHits = 0;
    }

    public getThreadId() {
        return this.threadId;
    }

    public setThreadId(threadId: number | string) {
        if (isString(threadId)) {
            threadId = parseInt(threadId as string, 10);
        }

        if (isNumber(threadId)) {
            this.threadId = threadId as number;
        }
    }

    public remove() {
        DwarfHooksManager.getInstance().removeHookAtAddress(this.hookAddress);
    }

    public onEnterCallback(thisArg: any, funcArgs: InvocationArguments | IArguments) {
        if (!this.isEnabled()) {
            return;
        }

        this.bActive = true;
        this.bpHits++;

        let breakExecution = false;
        if (isFunction(this.userCallback)) {
            let userReturn = 0;
            try {
                userReturn = (this.userCallback as Function).apply(thisArg, [funcArgs]);
                if (isDefined(userReturn) && userReturn == 1) {
                    breakExecution = true;
                }
            } catch (e) {
                logErr("DwarfHook::onEnterCallback() => userFunction() -> ", e);
                breakExecution = true;
            }
        } else if (this.userCallback.hasOwnProperty("onEnter") && isFunction(this.userCallback["onEnter"])) {
            let userReturn = 0;
            try {
                userReturn = (this.userCallback as ScriptInvocationListenerCallbacks).onEnter.apply(thisArg, [
                    funcArgs
                ]);
                if (isDefined(userReturn) && userReturn == 1) {
                    breakExecution = true;
                }
            } catch (e) {
                logErr("DwarfHook::onEnterCallback() => userOnEnter() -> ", e);
                breakExecution = true;
            }
        } else if(isString(this.userCallback) && this.userCallback === 'breakpoint') {
            breakExecution = true;
        }

        if (breakExecution) {
            if (this.hookType == DwarfHookType.JAVA) {
                let breakpointInfo = [];
                for (let i in funcArgs) {
                    breakpointInfo.push({
                        value: funcArgs[i],
                        type: thisArg.types[i]
                    });
                }
                DwarfCore.getInstance().onBreakpoint(
                    this.hookID,
                    this.threadId,
                    DwarfHaltReason.BREAKPOINT,
                    this.hookAddress,
                    breakpointInfo,
                    this
                );
            } else {
                DwarfCore.getInstance().onBreakpoint(
                    this.hookID,
                    Process.getCurrentThreadId(),
                    DwarfHaltReason.BREAKPOINT,
                    this.hookAddress,
                    thisArg.context
                );
            }
        }
    }

    public onLeaveCallback(thisArg: any, returnValue: InvocationReturnValue) {
        if (!this.isEnabled()) {
            return;
        }

        if(this.hookType === DwarfHookType.MEMORY) {
            return;
        }

        if (this.userCallback.hasOwnProperty("onLeave") && isFunction(this.userCallback["onLeave"])) {
            let userReturn = 0;
            let breakExecution = false;
            try {
                userReturn = (this.userCallback as ScriptInvocationListenerCallbacks).onLeave.apply(thisArg, [
                    returnValue
                ]);
                if (isDefined(userReturn) && userReturn == 1) {
                    breakExecution = true;
                }
            } catch (e) {
                logErr("DwarfHook::onLeaveCallback() => userOnEnter() -> ", e);
                breakExecution = true;
            }
            if (breakExecution) {
                if (this.hookType == DwarfHookType.JAVA) {
                } else {
                    DwarfCore.getInstance().onBreakpoint(
                        this.hookID,
                        Process.getCurrentThreadId(),
                        DwarfHaltReason.BREAKPOINT,
                        this.hookAddress,
                        thisArg.context
                    );
                }
            }
        }

        this.bActive = false;
        if (this.isSingleShot()) {
            DwarfHooksManager.getInstance().update();
        }
    }
}
