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

import { DwarfHookType, DwarfHaltReason } from "../consts";
import { DwarfCore } from "../DwarfCore";
import { DwarfHooksManager } from "../DwarfHooksManager";

/**
 * DwarfHook
 */
export class DwarfHook {
    protected bActive: boolean;
    protected bAttached: boolean;
    protected bEnabled: boolean;
    protected bpHits: number;
    protected bSingleShot: boolean;
    protected hookAddress: NativePointer | string;
    protected hookID: number;
    protected hookType: DwarfHookType;
    protected threadId: number;
    protected userCallback: ScriptInvocationListenerCallbacks | fArgReturn | string;

    /**
     * Creates an instance of DwarfHook.
     *
     * @param  {DwarfHookType} dwarfHookType
     * @param  {NativePointer|string} hookAddress
     * @param  {DwarfCallback} userCallback
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

        if (!isFunction(userCallback) && !isString(userCallback) && !isValidFridaListener(userCallback)) {
            throw new Error("DwarfHook() -> Invalid Callback!");
        }

        if (dwarfHookType === DwarfHookType.MEMORY) {
            if (isValidFridaListener(userCallback)) {
                throw new Error("DwarfHook() -> Invalid Callback!");
            }
        }

        this.hookType = dwarfHookType;
        this.hookAddress = hookAddress;
        this.userCallback = userCallback;
        this.bEnabled = isEnabled;
        this.bSingleShot = isSingleShot;
        this.bAttached = false;

        this.bpHits = 0;
        this.threadId = Process.getCurrentThreadId();
        this.hookID = DwarfHooksManager.getInstance().getNextHookID();
        this.bActive = false;
    }

    /**
     * Disables dwarf breakpoint
     */
    public disable(): void {
        trace("DwarfHook::disable()");

        this.bEnabled = false;
    }

    /**
     * Enables dwarf breakpoint
     */
    public enable(): void {
        trace("DwarfHook::enable()");

        this.bEnabled = true;
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
     * Gets id of Hook
     *
     * @returns number
     */
    public getHookId(): number {
        trace("DwarfHook::getHookId()");

        return this.hookID;
    }

    public getThreadId() {
        trace("DwarfHook::getThreadId()");

        return this.threadId;
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

    public isActive(): boolean {
        trace("DwarfHook::isActive()");

        return this.bActive === true;
    }

    public isAttached() {
        trace("DwarfHook::isActive()");

        return this.bAttached;
    }

    public isEnabled(): boolean {
        trace("DwarfHook::isEnabled()");

        return this.bEnabled === true;
    }

    /**
     * @returns boolean
     */
    public isSingleShot(): boolean {
        trace("DwarfHook::isSingleShot()");

        return this.bSingleShot;
    }

    /** @internal */
    public onEnterCallback(dwarfHook: DwarfHook, thisArg: any, funcArgs: InvocationArguments | IArguments) {
        trace("DwarfHook::onEnterCallback()");

        const self = dwarfHook;
        if (!self.isEnabled() || !self.isAttached()) {
            return;
        }

        self.bActive = true;
        self.bpHits++;

        let breakExecution = false;
        if (isFunction(self.userCallback)) {
            let userReturn = 0;
            try {
                userReturn = (self.userCallback as fArgReturn).apply(thisArg, [funcArgs]);
                if (isDefined(userReturn) && userReturn === 1) {
                    breakExecution = true;
                }
            } catch (e) {
                logErr("DwarfHook::onEnterCallback() => userFunction() -> ", e);
                breakExecution = true;
            }
        } else if (self.userCallback.hasOwnProperty("onEnter") && isFunction((self.userCallback as ScriptInvocationListenerCallbacks).onEnter)) {
            let userReturn = 0;
            try {
                userReturn = (self.userCallback as ScriptInvocationListenerCallbacks).onEnter.apply(thisArg, [funcArgs]);
                if (isDefined(userReturn) && userReturn === 1) {
                    breakExecution = true;
                }
            } catch (e) {
                logErr("DwarfHook::onEnterCallback() => userOnEnter() -> ", e);
                breakExecution = true;
            }
        } else if (isString(self.userCallback) && self.userCallback === "breakpoint") {
            breakExecution = true;
        }

        if (breakExecution) {
            if (self.hookType === DwarfHookType.JAVA) {
                const breakpointInfo = [];
                for (let i; i < funcArgs.length; i++) {
                    breakpointInfo.push({
                        value: funcArgs[i],
                        type: thisArg.types[i],
                    });
                }
                // @ts-ignore
                DwarfCore.getInstance().onBreakpoint(self.hookID, self.threadId, DwarfHaltReason.BREAKPOINT, self.hookAddress, breakpointInfo, thisArg);
            } else {
                DwarfCore.getInstance().onBreakpoint(self.hookID, self.threadId, DwarfHaltReason.BREAKPOINT, self.hookAddress, thisArg.context);
            }
        }
    }

    /** @internal */
    public onLeaveCallback(dwarfHook: DwarfHook, thisArg: any, returnValue: InvocationReturnValue) {
        trace("DwarfHook::onLeaveCallback()");

        const self = dwarfHook;
        if (!self.isEnabled()) {
            return;
        }

        if (self.hookType === DwarfHookType.MEMORY) {
            return;
        }

        if (isDefined(self.userCallback) && self.userCallback.hasOwnProperty("onLeave") && isFunction((self.userCallback as ScriptInvocationListenerCallbacks).onLeave)) {
            let userReturn = 0;
            let breakExecution = false;
            try {
                userReturn = (self.userCallback as ScriptInvocationListenerCallbacks).onLeave.apply(thisArg, [returnValue]);
                if (isDefined(userReturn) && userReturn === 1) {
                    breakExecution = true;
                }
            } catch (e) {
                logErr("DwarfHook::onLeaveCallback() => userOnLeave() -> ", e);
                breakExecution = true;
            }
            if (breakExecution) {
                if (self.hookType === DwarfHookType.JAVA) {
                    const breakpointInfo = [
                        {
                            value: returnValue,
                            type: thisArg.retType,
                        },
                    ];
                    // @ts-ignore
                    DwarfCore.getInstance().onBreakpoint(self.hookID, self.threadId, DwarfHaltReason.BREAKPOINT, self.hookAddress, breakpointInfo, thisArg);
                } else {
                    DwarfCore.getInstance().onBreakpoint(
                        self.hookID,
                        Process.getCurrentThreadId(),
                        DwarfHaltReason.BREAKPOINT,
                        self.hookAddress,
                        thisArg.context
                    );
                }
            }
        }
        for (const hook of DwarfHooksManager.getInstance().getHooks()) {
            hook.setActive(false);
            if (hook.isSingleShot() && hook.getHits() > 0 && !hook.isActive()) {
                hook.remove(false);
            }
        }
        DwarfHooksManager.getInstance().update(true);
    }

    public remove(syncUi: boolean) {
        trace("DwarfHook::remove()");

        DwarfHooksManager.getInstance().update(true);
    }

    public resetHitsCounter() {
        trace("DwarfHook::resetHitsCounter()");

        this.bpHits = 0;
    }

    public setActive(state: boolean) {
        trace("DwarfHook::getThreadId()");

        this.bActive = state;
    }

    public setCallback(userCallback: DwarfCallback) {
        trace("DwarfHook::setCallback()");

        if (isDefined(userCallback)) {
            if (this.getType() === DwarfHookType.MEMORY && !isFunction(userCallback) && !isString(userCallback)) {
                this.userCallback = "breakpoint";
            } else {
                this.userCallback = userCallback;
            }
            DwarfHooksManager.getInstance().update(true);
        } else {
            this.userCallback = "breakpoint";
            DwarfHooksManager.getInstance().update(true);
        }
    }

    /**
     * @param  {boolean=true} singleShot
     */
    public setSingleShot(singleShot: boolean = true) {
        trace("DwarfHook::setSingleShot()");

        this.bSingleShot = singleShot;
    }

    /** @internal */
    public setThreadId(threadId: number | string) {
        trace("DwarfHook::setThreadId()");

        if (isString(threadId)) {
            threadId = parseInt(threadId as string, 10);
        }

        if (isNumber(threadId)) {
            this.threadId = threadId as number;
        }
    }

    /** @internal */
    public toJSON() {
        const jsonRet: { [index: string]: any } = {};
        for (const item in this) {
            if (item === "invocationListener") {
                continue;
            }
            if (item === "userCallback") {
                if (isFunction(this[item])) {
                    jsonRet[item] = this[item].toString().replace("'", '"');
                } else if (isString(this[item])) {
                    jsonRet[item] = this[item];
                } else {
                    jsonRet[item] = JSON.stringify(this[item], function(key, val) {
                        if(isFunction(val)) {
                            return val.toString().replace("'", '"');
                        } else {
                            return val;
                        }
                    }, 4);
                }
            } else {
                jsonRet[item] = this[item];
            }
        }
        return jsonRet;
    }
}
