/**
    Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

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

import { DwarfBreakpoint } from "./types/dwarf_breakpoint"
import { NativeBreakpoint } from "./types/native_breakpoint";
import { JavaBreakpoint } from "./types/java_breakpoint";
import { MemoryBreakpoint } from "./types/memory_breakpoint";
import { DwarfCore } from "./dwarf";
import { DwarfBreakpointType, DwarfMemoryAccessType, DwarfHaltReason } from "./consts";
import { DwarfObserver } from "./dwarf_observer";

/**
 * DwarfBreakpointManager Singleton
 *
 * use Dwarf.getBreakpointManager() or DwarfBreakpointManager.getInstance()
 */
export class DwarfBreakpointManager {
    private static instanceRef: DwarfBreakpointManager;
    protected nextBPID: number;
    protected dwarfBreakpoints: Array<DwarfBreakpoint>;

    private constructor() {
        if (DwarfBreakpointManager.instanceRef) {
            throw new Error("DwarfBreakpointManager already exists! Use DwarfBreakpointManager.getInstance()/Dwarf.getBreakpointManager()");
        }
        trace('DwarfBreakpointManager()');
        this.dwarfBreakpoints = new Array<DwarfBreakpoint>();
        this.nextBPID = 0;
    }

    static getInstance() {
        if (!DwarfBreakpointManager.instanceRef) {
            DwarfBreakpointManager.instanceRef = new this();
        }
        return DwarfBreakpointManager.instanceRef;
    }

    public getNextBreakpointID(): number {
        this.nextBPID++;
        return this.nextBPID;
    }

    private checkExists(bpAddress: any): void {
        for (let dwarfBreakpoint of this.dwarfBreakpoints) {
            if (dwarfBreakpoint.getAddress().toString() == bpAddress.toString()) {
                throw new Error('DwarfBreakpointManager::addBreakpoint() -> Existing Breakpoint at given Address!')
            }
        }
    }

    /**
     * @param  {DwarfBreakpointType} bpType
     * @param  {NativePointer|string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addBreakpoint = (bpType: DwarfBreakpointType, bpAddress: NativePointer | string, bpEnabled?: boolean) => {
        trace('DwarfBreakpointManager::addBreakpoint()');

        this.checkExists(bpAddress);

        switch (bpType) {
            case DwarfBreakpointType.NATIVE:
                return this.addNativeBreakpoint(bpAddress, bpEnabled);
            case DwarfBreakpointType.JAVA:
                return this.addJavaBreakpoint(bpAddress as string, bpEnabled);
            case DwarfBreakpointType.OBJC:
                return this.addObjCBreakpoint(bpAddress as string, bpEnabled);
            case DwarfBreakpointType.MEMORY:
                return this.addMemoryBreakpoint(bpAddress, (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled);
        }
        throw new Error('DwarfBreakpointManager::addBreakpoint() -> Unknown BreakpointType!');
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addNativeBreakpoint = (bpAddress: NativePointer | string, bpEnabled?: boolean) => {
        trace('DwarfBreakpointManager::addNativeBreakpoint()');

        this.checkExists(bpAddress);

        try {
            const nativeBreakpoint = new NativeBreakpoint(makeNativePointer(bpAddress), bpEnabled);
            this.dwarfBreakpoints.push(nativeBreakpoint);
            this.update();
            return nativeBreakpoint;
        } catch (error) {

        }
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @param  {number=(DwarfMemoryAccessType.READ|DwarfMemoryAccessType.WRITE} bpFlags
     */
    public addMemoryBreakpoint = (bpAddress: NativePointer | string, bpFlags: number = (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled?: boolean) => {
        trace('DwarfBreakpointManager::addMemoryBreakpoint');

        this.checkExists(bpAddress);

        try {
            const memBreakpoint = new MemoryBreakpoint(makeNativePointer(bpAddress), (DwarfMemoryAccessType.READ | DwarfMemoryAccessType.WRITE), bpEnabled);
            this.dwarfBreakpoints.push(memBreakpoint);
            this.updateMemoryBreakpoints();
            this.update();
            return memBreakpoint;
        } catch (error) {
            logErr('DwarfBreakpointManager::addMemoryBreakpoint', error);
        }
    }

    public addMemoryBreakpointInternal = (memBp: MemoryBreakpoint) => {
        memBp['isInternal'] = true;
        this.dwarfBreakpoints.push(memBp);
        this.updateMemoryBreakpoints();
    }

    /**
     * @param  {string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addJavaBreakpoint = (bpAddress: string, bpEnabled?: boolean) => {
        trace('DwarfBreakpointManager::addJavaBreakpoint()');

        this.checkExists(bpAddress);

        try {
            const javaBreakpoint = new JavaBreakpoint(bpAddress, bpEnabled);
            this.dwarfBreakpoints.push(javaBreakpoint);
            this.update();
            return javaBreakpoint;
        } catch (error) {

        }
    }

    /**
     * @param  {string} bpAddress
     * @param  {boolean} bpEnabled?
     */
    public addObjCBreakpoint = (bpAddress: string, bpEnabled?: boolean) => {
        trace('DwarfBreakpointManager::addObjCBreakpoint()');

        this.checkExists(bpAddress);


        throw new Error('DwarfBreakpointManager::addObjCBreakpoint() -> Not implemented');
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public removeBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        trace('DwarfBreakpointManager::removeBreakpointAtAddress()');
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            this.dwarfBreakpoints = this.dwarfBreakpoints.filter((breakpoint) => {
                return breakpoint !== dwarfBreakpoint;
            });
            this.update();
            return true;
        }
        return false;
    }

    /**
     * @param  {number} bpID
     * @returns boolean
     */
    public removeBreakpointByID = (bpID: number): boolean => {
        trace('DwarfBreakpointManager::removeBreakpointByID()');

        let bpExisits = false;
        for (let dwarfBreakpoint of this.dwarfBreakpoints) {
            if (dwarfBreakpoint.getID() === bpID) {
                bpExisits = true;
                break;
            }
        }

        if (bpExisits) {
            this.dwarfBreakpoints = this.dwarfBreakpoints.filter((dwarfBreakpoint) => {
                return dwarfBreakpoint.getID() !== bpID;
            });
            this.update();
            return true;
        }
        return false;
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns DwarfBreakpoint
     */
    public getBreakpointByAddress = (bpAddress: NativePointer | string, checkEnabled: boolean = false, checkForType?: DwarfBreakpointType): DwarfBreakpoint | null => {
        trace('DwarfBreakpointManager::getBreakpointByAddress()');
        let bpFindAddress;
        if (typeof bpAddress === 'string') {
            bpFindAddress = bpAddress;
        } else if (typeof bpAddress === 'number') {
            bpFindAddress = ptr(bpAddress).toString();
        } else {
            if (bpAddress.constructor.name !== 'NativePointer' || bpAddress.isNull()) {
                throw new Error('DwarfBreakpointManager::getBreakpointByAddress() -> Invalid Address!');
            }
            bpFindAddress = bpAddress.toString();
        }
        let dwarfBreakpoint = null;
        for (let bp of this.dwarfBreakpoints) {
            if (bp.getAddress() === bpFindAddress) {
                if (checkEnabled && !bp.isEnabled()) {
                    continue;
                }
                if (checkForType && bp.getType() !== checkForType) {
                    continue;
                }
                dwarfBreakpoint = bp;
                break;
            }
        }

        return dwarfBreakpoint;
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public toggleBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        trace('DwarfBreakpointManager::toggleBreakpointAtAddress()');
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.toggleActive();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public enableBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        trace('DwarfBreakpointManager::enableBreakpointAtAddress()');
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.enable();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * @param  {NativePointer|string} bpAddress
     * @returns boolean
     */
    public disableBreakpointAtAddress = (bpAddress: NativePointer | string): boolean => {
        trace('DwarfBreakpointManager::disableBreakpointAtAddress()');
        let dwarfBreakpoint = this.getBreakpointByAddress(bpAddress);
        if (dwarfBreakpoint !== null) {
            dwarfBreakpoint.disable();
            return dwarfBreakpoint.isEnabled();
        }
    }

    /**
     * Windows related stuff to handle MemoryBreakpoints
     * Call it after something MemoryBreakpoint related changes
     */
    public updateMemoryBreakpoints = (): void => {
        trace('DwarfBreakpointManager::updateMemoryBreakpoints()');

        MemoryAccessMonitor.disable();

        //Get Watchlocations
        let memoryBreakpoints: Array<MemoryAccessRange> = DwarfObserver.getInstance().getLocationsInternal();

        //append our membreakpoints
        for (let memBreakpoint of this.dwarfBreakpoints) {
            if (memBreakpoint.getType() === DwarfBreakpointType.MEMORY) {
                if (memBreakpoint.isEnabled()) {
                    memoryBreakpoints.push({ 'base': (memBreakpoint.getAddress() as NativePointer), 'size': 1 });
                }
            }
        }
        if (memoryBreakpoints.length > 0) {
            MemoryAccessMonitor.enable(memoryBreakpoints, { onAccess: this.handleMemoryBreakpoints });
        }
    }

    public handleMemoryBreakpoints = (details: /*ExceptionDetails |*/ MemoryAccessDetails) => {
        trace('DwarfBreakpointManager::handleMemoryBreakpoints()');

        const memoryAddress = (details as MemoryAccessDetails).address;
        const dwarfBreakpoint = this.getBreakpointByAddress(memoryAddress, true, DwarfBreakpointType.MEMORY);

        //not in breakpoints
        if (dwarfBreakpoint === null) {
            //let dwarfobserver handle
            DwarfObserver.getInstance().handleMemoryAccess(details);
        } else {
            const memoryBreakpoint = dwarfBreakpoint as MemoryBreakpoint;
            memoryBreakpoint.onHit(details);
        }
    }

    public getBreakpoints = (): Array<DwarfBreakpoint> => {
        trace('DwarfBreakpointManager::getBreakpoints()');
        const dwarfBreakpoints = this.dwarfBreakpoints.filter((breakpoint) => {
            return !breakpoint.hasOwnProperty('isInternal');
        });
        return dwarfBreakpoints;
    }

    public update = () => {
        trace('DwarfBreakpointManager::update()');
        //remove singleshots
        this.dwarfBreakpoints = this.dwarfBreakpoints.filter((dwarfBreakpoint) => {
            return !(dwarfBreakpoint.isSingleShot() && (dwarfBreakpoint.getHits() > 0));
        });

        //sync ui
        DwarfCore.getInstance().sync({ breakpoints: this.dwarfBreakpoints });
    }
}