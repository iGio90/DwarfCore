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

import { DwarfBreakpointType } from "../consts";

/**
 * DwarfBreakpoint
 */
export class DwarfBreakpoint {
    protected bpHits: number;
    protected bpEnabled: boolean;
    protected bpType: DwarfBreakpointType;
    protected bpAddress: NativePointer | string;
    protected bpSingleShot: boolean;

    /**
     * Creates an instance of DwarfBreakpoint.
     *
     * @param  {DwarfBreakpointType} bpType
     * @param  {NativePointer|string} bpAddress
     * @param  {boolean=true} bpEnabled
     */
    public constructor(bpType: DwarfBreakpointType, bpAddress: NativePointer | string, bpEnabled: boolean = true) {
        if ((bpType < DwarfBreakpointType.NATIVE) || (bpType > DwarfBreakpointType.MEMORY)) {
            throw new Error('Invalid BreakpointType');
        }
        this.bpHits = 0;
        this.bpSingleShot = false;
        this.bpEnabled = bpEnabled;
        this.bpType = bpType;
        this.bpAddress = bpAddress;
    }

    /**
     * Gets type
     * @returns DwarfBreakpointType
     */
    public getType(): DwarfBreakpointType {
        return this.bpType;
    }

    public getAddress(): string {
        switch (this.bpType) {
            case DwarfBreakpointType.MEMORY:
            case DwarfBreakpointType.NATIVE:
                return this.bpAddress.toString();
            case DwarfBreakpointType.JAVA:
            case DwarfBreakpointType.OBJC:
                return this.bpAddress as string;
            default:
                return null;
        }
    }

    /**
     * Enables dwarf breakpoint
     */
    public enable(): void {
        this.bpEnabled = true;
    }

    /**
     * Disables dwarf breakpoint
     */
    public disable(): void {
        this.bpEnabled = false;
    }

    /**
     * Toggles active
     * @returns true if active
     */
    public toggleActive(): boolean {
        this.bpEnabled = !this.bpEnabled;
        return this.bpEnabled;
    }

    /**
     * Determines whether enabled is
     * @returns true if enabled
     */
    public isEnabled(): boolean {
        return (this.bpEnabled == true);
    }

    /**
     * Get Hits
     * @returns number of hits
     */
    public getHits(): number {
        return this.bpHits;
    }

    /**
     * @returns boolean
     */
    public isSingleShot(): boolean {
        return this.bpSingleShot;
    }

    /**
     * @param  {boolean=true} singleShot
     */
    public setSingleShot(singleShot: boolean = true) {
        this.bpSingleShot = singleShot;
    }

    public updateHitsCounter() {
        this.bpHits++;
    }

    public resetHitsCounter() {
        this.bpHits = 0;
    }

}
