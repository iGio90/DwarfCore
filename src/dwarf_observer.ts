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

import { DwarfCore } from "./dwarf";

interface DwarfObserverLocation {
    address: NativePointer;
    size: number;
    type: number;
    mode: number;
    expression: string | Function;
    storedValue: ArrayBuffer
}

export class DwarfObserver {
    private static instanceRef: DwarfObserver;
    protected observeLocations: Array<DwarfObserverLocation>;

    private constructor() {
        if (DwarfObserver.instanceRef) {
            throw new Error("DwarfObserver already exists! Use DwarfObserver.getInstance()");
        }
        trace('DwarfObserver()');
        this.observeLocations = new Array<DwarfObserverLocation>();
    }

    static getInstance() {
        if (!DwarfObserver.instanceRef) {
            DwarfObserver.instanceRef = new this();
        }
        return DwarfObserver.instanceRef;
    }

    addLocation = (npAddress: NativePointer | string, nSize: number, watchType: number, expression: string | Function) => {
        /*npAddress = makeNativePointer(npAddress);

        if(!isNumber(nSize)) {
            throw new Error('DwarfObserver::addLocation() => Invalid Argument: nSize!=number!');
        }

        if (npAddress !== null && !npAddress.isNull()) {
            this.observeLocations.push({
                'address': npAddress,
                'size': nSize,
                'type': watchType,
                'expression': expression,
                'storedValue': npAddress.readByteArray(nSize)
            });
            let newLocations = new Array<DwarfObserverLocation>();
            this.observeLocations.forEach(observeLocation => {
                observeLocation.storedValue = ba2hex(observeLocation.storedValue);
                newLocations.push(observeLocation);
            });
            DwarfCore.getInstance().getBreakpointManager().updateMemoryBreakpoints();
            DwarfCore.getInstance().sync({ observer: newLocations });
        }*/
    }

    handleMemoryAccess = (details: MemoryAccessDetails) => {
        const memAddress = details.address;
        for (let location of this.observeLocations) {
            if (location.address === memAddress) {
                const newValue = location.address.readByteArray(location.size);
                if (typeof location.expression === 'string') {
                    if (location.expression === 'changed') {
                        for (let i = 0; i < location.size; i++) {
                            if (newValue[i] != location.storedValue[i]) {
                                DwarfCore.getInstance().sync({
                                    'observer': {
                                        'type': 'changed',
                                        'address': location.address,
                                        'newValue': ba2hex(newValue),
                                        'oldValue': ba2hex(location.storedValue)
                                    }
                                });
                            }
                        }
                    }
                    else if (typeof location.expression === 'function') {
                        (location.expression as Function).call(DwarfCore.getInstance(), location.storedValue, newValue);
                    }
                }

            }
        }
    }

    /**
     * Helper to get our locations in MemoryAccessMonitor
     * @returns Array
     */
    getLocationsInternal = ():Array<MemoryAccessRange> => {
        let locations:Array<MemoryAccessRange> = new Array<MemoryAccessRange>();
        for(let location of this.observeLocations) {
            locations.push({
                'base': location.address,
                'size': location.size
            });
        }
        return locations;
    }

}