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
    type: string;
    mode: string;
    expression: string | Function;
    storedValue: ArrayBuffer
}

export class DwarfObserver {
    private static instanceRef: DwarfObserver;
    protected observeLocations: Array<DwarfObserverLocation>;
    private allowedTypes: Array<string>;
    private allowedModes: Array<string>;

    private constructor() {
        if (DwarfObserver.instanceRef) {
            throw new Error("DwarfObserver already exists! Use DwarfObserver.getInstance()");
        }
        trace('DwarfObserver()');
        this.observeLocations = new Array<DwarfObserverLocation>();
        this.allowedTypes = new Array<string>();
        this.allowedModes = new Array<string>();

        //TODO: add others
        this.allowedTypes.push('byte')
        this.allowedTypes.push('bytes');
        this.allowedTypes.push('int');
        this.allowedTypes.push('uint');
        this.allowedTypes.push('int64');
        this.allowedTypes.push('uint64');

        this.allowedModes.push('changed');
        this.allowedModes.push('true');
        this.allowedModes.push('false');
        this.allowedModes.push('increased');
        this.allowedModes.push('decreased');
    }

    static getInstance() {
        if (!DwarfObserver.instanceRef) {
            DwarfObserver.instanceRef = new this();
        }
        return DwarfObserver.instanceRef;
    }

    addLocation = (npAddress: NativePointer | string, watchType: string, nSize: number = 0, watchMode: string, expression: string | Function) => {
        trace('DwarfObserver::addLocation()');

        npAddress = makeNativePointer(npAddress);

        //check address
        if (npAddress === null || npAddress.isNull()) {
            throw new Error('DwarfObserver::addLocation() => Invalid Address!');
        }

        if (!this.isAddressReadable(npAddress)) {
            throw new Error('DwarfObserver::addLocation() => Unable to read given Address!');
        }

        //check type
        if (!isDefined(watchType)) {
            throw new Error('DwarfObserver::addLocation() => Invalid Argument: type');
        } else {
            let isValidType: Boolean = false;

            for (let allowedType of this.allowedTypes) {
                if (watchType === allowedType) {
                    isValidType = true;
                    break;
                }
            }
            if (!isValidType) {
                throw new Error('DwarfObserver::addLocation() => Invalid Type!');
            }
        }

        //check mode
        if (!isDefined(watchMode)) {
            throw new Error('DwarfObserver::addLocation() => Invalid Argument: mode');
        } else {
            let isValidMode: Boolean = false;

            for (let allowedMode of this.allowedModes) {
                if (watchMode === allowedMode) {
                    isValidMode = true;
                    break;
                }
            }
            if (!isValidMode) {
                throw new Error('DwarfObserver::addLocation() => Invalid Mode!');
            }
        }

        if (watchType === 'bytes' && watchMode !== 'changed') {
            throw new Error('DwarfObserver::addLocation() => Not supported!');
        }

        if (watchType === 'bytes' && nSize === 0) {
            throw new Error('DwarfObserver::addLocation() => Invalid Size!');
        } else {
            //throws error if wrong type
            nSize = this.getSizeForType(watchType);
        }

        let storedValue: any = this.getValue(npAddress, watchType, nSize);

        //add to array
        this.observeLocations.push({
            address: npAddress,
            size: nSize,
            type: watchType,
            mode: watchMode,
            expression: expression,
            storedValue: storedValue
        });

        //add to memoryaccesmon
        DwarfCore.getInstance().getBreakpointManager().updateMemoryBreakpoints();

        //sync ui
        DwarfCore.getInstance().sync({ observer: this.observeLocations });
    }

    handleMemoryAccess = (details: MemoryAccessDetails) => {
        trace('DwarfObserver::handleMemoryAccess()');
        const memAddress = details.address;
        for (let location of this.observeLocations) {
            if (location.address === memAddress) {
                let storedValue = location.storedValue;

                if (!this.isAddressReadable(location.address)) {
                    return;
                }

                const newValue = this.getValue(location.address, location.type, location.size);

                //TODO: callback handling
                if (location.mode === 'changed') {
                    let hasChanged: boolean = false;
                    if (location.type === 'bytes') {
                        for (let i = 0; i < location.size; i++) {
                            if (location.storedValue[i] != newValue[i]) {
                                hasChanged = true;
                                break;
                            }
                        }
                    } else {
                        if (storedValue != newValue) {
                            hasChanged = true;
                        }
                    }
                    if (hasChanged) {
                        location.storedValue = newValue;
                        location['event'] = 'changed';
                        DwarfCore.getInstance().sync({
                            observer: location
                        });
                    }
                } else if (location.mode === 'true') {
                    if (newValue === true) {
                        location.storedValue = newValue;
                        location['event'] = 'true';
                        DwarfCore.getInstance().sync({
                            observer: location
                        });
                    }
                } else if (location.mode === 'false') {
                    if (newValue !== true) {
                        location.storedValue = newValue;
                        location['event'] = 'false';
                        DwarfCore.getInstance().sync({
                            observer: location
                        });
                    }
                } else if (location.mode === 'increased') {
                    if (newValue < storedValue) {
                        location.storedValue = newValue;
                        location['event'] = 'increased';
                        DwarfCore.getInstance().sync({
                            observer: location
                        });
                    }
                } else if (location.mode === 'decreased') {
                    if (newValue > storedValue) {
                        location.storedValue = newValue;
                        location['event'] = 'decreased';
                        DwarfCore.getInstance().sync({
                            observer: location
                        });
                    }
                } else {
                    logDebug('DwarfObserver::handleMemoryAccess() => Unknown Mode: ' + location.mode);
                }
            }
        }
    }

    private getSizeForType = (watchType: string): number => {
        trace('DwarfObserver::getSizeForType()');
        switch (watchType) {
            case 'byte':
            case 'bool':
                return 1;
            case 'short':
            case 'ushort':
            case 'char':
                return 2;
            case 'int':
            case 'uint':
            case 'float':
                return 4;
            case 'int64':
            case 'uint64':
            case 'long':
            case 'ulong':
            case 'double':
                return 8;
            case 'pointer':
                return Process.pointerSize;
        }
        throw new Error('DwarfObserver::getRangeForType() => Invalid Type!');
    }

    private getValue = (npAddress: NativePointer, valueType: string, nSize: number = 0): any => {
        trace('DwarfObserver::getValue()');
        switch (valueType) {
            case 'bytes':
                return ba2hex(npAddress.readByteArray(nSize));
            case 'sbyte':
                return npAddress.readS8();
            case 'byte':
                return npAddress.readU8();
            case 'bool':
                return (npAddress.readU8() == 1) ? true : false;
            case 'short':
                return npAddress.readS16();
            case 'ushort':
                return npAddress.readU16();
            case 'int':
                return npAddress.readS32();
            case 'uint':
                return npAddress.readU32();
            case 'float':
                return npAddress.readFloat();
            case 'int64':
                return npAddress.readS64();
            case 'uint64':
                return npAddress.readU64();
            case 'long':
                return npAddress.readLong();
            case 'ulong':
                return npAddress.readULong();
            case 'double':
                return npAddress.readDouble();
            case 'pointer':
                return npAddress.readPointer();
        }
        throw new Error('DwarfObserver::getRangeForType() => Invalid Type!');
    }

    private isAddressReadable = (npAddress: NativePointer): boolean => {
        trace('DwarfObserver::isAddressReadable()');
        const rangeDetails = Process.findRangeByAddress(npAddress);
        if (rangeDetails === null) {
            throw new Error('DwarfObserver::getRangePermissionsForAddress() -> Unable to find MemoryRange!');
        }

        if (rangeDetails.protection.indexOf('r') != -1) {
            return true;
        }

        return false;
    }

    /**
     * Helper to get our locations in MemoryAccessMonitor
     * @returns Array
     */
    getLocationsInternal = (): Array<MemoryAccessRange> => {
        trace('DwarfObserver::getLocationsInternal()');
        let locations: Array<MemoryAccessRange> = new Array<MemoryAccessRange>();
        for (let location of this.observeLocations) {
            locations.push({
                'base': location.address,
                'size': location.size
            });
        }
        return locations;
    }

}