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

declare namespace NodeJS {
    interface Global {
        DEBUG: boolean;
        MAX_STACK_SIZE: number;
        timeStamp: Function;
        isNull: Function;
        isDefined: Function;
        isNumber: Function;
        isString: Function;
        isFunction: Function;
        isValidFridaListener: Function;
        ba2hex: Function;
        hex2a: Function;
        dethumbify: Function;
        uniqueBy: Function;
        logDebug: Function;
        logErr: Function;
        makeNativePointer: Function;
        checkNativePointer: Function;
        trace: Function;
        Dwarf: any;
        DwarfFile: any;
        readStdString: Function;
    }
}

declare function timeStamp(): string;
declare function isNull(value: any): boolean;
declare function isDefined(value: any): boolean;
declare function isNumber(value: any): boolean;
declare function isString(value: any): boolean;
declare function isFunction(value: any): boolean;
declare function isValidFridaListener(value: any): boolean;
declare function ba2hex(arrayBuffer: ArrayBuffer): string;
declare function hex2a(hex: string): [];
declare function dethumbify(ptrValue: NativePointer): NativePointer;
declare function uniqueBy(array: Array<any>): Array<any>;
declare function logDebug(...data: Array<any>): void;
declare function trace(...data: Array<any>): void;
declare function logErr(tag: string, err: Error): void;
declare function makeNativePointer(value: any): NativePointer;
declare function readStdString(str: any): string;
/**
 * Checks if given ptrValue is NativePointer
 *
 * @param  {NativePointer} ptrValue
 * @returns boolean
 */
declare function checkNativePointer(ptrValue: NativePointer): boolean;
declare var MAX_STACK_SIZE: number;
declare var DEBUG: boolean;
declare const Dwarf: any;

type DwarfHookAddress = NativePointer | string | null;
type DwarfCallback = ScriptInvocationListenerCallbacks | Function | string;

declare interface StringSearchResult {
    address: NativePointer;
    length: number;
    string: string;
}

declare interface DwarfObserverLocation {
    id: number;
    name: string;
    address: NativePointer;
    size: number;
    type: string;
    mode: string;
    handler: string | Function;
    storedValue: any;
    event: string;
    fromPtr: NativePointer;
}
