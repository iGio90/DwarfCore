/*
    Dwarf - Copyright (C) 2018-2021 Giovanni Rocca (iGio90)

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
*/

/**
 * @internal
 */
declare namespace NodeJS {
    interface Global {
        DEBUG: boolean;
        TRACE: boolean;
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
        readStdString: Function;
        getJNIFuncPtr: Function;
        Dwarf: any;
        ELFFile: any;
        FridaInterceptor:typeof Interceptor;
    }
}

declare type fEmptyVoid = () => void;
declare type fEmptyReturn = () => any;
declare type fArgVoid = (...args: any[]) => void;
declare type fArgReturn = (...args: any[]) => any;

declare function timeStamp(): string;
declare function isNull(value: any): boolean;
declare function isDefined(value: any): boolean;
declare function isNumber(value: any): boolean;
declare function isString(value: any): boolean;
declare function isFunction(value: any): boolean;
declare function isValidFridaListener(value: any): boolean;
declare function ba2hex(arrayBuffer: ArrayBuffer): string;
declare function hex2a(hex: string): Array<number>;
declare function dethumbify(ptrValue: NativePointer): NativePointer;
declare function uniqueBy(array: Array<any>): Array<any>;
declare function logDebug(...data: Array<any>): void;
declare function trace(...data: Array<any>): void;
declare function logErr(tag: string, err: Error): void;
declare function makeNativePointer(value: any): NativePointer;
declare function readStdString(str: any): string;
declare function getJNIFuncPtr(index: number): NativePointer;
/**
 * Checks if given ptrValue is NativePointer
 *
 * @param  {NativePointer} ptrValue
 * @returns boolean
 */

declare function checkNativePointer(ptrValue: NativePointer): boolean;

/**
 * @protected
 */
declare var MAX_STACK_SIZE: number;

/**
 * @protected
 */
declare var DEBUG: boolean;


declare var FridaInterceptor:typeof Interceptor;

/**
 * @protected
 */
declare var TRACE: boolean;

declare type DwarfHookAddress = NativePointer | string | null;
declare type DwarfCallback = ScriptInvocationListenerCallbacks | fArgReturn | string;

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

declare interface DwarfModule extends Module {
    imports:ModuleImportDetails[];
    exports:ModuleExportDetails[];
    symbols:ModuleSymbolDetails[];
}

declare interface NativeBreakpointInfo {

}