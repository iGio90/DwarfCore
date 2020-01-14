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

declare namespace NodeJS {
    interface Global {
        DEBUG:boolean;
        MAX_STACK_SIZE:number;
        isDefined:any;
        isNumber:any;
        isString:any;
        ba2hex:any;
        hex2a:any;
        dethumbify:any;
        uniqueBy:any;
        logDebug:any;
        logErr:any;
        makeNativePointer:any;
        checkNativePointer:any;
        trace:any;
        Dwarf:any;
    }
}

declare function isDefined(value:any): boolean;
declare function isNumber(value:any):boolean;
declare function isString(value:any):boolean;
declare function ba2hex(arrayBuffer: ArrayBuffer): string;
declare function hex2a(hex: string):[];
declare function dethumbify(ptrValue:NativePointer):NativePointer;
declare function uniqueBy(array: any[]);
declare function logDebug(...data):void;
declare function trace(...data):void;
declare function logErr(tag, err):void;
declare function makeNativePointer(value:any):NativePointer;
declare function checkNativePointer(ptrValue:NativePointer):boolean;
declare var MAX_STACK_SIZE:number;
declare var DEBUG:boolean;
declare const Dwarf:any;
