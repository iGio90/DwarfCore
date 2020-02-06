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

global.timeStamp = function(): string {
    const date = new Date();
    const time = new Date(date.valueOf() - 6e4 * date.getTimezoneOffset()).toISOString().replace("Z", "");
    return "[" + time.substring(time.indexOf("T") + 1) + "] ";
};

global.isNull = function(value: any): boolean {
    return value === null;
};

global.isDefined = function(value: any): boolean {
    return value !== undefined && value !== null && typeof value !== "undefined";
};

global.isNumber = function(value: any): boolean {
    if (isDefined(value)) {
        return typeof value === "number" && !isNaN(value);
    }
    return false;
};

global.isString = function(value: any): boolean {
    if (isDefined(value)) {
        return typeof value === "string";
    }
    return false;
};

global.isFunction = function(value: any): boolean {
    if (isDefined(value)) {
        return typeof value === "function";
    }
    return false;
};

global.isValidFridaListener = function(value: any): boolean {
    if (isDefined(value)) {
        if (value.hasOwnProperty("onEnter") || value.hasOwnProperty("onLeave")) {
            return true;
        }
    }
    return false;
};

/*function ba2hex(b: any) {
    const uint8arr = new Uint8Array(b);
    if (!uint8arr) {
        return '';
    }
    let hexStr = '';
    for (let i = 0; i < uint8arr.length; i++) {
        let hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }
    return hexStr;
}*/

global.ba2hex = function(arrayBuffer: ArrayBuffer): string {
    // 24,887 ops/s vs 427,496 ops/s
    //https://jsperf.com/convert-numeric-array-to-hex-string
    const byteArray = new Uint8Array(arrayBuffer);
    if (!isDefined(byteArray)) {
        return "";
    }
    const chars = [byteArray.length * 2];
    const alpha = "a".charCodeAt(0) - 10;
    const digit = "0".charCodeAt(0);

    let p = 0;
    for (let i = 0; i < byteArray.length; i++) {
        let nibble = byteArray[i] >>> 4;
        chars[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
        nibble = byteArray[i] & 0xf;
        chars[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
    }

    if (chars.length < MAX_STACK_SIZE) {
        return String.fromCharCode.apply(null, chars);
    } else {
        return Array.from(chars, function(c) {
            return String.fromCharCode(c);
        }).join("");
    }
};

global.hex2a = function(hex: string): Array<number> {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
};

global.dethumbify = function(pt: NativePointer): NativePointer {
    if (Process.arch.indexOf("arm") !== -1) {
        if ((parseInt(pt.toString(), 16) & 1) === 1) {
            pt = pt.sub(1);
        }
    }
    return pt;
};

global.uniqueBy = function(array: Array<any>): Array<any> {
    const seen: any = {};
    return array.filter(function(item) {
        const k = JSON.stringify(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
};

global.logDebug = function(...data: Array<any>): void {
    if (!DEBUG || !data.length) {
        return;
    }

    let outputMsg = "";

    for (let what of data) {
        if (what instanceof ArrayBuffer) {
            console.log(hexdump(what));
        } else if (what instanceof Object) {
            what = JSON.stringify(what, null, 2);
        }

        if (outputMsg.length) {
            outputMsg += "\t";
        }
        outputMsg += what;
    }

    if (outputMsg !== "") {
        console.log(timeStamp() + "[JS DEBUG] " + outputMsg);
    }
};

global.logErr = function(tag: string, err: Error): void {
    console.log(timeStamp() + "[JS ERROR] => " +  tag + " -> " + err);
};

global.trace = function(str: string): void {
    if (DEBUG) {
        console.log(timeStamp() + "[JS TRACE] -> " + str);
    }
};

global.makeNativePointer = function(value: any): NativePointer {
    if (!isDefined(value)) {
        throw new Error("Invalid Arguments!");
    }

    if (value.constructor.name === "NativePointer") {
        return value as NativePointer;
    }

    if ((isString(value) && value.startsWith("0x")) || isNumber(value)) {
        return ptr(value);
    }

    throw new Error("Invalid Arguments!");
};
/**
 * Checks if given ptrValue is NativePointer
 *
 * @param  {NativePointer} ptrValue
 * @returns boolean
 */
global.checkNativePointer = function(ptrValue: NativePointer): boolean {
    if (!isDefined(ptrValue)) {
        return false;
    }

    if (ptrValue.constructor.name !== "NativePointer") {
        return false;
    }

    if (ptrValue.isNull()) {
        return false;
    }
    return true;
};

//https://codeshare.frida.re/@oleavr/read-std-string/
global.readStdString = function(arg: NativePointer): string | null {
    const isTiny = (arg.readU8() & 1) === 0;
    if (isTiny) {
        return arg.add(1).readUtf8String();
    }

    return arg
        .add(2 * Process.pointerSize)
        .readPointer()
        .readUtf8String();
};
