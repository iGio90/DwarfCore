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

global.isDefined = function (value: any): boolean {
    return (value !== undefined) && (value !== null) && (typeof value !== 'undefined');
}


global.isNumber = function (value: any) {
    if (isDefined(value)) {
        return (typeof value === "number" && !isNaN(value));
    }
    return false;
}

global.isString = function (value: any) {
    if (isDefined(value)) {
        return (typeof value === "string");
    }
    return false;
}

global.isFunction = function(value:any) {
    if(isDefined(value)) {
        return (typeof value === 'function');
    }
    return false;
}

global.isValidFridaListener = function(value:any) {
    if(isDefined(value)) {
        if(value.hasOwnProperty('onEnter') || value.hasOwnProperty('onLeave')) {
            return true;
        }
    }
    return false;
}

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

global.ba2hex = function (arrayBuffer: ArrayBuffer): string {
    // 24,887 ops/s vs 427,496 ops/s
    //https://jsperf.com/convert-numeric-array-to-hex-string
    const byteArray = new Uint8Array(arrayBuffer);
    if (!isDefined(byteArray)) {
        return '';
    }
    const chars = [byteArray.length * 2];
    const alpha = 'a'.charCodeAt(0) - 10;
    const digit = '0'.charCodeAt(0);

    let p = 0;
    for (let i = 0; i < byteArray.length; i++) {
        let nibble = byteArray[i] >>> 4;
        chars[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
        nibble = byteArray[i] & 0xF;
        chars[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
    }

    if (chars.length < MAX_STACK_SIZE) {
        return String.fromCharCode.apply(null, chars);
    } else {
        return Array.from(chars, function (c) {
            return String.fromCharCode(c);
        }).join('');
    }
}

global.hex2a = function (hex: string) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

global.dethumbify = function (pt: NativePointer) {
    if (Process.arch.indexOf('arm') !== -1) {
        if ((parseInt(pt.toString(), 16) & 1) === 1) {
            pt = pt.sub(1);
        }
    }
    return pt;
}

global.uniqueBy = function (array: any[]) {
    const seen: any = {};
    return array.filter(function (item) {
        const k = JSON.stringify(item);
        return seen.hasOwnProperty(k) ? false : (seen[k] = true);
    });
}

global.logDebug = function (...data) {
    if (!DEBUG) {
        return;
    }

    const date = new Date();
    const now = date['getHourMinuteSecond']();
    let to_log = '[JS DEBUG] ';
    Object.keys(data).forEach(argN => {
        let what = data[argN];

        if (what instanceof ArrayBuffer) {
            console.log(hexdump(what))
        } else if (what instanceof Object) {
            what = JSON.stringify(what, null, 2);
        }

        if (to_log !== '') {
            to_log += '\t';
        }
        to_log += what;
    });

    if (to_log !== '') {
        console.log(now, to_log);
    }
}

global.logErr = function (tag, err) {
    console.log('[ERROR-' + tag + '] ' + err);
}

global.trace = function (str: string) {
    //TODO: dont use DEBUG
    if (DEBUG) {
        const date = new Date();
        const now = date['getHourMinuteSecond']();
        console.log(now + ' [JS TRACE] -> ' + str);
    }
}

global.makeNativePointer = function (value: any): NativePointer {
    if (value.constructor.name === 'NativePointer') {
        return value as NativePointer;
    }

    if ((typeof value === 'string' && value.startsWith('0x')) || typeof value === 'number') {
        return ptr(value);
    }

    return null;
}
/**
 * Checks if given ptrValue is NativePointer
 *
 * @param  {NativePointer} ptrValue
 * @returns boolean
 */
global.checkNativePointer = function (ptrValue: NativePointer): boolean {
    if (!isDefined(ptrValue)) {
        return false;
    }

    if (ptrValue.constructor.name !== 'NativePointer') {
        return false;
    }

    if (ptrValue.isNull()) {
        return false;
    }
    return true;
}

Date.prototype['getTwoDigitHour'] = function () {
    return (this.getHours() < 10) ? '0' + this.getHours() : this.getHours();
};

Date.prototype['getTwoDigitMinute'] = function () {
    return (this.getMinutes() < 10) ? '0' + this.getMinutes() : this.getMinutes();
};

Date.prototype['getTwoDigitSecond'] = function () {
    return (this.getSeconds() < 10) ? '0' + this.getSeconds() : this.getSeconds();
};

Date.prototype['getHourMinuteSecond'] = function () {
    return this.getTwoDigitHour() + ':' + this.getTwoDigitMinute() + ':' + this.getTwoDigitSecond();
};
