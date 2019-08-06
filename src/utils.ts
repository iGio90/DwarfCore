export module Utils {
    export function isDefined(value: any) {
        return (value !== undefined) && (value !== null) && (typeof value !== 'undefined');
    }

    export function isNumber(value: any) {
        if (isDefined(value)) {
            return (typeof value === "number" && !isNaN(value));
        }
        return false;
    }

    export function isString(value: any) {
        if (isDefined(value)) {
            return (typeof value === "string");
        }
        return false;
    }

    export function ba2hex(b: any) {
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
    }

    export function hex2a(hex: string) {
        let bytes = [];
        for (let c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    }

    export function dethumbify(pt: NativePointer) {
        if (Process.arch.indexOf('arm') !== -1) {
            if ((parseInt(pt.toString(), 16) & 1) === 1) {
                pt = pt.sub(1);
            }
        }
        return pt;
    }

    export function uniqueBy(array: any[]) {
        const seen: any = {};
        return array.filter(function (item) {
            const k = JSON.stringify(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    }

    export function logDebug(... data) {
        const date = new Date();
        const now = date['getHourMinuteSecond']();
        let to_log = '';
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

    export function logErr(tag, err) {
        logDebug('[ERROR-' + tag + '] ' + err);
    }
}