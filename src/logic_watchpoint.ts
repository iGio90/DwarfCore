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


import { Dwarf } from "./dwarf";
import {
    MEMORY_ACCESS_EXECUTE,
    MEMORY_ACCESS_READ,
    MEMORY_ACCESS_WRITE,
    MEMORY_WATCH_SINGLE_SHOT, Watchpoint
} from "./watchpoint";
import { Utils } from "./utils";
import { LogicBreakpoint } from "./logic_breakpoint";
import isDefined = Utils.isDefined;

export class LogicWatchpoint {
    static memoryWatchpoints = {};

    static attachMemoryAccessMonitor() {
        const monitorAddresses = [];
        Object.keys(LogicWatchpoint.memoryWatchpoints).forEach(pt => {
            monitorAddresses.push({ 'base': ptr(pt), 'size': 1 })
        });
        MemoryAccessMonitor.enable(monitorAddresses, { onAccess: LogicWatchpoint.onMemoryAccess });
    }

    static handleException(exception) {
        const tid = Process.getCurrentThreadId();
        let watchpoint: Watchpoint | null = null;
        if (Object.keys(LogicWatchpoint.memoryWatchpoints).length > 0) {
            // make sure it's access violation
            if (exception['type'] === 'access-violation') {
                watchpoint = LogicWatchpoint.memoryWatchpoints[exception['memory']['address']];
                if (Utils.isDefined(watchpoint)) {
                    const operation = exception.memory.operation;
                    if (Utils.isDefined(operation)) {
                        if ((watchpoint.flags & MEMORY_ACCESS_READ) && (operation === 'read')) {
                            watchpoint.restore();
                            Dwarf.loggedSend('watchpoint:::' + JSON.stringify(exception) + ':::' + tid);
                        } else if ((watchpoint.flags & MEMORY_ACCESS_WRITE) && (operation === 'write')) {
                            watchpoint.restore();
                            Dwarf.loggedSend('watchpoint:::' + JSON.stringify(exception) + ':::' + tid);
                        } else if ((watchpoint.flags & MEMORY_ACCESS_EXECUTE) && (operation === 'execute')) {
                            watchpoint.restore();
                            Dwarf.loggedSend('watchpoint:::' + JSON.stringify(exception) + ':::' + tid);
                        } else {
                            watchpoint = null;
                        }
                    } else {
                        watchpoint.restore();
                        Dwarf.loggedSend('watchpoint:::' + JSON.stringify(exception) + ':::' + tid);
                    }
                } else {
                    watchpoint = null;
                }
            }
        }

        if (watchpoint !== null) {
            const interceptor = Interceptor.attach(exception.address, function (args) {
                interceptor.detach();
                Interceptor['flush']();

                if (watchpoint.callback !== null) {
                    watchpoint.callback.call(this, args);
                } else {
                    LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_WATCHPOINT, this.context.pc, this.context);
                }

                if (isDefined(LogicWatchpoint.memoryWatchpoints[exception.memory.address]) &&
                    !(watchpoint.flags & MEMORY_WATCH_SINGLE_SHOT)) {
                    watchpoint.watch();
                }
            });
        }

        return watchpoint;
    }

    static onMemoryAccess(details) {
        const tid = Process.getCurrentThreadId();
        const operation = details.operation; // 'read' - 'write' - 'execute'
        const fromPtr = details.from;
        const address = details.address;

        let watchpoint = null;

        // watchpoints
        if (Object.keys(LogicWatchpoint.memoryWatchpoints).length > 0) {
            watchpoint = LogicWatchpoint.memoryWatchpoints[address];
            if (typeof watchpoint !== 'undefined') {
                const returnval = { 'memory': { 'operation': operation, 'address': address } };
                if ((watchpoint.flags & MEMORY_ACCESS_READ) && (operation === 'read')) {
                    MemoryAccessMonitor.disable();
                    Dwarf.loggedSend('watchpoint:::' + JSON.stringify(returnval) + ':::' + tid);
                } else if ((watchpoint.flags & MEMORY_ACCESS_WRITE) && (operation === 'write')) {
                    MemoryAccessMonitor.disable();
                    Dwarf.loggedSend('watchpoint:::' + JSON.stringify(returnval) + ':::' + tid);
                } else if ((watchpoint.flags & MEMORY_ACCESS_EXECUTE) && (operation === 'execute')) {
                    MemoryAccessMonitor.disable();
                    Dwarf.loggedSend('watchpoint:::' + JSON.stringify(returnval) + ':::' + tid);
                } else {
                    watchpoint = null;
                }
            } else {
                watchpoint = null;
            }
        }

        if (watchpoint !== null) {
            const interceptor = Interceptor.attach(fromPtr, function (args) {
                interceptor.detach();
                Interceptor['flush']();

                if (watchpoint.callback !== null) {
                    watchpoint.callback.call(this, args);
                } else {
                    LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_WATCHPOINT, this.context.pc, this.context);
                }

                if (isDefined(LogicWatchpoint.memoryWatchpoints[address]) &&
                    !(watchpoint.flags & MEMORY_WATCH_SINGLE_SHOT)) {
                    LogicWatchpoint.attachMemoryAccessMonitor();
                }
            });
        }
        return watchpoint !== null;
    }

    static putWatchpoint(address: any, flags?, callback?: Function): Watchpoint {
        address = ptr(address);

        let range;
        let watchpoint;

        if (typeof callback === 'undefined') {
            callback = null;
        }

        // default '--?'
        if (!Utils.isNumber(flags)) {
            flags = (MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE);
        }

        if (!Utils.isDefined(LogicWatchpoint.memoryWatchpoints[address.toString()])) {
            range = Process.findRangeByAddress(address);
            if (range === null) {
                console.log('failed to find memory range for ' + address.toString());
                return null;
            }

            watchpoint = new Watchpoint(address, flags, range.protection, callback);
            LogicWatchpoint.memoryWatchpoints[address.toString()] = watchpoint;
            Dwarf.loggedSend('watchpoint_added:::' + address.toString() + ':::' +
                flags + ':::' + JSON.stringify(watchpoint.debugSymbol));

            if (Process.platform === 'windows') {
                LogicWatchpoint.attachMemoryAccessMonitor();
            } else {
                if (watchpoint) {
                    watchpoint.watch();
                }
            }

            return watchpoint;
        } else {
            console.log(address.toString() + ' is already watched');
            return null;
        }
    }

    static removeWatchpoint(address: any) {
        address = ptr(address);
        const watchpoint = LogicWatchpoint.memoryWatchpoints[address.toString()];
        if (!Utils.isDefined(watchpoint)) {
            return false;
        }
        watchpoint.restore();
        delete LogicWatchpoint.memoryWatchpoints[address.toString()];
        if (Process.platform === 'windows') {
            LogicWatchpoint.attachMemoryAccessMonitor();
        }
        Dwarf.loggedSend('watchpoint_removed:::' + address.toString());
        return true;
    }
}