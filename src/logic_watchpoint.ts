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


/*
import { LogicBreakpoint } from "./logic_breakpoint";

export class LogicWatchpoint {
    static memoryWatchpoints: { [index: string]: Watchpoint } = {};

    static attachMemoryAccessMonitor() {
        let monitorAddresses: Array<MemoryAccessRange> = new Array<MemoryAccessRange>();
        Object.keys(LogicWatchpoint.memoryWatchpoints).forEach(pt => {
            monitorAddresses.push({ 'base': ptr(pt), 'size': 1 })
        });
        MemoryAccessMonitor.enable(monitorAddresses, { onAccess: LogicWatchpoint.onMemoryAccess });
    }

    static handleException(exception: ExceptionDetails) {
        const tid = Process.getCurrentThreadId();
        let watchpoint: Watchpoint | null = null;
        if (Object.keys(LogicWatchpoint.memoryWatchpoints).length > 0) {
            // make sure it's access violation
            if (exception.type === 'access-violation') {
                watchpoint = LogicWatchpoint.memoryWatchpoints[exception.memory.address.toString()];
                if (isDefined(watchpoint)) {
                    const operation = exception.memory.operation;
                    if (isDefined(operation)) {
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
            const invocationListener = Interceptor.attach(exception.address, function (args) {
                invocationListener.detach();
                Interceptor.flush();

                if (watchpoint.callback !== null) {
                    watchpoint.callback.call(this, args);
                } else {
                    LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_WATCHPOINT, this.context.pc, this.context);
                }

                if (isDefined(LogicWatchpoint.memoryWatchpoints[exception.memory.address.toString()]) &&
                    !(watchpoint.flags & MEMORY_WATCH_SINGLE_SHOT)) {
                    watchpoint.watch();
                }
            });
        }

        return watchpoint;
    }

    static onMemoryAccess(details: MemoryAccessDetails) {
        const tid = Process.getCurrentThreadId();
        const operation: MemoryOperation = details.operation; // 'read' - 'write' - 'execute'
        const fromPtr: NativePointer = details.from;
        const address: NativePointer = details.address;

        let watchpoint: Watchpoint | null = null;

        // watchpoints
        if (Object.keys(LogicWatchpoint.memoryWatchpoints).length > 0) {
            watchpoint = LogicWatchpoint.memoryWatchpoints[address.toString()];
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
            const invocationListener = Interceptor.attach(fromPtr, function (args) {
                invocationListener.detach();
                Interceptor.flush();

                if (watchpoint.callback !== null) {
                    watchpoint.callback.call(this, args);
                } else {
                    LogicBreakpoint.breakpoint(LogicBreakpoint.REASON_WATCHPOINT, this.context.pc, this.context);
                }

                if (isDefined(LogicWatchpoint.memoryWatchpoints[address.toString()]) &&
                    !(watchpoint.flags & MEMORY_WATCH_SINGLE_SHOT)) {
                    LogicWatchpoint.attachMemoryAccessMonitor();
                }
            });
        }
        return watchpoint !== null;
    }

    static putWatchpoint(address: NativePointer | string, flags: number = (MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE), callback?: Function): Watchpoint {
        let memPtr: NativePointer;

        if (typeof address === 'string') {
            memPtr = ptr(address as string);
        } else {
            memPtr = address;
        }

        if (memPtr.isNull()) {
            throw new Error('putWatchpoint: Invalid PointerValue!');
        }

        let watchpoint: Watchpoint | null = null;

        if (typeof callback === 'undefined') {
            callback = null;
        }

        if (!LogicWatchpoint.memoryWatchpoints.hasOwnProperty(memPtr.toString())) {
            const rangeDetails = Process.findRangeByAddress(memPtr);
            if (rangeDetails === null) {
                console.log('failed to find memory range for ' + memPtr.toString());
                return null;
            }

            watchpoint = new Watchpoint(memPtr, flags, rangeDetails.protection, callback);
            LogicWatchpoint.memoryWatchpoints[memPtr.toString()] = watchpoint;
            Dwarf.loggedSend('watchpoint_added:::' + memPtr.toString() + ':::' +
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
            console.log(memPtr.toString() + ' is already watched');
            return null;
        }
    }

    static removeWatchpoint(address: NativePointer | string) {
        let memPtr: NativePointer;

        if (typeof address === 'string') {
            memPtr = ptr(address as string);
        } else {
            memPtr = address;
        }

        if (memPtr.isNull()) {
            throw new Error('removeWatchpoint: Invalid PointerValue!');
        }

        if (!LogicWatchpoint.memoryWatchpoints.hasOwnProperty(memPtr.toString())) {
            throw new Error('removeWatchpoint: No Watchpoint for given address!');
        }

        const watchpoint = LogicWatchpoint.memoryWatchpoints[memPtr.toString()];
        if (Process.platform === 'windows') {
            MemoryAccessMonitor.disable();
        }
        watchpoint.restore();
        delete LogicWatchpoint.memoryWatchpoints[memPtr.toString()];
        if (Process.platform === 'windows') {
            LogicWatchpoint.attachMemoryAccessMonitor();
        }
        Dwarf.loggedSend('watchpoint_removed:::' + memPtr.toString());
        return true;
    }
}*/