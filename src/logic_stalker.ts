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



import { LogicBreakpoint } from "./logic_breakpoint";
import { StalkerInfo } from "./stalker_info";
import { DwarfHaltReason } from "./consts";
import { DwarfCore } from "./dwarf";

export class LogicStalker {
    static stalkerInfoMap = {};
    static straceCallback: Function | null = null;

    static hitPreventRelease() {
        const tid = Process.getCurrentThreadId();
        const threadContext = Dwarf.threadContexts[tid];
        if (isDefined(threadContext)) {
            threadContext.preventSleep = true;
        }
    }

    static stalk(threadId?: number): StalkerInfo | null {
        LogicStalker.hitPreventRelease();

        const arch = Process.arch;
        const isArm64 = arch === 'arm64';

        if (!isArm64 && arch !== 'x64') {
            console.log('stalker is not supported on current arch: ' + arch);
            return null;
        }

        let tid;
        if (isDefined(threadId)) {
            tid = threadId;
        } else {
            tid = Process.getCurrentThreadId();
        }

        let stalkerInfo = LogicStalker.stalkerInfoMap[tid];
        if (!isDefined(stalkerInfo)) {
            const context = Dwarf.threadContexts[tid];
            if (!isDefined(context)) {
                console.log('cant start stalker outside a valid native context');
                return null;
            }

            stalkerInfo = new StalkerInfo(tid);
            LogicStalker.stalkerInfoMap[tid] = stalkerInfo;

            const initialContextAddress = ptr(parseInt(context.context.pc));

            // this will maybe be replaced in the future
            // when we start stepping, the first basic block is copied into frida space and executed there
            // we need to calculate when it is executed somehow
            let retCount = 0;
            let arm64BlockCount = 0;
            let firstInstructionExec = false;
            let firstBlockCallout = false;
            let calloutHandled = false;

            if (DEBUG) {
                logDebug('[' + tid + '] stalk: ' + 'attaching stalker')
            }

            Stalker.follow(tid, {
                transform: function (iterator) {
                    let instruction;

                    if (DEBUG) {
                        logDebug('[' + tid + '] stalk: ' + 'transform begin')
                    }

                    while ((instruction = iterator.next()) !== null) {
                        iterator.keep();

                        if (instruction.groups.indexOf('jump') < 0 && instruction.groups.indexOf('call') < 0) {
                            stalkerInfo.lastBlockInstruction = { groups: instruction.groups, address: instruction.address };
                        } else {
                            stalkerInfo.lastCallJumpInstruction = { groups: instruction.groups, address: instruction.address };
                        }

                        if (!calloutHandled) {
                            if (retCount > 4) {
                                if (isArm64 && arm64BlockCount < 2) {
                                    continue;
                                }

                                if (!firstInstructionExec) {
                                    if (DEBUG) {
                                        logDebug('[' + tid + '] stalk: ' + 'executing first instruction',
                                            instruction.address.toString(), instruction.toString());
                                    }

                                    stalkerInfo.initialContextAddress = initialContextAddress.add(instruction.size);
                                    firstInstructionExec = true;
                                    continue;
                                }

                                if (DEBUG) {
                                    logDebug('[' + tid + '] stalk: ' + 'executing first basic block instructions',
                                        instruction.address.toString(), instruction.toString());
                                }

                                calloutHandled = true;
                                firstBlockCallout = true;

                                LogicStalker.putCalloutIfNeeded(iterator, stalkerInfo, instruction);
                            }

                            if (instruction.mnemonic === 'ret') {
                                retCount++;
                            }
                        } else {
                            LogicStalker.putCalloutIfNeeded(iterator, stalkerInfo, instruction);
                        }
                    }

                    if (DEBUG) {
                        logDebug('[' + tid + '] stalk: ' + 'transform done')
                    }

                    if (stalkerInfo.terminated) {
                        if (DEBUG) {
                            logDebug('[' + tid + '] stopStep: ' + 'unfollowing tid');
                        }

                        Stalker.flush();
                        Stalker.unfollow(tid);
                        Stalker.garbageCollect();

                        delete LogicStalker.stalkerInfoMap[stalkerInfo.tid];
                    }

                    if (retCount > 4 && isArm64) {
                        arm64BlockCount += 1;
                    }

                    if (firstBlockCallout) {
                        firstBlockCallout = false;
                    }
                }
            });
        }

        return stalkerInfo;
    }

    private static putCalloutIfNeeded(iterator, stalkerInfo: StalkerInfo, instruction: Instruction): void {
        let putCallout = true;
        // todo: add conditions
        if (putCallout) {
            if (DEBUG) {
                logDebug('[' + Process.getCurrentThreadId() + '] stalk: ' + 'executing instruction',
                    instruction.address.toString(), instruction.toString());
            }

            iterator.putCallout(LogicStalker.stalkerCallout);
        }
    }

    static stalkerCallout(context) {
        const tid = Process.getCurrentThreadId();
        const stalkerInfo = LogicStalker.stalkerInfoMap[tid];

        if (!isDefined(stalkerInfo) || stalkerInfo.terminated) {
            return;
        }

        let pc = context.pc;
        const insn = Instruction.parse(pc);

        if (DEBUG) {
            logDebug('[' + tid + '] stalkerCallout: ' + 'running callout', insn.address, insn.toString());
        }

        if (!stalkerInfo.didFistJumpOut) {
            pc = stalkerInfo.initialContextAddress;

            const lastInt = parseInt(stalkerInfo.lastContextAddress);
            if (lastInt > 0) {
                const pcInt = parseInt(context.pc);

                if (pcInt < lastInt || pcInt > lastInt + insn.size) {
                    pc = context.pc;
                    stalkerInfo.didFistJumpOut = true;
                }
            }
        }

        let shouldBreak = false;

        if (stalkerInfo.currentMode !== null) {
            if (typeof stalkerInfo.currentMode === 'function') {
                shouldBreak = false;

                const that = {
                    context: context,
                    instruction: insn,
                    stop: function () {
                        stalkerInfo.terminated = true;
                    }
                };

                stalkerInfo.currentMode.apply(that);
            } else if (stalkerInfo.lastContextAddress !== null &&
                stalkerInfo.lastCallJumpInstruction !== null) {
                if (DEBUG) {
                    logDebug('[' + tid + '] stalkerCallout: ' + 'using mode ->', stalkerInfo.currentMode);
                }
                // call and jumps doesn't receive callout
                const isAddressBeforeJumpOrCall = parseInt(context.pc) === parseInt(
                    stalkerInfo.lastBlockInstruction.address);

                if (isAddressBeforeJumpOrCall) {
                    if (stalkerInfo.currentMode === 'call') {
                        if (stalkerInfo.lastCallJumpInstruction.groups.indexOf('call') >= 0) {
                            shouldBreak = true;
                        }
                    } else if (stalkerInfo.currentMode === 'block') {
                        if (stalkerInfo.lastCallJumpInstruction.groups.indexOf('jump') >= 0) {
                            shouldBreak = true;
                        }
                    }
                }
            }
        } else {
            shouldBreak = true;
        }

        if (shouldBreak) {
            stalkerInfo.context = context;
            stalkerInfo.lastContextAddress = context.pc;

            DwarfCore.getInstance().onBreakpoint(DwarfHaltReason.STEP, pc, stalkerInfo.context, null);

            if (DEBUG) {
                logDebug('[' + tid + '] callOut: ' + 'post onHook');
            }
        }

        if (!stalkerInfo.didFistJumpOut) {
            stalkerInfo.initialContextAddress = stalkerInfo.initialContextAddress.add(insn.size);
        }
    }

    static strace(callback: Function): boolean {
        if (LogicStalker.straceCallback !== null) {
            return false;
        }

        LogicStalker.straceCallback = callback;
        if (typeof callback === 'function') {
            Process.enumerateThreads().forEach(thread => {
                Stalker.follow(thread.id, {
                    transform: function (iterator) {
                        let instruction;
                        while ((instruction = iterator.next()) !== null) {
                            iterator.keep();
                            if (instruction.mnemonic === 'svc' ||
                                instruction.mnemonic === 'int') {
                                iterator.putCallout(LogicStalker.straceCallout);
                            }
                        }
                        if (LogicStalker.straceCallback === null) {
                            Stalker.flush();
                            Stalker.unfollow(thread.id);
                            Stalker.garbageCollect();
                        }
                    }
                });
            });

            return true;
        }

        return false;
    }

    static straceCallout(context) {
        const that = {
            context: context,
            instruction: Instruction.parse(context.pc),
            stop: function () {
                LogicStalker.straceCallback = null;
            }
        };

        LogicStalker.straceCallback.apply(that);
    }
}
