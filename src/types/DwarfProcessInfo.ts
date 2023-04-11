/**
 * Dwarf - Copyright (C) 2018-2023 Giovanni Rocca (iGio90), PinkiePieStyle
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import { DwarfArch, DwarfBits, DwarfPlatform } from "../consts";

export class DwarfProcessInfo {
    protected architecture: DwarfArch;
    protected name: string;
    protected pageSize: number;
    protected pid: number;
    protected platform: DwarfPlatform;
    protected pointerSize: number;
    protected spawned: boolean;
    protected threadId: number;
    protected modules: DwarfModuleInfo[];
    protected threads: ThreadDetails[];
    protected regions: RangeDetails[];

    /**
     * @internal
     */
    constructor(
        name: string = "",
        spawned: boolean = false,
        fullParse:boolean = true
    ) {
        trace("DwarfProcessInfo()");

        this.name = name;
        this.spawned = spawned;
        this.pointerSize = Process.pointerSize;
        this.pageSize = Process.pageSize;
        this.pid = Process.id;
        this.threadId = Process.getCurrentThreadId();

        if (typeof Process.arch === "string") {
            switch (Process.arch.toLowerCase()) {
                case "ia32":
                    this.architecture = DwarfArch.ARCH_X86;
                    break;
                case "x64":
                    this.architecture = DwarfArch.ARCH_X64;
                    break;
                case "arm":
                    this.architecture = DwarfArch.ARCH_ARM;
                    break;
                case "arm64":
                    this.architecture = DwarfArch.ARCH_ARM64;
                    break;
                default:
                    throw new Error("Unknown architecture!");
            }
        }

        if (typeof Process.platform === "string") {
            switch (Process.platform.toLowerCase()) {
                case "windows":
                    this.platform = DwarfPlatform.OS_WINDOWS;
                    break;
                case "darwin":
                    this.platform = DwarfPlatform.OS_DARWIN;
                    break;
                case "linux":
                    this.platform = DwarfPlatform.OS_LINUX;
                    break;
                case "qnx":
                    this.platform = DwarfPlatform.OS_QNX;
                    break;
                default:
                    throw new Error("Unknown platform!");
            }
        }

        this.modules = [];
        Process.enumerateModules().forEach((module) => {
            this.modules.push({
                name: module.name,
                base: module.base.toString(),
                size: module.size,
                path: module.path,
                imports: fullParse ? module.enumerateImports() : [],
                exports: fullParse ? module.enumerateExports() : [],
                symbols: fullParse ? module.enumerateSymbols() : [],
            });
        });
        this.regions = Process.enumerateRanges("---");
        this.threads = Process.enumerateThreads();
    }

    public getArchitecture(): DwarfArch {
        return this.architecture;
    }

    public getBits(): DwarfBits {
        if (this.architecture === DwarfArch.ARCH_ARM64 || this.architecture === DwarfArch.ARCH_X64) {
            return DwarfBits.BITS_64;
        }
        return DwarfBits.BITS_32;
    }

    public getName(): string {
        return this.name;
    }

    public getPageSize(): number {
        return this.pageSize;
    }

    public getPID(): number {
        return this.pid;
    }

    public getPlatform(): DwarfPlatform {
        return this.platform;
    }

    public getPointerSize(): number {
        return this.pointerSize;
    }

    public getTID(): number {
        return this.threadId;
    }

    public wasSpawned(): boolean {
        return this.spawned;
    }
}
