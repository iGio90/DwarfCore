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

import { DwarfArch, DwarfBits, DwarfPlatform } from "../consts";

export class DwarfProcessInfo {
    protected name: string;
    protected spawned: boolean;
    protected pid: number;
    protected architecture: DwarfArch;
    protected platform: DwarfPlatform;
    protected page_size: number;
    protected pointer_size: number;
    protected java_available: boolean;
    protected objc_available: boolean;
    protected threadId: number;

    /**
     * @internal
     */
    constructor(
        name: string = "",
        spawned: boolean = false,
        pid: number = 0,
        tid: number = 0,
        architecture = "",
        platform = "",
        page_size: number = 0,
        pointer_size: number = 0,
        java: boolean = false,
        objc: boolean = false
    ) {
        trace("DwarfProcessInfo()");

        this.name = name;
        this.spawned = spawned;
        this.pid = pid;
        this.threadId = tid;

        if (typeof architecture === "string") {
            switch (architecture.toLowerCase()) {
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
        } else if (typeof architecture === "number") {
            if (architecture >= DwarfArch.ARCH_X86 && architecture <= DwarfArch.ARCH_ARM64) {
                this.architecture = architecture;
            } else {
                throw new Error("Unknown architecture!");
            }
        } else {
            throw new Error("Unknown architecture!");
        }

        if (typeof platform === "string") {
            switch (platform.toLowerCase()) {
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
        } else if (typeof platform === "number") {
            if (platform >= DwarfPlatform.OS_WINDOWS && platform <= DwarfPlatform.OS_QNX) {
                this.platform = platform;
            } else {
                throw new Error("Unknown platform!");
            }
        } else {
            throw new Error("Unknown platform!");
        }

        this.page_size = page_size;
        this.pointer_size = pointer_size;
        this.java_available = java;
        this.objc_available = objc;
    }

    public getName(): string {
        return this.name;
    }

    public wasSpawned(): boolean {
        return this.spawned;
    }

    public getPID(): number {
        return this.pid;
    }

    public getTID(): number {
        return this.threadId;
    }

    public getArchitecture(): DwarfArch {
        return this.architecture;
    }

    public getPlatform(): DwarfPlatform {
        return this.platform;
    }

    public getPageSize(): number {
        return this.page_size;
    }

    public getPointerSize(): number {
        return this.pointer_size;
    }

    public getBits(): DwarfBits {
        if (this.architecture == DwarfArch.ARCH_ARM64 || this.architecture == DwarfArch.ARCH_X64) {
            return DwarfBits.BITS_64;
        }
        return DwarfBits.BITS_32;
    }

    public isJavaAvailable(): boolean {
        return this.java_available;
    }

    public isObjCAvailable(): boolean {
        return this.objc_available;
    }
}
