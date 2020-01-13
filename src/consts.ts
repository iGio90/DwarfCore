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

export const enum DwarfLogType {
    PRINT = 1,
    DEBUG = 2,
    WARNING = 3,
    ERROR = 4
}

export const enum DwarfPlatform {
    OS_WINDOWS = 1,
    OS_DARWIN = 2,
    OS_LINUX = 3,
    OS_QNX = 4
}

export const enum DwarfArch {
    ARCH_X86 = 1,
    ARCH_X64 = 2,
    ARCH_ARM = 3,
    ARCH_ARM64 = 4
}

export const enum DwarfBits {
    BITS_32 = 1,
    BITS_64 = 2
}

export const enum DwarfEndian {
    LITTLE_ENDIAN = 1,
    BIG_ENDIAN = 2
}

export const enum DwarfSessionType {
    ANDROID = 1,
    LOCAL = 2,
    IOS = 3,
    REMOTE = 4
}

export const enum DwarfBreakpointType {
    NATIVE = 1,
    JAVA = 2,
    OBJC = 3,
    MEMORY = 4
}

export const enum DwarfMemoryAccessType {
    READ = 1,
    WRITE = 2,
    EXECUTE = 4
}

export const enum DwarfHaltReason {
    INITIAL_CONTEXT = 1,
    BP_INITIALIZATION = 2,
    BREAKPOINT = 3,
    STEP = 4
}