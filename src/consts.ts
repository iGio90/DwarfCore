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


const enum DwarfArch {
    ARCH_X86 = 1,
    ARCH_X64 = 2,
    ARCH_ARM = 3,
    ARCH_ARM64 = 4
}

const enum DwarfBits {
    BITS_32 = 1,
    BITS_64 = 2
}

const enum DwarfEndian {
    LITTLE = 1,
    BIG = 2
}

const enum DwarfSessionType {
    ANDROID = 1,
    LOCAL = 2,
    IOS = 3,
    REMOTE = 4
}

const enum DwarfBreakpointType {
    NATIVE = 1,
    JAVA = 2,
    INITIALIZATION = 3, // TODO: remove - use internal flag
    OBJC = 4,
    MEMORY = 5
}

const enum DwarfMemoryAccessType {
    READ = 1,
    WRITE = 2,
    EXECUTE = 4
}