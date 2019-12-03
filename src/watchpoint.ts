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


export const MEMORY_ACCESS_READ = 1;
export const MEMORY_ACCESS_WRITE = 2;
export const MEMORY_ACCESS_EXECUTE = 4;
export const MEMORY_WATCH_SINGLE_SHOT = 8;


export class Watchpoint {
    address: NativePointer;
    flags: number;
    originalPermissions: string;
    debugSymbol: DebugSymbol;
    callback: Function | null;

    constructor(address: NativePointer, flags: number, perm: string, callback: Function | null) {
        this.address = address;
        this.debugSymbol = DebugSymbol.fromAddress(address);
        this.flags = flags;
        this.originalPermissions = perm;
        this.callback = callback;
    }

    watch = () => {
        let perm = '';
        if (this.flags & MEMORY_ACCESS_READ) {
            perm += '-';
        } else {
            perm += this.originalPermissions[0];
        }
        if (this.flags & MEMORY_ACCESS_WRITE) {
            perm += '-';
        } else {
            perm += this.originalPermissions[1];
        }
        if (this.flags & MEMORY_ACCESS_EXECUTE) {
            perm += '-';
        } else {
            if (this.originalPermissions[2] === 'x') {
                perm += 'x';
            } else {
                perm += '-';
            }
        }
        Memory.protect(this.address, 1, perm);
    }

    restore =():void =>{
        Memory.protect(this.address, 1, this.originalPermissions)
    }
}