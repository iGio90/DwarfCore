/*
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
*/

import { DwarfFS } from "../DwarfFS";

export class DwarfFile {
    private filePointer: NativePointer;
    private filePath: string;
    private fileSize: number;

    constructor(filePath: string, openMode: string = "rt") {
        if (openMode.indexOf("r") != -1) {
            if (DwarfFS.getInstance().access(filePath, 0) != -1) {
                throw new Error("File: " + filePath + " doesnt exists!");
            }
        }
        this.filePointer = DwarfFS.getInstance().fopen(filePath, openMode) as NativePointer;
        if (isDefined(this.filePointer) && !this.filePointer.isNull()) {
            this.filePath = filePath;

            DwarfFS.getInstance().fseek(this.filePointer, 0, DwarfFS.SeekDirection.SEEK_END);
            //this.fileSize = DwarfFS.getInstance().ftell(this.filePointer).toNumber();
            DwarfFS.getInstance().fseek(this.filePointer, 0, DwarfFS.SeekDirection.SEEK_SET);
        }
    }

    read = (readLen: number = -1) => {
        if (isDefined(this.filePointer) && !this.filePointer.isNull()) {
            if(readLen === -1) {
                readLen = this.fileSize;
            }
            let buffer = Memory.alloc(readLen + 1);
            Memory.protect(buffer, readLen, "rw-");
            DwarfFS.getInstance().fread(buffer, readLen + 1, readLen, this.filePointer);
            return buffer.readByteArray(readLen); //TODO: garbage collected???
        }
    };

    readLine = (): string => {
        //TODO: implement
        return "";
    };

    write = () => {
        //TODO: implement
    };

    close = () => {
        const retVal = DwarfFS.getInstance().fclose(this.filePointer) as number;
        return retVal;
    };

    getFilePointer = () => {
        return this.filePointer;
    };

    getFilePath = () => {
        return this.filePath;
    };
}
