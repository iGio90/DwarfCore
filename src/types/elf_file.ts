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

/*
    http://man7.org/linux/man-pages/man5/elf.5.html
    #define EI_NIDENT 16
    typedef struct {
        unsigned char e_ident[EI_NIDENT];
        uint16_t      e_type;
        uint16_t      e_machine;
        uint32_t      e_version;
        ElfN_Addr     e_entry;
        ElfN_Off      e_phoff;
        ElfN_Off      e_shoff;
        uint32_t      e_flags;
        uint16_t      e_ehsize;
        uint16_t      e_phentsize;
        uint16_t      e_phnum;
        uint16_t      e_shentsize;
        uint16_t      e_shnum;
        uint16_t      e_shstrndx;
    } ElfN_Ehdr;
    typedef struct {                typedef struct {
        uint32_t   p_type;              uint32_t   p_type;
        Elf32_Off  p_offset;            uint32_t   p_flags;
        Elf32_Addr p_vaddr;             Elf64_Off  p_offset;
        Elf32_Addr p_paddr;             Elf64_Addr p_vaddr;
        uint32_t   p_filesz;            Elf64_Addr p_paddr;
        uint32_t   p_memsz;             uint64_t   p_filesz;
        uint32_t   p_flags;             uint64_t   p_memsz;
        uint32_t   p_align;             uint64_t   p_align;
    } Elf32_Phdr;                   } Elf64_Phdr;
    typedef struct {                typedef struct {
        uint32_t   sh_name;             uint32_t   sh_name;
        uint32_t   sh_type;             uint32_t   sh_type;
        uint32_t   sh_flags;            uint64_t   sh_flags;
        Elf32_Addr sh_addr;             Elf64_Addr sh_addr;
        Elf32_Off  sh_offset;           Elf64_Off  sh_offset;
        uint32_t   sh_size;             uint64_t   sh_size;
        uint32_t   sh_link;             uint32_t   sh_link;
        uint32_t   sh_info;             uint32_t   sh_info;
        uint32_t   sh_addralign;        uint64_t   sh_addralign;
        uint32_t   sh_entsize;          uint64_t   sh_entsize;
    } Elf32_Shdr;                   } Elf64_Shdr;
*/

import { DwarfApi } from "./../api";
import { DwarfFS } from "./../DwarfFS";

/**
 * ELF Fileparser
 */
export class ELF_File {
    is64Bit: boolean = false;
    endian: string = "little";
    fileHeader: ELF_File.ELF_Header | null = null;
    programHeaders: ELF_File.ELF_ProgamHeader[] = [];
    sectionHeaders: ELF_File.ELF_SectionHeader[] = [];

    /**
     * constructor
     *
     * @param filePath string
     */
    constructor(filePath: string) {
        if (!isString(filePath)) {
            throw new Error("InvalidArgs: No Path given!");
        }

        const dwarfApi = DwarfApi.getInstance();
        const dwarfFS = DwarfFS.getInstance();

        if (!isDefined(dwarfApi)) {
            throw new Error("DwarfApi missing!");
        }

        if (!isDefined(dwarfFS)) {
            throw new Error("DwarfFs missing!");
        }

        let _file: NativePointer = dwarfFS.fopen(filePath, "r") as NativePointer;
        if (!isDefined(_file) || _file.isNull()) {
            throw new Error("Failed to open File: " + filePath);
        }

        let headerBuffer: NativePointer = dwarfFS.allocateRw(0x40);
        if (!isDefined(headerBuffer) || headerBuffer.isNull()) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to allocate Memory!");
        }

        if (dwarfFS.fread(headerBuffer, 1, 0x40, _file) != 0x40) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }

        this.fileHeader = new ELF_File.ELF_Header(headerBuffer);
        // check for 'ELF'
        if (this.fileHeader.e_ident[0] !== 0x7f || this.fileHeader.e_ident[1] !== 0x45 || this.fileHeader.e_ident[2] !== 0x4c || this.fileHeader.e_ident[3] !== 0x46) {
            dwarfFS.fclose(_file);
            throw new Error("No valid ELF File!");
        }

        // EI_VERSION must be 1 == EV_CURRENT
        if (this.fileHeader.e_ident[6] !== 1) {
            dwarfFS.fclose(_file);
            throw new Error("No valid ELF File!");
        }

        //E_VERSION must be 1 == EV_CURRENT
        if (this.fileHeader.e_version !== 1) {
            dwarfFS.fclose(_file);
            throw new Error("No valid ELF File!");
        }

        //EI_CLASS
        if (this.fileHeader.e_ident[4] === 0) {
            dwarfFS.fclose(_file);
            throw new Error("No valid ELF File!");
        } else if (this.fileHeader.e_ident[4] === 1) {
            this.is64Bit = false;
        } else if (this.fileHeader.e_ident[4] === 2) {
            this.is64Bit = true;
        }

        //EI_DATA 1=LSB, 2=MSB
        if (this.fileHeader.e_ident[5] === 0) {
            dwarfFS.fclose(_file);
            throw new Error("No valid ELF File!");
        } else if (this.fileHeader.e_ident[5] === 1) {
            this.endian = "little";
        } else if (this.fileHeader.e_ident[5] === 2) {
            this.endian = "big";
        }

        //get progheaders
        let progHeadersBuffer = dwarfFS.allocateRw(this.fileHeader.e_phnum * this.fileHeader.e_phentsize);
        if (!isDefined(progHeadersBuffer) || progHeadersBuffer.isNull()) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to allocate Memory!");
        }

        if (dwarfFS.fseek(_file, this.fileHeader.e_phoff, DwarfFS.SeekDirection.SEEK_SET) !== 0) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }

        if (dwarfFS.fread(progHeadersBuffer, 1, this.fileHeader.e_phentsize * this.fileHeader.e_phnum, _file) != this.fileHeader.e_phentsize * this.fileHeader.e_phnum) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }

        for (let i = 0; i < this.fileHeader.e_phnum; i++) {
            this.programHeaders.push(new ELF_File.ELF_ProgamHeader(progHeadersBuffer.add(this.fileHeader.e_phentsize * i), this.is64Bit));
        }

        let strTableBuffer = dwarfFS.allocateRw(this.fileHeader.e_shentsize);
        if (!isDefined(strTableBuffer) || strTableBuffer.isNull()) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to allocate Memory!");
        }

        //get strtable
        if (dwarfFS.fseek(_file, this.fileHeader.e_shoff + this.fileHeader.e_shentsize * this.fileHeader.e_shstrndx, DwarfFS.SeekDirection.SEEK_SET) !== 0) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }
        if (dwarfFS.fread(strTableBuffer, 1, this.fileHeader.e_shentsize, _file) !== this.fileHeader.e_shentsize) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }
        let section = new ELF_File.ELF_SectionHeader(strTableBuffer, this.is64Bit);

        if (dwarfFS.fseek(_file, section.sh_offset, DwarfFS.SeekDirection.SEEK_SET) !== 0) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }

        let strSectionBuffer = dwarfFS.allocateRw(section.sh_size);
        if (!isDefined(strSectionBuffer) || strSectionBuffer.isNull()) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to allocate Memory!");
        }

        if (dwarfFS.fread(strSectionBuffer, 1, section.sh_size, _file) !== section.sh_size) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }

        let string_table: (string | null)[] = [];
        let pos = 0;
        while (pos < section.sh_size) {
            let str: string | null = strSectionBuffer.add(pos).readCString() || "NULL";
            if (isDefined(str) && str !== null && str.length > 0) {
                string_table[pos] = str;
                pos += str.length + 1;
            } else {
                string_table[pos] = "";
                pos += 1;
            }
        }

        //get sesctions
        let sectionsBuffer = dwarfFS.allocateRw(this.fileHeader.e_shentsize * this.fileHeader.e_shnum);
        if (!isDefined(sectionsBuffer) || sectionsBuffer.isNull()) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to allocate Memory!");
        }

        if (dwarfFS.fseek(_file, this.fileHeader.e_shoff, DwarfFS.SeekDirection.SEEK_SET) !== 0) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }

        if (dwarfFS.fread(sectionsBuffer, 1, this.fileHeader.e_shentsize * this.fileHeader.e_shnum, _file) !== this.fileHeader.e_shentsize * this.fileHeader.e_shnum) {
            dwarfFS.fclose(_file);
            throw new Error("Failed to read from File!");
        }

        for (let i = 0; i < this.fileHeader.e_shnum; i++) {
            section = new ELF_File.ELF_SectionHeader(sectionsBuffer.add(this.fileHeader.e_shentsize * i), this.is64Bit);
            section.name = strSectionBuffer.add(section.sh_name).readCString() || "NULL";

            if (section.name === ".init_array") {
                let initArrayBuffer = dwarfFS.allocateRw(section.sh_size);

                if (!isDefined(initArrayBuffer) || initArrayBuffer.isNull()) {
                    dwarfFS.fclose(_file);
                    throw new Error("Failed to allocate Memory!");
                }
                if (dwarfFS.fseek(_file, section.sh_offset, DwarfFS.SeekDirection.SEEK_SET) !== 0) {
                    dwarfFS.fclose(_file);
                    throw new Error("Failed to read from File!");
                }
                if (dwarfFS.fread(initArrayBuffer, 1, section.sh_size, _file) !== section.sh_size) {
                    dwarfFS.fclose(_file);
                    throw new Error("Failed to read from File!");
                }
                section.data = [];
                let size = 4;
                if (this.is64Bit) {
                    size += 4;
                }
                for (let a = 0; a < section.sh_size; a += Process.pointerSize) {
                    section.data.push(initArrayBuffer.add(a).readPointer());
                }
            }
            this.sectionHeaders.push(section);
        }
        dwarfFS.fclose(_file);
    }
}

export namespace ELF_File {
    export class ELF_Header {
        e_ident: number[] = [];
        e_type: number = 0;
        e_machine: number = 0;
        e_version: number = 0;
        e_entry: number = 0;
        e_phoff: number = 0;
        e_shoff: number = 0;
        e_flags: number = 0;
        e_ehsize: number = 0;
        e_phentsize: number = 0;
        e_phnum: number = 0;
        e_shentsize: number = 0;
        e_shnum: number = 0;
        e_shstrndx: number = 0;

        /**
         * constructor
         *
         * @param dataPtr NativePointer
         */
        constructor(dataPtr: NativePointer) {
            //parse header
            if (isDefined(dataPtr) && !dataPtr.isNull()) {
                this.e_ident = [];
                for (let i = 0; i < ELF_Header.EI_NIDENT; i++) {
                    this.e_ident.push(dataPtr.add(i).readU8());
                }

                this.e_type = dataPtr.add(0x10).readU16();
                this.e_machine = dataPtr.add(0x12).readU16();
                this.e_version = dataPtr.add(0x14).readU32();

                let pos = 0;
                if (this.e_ident[4] === 1) {
                    // ELFCLASS32
                    this.e_entry = dataPtr.add(0x18).readU32();
                    this.e_phoff = dataPtr.add(0x1c).readU32();
                    this.e_shoff = dataPtr.add(0x20).readU32();
                    pos = 0x24;
                } else if (this.e_ident[4] === 2) {
                    //ELFCLASS64
                    this.e_entry = dataPtr
                        .add(0x18)
                        .readU64()
                        .toNumber();
                    this.e_phoff = dataPtr
                        .add(0x20)
                        .readU64()
                        .toNumber();
                    this.e_shoff = dataPtr
                        .add(0x28)
                        .readU64()
                        .toNumber();
                    pos = 0x30;
                } else {
                    return {
                        e_ident: [],
                        e_type: 0,
                        e_machine: 0,
                        e_version: 0,
                        e_entry: 0,
                        e_phoff: 0,
                        e_shoff: 0,
                        e_flags: 0,
                        e_ehsize: 0,
                        e_phentsize: 0,
                        e_phnum: 0,
                        e_shentsize: 0,
                        e_shnum: 0,
                        e_shstrndx: 0
                    };
                }

                this.e_flags = dataPtr.add(pos).readU32();
                this.e_ehsize = dataPtr.add(pos + 0x4).readU16();
                this.e_phentsize = dataPtr.add(pos + 0x6).readU16();
                this.e_phnum = dataPtr.add(pos + 0x8).readU16();
                this.e_shentsize = dataPtr.add(pos + 0xa).readU16();
                this.e_shnum = dataPtr.add(pos + 0xc).readU16();
                this.e_shstrndx = dataPtr.add(pos + 0xe).readU16();
            }
        }

        public toString = (): string => {
            let str: string[] = [];
            str.push("e_ident: " + this.e_ident.toString());
            str.push("e_type: 0x" + this.e_type.toString(16));
            str.push("e_machine: 0x" + this.e_machine.toString(16));
            str.push("e_version: 0x" + this.e_version.toString(16));
            str.push("e_entry: 0x" + this.e_entry.toString(16));
            str.push("e_phoff: 0x" + this.e_phoff.toString(16));
            str.push("e_shoff: 0x" + this.e_shoff.toString(16));
            str.push("e_flags: 0x" + this.e_flags.toString(16));
            str.push("e_ehsize: 0x" + this.e_ehsize.toString(16));
            str.push("e_phentsize: 0x" + this.e_phentsize.toString(16));
            str.push("e_phnum: 0x" + this.e_phnum.toString(16));
            str.push("e_shentsize: 0x" + this.e_shentsize.toString(16));
            str.push("e_shnum: 0x" + this.e_shnum.toString(16));
            str.push("e_shstrndx: 0x" + this.e_shstrndx.toString(16));
            return str.join("\n");
        };
    }

    export namespace ELF_Header {
        /**
         * sizeof E_IDENT Array
         */
        export const EI_NIDENT: number = 16;
    }

    /**
     * ProgramHeader
     */
    export class ELF_ProgamHeader {
        p_type: number = 0;
        p_vaddr: number = 0;
        p_paddr: number = 0;
        p_filesz: number = 0;
        p_memsz: number = 0;
        p_offset: number = 0;
        p_flags: number = 0;
        p_align: number = 0;

        /**
         * constructor
         *
         * @param dataPtr NativePointer
         * @param is64Bit boolean
         */
        constructor(dataPtr: NativePointer, is64Bit: boolean = false) {
            if (isDefined(dataPtr) && !dataPtr.isNull()) {
                this.p_type = dataPtr.readU32();
                if (!is64Bit) {
                    this.p_offset = dataPtr.add(0x4).readU32();
                    this.p_vaddr = dataPtr.add(0x8).readU32();
                    this.p_paddr = dataPtr.add(0xc).readU32();
                    this.p_filesz = dataPtr.add(0x10).readU32();
                    this.p_memsz = dataPtr.add(0x14).readU32();
                    this.p_flags = dataPtr.add(0x18).readU32();
                    this.p_align = dataPtr.add(0x1c).readU32();
                } else {
                    this.p_flags = dataPtr.add(0x4).readU32();
                    this.p_offset = dataPtr
                        .add(0x8)
                        .readU64()
                        .toNumber();
                    this.p_vaddr = dataPtr
                        .add(0x10)
                        .readU64()
                        .toNumber();
                    this.p_paddr = dataPtr
                        .add(0x18)
                        .readU64()
                        .toNumber();
                    this.p_filesz = dataPtr
                        .add(0x20)
                        .readU64()
                        .toNumber();
                    this.p_memsz = dataPtr
                        .add(0x28)
                        .readU64()
                        .toNumber();
                    this.p_align = dataPtr
                        .add(0x30)
                        .readU64()
                        .toNumber();
                }
            }
        }

        public toString = (): string => {
            let str: string[] = [];
            str.push("p_type: 0x" + this.p_type.toString(16) + " - " + ELF_ProgamHeader.PT_TYPE_NAME[this.p_type]);
            str.push("p_offset: 0x" + this.p_offset.toString(16));
            str.push("p_vaddr: 0x" + this.p_vaddr.toString(16));
            str.push("p_paddr: 0x" + this.p_paddr.toString(16));
            str.push("p_filesz: 0x" + this.p_filesz.toString(16));
            str.push("p_memsz: 0x" + this.p_memsz.toString(16));
            str.push("p_flags: 0x" + this.p_flags.toString(16));
            str.push("p_align: 0x" + this.p_align.toString(16));
            return str.join("\n");
        };
    }

    export namespace ELF_ProgamHeader {
        export const PT_TYPE_NAME: object = {
            0: "NULL",
            1: "LOAD",
            2: "DYNAMIC",
            3: "INTERP",
            4: "NOTE",
            5: "SHLIB",
            6: "PHDR",
            0x60000000: "LOOS",
            0x6474e550: "PT_GNU_EH_FRAME",
            0x6474e551: "PT_GNU_STACK",
            0x6474e552: "PT_GNU_RELO",
            0x6fffffff: "HIOS",
            0x70000000: "LOPROC",
            0x7fffffff: "HIPROC"
        };
    }

    /**
     * SectionHeader
     */
    export class ELF_SectionHeader {
        name: string | null = "";
        data: NativePointer[] = [];
        sh_name: number = 0;
        sh_type: number = 0;
        sh_flags: number = 0;
        sh_addr: number = 0;
        sh_offset: number = 0;
        sh_size: number = 0;
        sh_link: number = 0;
        sh_info: number = 0;
        sh_addralign: number = 0;
        sh_entsize: number = 0;

        /**
         * constructor
         *
         * @param dataPtr NativePointer
         * @param is64Bit boolean
         */
        constructor(dataPtr: NativePointer, is64Bit: boolean = false) {
            if (isDefined(dataPtr) && !dataPtr.isNull()) {
                this.name = "";
                this.sh_name = dataPtr.add(0x0).readU32();
                this.sh_type = dataPtr.add(0x4).readU32();

                if (!is64Bit) {
                    this.sh_flags = dataPtr.add(0x8).readU32();
                    this.sh_addr = dataPtr.add(0xc).readU32();
                    this.sh_offset = dataPtr.add(0x10).readU32();
                    this.sh_size = dataPtr.add(0x14).readU32();
                    this.sh_link = dataPtr.add(0x18).readU32();
                    this.sh_info = dataPtr.add(0x1c).readU32();
                    this.sh_addralign = dataPtr.add(0x20).readU32();
                    this.sh_entsize = dataPtr.add(0x24).readU32();
                } else {
                    this.sh_flags = dataPtr
                        .add(0x8)
                        .readU64()
                        .toNumber();
                    this.sh_addr = dataPtr
                        .add(0x10)
                        .readU64()
                        .toNumber();
                    this.sh_offset = dataPtr
                        .add(0x18)
                        .readU64()
                        .toNumber();
                    this.sh_size = dataPtr
                        .add(0x20)
                        .readU64()
                        .toNumber();
                    this.sh_link = dataPtr.add(0x28).readU32();
                    this.sh_info = dataPtr.add(0x2c).readU32();
                    this.sh_addralign = dataPtr
                        .add(0x30)
                        .readU64()
                        .toNumber();
                    this.sh_entsize = dataPtr
                        .add(0x38)
                        .readU64()
                        .toNumber();
                }
            }
        }

        public toString = (): string => {
            let str: string[] = [];
            str.push("sh_name: 0x" + this.sh_name.toString(16) + " - " + this.name);
            str.push("sh_type: 0x" + this.sh_type.toString(16) + " - " + ELF_SectionHeader.SH_TYPE_NAME[this.sh_type]);
            str.push("sh_flags: 0x" + this.sh_flags.toString(16));
            str.push("sh_addr: 0x" + this.sh_addr.toString(16));
            str.push("sh_offset: 0x" + this.sh_offset.toString(16));
            str.push("sh_size: 0x" + this.sh_size.toString(16));
            str.push("sh_link: 0x" + this.sh_link.toString(16));
            str.push("sh_info: 0x" + this.sh_info.toString(16));
            str.push("sh_addralign: 0x" + this.sh_addralign.toString(16));
            str.push("sh_entsize: 0x" + this.sh_entsize.toString(16));
            return str.join("\n");
        };
    }

    export namespace ELF_SectionHeader {
        export const SH_TYPE_NAME: Object = {
            0: "NULL",
            1: "PROGBITS",
            2: "SYMTAB",
            3: "STRTAB",
            4: "RELA",
            5: "HASH",
            6: "DYNAMIC",
            7: "NOTE",
            8: "NOBITS",
            9: "REL",
            10: "SHLIB",
            11: "DYNSYM",
            14: "INIT_ARRAY",
            15: "FINI_ARRAY",
            16: "PREINIT_ARRAY",
            17: "GROUP",
            18: "SYMTAB_SHNDX",
            19: "RELR",
            0x60000000: "LOOS",
            0x60000001: "ANDROID_REL",
            0x60000002: "ANDROID_RELA",
            0x6fff4c00: "LLVM_ORDTAB",
            0x6fff4c01: "LLVM_LINKER_OPTIONS",
            0x6fff4c02: "LLVM_CALL_GRAPH_PROFILE",
            0x6fff4c03: "LLVM_ADDRSIG",
            0x6fff4c04: "LLVM_DEPENDENT_LIBRARIES",
            0x6fffff00: "ANDROID_RELR",
            0x6ffffff5: "GNU_ATTRIBUTES",
            0x6fffffff: "GNU_VERSYM",
            0x6ffffff6: "GNU_HASH",
            0x6ffffffd: "GNU_VERDEF",
            0x6ffffffe: "GNU_VERNEED",
            0x70000000: "LOPROC",
            0x7fffffff: "HIPROC",
            0x80000000: "LOUSER",
            0xffffffff: "HIUSER"
        };
    }
}
