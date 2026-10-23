export interface ElfSection {
  index: number;
  name: string;
  type: string;
  flags: string;
  address: string;
  offset: number;
  size: number;
}

export interface ElfSymbol {
  name: string;
  bind: string;
  type: string;
  section: string;
  value: string;
  size: number;
}

export interface ElfProgramHeader {
  type: string;
  flags: string;
  offset: number;
  address: string;
  fileSize: number;
  memorySize: number;
}

export interface ElfFile {
  summary: {
    class: string;
    encoding: string;
    type: string;
    machine: string;
    entry: string;
    osAbi: string;
    fileSize: number;
    sectionCount: number;
    symbolCount: number;
    soname: string;
  };
  needed: string[];
  sections: ElfSection[];
  programHeaders: ElfProgramHeader[];
  symbols: ElfSymbol[];
  strings: string[];
  notes: string[];
}

const MACHINES: Record<number, string> = {
  3: "x86",
  40: "ARM",
  62: "x86-64",
  183: "AArch64",
  243: "RISC-V",
};

const SECTION_TYPES: Record<number, string> = {
  0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA", 5: "HASH", 6: "DYNAMIC",
  7: "NOTE", 8: "NOBITS", 9: "REL", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
};

const PROGRAM_TYPES: Record<number, string> = {
  0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE", 5: "SHLIB", 6: "PHDR", 7: "TLS",
  0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK", 0x6474e552: "GNU_RELRO",
  0x6474e553: "GNU_PROPERTY",
};

export function parseElf(data: Uint8Array): ElfFile {
  if (data.length < 64 || data[0] !== 0x7f || ascii(data, 1, 3) !== "ELF") {
    throw new Error("This file does not start with an ELF header.");
  }
  const elfClass = data[4];
  const encoding = data[5];
  if ((elfClass !== 1 && elfClass !== 2) || (encoding !== 1 && encoding !== 2)) {
    throw new Error("This ELF class or endianness is not supported.");
  }
  const bits64 = elfClass === 2;
  const little = encoding === 1;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const u16 = (offset: number): number => view.getUint16(offset, little);
  const u32 = (offset: number): number => view.getUint32(offset, little);
  const u64 = (offset: number): bigint => view.getBigUint64(offset, little);
  const word = (offset: number): bigint => bits64 ? u64(offset) : BigInt(u32(offset));

  const type = u16(16);
  const machine = u16(18);
  const entry = bits64 ? u64(24) : BigInt(u32(24));
  const phoff = Number(bits64 ? u64(32) : BigInt(u32(28)));
  const shoff = Number(bits64 ? u64(40) : BigInt(u32(32)));
  const ehsize = bits64 ? u16(52) : u16(40);
  const phentsize = bits64 ? u16(54) : u16(42);
  const phnum = bits64 ? u16(56) : u16(44);
  const shentsize = bits64 ? u16(58) : u16(46);
  const shnum = bits64 ? u16(60) : u16(48);
  const shstrndx = bits64 ? u16(62) : u16(50);
  const notes: string[] = [];
  if (ehsize === 0) notes.push("ELF header size is zero.");

  interface RawSection { nameOff: number; type: number; flags: bigint; addr: bigint; offset: number; size: number; link: number; info: number; entsize: number }
  const rawSections: RawSection[] = [];
  for (let index = 0; index < shnum; index++) {
    const at = shoff + index * shentsize;
    if (bits64) {
      rawSections.push({
        nameOff: u32(at), type: u32(at + 4), flags: u64(at + 8), addr: u64(at + 16),
        offset: Number(u64(at + 24)), size: Number(u64(at + 32)), link: u32(at + 40),
        info: u32(at + 44), entsize: Number(u64(at + 56)),
      });
    } else {
      rawSections.push({
        nameOff: u32(at), type: u32(at + 4), flags: BigInt(u32(at + 8)), addr: BigInt(u32(at + 12)),
        offset: u32(at + 16), size: u32(at + 20), link: u32(at + 24), info: u32(at + 28), entsize: u32(at + 36),
      });
    }
  }
  const nameBase = rawSections[shstrndx];
  const sectionName = (nameOff: number): string => nameBase ? readCString(data, nameBase.offset + nameOff) : "";
  const sections: ElfSection[] = rawSections.map((section, index) => ({
    index,
    name: sectionName(section.nameOff),
    type: SECTION_TYPES[section.type] ?? `0x${section.type.toString(16)}`,
    flags: sectionFlags(section.flags),
    address: hex(section.addr),
    offset: section.offset,
    size: section.size,
  }));

  const programHeaders: ElfProgramHeader[] = [];
  const loads: Array<{ offset: number; vaddr: bigint; filesz: bigint }> = [];
  for (let index = 0; index < phnum; index++) {
    const at = phoff + index * phentsize;
    const pType = u32(at);
    if (bits64) {
      const flags = u32(at + 4);
      const offset = Number(u64(at + 8));
      const vaddr = u64(at + 16);
      const filesz = u64(at + 32);
      const memsz = u64(at + 40);
      programHeaders.push({ type: PROGRAM_TYPES[pType] ?? `0x${pType.toString(16)}`, flags: pFlags(flags), offset, address: hex(vaddr), fileSize: Number(filesz), memorySize: Number(memsz) });
      if (pType === 1) loads.push({ offset, vaddr, filesz });
    } else {
      const offset = u32(at + 4);
      const vaddr = BigInt(u32(at + 8));
      const filesz = BigInt(u32(at + 16));
      const memsz = BigInt(u32(at + 20));
      const flags = u32(at + 24);
      programHeaders.push({ type: PROGRAM_TYPES[pType] ?? `0x${pType.toString(16)}`, flags: pFlags(flags), offset, address: hex(vaddr), fileSize: Number(filesz), memorySize: Number(memsz) });
      if (pType === 1) loads.push({ offset, vaddr, filesz });
    }
  }

  const toOffset = (vaddr: bigint): number | undefined => {
    for (const load of loads) {
      if (vaddr >= load.vaddr && vaddr < load.vaddr + load.filesz) return load.offset + Number(vaddr - load.vaddr);
    }
    return undefined;
  };

  let needed: string[] = [];
  let soname = "";
  const dynamic = programHeaders.find((header) => header.type === "DYNAMIC");
  const dynstr = sections.find((section) => section.name === ".dynstr");
  if (dynamic) {
    const stride = bits64 ? 16 : 8;
    for (let cursor = dynamic.offset; cursor + stride <= dynamic.offset + dynamic.fileSize && cursor + stride <= data.length; cursor += stride) {
      const tag = bits64 ? u64(cursor) : BigInt(u32(cursor));
      const value = bits64 ? u64(cursor + 8) : BigInt(u32(cursor + 4));
      if (tag === 0n) break;
      if ((tag === 1n || tag === 14n) && dynstr) {
        const text = readCString(data, dynstr.offset + Number(value));
        if (tag === 1n) needed.push(text);
        else soname = text;
      }
      if (tag === 5n && !dynstr) {
        const off = toOffset(value);
        if (off !== undefined && tag === 5n) notes.push(`Dynamic string table at file offset 0x${off.toString(16)}.`);
      }
    }
  }
  if (needed.length === 0) {
    const dynamicSection = rawSections.find((section) => section.type === 6);
    if (dynamicSection && dynstr) {
      const stride = bits64 ? 16 : 8;
      for (let cursor = dynamicSection.offset; cursor + stride <= dynamicSection.offset + dynamicSection.size; cursor += stride) {
        const tag = Number(word(cursor));
        const value = word(cursor + (bits64 ? 8 : 4));
        if (tag === 0) break;
        if (tag === 1) needed.push(readCString(data, dynstr.offset + Number(value)));
        if (tag === 14) soname = readCString(data, dynstr.offset + Number(value));
      }
    }
  }

  const symbols: ElfSymbol[] = [];
  const symbolSections = rawSections
    .map((section, index) => ({ section, index }))
    .filter((item) => item.section.type === 2 || item.section.type === 11);
  for (const item of symbolSections) {
    const nameSection = rawSections[item.section.link];
    const entsize = item.section.entsize || (bits64 ? 24 : 16);
    const count = entsize > 0 ? Math.floor(item.section.size / entsize) : 0;
    const cap = Math.min(count, 20000);
    if (count > cap) notes.push(`${sections[item.index]?.name ?? "symbol table"} has ${count} symbols. The first ${cap} are shown; search still covers those.`);
    for (let index = 0; index < cap; index++) {
      const at = item.section.offset + index * entsize;
      let nameOff = 0;
      let info = 0;
      let shndx = 0;
      let value = 0n;
      let size = 0;
      if (bits64) {
        nameOff = u32(at);
        info = data[at + 4] ?? 0;
        shndx = u16(at + 6);
        value = u64(at + 8);
        size = Number(u64(at + 16));
      } else {
        nameOff = u32(at);
        value = BigInt(u32(at + 4));
        size = u32(at + 8);
        info = data[at + 12] ?? 0;
        shndx = u16(at + 14);
      }
      const name = nameSection ? readCString(data, nameSection.offset + nameOff) : "";
      if (!name) continue;
      symbols.push({
        name,
        bind: ["local", "global", "weak"][(info >> 4)] ?? `bind ${info >> 4}`,
        type: ["none", "object", "func", "section", "file"][info & 0xf] ?? `type ${info & 0xf}`,
        section: shndx === 0xfff1 ? "ABS" : shndx === 0xfff2 ? "COMMON" : shndx === 0 ? "UND" : (sections[shndx]?.name || `#${shndx}`),
        value: hex(value),
        size,
      });
    }
  }

  const strings = collectStrings(data, sections);
  return {
    summary: {
      class: bits64 ? "ELF64" : "ELF32",
      encoding: little ? "little-endian" : "big-endian",
      type: ["none", "relocatable", "executable", "shared object", "core"][type] ?? `type ${type}`,
      machine: MACHINES[machine] ?? `machine ${machine}`,
      entry: hex(entry),
      osAbi: ["System V", "HP-UX", "NetBSD", "Linux", "GNU Hurd", "Solaris", "AIX", "IRIX", "FreeBSD", "Tru64", "Novell Modesto", "OpenBSD", "OpenVMS", "NonStop", "AROS", "FenixOS", "CloudABI", "OpenVOS"][data[7] ?? 0] ?? `OS ABI ${data[7]}`,
      fileSize: data.length,
      sectionCount: shnum,
      symbolCount: symbols.length,
      soname,
    },
    needed,
    sections,
    programHeaders,
    symbols,
    strings,
    notes,
  };
}

function collectStrings(data: Uint8Array, sections: ElfSection[]): string[] {
  const interesting = sections.filter((section) => section.name === ".rodata" || section.name === ".dynstr" || section.name === ".strtab" || section.name === ".comment");
  const chosen = interesting.length > 0 ? interesting : sections.filter((section) => section.type === "PROGBITS").slice(0, 2);
  const found: string[] = [];
  const seen = new Set<string>();
  for (const section of chosen) {
    const start = section.offset;
    const end = Math.min(data.length, start + Math.min(section.size, 256 * 1024));
    let cursor = start;
    while (cursor < end && found.length < 1500) {
      while (cursor < end && !isPrintable(data[cursor] ?? 0)) cursor++;
      const from = cursor;
      while (cursor < end && isPrintable(data[cursor] ?? 0)) cursor++;
      if (cursor - from >= 4) {
        const text = ascii(data, from, cursor - from);
        if (!seen.has(text)) {
          seen.add(text);
          found.push(text);
        }
      }
    }
  }
  return found;
}

function sectionFlags(flags: bigint): string {
  const names: Array<[bigint, string]> = [[1n, "W"], [2n, "A"], [4n, "X"], [0x10n, "M"], [0x20n, "S"], [0x40n, "I"]];
  return names.filter(([bit]) => (flags & bit) !== 0n).map(([, name]) => name).join("") || "-";
}

function pFlags(flags: number): string {
  return `${flags & 4 ? "R" : "-"}${flags & 2 ? "W" : "-"}${flags & 1 ? "X" : "-"}`;
}

function readCString(data: Uint8Array, offset: number): string {
  if (offset < 0 || offset >= data.length) return "";
  let end = offset;
  const limit = Math.min(data.length, offset + 4096);
  while (end < limit && data[end] !== 0) end++;
  return ascii(data, offset, end - offset);
}

function ascii(data: Uint8Array, offset: number, length: number): string {
  let out = "";
  for (let index = 0; index < length; index++) out += String.fromCharCode(data[offset + index] ?? 0);
  return out;
}

function isPrintable(byte: number): boolean {
  return byte >= 0x20 && byte <= 0x7e;
}

function hex(value: bigint): string {
  return `0x${value.toString(16)}`;
}
