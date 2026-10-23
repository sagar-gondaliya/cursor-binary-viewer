/** Dalvik bytecode decoder. Offsets shown to the user are byte offsets, matching smali. */

export interface DalvikResolver {
  stringAt(index: number): string;
  typeAt(index: number): string;
  fieldAt(index: number): string;
  methodAt(index: number): string;
}

export interface DalvikLine {
  address: number;
  text: string;
}

const NAMES: string[] = [
  "nop", "move", "move/from16", "move/16", "move-wide", "move-wide/from16", "move-wide/16",
  "move-object", "move-object/from16", "move-object/16", "move-result", "move-result-wide",
  "move-result-object", "move-exception", "return-void", "return", "return-wide", "return-object",
  "const/4", "const/16", "const", "const/high16", "const-wide/16", "const-wide/32", "const-wide",
  "const-wide/high16", "const-string", "const-string/jumbo", "const-class", "monitor-enter",
  "monitor-exit", "check-cast", "instance-of", "array-length", "new-instance", "new-array",
  "filled-new-array", "filled-new-array/range", "fill-array-data", "throw", "goto", "goto/16",
  "goto/32", "packed-switch", "sparse-switch", "cmpl-float", "cmpg-float", "cmpl-double",
  "cmpg-double", "cmp-long", "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le", "if-eqz",
  "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez", "unused", "unused", "unused", "unused",
  "unused", "unused", "aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char",
  "aget-short", "aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char",
  "aput-short", "iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char",
  "iget-short", "iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char",
  "iput-short", "sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char",
  "sget-short", "sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char",
  "sput-short", "invoke-virtual", "invoke-super", "invoke-direct", "invoke-static",
  "invoke-interface", "unused", "invoke-virtual/range", "invoke-super/range", "invoke-direct/range",
  "invoke-static/range", "invoke-interface/range", "unused", "unused", "neg-int", "not-int",
  "neg-long", "not-long", "neg-float", "neg-double", "int-to-long", "int-to-float", "int-to-double",
  "long-to-int", "long-to-float", "long-to-double", "float-to-int", "float-to-long", "float-to-double",
  "double-to-int", "double-to-long", "double-to-float", "int-to-byte", "int-to-char", "int-to-short",
  "add-int", "sub-int", "mul-int", "div-int", "rem-int", "and-int", "or-int", "xor-int", "shl-int",
  "shr-int", "ushr-int", "add-long", "sub-long", "mul-long", "div-long", "rem-long", "and-long",
  "or-long", "xor-long", "shl-long", "shr-long", "ushr-long", "add-float", "sub-float", "mul-float",
  "div-float", "rem-float", "add-double", "sub-double", "mul-double", "div-double", "rem-double",
  "add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr", "rem-int/2addr", "and-int/2addr",
  "or-int/2addr", "xor-int/2addr", "shl-int/2addr", "shr-int/2addr", "ushr-int/2addr", "add-long/2addr",
  "sub-long/2addr", "mul-long/2addr", "div-long/2addr", "rem-long/2addr", "and-long/2addr",
  "or-long/2addr", "xor-long/2addr", "shl-long/2addr", "shr-long/2addr", "ushr-long/2addr",
  "add-float/2addr", "sub-float/2addr", "mul-float/2addr", "div-float/2addr", "rem-float/2addr",
  "add-double/2addr", "sub-double/2addr", "mul-double/2addr", "div-double/2addr", "rem-double/2addr",
  "add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16", "rem-int/lit16", "and-int/lit16",
  "or-int/lit16", "xor-int/lit16", "add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8",
  "rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8", "shl-int/lit8", "shr-int/lit8",
  "ushr-int/lit8",
];

type Format =
  | "10x" | "12x" | "11n" | "11x" | "10t" | "20t" | "22x" | "21t" | "21s" | "21h" | "21c"
  | "23x" | "22b" | "22t" | "22s" | "22c" | "30t" | "32x" | "31i" | "31t" | "31c" | "35c"
  | "3rc" | "51l" | "unk";

const FORMATS: Format[] = new Array<Format>(256).fill("unk");

function fill(from: number, to: number, format: Format): void {
  for (let op = from; op <= to; op++) FORMATS[op] = format;
}

FORMATS[0x00] = "10x";
FORMATS[0x01] = "12x";
FORMATS[0x02] = "22x";
FORMATS[0x03] = "32x";
FORMATS[0x04] = "12x";
FORMATS[0x05] = "22x";
FORMATS[0x06] = "32x";
FORMATS[0x07] = "12x";
FORMATS[0x08] = "22x";
FORMATS[0x09] = "32x";
fill(0x0a, 0x0d, "11x");
FORMATS[0x0e] = "10x";
fill(0x0f, 0x11, "11x");
FORMATS[0x12] = "11n";
FORMATS[0x13] = "21s";
FORMATS[0x14] = "31i";
FORMATS[0x15] = "21h";
FORMATS[0x16] = "21s";
FORMATS[0x17] = "31i";
FORMATS[0x18] = "51l";
FORMATS[0x19] = "21h";
FORMATS[0x1a] = "21c";
FORMATS[0x1b] = "31c";
FORMATS[0x1c] = "21c";
fill(0x1d, 0x1e, "11x");
FORMATS[0x1f] = "21c";
FORMATS[0x20] = "22c";
FORMATS[0x21] = "12x";
FORMATS[0x22] = "21c";
FORMATS[0x23] = "22c";
FORMATS[0x24] = "35c";
FORMATS[0x25] = "3rc";
FORMATS[0x26] = "31t";
FORMATS[0x27] = "11x";
FORMATS[0x28] = "10t";
FORMATS[0x29] = "20t";
FORMATS[0x2a] = "30t";
FORMATS[0x2b] = "31t";
FORMATS[0x2c] = "31t";
fill(0x2d, 0x31, "23x");
fill(0x32, 0x37, "22t");
fill(0x38, 0x3d, "21t");
fill(0x44, 0x51, "23x");
fill(0x52, 0x5f, "22c");
fill(0x60, 0x6d, "21c");
fill(0x6e, 0x72, "35c");
fill(0x74, 0x78, "3rc");
fill(0x7b, 0x8f, "12x");
fill(0x90, 0xaf, "23x");
fill(0xb0, 0xcf, "12x");
fill(0xd0, 0xd7, "22s");
fill(0xd8, 0xe2, "22b");

function s4(value: number): number {
  return (value << 28) >> 28;
}

function s8(value: number): number {
  return (value << 24) >> 24;
}

function s16(value: number): number {
  return (value << 16) >> 16;
}

function s32(value: number): number {
  return value | 0;
}

function hex(value: number, width = 4): string {
  return (value >>> 0).toString(16).padStart(width, "0");
}

function lit(value: number): string {
  return value < 0 ? `#${value}` : `#${value}`;
}

function u16(insns: Uint16Array, index: number): number {
  return index < insns.length ? insns[index] : 0;
}

function ref(kind: "string" | "type" | "field" | "method", index: number, resolver: DalvikResolver): string {
  const id = `${kind}@${hex(index)}`;
  try {
    const name = kind === "string" ? resolver.stringAt(index)
      : kind === "type" ? resolver.typeAt(index)
      : kind === "field" ? resolver.fieldAt(index)
      : resolver.methodAt(index);
    const shown = kind === "string" ? JSON.stringify(name) : name;
    return `${id}  // ${shown}`;
  } catch {
    return id;
  }
}

function regsFromNibbleWord(word: number, count: number, extra: number): string {
  const regs = [word & 0xf, (word >> 4) & 0xf, (word >> 8) & 0xf, (word >> 12) & 0xf, extra];
  return `{${regs.slice(0, count).map((reg) => `v${reg}`).join(", ")}}`;
}

export function disassembleInsns(insns: Uint16Array, resolver: DalvikResolver): DalvikLine[] {
  const lines: DalvikLine[] = [];
  let cursor = 0;
  while (cursor < insns.length) {
    const address = cursor * 2;
    const first = insns[cursor];
    if (first === 0x0100 || first === 0x0200 || first === 0x0300) {
      const payload = skipPayload(insns, cursor);
      lines.push({ address, text: payload.text });
      cursor += payload.size;
      continue;
    }
    const opcode = first & 0xff;
    const name = NAMES[opcode] ?? `op_${hex(opcode, 2)}`;
    const format = FORMATS[opcode] ?? "unk";
    const decoded = decode(insns, cursor, opcode, name, format, resolver);
    lines.push({ address, text: decoded.text });
    cursor += decoded.size;
  }
  return lines;
}

function skipPayload(insns: Uint16Array, cursor: number): { size: number; text: string } {
  const ident = insns[cursor];
  if (ident === 0x0100 || ident === 0x0200) {
    const size = u16(insns, cursor + 1);
    const width = ident === 0x0100 ? 2 : 4;
    const units = 2 + size * width;
    const label = ident === 0x0100 ? "packed-switch-payload" : "sparse-switch-payload";
    return { size: Math.max(1, Math.min(units, insns.length - cursor)), text: `${label} (${size} entries)` };
  }
  const elementWidth = u16(insns, cursor + 1);
  const count = u16(insns, cursor + 2) | (u16(insns, cursor + 3) << 16);
  const bytes = elementWidth * count;
  const units = 4 + Math.ceil(bytes / 2);
  return { size: Math.max(1, Math.min(units, insns.length - cursor)), text: `fill-array-data-payload (${count} x ${elementWidth} bytes)` };
}

function decode(
  insns: Uint16Array,
  cursor: number,
  opcode: number,
  name: string,
  format: Format,
  resolver: DalvikResolver,
): { size: number; text: string } {
  const first = insns[cursor];
  const a = (first >> 8) & 0xf;
  const b = (first >> 12) & 0xf;
  const aa = (first >> 8) & 0xff;
  const remaining = insns.length - cursor;

  const need = (units: number): boolean => remaining >= units;

  switch (format) {
    case "10x":
      return { size: 1, text: name };
    case "12x":
      return { size: 1, text: `${name} v${a}, v${b}` };
    case "11n":
      return { size: 1, text: `${name} v${a}, ${lit(s4(b))}` };
    case "11x":
      return { size: 1, text: `${name} v${aa}` };
    case "10t":
      return { size: 1, text: branch(name, cursor, s8(aa)) };
    case "20t":
      return need(2)
        ? { size: 2, text: branch(name, cursor, s16(u16(insns, cursor + 1))) }
        : { size: 1, text: `${name} <truncated>` };
    case "22x":
      return need(2)
        ? { size: 2, text: `${name} v${aa}, v${u16(insns, cursor + 1)}` }
        : { size: 1, text: `${name} <truncated>` };
    case "21t":
      return need(2)
        ? { size: 2, text: `${name} v${aa}, ${branchTarget(cursor, s16(u16(insns, cursor + 1)))}` }
        : { size: 1, text: `${name} <truncated>` };
    case "21s":
      return need(2)
        ? { size: 2, text: `${name} v${aa}, ${lit(s16(u16(insns, cursor + 1)))}` }
        : { size: 1, text: `${name} <truncated>` };
    case "21h": {
      if (!need(2)) return { size: 1, text: `${name} <truncated>` };
      const raw = u16(insns, cursor + 1);
      const value = opcode === 0x19 ? BigInt(raw) << 48n : raw << 16;
      return { size: 2, text: `${name} v${aa}, #${value}` };
    }
    case "21c":
      return need(2)
        ? { size: 2, text: `${name} v${aa}, ${constRef(opcode, u16(insns, cursor + 1), resolver)}` }
        : { size: 1, text: `${name} <truncated>` };
    case "23x":
      return need(2)
        ? { size: 2, text: `${name} v${aa}, v${u16(insns, cursor + 1) & 0xff}, v${(u16(insns, cursor + 1) >> 8) & 0xff}` }
        : { size: 1, text: `${name} <truncated>` };
    case "22b":
      return need(2)
        ? { size: 2, text: `${name} v${aa}, v${u16(insns, cursor + 1) & 0xff}, ${lit(s8((u16(insns, cursor + 1) >> 8) & 0xff))}` }
        : { size: 1, text: `${name} <truncated>` };
    case "22t":
      return need(2)
        ? { size: 2, text: `${name} v${a}, v${b}, ${branchTarget(cursor, s16(u16(insns, cursor + 1)))}` }
        : { size: 1, text: `${name} <truncated>` };
    case "22s":
      return need(2)
        ? { size: 2, text: `${name} v${a}, v${b}, ${lit(s16(u16(insns, cursor + 1)))}` }
        : { size: 1, text: `${name} <truncated>` };
    case "22c":
      return need(2)
        ? { size: 2, text: `${name} v${a}, v${b}, ${fieldOrType(opcode, u16(insns, cursor + 1), resolver)}` }
        : { size: 1, text: `${name} <truncated>` };
    case "30t":
      return need(3)
        ? { size: 3, text: branch(name, cursor, s32(u16(insns, cursor + 1) | (u16(insns, cursor + 2) << 16))) }
        : { size: Math.min(3, remaining), text: `${name} <truncated>` };
    case "32x":
      return need(3)
        ? { size: 3, text: `${name} v${u16(insns, cursor + 1)}, v${u16(insns, cursor + 2)}` }
        : { size: Math.min(3, remaining), text: `${name} <truncated>` };
    case "31i":
      return need(3)
        ? { size: 3, text: `${name} v${aa}, ${lit(s32(u16(insns, cursor + 1) | (u16(insns, cursor + 2) << 16)))}` }
        : { size: Math.min(3, remaining), text: `${name} <truncated>` };
    case "31t":
      return need(3)
        ? { size: 3, text: `${name} v${aa}, ${branchTarget(cursor, s32(u16(insns, cursor + 1) | (u16(insns, cursor + 2) << 16)))}` }
        : { size: Math.min(3, remaining), text: `${name} <truncated>` };
    case "31c":
      return need(3)
        ? { size: 3, text: `${name} v${aa}, ${ref("string", u16(insns, cursor + 1) | (u16(insns, cursor + 2) << 16), resolver)}` }
        : { size: Math.min(3, remaining), text: `${name} <truncated>` };
    case "35c": {
      if (!need(3)) return { size: Math.min(3, remaining), text: `${name} <truncated>` };
      const method = u16(insns, cursor + 1);
      const regs = u16(insns, cursor + 2);
      const count = aa >> 4;
      const list = regsFromNibbleWord(regs, count, a);
      return { size: 3, text: `${name} ${list}, ${invokeRef(opcode, method, resolver)}` };
    }
    case "3rc": {
      if (!need(3)) return { size: Math.min(3, remaining), text: `${name} <truncated>` };
      const method = u16(insns, cursor + 1);
      const start = u16(insns, cursor + 2);
      const count = aa;
      const list = Array.from({ length: count }, (_, index) => `v${start + index}`).join(", ");
      return { size: 3, text: `${name} {${list}}, ${invokeRef(opcode, method, resolver)}` };
    }
    case "51l": {
      if (!need(5)) return { size: Math.min(5, remaining), text: `${name} <truncated>` };
      let value = 0n;
      for (let part = 0; part < 4; part++) value |= BigInt(u16(insns, cursor + 1 + part)) << BigInt(part * 16);
      if (value & (1n << 63n)) value -= 1n << 64n;
      return { size: 5, text: `${name} v${aa}, #${value}` };
    }
    default:
      return { size: 1, text: `${name} <unknown format>` };
  }
}

function branch(name: string, cursor: number, offset: number): string {
  return `${name} ${branchTarget(cursor, offset)}`;
}

function branchTarget(cursor: number, offset: number): string {
  const target = (cursor + offset) * 2;
  const sign = offset < 0 ? "" : "+";
  return `${sign}${offset} -> :${hex(target, 4)}`;
}

function constRef(opcode: number, index: number, resolver: DalvikResolver): string {
  if (opcode === 0x1a) return ref("string", index, resolver);
  if (opcode === 0x1c || opcode === 0x1f || opcode === 0x22) return ref("type", index, resolver);
  if (opcode >= 0x60 && opcode <= 0x6d) return ref("field", index, resolver);
  return ref("type", index, resolver);
}

function fieldOrType(opcode: number, index: number, resolver: DalvikResolver): string {
  if (opcode === 0x20 || opcode === 0x23) return ref("type", index, resolver);
  if (opcode >= 0x52 && opcode <= 0x5f) return ref("field", index, resolver);
  return ref("field", index, resolver);
}

function invokeRef(opcode: number, index: number, resolver: DalvikResolver): string {
  if (opcode === 0x24 || opcode === 0x25) return ref("type", index, resolver);
  return ref("method", index, resolver);
}
