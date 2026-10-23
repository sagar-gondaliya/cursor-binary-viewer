import { createHash } from "node:crypto";
import { disassembleInsns, type DalvikLine } from "./dalvik";

export interface DexClassSummary {
  index: number;
  name: string;
  jniName: string;
  access: string;
  superClass: string;
  sourceFile: string;
}

export interface DexMember {
  index: number;
  name: string;
  descriptor: string;
  access: string;
  kind: "field" | "method";
  hasCode: boolean;
}

export interface DexClassDetail {
  summary: DexClassSummary;
  interfaces: string[];
  fields: DexMember[];
  methods: DexMember[];
}

export interface DexHeader {
  version: string;
  fileSize: number;
  headerSize: number;
  endian: string;
  checksumOk: boolean;
  signatureOk: boolean;
  checksum: string;
  signature: string;
  stringCount: number;
  typeCount: number;
  protoCount: number;
  fieldCount: number;
  methodCount: number;
  classCount: number;
}

export interface DexFile {
  header: DexHeader;
  classes: DexClassSummary[];
  classDetail(index: number): DexClassDetail;
  methodCode(classIndex: number, methodIndex: number): { header: string; lines: DalvikLine[] };
  searchStrings(query: string, limit: number): string[];
}

const ACCESS_FLAGS: Array<[number, string]> = [
  [0x1, "public"],
  [0x2, "private"],
  [0x4, "protected"],
  [0x8, "static"],
  [0x10, "final"],
  [0x20, "synchronized"],
  [0x40, "volatile"],
  [0x80, "transient"],
  [0x100, "native"],
  [0x200, "interface"],
  [0x400, "abstract"],
  [0x800, "strictfp"],
  [0x1000, "synthetic"],
  [0x2000, "annotation"],
  [0x4000, "enum"],
  [0x10000, "constructor"],
  [0x20000, "declared-synchronized"],
];

export function parseDex(data: Uint8Array): DexFile {
  if (data.length < 0x70 || ascii(data, 0, 4) !== "dex\n") {
    throw new Error("This file does not start with a DEX header.");
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const endianTag = view.getUint32(40, true);
  if (endianTag !== 0x12345678) {
    throw new Error("This DEX file is not little-endian. The viewer reads standard Android DEX files.");
  }
  const version = ascii(data, 4, 3);
  const checksum = view.getUint32(8, true);
  const signature = bytesToHex(data.subarray(12, 32));
  const fileSize = view.getUint32(32, true);
  const headerSize = view.getUint32(36, true);
  const stringIdsSize = view.getUint32(56, true);
  const stringIdsOff = view.getUint32(60, true);
  const typeIdsSize = view.getUint32(64, true);
  const typeIdsOff = view.getUint32(68, true);
  const protoIdsSize = view.getUint32(72, true);
  const protoIdsOff = view.getUint32(76, true);
  const fieldIdsSize = view.getUint32(80, true);
  const fieldIdsOff = view.getUint32(84, true);
  const methodIdsSize = view.getUint32(88, true);
  const methodIdsOff = view.getUint32(92, true);
  const classDefsSize = view.getUint32(96, true);
  const classDefsOff = view.getUint32(100, true);

  const stringOffs = readU32Table(view, stringIdsOff, stringIdsSize);
  const typeNameIdx = readU32Table(view, typeIdsOff, typeIdsSize);
  const stringCache = new Array<string | undefined>(stringIdsSize);

  const getString = (index: number): string => {
    if (index < 0 || index >= stringIdsSize) return `<string #${index}>`;
    const cached = stringCache[index];
    if (cached !== undefined) return cached;
    const decoded = readMutf8String(data, stringOffs[index] ?? 0);
    stringCache[index] = decoded;
    return decoded;
  };
  const getType = (index: number): string => {
    if (index < 0 || index >= typeIdsSize || index === 0xffffffff) return "";
    return getString(typeNameIdx[index] ?? -1);
  };

  const protos = new Array<{ shorty: number; returnType: number; parametersOff: number }>(protoIdsSize);
  for (let index = 0; index < protoIdsSize; index++) {
    const at = protoIdsOff + index * 12;
    protos[index] = {
      shorty: view.getUint32(at, true),
      returnType: view.getUint32(at + 4, true),
      parametersOff: view.getUint32(at + 8, true),
    };
  }
  const fields = new Array<{ classIdx: number; typeIdx: number; nameIdx: number }>(fieldIdsSize);
  for (let index = 0; index < fieldIdsSize; index++) {
    const at = fieldIdsOff + index * 8;
    fields[index] = {
      classIdx: view.getUint16(at, true),
      typeIdx: view.getUint16(at + 2, true),
      nameIdx: view.getUint32(at + 4, true),
    };
  }
  const methods = new Array<{ classIdx: number; protoIdx: number; nameIdx: number }>(methodIdsSize);
  for (let index = 0; index < methodIdsSize; index++) {
    const at = methodIdsOff + index * 8;
    methods[index] = {
      classIdx: view.getUint16(at, true),
      protoIdx: view.getUint16(at + 2, true),
      nameIdx: view.getUint32(at + 4, true),
    };
  }

  const protoText = (index: number): string => {
    const proto = protos[index];
    if (!proto) return "()";
    const params = proto.parametersOff === 0 ? [] : readTypeList(view, proto.parametersOff).map((type) => humanType(getType(type)));
    return `(${params.join(", ")})${humanType(getType(proto.returnType))}`;
  };
  const fieldText = (index: number): string => {
    const field = fields[index];
    if (!field) return `<field #${index}>`;
    return `${humanType(getType(field.classIdx))}.${getString(field.nameIdx)}:${humanType(getType(field.typeIdx))}`;
  };
  const methodText = (index: number): string => {
    const method = methods[index];
    if (!method) return `<method #${index}>`;
    return `${humanType(getType(method.classIdx))}.${getString(method.nameIdx)}${protoText(method.protoIdx)}`;
  };

  const classDefs = new Array<{
    classIdx: number;
    access: number;
    superclassIdx: number;
    interfacesOff: number;
    sourceFileIdx: number;
    classDataOff: number;
  }>(classDefsSize);
  const classes: DexClassSummary[] = [];
  for (let index = 0; index < classDefsSize; index++) {
    const at = classDefsOff + index * 32;
    const classIdx = view.getUint32(at, true);
    const access = view.getUint32(at + 4, true);
    const superclassIdx = view.getUint32(at + 8, true);
    const interfacesOff = view.getUint32(at + 12, true);
    const sourceFileIdx = view.getUint32(at + 16, true);
    const classDataOff = view.getUint32(at + 24, true);
    classDefs[index] = { classIdx, access, superclassIdx, interfacesOff, sourceFileIdx, classDataOff };
    const jniName = getType(classIdx);
    classes.push({
      index,
      jniName,
      name: humanType(jniName),
      access: accessFlags(access),
      superClass: superclassIdx === 0xffffffff ? "" : humanType(getType(superclassIdx)),
      sourceFile: sourceFileIdx === 0xffffffff ? "" : getString(sourceFileIdx),
    });
  }

  const readClassData = (index: number): DexClassDetail => {
    const summary = classes[index];
    const def = classDefs[index];
    if (!summary || !def) throw new Error(`Class #${index} is outside this DEX file.`);
    const interfaces = def.interfacesOff === 0 ? [] : readTypeList(view, def.interfacesOff).map((type) => humanType(getType(type)));
    const fieldMembers: DexMember[] = [];
    const methodMembers: DexMember[] = [];
    if (def.classDataOff !== 0) {
      let cursor = def.classDataOff;
      const staticFields = readUleb(data, cursor);
      cursor = staticFields[1];
      const instanceFields = readUleb(data, cursor);
      cursor = instanceFields[1];
      const directMethods = readUleb(data, cursor);
      cursor = directMethods[1];
      const virtualMethods = readUleb(data, cursor);
      cursor = virtualMethods[1];
      let fieldIndex = 0;
      for (const count of [staticFields[0], instanceFields[0]]) {
        for (let item = 0; item < count; item++) {
          const diff = readUleb(data, cursor);
          cursor = diff[1];
          const flags = readUleb(data, cursor);
          cursor = flags[1];
          fieldIndex += diff[0];
          const field = fields[fieldIndex];
          fieldMembers.push({
            index: fieldMembers.length,
            kind: "field",
            name: field ? getString(field.nameIdx) : `<field #${fieldIndex}>`,
            descriptor: field ? humanType(getType(field.typeIdx)) : "",
            access: accessFlags(flags[0]),
            hasCode: false,
          });
        }
      }
      let methodIndex = 0;
      for (const count of [directMethods[0], virtualMethods[0]]) {
        for (let item = 0; item < count; item++) {
          const diff = readUleb(data, cursor);
          cursor = diff[1];
          const flags = readUleb(data, cursor);
          cursor = flags[1];
          const codeOff = readUleb(data, cursor);
          cursor = codeOff[1];
          methodIndex += diff[0];
          const method = methods[methodIndex];
          methodMembers.push({
            index: methodMembers.length,
            kind: "method",
            name: method ? getString(method.nameIdx) : `<method #${methodIndex}>`,
            descriptor: method ? protoText(method.protoIdx) : "",
            access: accessFlags(flags[0]),
            hasCode: codeOff[0] !== 0,
          });
        }
      }
    }
    return { summary, interfaces, fields: fieldMembers, methods: methodMembers };
  };

  const codeOffFor = (classIndex: number, memberIndex: number): number => {
    const def = classDefs[classIndex];
    if (!def || def.classDataOff === 0) return 0;
    let cursor = def.classDataOff;
    const counts = [0, 0, 0, 0];
    for (let part = 0; part < 4; part++) {
      const value = readUleb(data, cursor);
      counts[part] = value[0];
      cursor = value[1];
    }
    const fieldCount = (counts[0] ?? 0) + (counts[1] ?? 0);
    for (let item = 0; item < fieldCount; item++) {
      cursor = readUleb(data, cursor)[1];
      cursor = readUleb(data, cursor)[1];
    }
    let seen = 0;
    const methodCount = (counts[2] ?? 0) + (counts[3] ?? 0);
    for (let item = 0; item < methodCount; item++) {
      cursor = readUleb(data, cursor)[1];
      cursor = readUleb(data, cursor)[1];
      const codeOff = readUleb(data, cursor);
      cursor = codeOff[1];
      if (seen === memberIndex) return codeOff[0];
      seen++;
    }
    return 0;
  };

  return {
    header: {
      version,
      fileSize,
      headerSize,
      endian: "little",
      checksumOk: adler32(data, 12) === checksum,
      signatureOk: createHash("sha1").update(data.subarray(32)).digest("hex") === signature,
      checksum: checksum.toString(16).padStart(8, "0"),
      signature,
      stringCount: stringIdsSize,
      typeCount: typeIdsSize,
      protoCount: protoIdsSize,
      fieldCount: fieldIdsSize,
      methodCount: methodIdsSize,
      classCount: classDefsSize,
    },
    classes,
    classDetail: readClassData,
    methodCode: (classIndex, methodIndex) => {
      const detail = readClassData(classIndex);
      const method = detail.methods[methodIndex];
      if (!method) throw new Error("That method is not in this class.");
      const codeOff = codeOffFor(classIndex, methodIndex);
      if (codeOff === 0) {
        return { header: `${method.access} ${method.name}${method.descriptor}  (no code)`.trim(), lines: [] };
      }
      const registers = view.getUint16(codeOff, true);
      const ins = view.getUint16(codeOff + 2, true);
      const outs = view.getUint16(codeOff + 4, true);
      const tries = view.getUint16(codeOff + 6, true);
      const insnsSize = view.getUint32(codeOff + 12, true);
      const insns = new Uint16Array(insnsSize);
      for (let unit = 0; unit < insnsSize; unit++) insns[unit] = view.getUint16(codeOff + 16 + unit * 2, true);
      return {
        header: `${method.access} ${method.name}${method.descriptor}   registers=${registers} ins=${ins} outs=${outs} tries=${tries}`.trim(),
        lines: disassembleInsns(insns, {
          stringAt: getString,
          typeAt: (index) => humanType(getType(index)),
          fieldAt: fieldText,
          methodAt: methodText,
        }),
      };
    },
    searchStrings: (query, limit) => {
      const needle = query.toLowerCase();
      const hits: string[] = [];
      for (let index = 0; index < stringIdsSize && hits.length < limit; index++) {
        const value = getString(index);
        if (value.toLowerCase().includes(needle)) hits.push(value);
      }
      return hits;
    },
  };
}

export function humanType(descriptor: string): string {
  let depth = 0;
  while (descriptor[depth] === "[") depth++;
  const raw = descriptor.slice(depth);
  const primitive: Record<string, string> = {
    V: "void", Z: "boolean", B: "byte", S: "short", C: "char", I: "int", J: "long", F: "float", D: "double",
  };
  let name = primitive[raw] ?? raw;
  if (raw.startsWith("L") && raw.endsWith(";")) name = raw.slice(1, -1).replaceAll("/", ".");
  return depth > 0 ? `${name}${"[]".repeat(depth)}` : name;
}

export function accessFlags(flags: number): string {
  const names = ACCESS_FLAGS.filter(([bit]) => (flags & bit) !== 0).map(([, name]) => name);
  return names.join(" ");
}

function ascii(data: Uint8Array, offset: number, length: number): string {
  return String.fromCharCode(...data.subarray(offset, offset + length));
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function readU32Table(view: DataView, offset: number, count: number): number[] {
  const values = new Array<number>(count);
  for (let index = 0; index < count; index++) values[index] = view.getUint32(offset + index * 4, true);
  return values;
}

function readTypeList(view: DataView, offset: number): number[] {
  const size = view.getUint32(offset, true);
  const values: number[] = [];
  for (let index = 0; index < size; index++) values.push(view.getUint16(offset + 4 + index * 2, true));
  return values;
}

function readUleb(data: Uint8Array, offset: number): [number, number] {
  let result = 0;
  let shift = 0;
  let cursor = offset;
  while (cursor < data.length && shift <= 28) {
    const byte = data[cursor++] ?? 0;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return [result >>> 0, cursor];
    shift += 7;
  }
  return [result >>> 0, cursor];
}

function readMutf8String(data: Uint8Array, offset: number): string {
  let cursor = readUleb(data, offset)[1];
  const start = cursor;
  while (cursor < data.length && data[cursor] !== 0) cursor++;
  return decodeMutf8(data.subarray(start, cursor));
}

function decodeMutf8(bytes: Uint8Array): string {
  let out = "";
  for (let index = 0; index < bytes.length; index++) {
    const a = bytes[index] ?? 0;
    if (a < 0x80) out += String.fromCharCode(a);
    else if ((a & 0xe0) === 0xc0) out += String.fromCharCode(((a & 0x1f) << 6) | ((bytes[++index] ?? 0) & 0x3f));
    else out += String.fromCharCode(((a & 0x0f) << 12) | (((bytes[++index] ?? 0) & 0x3f) << 6) | ((bytes[++index] ?? 0) & 0x3f));
  }
  return out;
}

function adler32(data: Uint8Array, start: number): number {
  let a = 1;
  let b = 0;
  for (let index = start; index < data.length; index++) {
    a = (a + (data[index] ?? 0)) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}
