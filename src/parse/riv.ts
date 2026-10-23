export interface RivInfo {
  valid: boolean;
  version: string;
  major: number;
  minor: number;
  fileId: string;
  strings: string[];
  note: string;
}

/** Reads the Rive container header and the printable names stored in a .riv file. */
export function parseRiv(data: Uint8Array): RivInfo {
  const valid = data.length >= 4 && ascii(data, 0, 4) === "RIVE";
  if (!valid) {
    return { valid: false, version: "", major: 0, minor: 0, fileId: "", strings: [], note: "This file does not start with a RIVE header." };
  }
  const major = data[4] ?? 0;
  const minor = data[5] ?? 0;
  const fileId = data.length >= 22 ? bytesToHex(data.subarray(6, 22)) : "";
  return {
    valid: true,
    version: `${major}.${minor}`,
    major,
    minor,
    fileId,
    strings: extractNames(data),
    note: "The canvas plays the default artboard. Names below are readable labels stored in the file.",
  };
}

function extractNames(data: Uint8Array): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  let cursor = 0;
  while (cursor < data.length && found.length < 400) {
    while (cursor < data.length && !isNameChar(data[cursor] ?? 0)) cursor++;
    const start = cursor;
    while (cursor < data.length && isNameChar(data[cursor] ?? 0)) cursor++;
    if (cursor - start >= 3) {
      const text = ascii(data, start, cursor - start);
      if (!seen.has(text) && /[A-Za-z]/.test(text)) {
        seen.add(text);
        found.push(text);
      }
    }
  }
  return found;
}

function isNameChar(byte: number): boolean {
  return (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) || byte === 0x20 || byte === 0x5f || byte === 0x2d || byte === 0x2e;
}

function ascii(data: Uint8Array, offset: number, length: number): string {
  let out = "";
  for (let index = 0; index < length; index++) out += String.fromCharCode(data[offset + index] ?? 0);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
