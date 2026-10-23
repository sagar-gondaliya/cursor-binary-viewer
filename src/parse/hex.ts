export function hexPreview(data: Uint8Array, length = 256): string[] {
  const end = Math.min(data.length, length);
  const lines: string[] = [];
  for (let offset = 0; offset < end; offset += 16) {
    const slice = data.subarray(offset, Math.min(end, offset + 16));
    const hex = [...slice].map((byte) => byte.toString(16).padStart(2, "0")).join(" ");
    const text = [...slice].map((byte) => (byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".")).join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex.padEnd(16 * 3, " ")} ${text}`);
  }
  return lines;
}
