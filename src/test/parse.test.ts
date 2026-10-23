import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { disassembleInsns } from "../parse/dalvik";
import { humanType, parseDex } from "../parse/dex";
import { parseElf } from "../parse/elf";
import { parseJarManifest, parseSignatureBlock } from "../parse/jarSign";
import { parseRiv } from "../parse/riv";

const repo = "/Users/Apple/Downloads/REA";
const resolver = {
  stringAt: (index: number) => `string${index}`,
  typeAt: (index: number) => `Type${index}`,
  fieldAt: (index: number) => `Field${index}`,
  methodAt: (index: number) => `Method${index}`,
};

test("dalvik formats match the instruction set", () => {
  const lines = disassembleInsns(new Uint16Array([0x000e, 0x0012, 0x000c, 0x0011]), resolver);
  assert.equal(lines[0]?.text, "return-void");
  assert.match(lines[1]?.text ?? "", /^const\/4 v0, #0/);
  assert.match(lines[2]?.text ?? "", /^move-result-object v0/);
  assert.match(lines[3]?.text ?? "", /^return-object v0/);

  const invoke = disassembleInsns(new Uint16Array([0x1054, 0x0002]), resolver);
  assert.match(invoke[0]?.text ?? "", /^iget-object v0, v1, field@0002/);
});

test("type descriptors become readable names", () => {
  assert.equal(humanType("Ljava/lang/String;"), "java.lang.String");
  assert.equal(humanType("[I"), "int[]");
  assert.equal(humanType("[[Ljava/lang/Object;"), "java.lang.Object[][]");
});

test("classes6.dex opens and disassembles a method with code", () => {
  const bytes = execFileSync("unzip", ["-p", `${repo}/apk/music-9-42-52.apk`, "classes6.dex"], { maxBuffer: 20 * 1024 * 1024 });
  const dex = parseDex(bytes);
  assert.match(dex.header.version, /^03[5-9]$/);
  assert.equal(dex.header.checksumOk, true);
  assert.equal(dex.header.signatureOk, true);
  assert.ok(dex.header.classCount > 100);
  const withCode = dex.classes.find((item) => dex.classDetail(item.index).methods.some((method) => method.hasCode));
  assert.ok(withCode);
  const detail = dex.classDetail(withCode.index);
  const method = detail.methods.findIndex((item) => item.hasCode);
  const code = dex.methodCode(withCode.index, method);
  assert.ok(code.lines.length > 0);
  assert.match(code.header, /registers=/);
});

test("arm64 shared library exposes machine, sections, and symbols", () => {
  const bytes = new Uint8Array(readFileSync(`${repo}/apk/work/music-noads/lib/arm64-v8a/libandroidx.graphics.path.so`));
  const elf = parseElf(bytes);
  assert.equal(elf.summary.class, "ELF64");
  assert.equal(elf.summary.machine, "AArch64");
  assert.equal(elf.summary.type, "shared object");
  assert.ok(elf.sections.some((section) => section.name === ".dynsym"));
  assert.ok(elf.symbols.some((symbol) => symbol.name.includes("JNI_OnLoad") || symbol.type === "func"));
  assert.ok(elf.needed.length > 0);
});

test("apk manifest, signature file, and RSA block parse", () => {
  const zip = `${repo}/apk/music-9-42-52-noads.apk`;
  const manifest = parseJarManifest(execFileSync("unzip", ["-p", zip, "META-INF/MANIFEST.MF"], { maxBuffer: 8 * 1024 * 1024 }), "mf");
  const signature = parseJarManifest(execFileSync("unzip", ["-p", zip, "META-INF/ANDROIDD.SF"], { maxBuffer: 8 * 1024 * 1024 }), "sf");
  const block = parseSignatureBlock(execFileSync("unzip", ["-p", zip, "META-INF/ANDROIDD.RSA"]), "rsa");
  assert.equal(manifest.main[0]?.key, "Manifest-Version");
  assert.equal(manifest.entries.length, 4717);
  assert.equal(manifest.entries[0]?.name, "AndroidManifest.xml");
  assert.equal(manifest.entries[0]?.digests[0]?.key, "SHA-256-Digest");
  const wrapped = manifest.entries.find((entry) => entry.name.includes("AppSearchDocumentClassMap"));
  assert.ok(wrapped && !wrapped.name.endsWith("M"));
  assert.equal(signature.main.find((item) => item.key === "Signature-Version")?.value, "1.0");
  assert.ok(signature.main.some((item) => item.key === "SHA-256-Digest-Manifest"));
  assert.equal(block.contentType, "signedData");
  assert.deepEqual(block.digestAlgorithms, ["sha256"]);
  assert.equal(block.certificates.length, 1);
  assert.match(block.certificates[0]?.subject ?? "", /Android Debug/);
  assert.match(block.certificates[0]?.publicKey ?? "", /^RSA /);
  assert.equal(block.signers[0]?.digestAlgorithm, "sha256");
  assert.equal(block.signers[0]?.signatureAlgorithm, "rsaEncryption");
  assert.equal(block.signers[0]?.signatureBytes, 256);
  const rsaBytes = execFileSync("unzip", ["-p", zip, "META-INF/ANDROIDD.RSA"]);
  const asDsa = parseSignatureBlock(rsaBytes, "dsa");
  assert.ok(asDsa.notes.some((note) => note.includes("RSA")));
});

test("empty rive file keeps its artboard name", () => {
  const bytes = new Uint8Array(readFileSync(`${repo}/apk/work/music-noads/unknown/com/google/android/libraries/youtube/rendering/rive/EmptyArtboard.riv`));
  const riv = parseRiv(bytes);
  assert.equal(riv.valid, true);
  assert.ok(riv.strings.includes("Artboard"));
  assert.ok(riv.strings.some((name) => name.includes("State Machine")));
});
