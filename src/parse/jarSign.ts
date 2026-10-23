import { X509Certificate } from "node:crypto";

export interface JarAttribute {
  key: string;
  value: string;
}

export interface JarEntry {
  name: string;
  digests: JarAttribute[];
}

export interface JarManifest {
  kind: "mf" | "sf";
  label: string;
  main: JarAttribute[];
  entries: JarEntry[];
}

export interface SignerCertificate {
  subject: string;
  issuer: string;
  serial: string;
  validFrom: string;
  validTo: string;
  fingerprint256: string;
  fingerprint: string;
  publicKey: string;
  selfSigned: boolean;
}

export interface SignerInfo {
  version: number;
  digestAlgorithm: string;
  signatureAlgorithm: string;
  signatureBytes: number;
  attributes: JarAttribute[];
}

export interface SignatureBlock {
  kind: "rsa" | "dsa";
  label: string;
  contentType: string;
  digestAlgorithms: string[];
  certificates: SignerCertificate[];
  signers: SignerInfo[];
  notes: string[];
}

const OIDS: Record<string, string> = {
  "1.2.840.113549.1.7.1": "data",
  "1.2.840.113549.1.7.2": "signedData",
  "1.2.840.113549.1.1.1": "rsaEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10040.4.1": "dsa",
  "1.2.840.10040.4.3": "sha1WithDSA",
  "2.16.840.1.101.3.4.3.2": "sha256WithDSA",
  "1.3.14.3.2.26": "sha1",
  "2.16.840.1.101.3.4.2.1": "sha256",
  "2.16.840.1.101.3.4.2.2": "sha384",
  "2.16.840.1.101.3.4.2.3": "sha512",
  "1.2.840.113549.1.9.3": "contentType",
  "1.2.840.113549.1.9.4": "messageDigest",
  "1.2.840.113549.1.9.5": "signingTime",
};

export function parseJarManifest(data: Uint8Array, kind: "mf" | "sf"): JarManifest {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(data);
  if (text.includes("\u0000")) throw new Error("This file is not a JAR manifest or signature file.");
  const lines = unfold(text);
  const sections: string[][] = [[]];
  for (const line of lines) {
    if (line.trim() === "") {
      if ((sections[sections.length - 1]?.length ?? 0) > 0) sections.push([]);
      continue;
    }
    sections[sections.length - 1]?.push(line);
  }
  const main: JarAttribute[] = [];
  const entries: JarEntry[] = [];
  for (const section of sections) {
    if (section.length === 0) continue;
    const attributes = section.map(parseAttribute).filter((item): item is JarAttribute => item !== undefined);
    const name = attributes.find((item) => item.key === "Name");
    if (!name) {
      main.push(...attributes);
      continue;
    }
    entries.push({
      name: name.value,
      digests: attributes.filter((item) => item.key !== "Name"),
    });
  }
  const versionKey = kind === "mf" ? "Manifest-Version" : "Signature-Version";
  if (!main.some((item) => item.key === versionKey) && entries.length === 0) {
    throw new Error(kind === "mf"
      ? "This file has no Manifest-Version header."
      : "This file has no Signature-Version header.");
  }
  return {
    kind,
    label: kind === "mf" ? "JAR manifest" : "JAR signature file",
    main,
    entries,
  };
}

export function parseSignatureBlock(data: Uint8Array, kind: "rsa" | "dsa"): SignatureBlock {
  if (data.length < 4 || data[0] !== 0x30) {
    throw new Error("This file is not a PKCS #7 signature block.");
  }
  const notes: string[] = [];
  const root = readNode(data, 0);
  const children = readChildren(data, root);
  const contentOid = children[0]?.tag === 0x06 ? decodeOid(data.subarray(children[0].start, children[0].end)) : "";
  const signedWrapper = children.find((node) => node.tag === 0xa0);
  const signed = signedWrapper ? readChildren(data, signedWrapper)[0] : undefined;
  const signedChildren = signed ? readChildren(data, signed) : [];
  const digestAlgorithms: string[] = [];
  const signers: SignerInfo[] = [];
  if (contentOid && contentOid !== "1.2.840.113549.1.7.2") notes.push(`Content type is ${oidName(contentOid)}, not signedData.`);
  for (const node of signedChildren) {
    if (node.tag === 0x31 && digestAlgorithms.length === 0 && signers.length === 0) {
      for (const algorithm of readChildren(data, node)) digestAlgorithms.push(algorithmName(data, algorithm));
    }
  }
  const signerSet = [...signedChildren].reverse().find((node) => node.tag === 0x31);
  if (signerSet && signedChildren.indexOf(signerSet) > 1) {
    for (const info of readChildren(data, signerSet)) {
      if (info.tag === 0x30) signers.push(readSigner(data, info));
    }
  }
  const certificates = collectCertificates(data);
  const declared = kind === "rsa" ? "RSA" : "DSA";
  for (const certificate of certificates) {
    const actual = certificate.publicKey.split(" ")[0] ?? "";
    if (actual && actual !== declared) notes.push(`This .${kind} block contains a ${actual} key.`);
  }
  if (certificates.length === 0) notes.push("No X.509 certificate was found in this block.");
  return {
    kind,
    label: kind === "rsa" ? "PKCS #7 RSA block" : "PKCS #7 DSA block",
    contentType: contentOid ? oidName(contentOid) : "unknown",
    digestAlgorithms,
    certificates,
    signers,
    notes,
  };
}

function unfold(text: string): string[] {
  const raw = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const lines: string[] = [];
  for (const line of raw) {
    if (line.startsWith(" ") && lines.length > 0) lines[lines.length - 1] += line.slice(1);
    else lines.push(line);
  }
  return lines;
}

function parseAttribute(line: string): JarAttribute | undefined {
  const split = line.indexOf(":");
  if (split <= 0) return undefined;
  return { key: line.slice(0, split).trim(), value: line.slice(split + 1).trim() };
}

interface DerNode { tag: number; start: number; end: number; offset: number; constructed: boolean }

function readNode(data: Uint8Array, offset: number): DerNode {
  if (offset + 2 > data.length) throw new Error("The signature block is truncated.");
  const tag = data[offset] ?? 0;
  let length = data[offset + 1] ?? 0;
  let header = 2;
  if ((length & 0x80) !== 0) {
    const count = length & 0x7f;
    if (count === 0 || offset + 2 + count > data.length) throw new Error("The signature block has an invalid ASN.1 length.");
    length = 0;
    for (let index = 0; index < count; index++) length = (length * 256) + (data[offset + 2 + index] ?? 0);
    header = 2 + count;
  }
  const start = offset + header;
  const end = start + length;
  if (end > data.length) throw new Error("An ASN.1 value runs past the end of the signature block.");
  return { tag, start, end, offset, constructed: (tag & 0x20) !== 0 };
}

function readChildren(data: Uint8Array, node: DerNode): DerNode[] {
  if (!node.constructed) return [];
  const children: DerNode[] = [];
  let cursor = node.start;
  while (cursor < node.end) {
    const child = readNode(data, cursor);
    if (child.end <= cursor) break;
    children.push(child);
    cursor = child.end;
  }
  return children;
}

function decodeOid(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  const first = bytes[0] ?? 0;
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let index = 1; index < bytes.length; index++) {
    const byte = bytes[index] ?? 0;
    value = (value * 128) + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

function oidName(oid: string): string {
  return OIDS[oid] ?? oid;
}

function algorithmName(data: Uint8Array, node: DerNode): string {
  const oid = readChildren(data, node).find((child) => child.tag === 0x06);
  return oid ? oidName(decodeOid(data.subarray(oid.start, oid.end))) : "unknown";
}

function readSigner(data: Uint8Array, node: DerNode): SignerInfo {
  const children = readChildren(data, node);
  const version = children[0]?.tag === 0x02 ? readInteger(data, children[0]) : 0;
  let cursor = 2;
  const digestNode = children[cursor];
  const digestAlgorithm = digestNode ? algorithmName(data, digestNode) : "unknown";
  cursor += 1;
  const attributes: JarAttribute[] = [];
  if (children[cursor]?.tag === 0xa0) {
    attributes.push(...readAttributes(data, children[cursor]!));
    cursor += 1;
  }
  const signatureAlgorithm = children[cursor] ? algorithmName(data, children[cursor]!) : "unknown";
  cursor += 1;
  const signature = children[cursor];
  return {
    version,
    digestAlgorithm,
    signatureAlgorithm,
    signatureBytes: signature ? signature.end - signature.start : 0,
    attributes,
  };
}

function readAttributes(data: Uint8Array, node: DerNode): JarAttribute[] {
  const attributes: JarAttribute[] = [];
  for (const attribute of readChildren(data, node)) {
    const parts = readChildren(data, attribute);
    const oidNode = parts.find((part) => part.tag === 0x06);
    const values = parts.find((part) => part.tag === 0x31);
    const name = oidNode ? oidName(decodeOid(data.subarray(oidNode.start, oidNode.end))) : "attribute";
    const valueNode = values ? readChildren(data, values)[0] : undefined;
    attributes.push({ key: name, value: valueNode ? formatValue(data, valueNode) : "" });
  }
  return attributes;
}

function formatValue(data: Uint8Array, node: DerNode): string {
  const bytes = data.subarray(node.start, node.end);
  if (node.tag === 0x06) return oidName(decodeOid(bytes));
  if (node.tag === 0x17 || node.tag === 0x18 || node.tag === 0x13 || node.tag === 0x0c) return ascii(bytes);
  if (node.tag === 0x04) return bytesToHex(bytes);
  if (node.tag === 0x02) return readInteger(data, node).toString();
  return bytesToHex(bytes);
}

function readInteger(data: Uint8Array, node: DerNode): number {
  let value = 0;
  for (let index = node.start; index < node.end; index++) value = (value * 256) + (data[index] ?? 0);
  return value;
}

function collectCertificates(data: Uint8Array): SignerCertificate[] {
  const found: SignerCertificate[] = [];
  const seen = new Set<string>();
  const visit = (offset: number): void => {
    if (offset >= data.length) return;
    const node = readNode(data, offset);
    if (node.tag === 0x30 && node.end - node.offset > 64) {
      try {
        const certificate = new X509Certificate(Buffer.from(data.subarray(node.offset, node.end)));
        if (!seen.has(certificate.fingerprint256)) {
          seen.add(certificate.fingerprint256);
          found.push(describeCertificate(certificate));
        }
      } catch {
        // Nested sequences that are not certificates are ignored.
      }
    }
    if (node.constructed) {
      let cursor = node.start;
      while (cursor < node.end) {
        const child = readNode(data, cursor);
        if (child.end <= cursor) break;
        visit(child.offset);
        cursor = child.end;
      }
    }
  };
  visit(0);
  return found;
}

function describeKey(certificate: X509Certificate): string {
  const key = certificate.publicKey;
  const kind = (key.asymmetricKeyType ?? "unknown").toUpperCase();
  const details = key.asymmetricKeyDetails as { modulusLength?: number; namedCurve?: string } | undefined;
  const extra = details?.modulusLength ? `${details.modulusLength}-bit` : details?.namedCurve ?? "";
  return [kind, extra].filter(Boolean).join(" ");
}

function describeCertificate(certificate: X509Certificate): SignerCertificate {
  let selfSigned = certificate.subject === certificate.issuer;
  try {
    selfSigned = certificate.checkIssued(certificate);
  } catch {
    // Some certificates cannot be checked against themselves.
  }
  return {
    subject: certificate.subject,
    issuer: certificate.issuer,
    serial: certificate.serialNumber,
    validFrom: certificate.validFrom,
    validTo: certificate.validTo,
    fingerprint256: certificate.fingerprint256,
    fingerprint: certificate.fingerprint,
    publicKey: describeKey(certificate),
    selfSigned,
  };
}

function ascii(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
