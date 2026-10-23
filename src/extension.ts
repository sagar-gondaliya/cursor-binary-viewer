import * as vscode from "vscode";
import { parseDex, type DexFile } from "./parse/dex";
import { parseElf, type ElfFile } from "./parse/elf";
import { hexPreview } from "./parse/hex";
import { parseJarManifest, parseSignatureBlock, type JarManifest } from "./parse/jarSign";
import { parseRiv } from "./parse/riv";

interface Session {
  kind: "dex" | "elf" | "jar" | "pkcs" | "riv";
  dex?: DexFile;
  elf?: ElfFile;
  manifest?: JarManifest;
}

export function activate(context: vscode.ExtensionContext): void {
  const mediaRoot = vscode.Uri.joinPath(context.extensionUri, "media");
  const sessions = new Map<string, Session>();
  const provider = new BinaryEditorProvider(mediaRoot, sessions);
  for (const viewType of [
    "cursorBinaryViewer.dex",
    "cursorBinaryViewer.elf",
    "cursorBinaryViewer.rive",
    "cursorBinaryViewer.mf",
    "cursorBinaryViewer.sf",
    "cursorBinaryViewer.rsa",
    "cursorBinaryViewer.dsa",
  ]) {
    context.subscriptions.push(vscode.window.registerCustomEditorProvider(viewType, provider, {
      webviewOptions: { retainContextWhenHidden: false },
      supportsMultipleEditorsPerDocument: false,
    }));
  }
}

export function deactivate(): void {}

class BinaryDocument implements vscode.CustomDocument {
  constructor(readonly uri: vscode.Uri) {}
  dispose(): void {}
}

class BinaryEditorProvider implements vscode.CustomReadonlyEditorProvider<BinaryDocument> {
  constructor(
    private readonly mediaRoot: vscode.Uri,
    private readonly sessions: Map<string, Session>,
  ) {}

  openCustomDocument(uri: vscode.Uri): BinaryDocument {
    return new BinaryDocument(uri);
  }

  async resolveCustomEditor(document: BinaryDocument, panel: vscode.WebviewPanel): Promise<void> {
    const webview = panel.webview;
    webview.options = { enableScripts: true, localResourceRoots: [this.mediaRoot] };
    const nonce = Math.random().toString(16).slice(2);
    const script = webview.asWebviewUri(vscode.Uri.joinPath(this.mediaRoot, "viewer.js"));
    const style = webview.asWebviewUri(vscode.Uri.joinPath(this.mediaRoot, "viewer.css"));
    const riveUrl = webview.asWebviewUri(vscode.Uri.joinPath(this.mediaRoot, "rive.js"));
    const wasmUrl = webview.asWebviewUri(vscode.Uri.joinPath(this.mediaRoot, "rive.wasm"));
    const key = document.uri.toString();
    let ready = false;
    const history: unknown[] = [];
    const send = (message: unknown): void => {
      history.push(message);
      if (ready) void webview.postMessage(message);
    };

    webview.onDidReceiveMessage(async (message: { cmd?: string; index?: number; method?: number; query?: string }) => {
      if (message.cmd === "ready") {
        ready = true;
        for (const item of history) await webview.postMessage(item);
        return;
      }
      const session = this.sessions.get(key);
      if (!session) return;
      try {
        if (message.cmd === "dexList" && session.dex) {
          send(pageClasses(session.dex, message.query ?? ""));
        } else if (message.cmd === "dexClass" && session.dex && typeof message.index === "number") {
          send({ cmd: "dexClass", detail: session.dex.classDetail(message.index) });
        } else if (message.cmd === "dexMethod" && session.dex && typeof message.index === "number" && typeof message.method === "number") {
          send({ cmd: "dexMethod", code: session.dex.methodCode(message.index, message.method) });
        } else if (message.cmd === "dexStrings" && session.dex) {
          send({ cmd: "dexStrings", strings: session.dex.searchStrings(message.query ?? "", 200) });
        } else if (message.cmd === "elfFilter" && session.elf) {
          const query = (message.query ?? "").toLowerCase();
          const symbols = session.elf.symbols.filter((symbol) => symbol.name.toLowerCase().includes(query)).slice(0, 300);
          send({ cmd: "elfSymbols", symbols, total: session.elf.symbols.length, shown: symbols.length });
        } else if (message.cmd === "jarList" && session.manifest) {
          send(pageEntries(session.manifest, message.query ?? ""));
        }
      } catch (error) {
        send({ cmd: "error", message: error instanceof Error ? error.message : String(error) });
      }
    });

    webview.html = html(webview.cspSource, nonce, script, style, document.uri.path.split("/").pop() ?? "file");

    try {
      const started = Date.now();
      const bytes = await vscode.workspace.fs.readFile(document.uri);
      const name = document.uri.path.split("/").pop() ?? document.uri.path;
      const view = panel.viewType;
      if (view.endsWith(".dex")) {
        const dex = parseDex(bytes);
        this.sessions.set(key, { kind: "dex", dex });
        send({
          cmd: "dex",
          name,
          elapsedMs: Date.now() - started,
          header: dex.header,
          hex: hexPreview(bytes),
        });
        send(pageClasses(dex, ""));
      } else if (view.endsWith(".elf")) {
        const elf = parseElf(bytes);
        this.sessions.set(key, { kind: "elf", elf });
        send({
          cmd: "elf",
          name,
          elapsedMs: Date.now() - started,
          file: {
            summary: elf.summary,
            needed: elf.needed,
            sections: elf.sections,
            programHeaders: elf.programHeaders,
            strings: elf.strings.slice(0, 400),
            notes: elf.notes,
          },
          hex: hexPreview(bytes),
        });
        const symbols = elf.symbols.slice(0, 300);
        send({ cmd: "elfSymbols", symbols, total: elf.symbols.length, shown: symbols.length });
      } else if (view.endsWith(".mf") || view.endsWith(".sf")) {
        const manifest = parseJarManifest(bytes, view.endsWith(".mf") ? "mf" : "sf");
        this.sessions.set(key, { kind: "jar", manifest });
        send({
          cmd: "jar",
          name,
          elapsedMs: Date.now() - started,
          manifest: { label: manifest.label, main: manifest.main, entryCount: manifest.entries.length },
          hex: hexPreview(bytes),
        });
        send(pageEntries(manifest, ""));
      } else if (view.endsWith(".rsa") || view.endsWith(".dsa")) {
        const block = parseSignatureBlock(bytes, view.endsWith(".rsa") ? "rsa" : "dsa");
        this.sessions.set(key, { kind: "pkcs" });
        send({
          cmd: "pkcs",
          name,
          elapsedMs: Date.now() - started,
          block,
          hex: hexPreview(bytes),
        });
      } else {
        const info = parseRiv(bytes);
        this.sessions.set(key, { kind: "riv" });
        const limit = 2 * 1024 * 1024;
        send({
          cmd: "riv",
          name,
          elapsedMs: Date.now() - started,
          info,
          hex: hexPreview(bytes),
          riveUrl: String(riveUrl),
          wasmUrl: String(wasmUrl),
          bytes: bytes.byteLength <= limit ? Buffer.from(bytes).toString("base64") : "",
          truncated: bytes.byteLength > limit,
        });
      }
    } catch (error) {
      send({ cmd: "error", message: error instanceof Error ? error.message : String(error) });
    }

    panel.onDidDispose(() => this.sessions.delete(key));
  }
}

function pageClasses(dex: DexFile, query: string): { cmd: "dexList"; classes: DexFile["classes"]; shown: number; total: number } {
  const needle = query.trim().toLowerCase();
  const matches = needle
    ? dex.classes.filter((item) => item.name.toLowerCase().includes(needle) || item.jniName.toLowerCase().includes(needle))
    : dex.classes;
  const classes = matches.slice(0, 200);
  return { cmd: "dexList", classes, shown: classes.length, total: matches.length };
}

function pageEntries(manifest: JarManifest, query: string): { cmd: "jarList"; entries: JarManifest["entries"]; shown: number; total: number } {
  const needle = query.trim().toLowerCase();
  const matches = needle ? manifest.entries.filter((entry) => entry.name.toLowerCase().includes(needle)) : manifest.entries;
  const entries = matches.slice(0, 200);
  return { cmd: "jarList", entries, shown: entries.length, total: matches.length };
}

function html(csp: string, nonce: string, script: vscode.Uri, style: vscode.Uri, title: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${csp} 'unsafe-inline'; script-src 'nonce-${nonce}' ${csp} 'wasm-unsafe-eval'; connect-src ${csp};">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="${style}">
<title>${escapeHtml(title)}</title>
</head>
<body>
<div id="app"><p class="muted">Reading ${escapeHtml(title)}…</p></div>
<script nonce="${nonce}" src="${script}"></script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char] ?? char));
}
