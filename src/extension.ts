import * as vscode from "vscode";
import { parseDex, type DexFile } from "./parse/dex";
import { parseElf, type ElfFile } from "./parse/elf";
import { hexPreview } from "./parse/hex";
import { parseJarManifest, parseSignatureBlock } from "./parse/jarSign";
import { parseRiv } from "./parse/riv";

interface Session {
  kind: "dex" | "elf" | "riv";
  dex?: DexFile;
  elf?: ElfFile;
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
      webviewOptions: { retainContextWhenHidden: true },
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
    const rive = webview.asWebviewUri(vscode.Uri.joinPath(this.mediaRoot, "rive.js"));
    const wasm = webview.asWebviewUri(vscode.Uri.joinPath(this.mediaRoot, "rive.wasm"));
    webview.html = html(webview.cspSource, nonce, script, style, rive, wasm, document.uri.path.split("/").pop() ?? "file");

    const key = document.uri.toString();
    webview.onDidReceiveMessage(async (message: { cmd?: string; index?: number; method?: number; query?: string }) => {
      const session = this.sessions.get(key);
      if (!session) return;
      try {
        if (message.cmd === "dexClass" && session.dex && typeof message.index === "number") {
          await webview.postMessage({ cmd: "dexClass", detail: session.dex.classDetail(message.index) });
        } else if (message.cmd === "dexMethod" && session.dex && typeof message.index === "number" && typeof message.method === "number") {
          await webview.postMessage({ cmd: "dexMethod", code: session.dex.methodCode(message.index, message.method) });
        } else if (message.cmd === "dexStrings" && session.dex) {
          await webview.postMessage({ cmd: "dexStrings", strings: session.dex.searchStrings(message.query ?? "", 200) });
        } else if (message.cmd === "elfFilter" && session.elf) {
          const query = (message.query ?? "").toLowerCase();
          const symbols = session.elf.symbols.filter((symbol) => symbol.name.toLowerCase().includes(query)).slice(0, 500);
          await webview.postMessage({ cmd: "elfSymbols", symbols, total: session.elf.symbols.length, shown: symbols.length });
        }
      } catch (error) {
        await webview.postMessage({ cmd: "error", message: error instanceof Error ? error.message : String(error) });
      }
    });

    try {
      const started = Date.now();
      const bytes = await vscode.workspace.fs.readFile(document.uri);
      const name = document.uri.path.split("/").pop() ?? document.uri.path;
      const view = panel.viewType;
      if (view.endsWith(".dex")) {
        const dex = parseDex(bytes);
        this.sessions.set(key, { kind: "dex", dex });
        await webview.postMessage({
          cmd: "dex",
          name,
          elapsedMs: Date.now() - started,
          header: dex.header,
          classes: dex.classes,
          hex: hexPreview(bytes),
        });
      } else if (view.endsWith(".elf")) {
        const elf = parseElf(bytes);
        this.sessions.set(key, { kind: "elf", elf });
        await webview.postMessage({
          cmd: "elf",
          name,
          elapsedMs: Date.now() - started,
          file: {
            summary: elf.summary,
            needed: elf.needed,
            sections: elf.sections,
            programHeaders: elf.programHeaders,
            strings: elf.strings,
            notes: elf.notes,
          },
          hex: hexPreview(bytes),
        });
        const symbols = elf.symbols.slice(0, 500);
        await webview.postMessage({ cmd: "elfSymbols", symbols, total: elf.symbols.length, shown: symbols.length });
      } else if (view.endsWith(".mf") || view.endsWith(".sf")) {
        const manifest = parseJarManifest(bytes, view.endsWith(".mf") ? "mf" : "sf");
        this.sessions.set(key, { kind: "riv" });
        await webview.postMessage({
          cmd: "jar",
          name,
          elapsedMs: Date.now() - started,
          manifest,
          hex: hexPreview(bytes),
        });
      } else if (view.endsWith(".rsa") || view.endsWith(".dsa")) {
        const block = parseSignatureBlock(bytes, view.endsWith(".rsa") ? "rsa" : "dsa");
        this.sessions.set(key, { kind: "riv" });
        await webview.postMessage({
          cmd: "pkcs",
          name,
          elapsedMs: Date.now() - started,
          block,
          hex: hexPreview(bytes),
        });
      } else {
        const info = parseRiv(bytes);
        this.sessions.set(key, { kind: "riv" });
        const limit = 20 * 1024 * 1024;
        await webview.postMessage({
          cmd: "riv",
          name,
          elapsedMs: Date.now() - started,
          info,
          hex: hexPreview(bytes),
          bytes: bytes.byteLength <= limit ? Buffer.from(bytes).toString("base64") : "",
          truncated: bytes.byteLength > limit,
        });
      }
    } catch (error) {
      await webview.postMessage({ cmd: "error", message: error instanceof Error ? error.message : String(error) });
    }

    panel.onDidDispose(() => this.sessions.delete(key));
  }
}

function html(csp: string, nonce: string, script: vscode.Uri, style: vscode.Uri, rive: vscode.Uri, wasm: vscode.Uri, title: string): string {
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
<script nonce="${nonce}" src="${rive}"></script>
<script nonce="${nonce}">window.__RIVE_WASM__ = ${JSON.stringify(String(wasm))};</script>
<script nonce="${nonce}" src="${script}"></script>
</body>
</html>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char] ?? char));
}
