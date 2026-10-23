# DEX, ELF, Rive, and APK Signature Viewer

Developer: **Sagar Gondaliya**

Custom editors for binary formats that otherwise open as raw text in Cursor and VS Code:

- `.dex` shows classes, fields, methods, the string pool, and Dalvik bytecode.
- `.so` shows the ELF header, segments, sections, dynamic libraries, symbols, and readable strings.
- `.riv` plays the animation with the Rive runtime and lists names stored in the file.
- `.mf` shows the JAR manifest main attributes and every entry digest.
- `.sf` shows the signature file, including the manifest digest.
- `.rsa` and `.dsa` show the PKCS #7 certificate, validity, fingerprints, and signer algorithms.

## Install

Download the `.vsix` from the [latest release](https://github.com/sagar-gondaliya/cursor-binary-viewer/releases/latest).

In Cursor or VS Code, open the Extensions view, choose **Install from VSIX…**, and select that file. Reopen a `.dex`, `.so`, `.riv`, `.mf`, `.sf`, `.rsa`, or `.dsa` file. The viewer is the default editor for those extensions.

## Develop

```bash
npm install
npm test
npm run compile
```

Open this folder and launch **Run Binary Viewer**.
