<img src="pics/title.png" style="align: center;">
<!-- <h1 align="center"></h1> -->
<p align="center"><b>Post-protection structural mutator for x86/x64 PE files</b></p>
<p align="center">Surgical header mutation for hardened binaries — bypass unpackers, break signatures, preserve execution</p>

---

Astral-PE is a **low-level mutator** for Windows PE files (`.exe`, `.dll`) that rewrites structural metadata after protection — **without breaking execution**.

It **does not pack, encrypt or inject**. Instead, it mutates low-hanging but critical structures like timestamps, headers, section flags, debug info, import/export names, and more.

> [!NOTE]
> Can be used **after** packers/protectors like VMProtect, Themida, Enigma, UPX, etc.

## 🔧 In what cases is it useful?

You’ve protected a binary — but public unpackers or YARA rules still target its **unchanged structure**.

> ### Use Astral-PE as a **post-processing step** to:
> - Prevent automated unpacking
> - Break static unpacker logic
> - Invalidate reverse-engineering signatures
> - Disrupt clustering in sandboxes
> - Strip metadata, overlays, debug traces

> ### **Perfect for:**
> - Old protector builds (e.g. legacy Enigma)
> - Repacked or cracked stubs
> - VMP-ed samples with reused headers
> - Hardened loaders that remain structurally default

## ✨ What it modifies

Astral-PE applies precise, compliant, and execution-safe mutations:

| Target                  | Description                                                |
|-------------------------|------------------------------------------------------------|
| 🕓 Timestamp            | Clears `TimeDateStamp` in file headers                    |
| 🧠 Rich Header          | Fully removed — breaks toolchain fingerprinting           |
| 📜 Section Names        | Wiped (`.text`, `.rsrc`, etc. → null)                     |
| 📎 Checksum              | Reset to zero                                             |
| 📦 Overlay              | Stripped if signed junk detected                          |
| 🧵 TLS Directory        | Removed if unused                                         |
| ⚙ Load Config           | Deleted (if CFG not present)                              |
| 🧬 Relocations          | `.reloc` section removed if not required                  |
| 📋 Version Info         | Erased from optional header                               |
| 📁 Original Filename    | Located and zeroed in binary tail                         |
| 🔎 Debug Info           | PDB paths wiped, Debug Directory erased                   |
| 🚀 Entry Point Patch    | Replaces or shuffles PUSH/PROLOGUE bytes (e.g. UPX64)     |
| 🧪 Import Table         | DLL names mutated: case, prefix, randomized formatting    |
| 🏷 Export Table          | Faked if absent (baits certain scanners)                  |
| 📚 Data Directory       | All unused entries cleaned                                |
| 💾 Permissions          | R/W/X + code flags applied to all sections                |
| 📄 DOS Stub             | Reset to clean "MZ", patched `e_lfanew`                   |

📝 **Does not support .NET binaries**. Native PE only.

## 🚀 Usage

```cmd
AstralPE.exe <input.exe> -o <output.exe>
```

- `-o`, `--output` — output file name (optional)
- Default output: `<input>_ast.exe`
- No args? Shows help


## 🧪 Example

```cmds
AstralPE.exe payload.exe -o payload_clean.exe
```

## 📎 Combination with other protections

Use Astral-PE **after** applying protectors.  
Chain it into your CI, cryptor, or loader pipeline:

```
Build → Any packer → AstralPE → Sign / Pack → Distribute
```

## 🔬 What it’s not

- Not a cryptor
- Not a stub injector
- Not a runtime packer
- Not a code obfuscator (this is a advanced PE-headers obfuscator)

It’s a **surgical metadata cleaner** and **headers mutator** for post-processing protected binaries.