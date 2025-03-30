/*
 * This file is part of the Astral-PE project.
 * Copyright (c) 2025 DosX. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Astral-PE is a low-level post-compilation PE header mutator (obfuscator) for native
 * Windows x86/x64 binaries. It modifies structural metadata while preserving execution integrity.
 *
 * For source code, updates, and documentation, visit:
 * https://github.com/DosX-dev/Astral-PE
 */

using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class EntryPointPatcher : IAstralPeModule {

        /// <summary>
        /// Patches the entry point in the PE file.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator to shuffle bytes (used in the second patch).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Ensure the PE file is valid
            if (pe.ImageNtHeaders == null || pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            uint epRva = pe.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint,
                 epOffset = epRva.RvaToOffset(pe.ImageSectionHeaders);

            if (epOffset >= raw.Length)
                throw new Exception("EntryPoint offset is out of file bounds.");

            List<byte> instructions = pe.Is64Bit ? new List<byte> {
                // PUSH rAX–rDI (0x50–0x57), without 0x54 (PUSH rSP)
                0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,

                // Other x64-safe instructions
                0x90, // NOP
                0xF8, // CLC
                0xF9, // STC
                0xFC, // CLD
                0xF3, // REP
                0xF2, // REPNE
                0x64, // FS override
                0x65  // GS override
            } : new List<byte> {
                // PUSH rAX–rDI (0x50–0x57), without 0x54 (PUSH rSP)
                0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,

                // INC rAX–rDI (0x40–0x47), without 0x44 (INC rSP)
                0x40, 0x41, 0x42, 0x43, 0x45, 0x46, 0x47,

                // DEC rAX–rDI (0x48–0x4F), without 0x4C (DEC rSP)
                0x48, 0x49, 0x4A, 0x4B, 0x4D, 0x4E, 0x4F,

                // Legacy single-byte x86 instructions
                0x90, // NOP
                0xF8, // CLC
                0xF9, // STC
                0xFC, // CLD
                0x27, // DAA
                0x2F, // DAS
                0x3F, // AAS
                0x61, // POPAD
                0x9C, // PUSHFD
                0xF3, // REP
                0xF2, // REPNE
                0x2E, // CS
                0x36, // SS
                0x3E, // DS
                0x26, // ES
                0x64, // FS
                0x65  // GS
            };

            // Randomly patch or remove 0x60 (PUSHAD/PUSHAL)
            if (raw[epOffset] == 0x60) {
                if (rnd.Next(2) == 0) { // Remove
                    raw[epOffset] = 0xCC;
                    epOffset++;
                } else { // Patch
                    raw[epOffset] = instructions[rnd.Next(instructions.Count)];
                }
            }

            // Shuffle PUSH instructions in UPX64 signature
            if (epOffset + 4 < raw.Length &&
                raw[epOffset + 0] == 0x53 && raw[epOffset + 1] == 0x56 &&
                raw[epOffset + 2] == 0x57 && raw[epOffset + 3] == 0x55) {

                byte[] pushes = { 0x53, 0x56,
                                  0x57, 0x55 };

                for (int i = pushes.Length - 1; i > 0; i--) {
                    int j = rnd.Next(i + 1);
                    (pushes[i], pushes[j]) = (pushes[j], pushes[i]);
                }

                for (int i = 0; i < pushes.Length; i++)
                    raw[epOffset + i] = pushes[i];
            }

            bool isVcStyle = false,
                 isMinGwStyle = false;

            // VC++ or MinGW EP stack alignment mutation + NOP/trap sequence replacement
            if (pe.Is64Bit && epOffset + 32 < raw.Length) {
                // Check if entry point starts with VC++-style prologue:
                // sub rsp, imm8; call; add rsp, imm8
                isVcStyle =
                    raw[epOffset + 0] == 0x48 && raw[epOffset + 1] == 0x83 && raw[epOffset + 2] == 0xEC &&
                    raw[epOffset + 4] == 0xE8 &&
                    raw[epOffset + 9] == 0x48 && raw[epOffset + 10] == 0x83 && raw[epOffset + 11] == 0xC4;

                // Check if entry point starts with MinGW-style prologue:
                // sub rsp, imm8; mov rax, [rip+...]
                isMinGwStyle =
                    raw[epOffset + 0] == 0x48 && raw[epOffset + 1] == 0x83 && raw[epOffset + 2] == 0xEC &&
                    raw[epOffset + 4] == 0x48 && raw[epOffset + 5] == 0x8B && raw[epOffset + 6] == 0x05;

                // Proceed only if one of the patterns matched
                if (isVcStyle || isMinGwStyle) {
                    // // Nop mutation for MinGW
                    if (isMinGwStyle) {
                        for (uint i = epOffset + 12; i < epOffset + 32 && i + 2 < raw.Length; i++) {
                            if (raw[i] == 0x90 && raw[i + 1] == 0x90 && raw[i + 2] == 0x90) {
                                int variant = rnd.Next(4);

                                switch (variant) {
                                    case 0: raw[i] = 0x0F; raw[i + 1] = 0x1F; raw[i + 2] = 0x00; break;
                                    case 1: raw[i] = 0x66; raw[i + 1] = 0x90; raw[i + 2] = 0x90; break;
                                    case 2: raw[i] = 0x90; raw[i + 1] = 0x66; raw[i + 2] = 0x90; break;
                                    case 3: break; // leave 90 90 90 as-is
                                }

                                break;
                            }
                        }
                    }

                    // Dead bytes garbage after JMP for VC++
                    if (isVcStyle &&
                        raw[epOffset + 13] == 0xE9 && // jmp
                        raw[epOffset + 18] == 0xCC && raw[epOffset + 19] == 0xCC) { // 2x int3
                        Span<byte> garbage = stackalloc byte[2];
                        rnd.NextBytes(garbage);

                        raw[epOffset + 18] = garbage[0]; // first int3
                        raw[epOffset + 19] = garbage[1]; // second int3
                    }
                }
            }

            // 1. If free space is available, inject a short obfuscation sequence
            // 2. If not -> slide over known NOP sleds
            // 3. If not -> mutate entrypoint stack alignment

            // EntryPoint shift mutation w/ multi-level obfuscation (5/2/1-byte options)
            if (epOffset >= 1) {
                int space = 0;

                if (epOffset >= 1 &&
                    (raw[epOffset - 5] != 0xE9)) { // Skip Microsoft VC++ 19.35.32217 debug builds by checking for CALL opcode
                    byte fill = raw[epOffset - 1];

                    if (fill == 0x00 || fill == 0x90 || fill == 0xCC) {
                        for (int i = 1; i <= Math.Min(5, epOffset); i++) {
                            if (raw[epOffset - i] == fill)
                                space++;
                            else
                                break;
                        }
                    }
                }

                if (space >= 5) {
                    // Inject xor REG, REG + jz + trap byte
                    List<byte> regVariants = new() {
                        0xC0, // rAX
                        0xC9, // rCX
                        0xD2, // rDX
                        0xDB, // rBX
                        0xED, // rBP
                        0xF6, // rSI
                        0xFF  // rDI
                    };
                    byte reg = regVariants[rnd.Next(regVariants.Count)];

                    raw[epOffset - 5] = 0x31; // xor
                    raw[epOffset - 4] = reg;  // reg/reg
                    raw[epOffset - 3] = 0x74; // jz short
                    raw[epOffset - 2] = 0x01; // +1 offset
                    raw[epOffset - 1] = (byte)rnd.Next(0x00, 0xFF); // junk/trap

                    epOffset -= 5;
                } else if (space >= 3) {
                    // Inject universal 2-byte garbage op
                    List<byte[]> epGarbage = new() {
                        new byte[] { 0x0F, 0xA2 }, // cpuid
                        new byte[] { 0x0F, 0x31 }, // rdtsc
                        new byte[] { 0x66, 0x90 }, // nop (xchg ax, ax)
                        new byte[] { 0x84, 0xC0 }, // test al, al
                        new byte[] { 0x85, 0xC0 }, // test eax, eax
                        new byte[] { 0x09, 0xC0 }, // or eax, eax
                        new byte[] { 0x33, 0xC0 }, // xor eax, eax
                        new byte[] { 0x33, 0xC9 }, // xor ecx, ecx
                        new byte[] { 0x33, 0xD2 }, // xor edx, edx
                        new byte[] { 0x33, 0xDB }, // xor ebx, ebx
                        new byte[] { 0x33, 0xF6 }, // xor esi, esi
                        new byte[] { 0x33, 0xFF }, // xor edi, edi
                        new byte[] { 0xFC, 0x90 }, // cld; nop
                        new byte[] { 0xF8, 0x90 }, // clc; nop
                        new byte[] { 0xF9, 0x90 }, // stc; nop
                    };

                    byte[] instr = epGarbage[rnd.Next(epGarbage.Count)];
                    raw[epOffset - 2] = instr[0];
                    raw[epOffset - 1] = instr[1];
                    epOffset -= 2;
                } else if (space >= 2 || // If free space is 2 bytes, inject 1-byte NOP
                          (raw[epOffset - 6] == 0xE8) && raw[epOffset - 1] == 0xCC) { // Microsoft VC++ 19.36.33523, 32-bit support; CALL + 0xCC, we can change last byte

                    raw[epOffset - 1] = 0x90;
                    epOffset -= 1;
                } else { // If no free space

                    // Try to slide EntryPoint back over multiple consecutive NOP sleds
                    byte[][] knownNops = new byte[][] {
                        new byte[] { 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 }, // 9-byte
                        new byte[] { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 },       // 8-byte
                        new byte[] { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 },             // 7-byte
                        new byte[] { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 },                   // 6-byte
                        new byte[] { 0x0F, 0x1F, 0x44, 0x00, 0x00 },                         // 5-byte
                        new byte[] { 0x0F, 0x1F, 0x40, 0x00 },                               // 4-byte
                        new byte[] { 0x0F, 0x1F, 0x00 },                                     // 3-byte
                        new byte[] { 0x66, 0x90 },                                           // 2-byte
                        new byte[] { 0x90 }                                                  // 1-byte
                    };

                    bool shifted = false;
                    bool foundAny;

                    do {
                        foundAny = false;

                        foreach (var nop in knownNops) {
                            int len = nop.Length;
                            if (epOffset >= len) {
                                bool match = true;
                                for (int i = 0; i < len; i++) {
                                    if (raw[epOffset - len + i] != nop[i]) {
                                        match = false;
                                        break;
                                    }
                                }

                                if (match) {
                                    epOffset -= (uint)len;
                                    foundAny = true;
                                    shifted = true;
                                    break; // start again from new offset
                                }
                            }
                        }

                    } while (foundAny);


                    // If not slid over NOPs, try mutating entrypoint stack alignment
                    if (!shifted && (isMinGwStyle || isVcStyle)) {
                        byte originalStackVal = raw[epOffset + 3];
                        List<byte> stackVariants = new() { 0x38, 0x48, 0x58 };
                        stackVariants.Remove(originalStackVal);
                        byte newStackVal = stackVariants[rnd.Next(stackVariants.Count)];

                        raw[epOffset + 3] = newStackVal;

                        if (isVcStyle) {
                            raw[epOffset + 12] = newStackVal;
                        } else if (isMinGwStyle) {
                            for (uint i = epOffset + 7; i < epOffset + 32 && i + 4 < raw.Length; i++) {
                                if (raw[i] == 0x48 && raw[i + 1] == 0x83 && raw[i + 2] == 0xC4 &&
                                    raw[i + 3] == originalStackVal && raw[i + 4] == 0xC3) {
                                    raw[i + 3] = newStackVal;
                                    break;
                                }
                            }
                        }
                    }
                }

                uint newEpRva = epOffset.OffsetToRva(pe.ImageSectionHeaders);
                pe.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint = newEpRva;
                BitConverter.GetBytes(newEpRva).CopyTo(raw, optStart + 0x10);
            }
        }
    }
}
