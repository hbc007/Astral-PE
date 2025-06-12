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
using PeNet.Header.Pe;

namespace AstralPE.Obfuscator.Modules {
    public class ExportFaker : IAstralPeModule {

        /// <summary>
        /// If the PE file has no export directory, this method creates a minimal valid export directory
        /// that is compatible with Windows XP by writing actual export table structures.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator.</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Ensure section headers are present
            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // If the PE file already has exports, no need to fake them
            if (pe.ExportedFunctions != null)
                return;

            // Find a suitable section to place the fake export table (preferably .rdata or last section)
            ImageSectionHeader? targetSection = FindSuitableSection(pe);
            if (targetSection == null)
                throw new Exception("No suitable section found for fake export directory.");

            // Calculate where to place the fake export table
            uint exportTableRVA = CalculateExportTableRVA(targetSection);
            uint exportTableFileOffset = RVAToFileOffset(exportTableRVA, pe);

            // Ensure we have enough space in the raw byte array
            if (exportTableFileOffset + 0x28 > raw.Length) {
                // Extend the raw array if necessary
                Array.Resize(ref raw, (int)(exportTableFileOffset + 0x28));
            }

            // Create a minimal valid export directory table
            CreateMinimalExportTable(raw, exportTableFileOffset, exportTableRVA, pe);

            // Update the Optional Header to point to our fake export directory
            UpdateOptionalHeader(raw, optStart, exportTableRVA);
        }

        /// <summary>
        /// Finds a suitable section to place the export table.
        /// Prefers .rdata section, falls back to the last section with enough space.
        /// </summary>
        private ImageSectionHeader? FindSuitableSection(PeFile pe) {
            // Try to find .rdata section first
            var rdataSection = pe.ImageSectionHeaders?.FirstOrDefault(s => 
                s.Name?.Trim('\0').Equals(".rdata", StringComparison.OrdinalIgnoreCase) == true);
            
            if (rdataSection != null && HasEnoughSpace(rdataSection))
                return rdataSection;

            // Fall back to the last section if it has enough space
            var lastSection = pe.ImageSectionHeaders?.LastOrDefault();
            if (lastSection != null && HasEnoughSpace(lastSection))
                return lastSection;

            // If no section has enough space, use the first available section
            return pe.ImageSectionHeaders?.FirstOrDefault();
        }

        /// <summary>
        /// Checks if a section has enough space for the export table.
        /// </summary>
        private bool HasEnoughSpace(ImageSectionHeader section) {
            // We need at least 0x28 bytes for the minimal export table
            return section.SizeOfRawData >= 0x28;
        }

        /// <summary>
        /// Calculates the RVA where the export table should be placed.
        /// </summary>
        private uint CalculateExportTableRVA(ImageSectionHeader section) {
            // Place it at the end of the section's used space, aligned to 4 bytes
            uint baseRVA = section.VirtualAddress;
            uint usedSize = Math.Min(section.VirtualSize, section.SizeOfRawData);
            
            // Align to 4-byte boundary
            if (usedSize > 0x28) {
                uint alignedOffset = (usedSize - 0x28) & 0xFFFFFFFC;
                return baseRVA + alignedOffset;
            }
            
            return baseRVA;
        }

        /// <summary>
        /// Converts RVA to file offset.
        /// </summary>
        private uint RVAToFileOffset(uint rva, PeFile pe) {
            foreach (var section in pe.ImageSectionHeaders!) {
                uint sectionStart = section.VirtualAddress;
                uint sectionEnd = sectionStart + Math.Max(section.VirtualSize, section.SizeOfRawData);
                
                if (rva >= sectionStart && rva < sectionEnd) {
                    uint offsetInSection = rva - sectionStart;
                    return section.PointerToRawData + offsetInSection;
                }
            }
            
            throw new Exception($"Could not convert RVA 0x{rva:X8} to file offset.");
        }

        /// <summary>
        /// Creates a minimal but valid export directory table.
        /// </summary>
        private void CreateMinimalExportTable(byte[] raw, uint fileOffset, uint rva, PeFile pe) {
            // Clear the area first
            Array.Clear(raw, (int)fileOffset, 0x28);

            // IMAGE_EXPORT_DIRECTORY structure (40 bytes)
            int offset = (int)fileOffset;

            // Export Flags (4 bytes) - set to 0
            BitConverter.GetBytes(0u).CopyTo(raw, offset);
            offset += 4;

            // TimeDateStamp (4 bytes) - use current timestamp or 0
            BitConverter.GetBytes(0u).CopyTo(raw, offset);
            offset += 4;

            // MajorVersion (2 bytes) - set to 0
            BitConverter.GetBytes((ushort)0).CopyTo(raw, offset);
            offset += 2;

            // MinorVersion (2 bytes) - set to 0
            BitConverter.GetBytes((ushort)0).CopyTo(raw, offset);
            offset += 2;

            // Name RVA (4 bytes) - set to 0 (no name)
            BitConverter.GetBytes(0u).CopyTo(raw, offset);
            offset += 4;

            // Ordinal Base (4 bytes) - set to 1
            BitConverter.GetBytes(1u).CopyTo(raw, offset);
            offset += 4;

            // Number of Functions (4 bytes) - set to 0
            BitConverter.GetBytes(0u).CopyTo(raw, offset);
            offset += 4;

            // Number of Names (4 bytes) - set to 0
            BitConverter.GetBytes(0u).CopyTo(raw, offset);
            offset += 4;

            // Address of Functions (4 bytes) - set to 0
            BitConverter.GetBytes(0u).CopyTo(raw, offset);
            offset += 4;

            // Address of Names (4 bytes) - set to 0
            BitConverter.GetBytes(0u).CopyTo(raw, offset);
            offset += 4;

            // Address of Name Ordinals (4 bytes) - set to 0
            BitConverter.GetBytes(0u).CopyTo(raw, offset);
        }

        /// <summary>
        /// Updates the Optional Header to point to the fake export directory.
        /// </summary>
        private void UpdateOptionalHeader(byte[] raw, int optStart, uint exportTableRVA) {
            // Calculate the offset for the export directory in the Optional Header
            int exportDirOffset = optStart + 0x60 + 0 * 8;

            // Write the export RVA and size to the Optional Header
            BitConverter.GetBytes(exportTableRVA).CopyTo(raw, exportDirOffset);     // Export RVA
            BitConverter.GetBytes(0x28u).CopyTo(raw, exportDirOffset + 4);         // Export size (40 bytes)
        }
    }
}
