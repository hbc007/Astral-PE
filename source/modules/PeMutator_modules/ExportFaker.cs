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
        /// If the PE file has no export directory, this method fakes the export directory
        /// by setting the export RVA to the first section's virtual address and setting a fake size.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator (not used in this method).</param>
        /// <summary>
        /// If the PE file has no export directory, this method fakes the export directory
        /// by setting the export RVA to the first section's virtual address and setting a fake size.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator (used for randomized offset).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // If the PE file already has exports, no need to fake them
            if (pe.ExportedFunctions != null)
                return;

            // Get the first section header to use its Virtual Address and RawData
            ImageSectionHeader? firstSection = pe.ImageSectionHeaders.FirstOrDefault();

            if (firstSection == null)
                throw new Exception("No section headers found. Cannot fake export directory.");

            // Calculate max range for randomized export offset inside the first section
            int maxOffsetInSection = (int)Math.Min(firstSection.VirtualSize, firstSection.SizeOfRawData),
                availableRoom = maxOffsetInSection - 0x28; // minimum size for IMAGE_EXPORT_DIRECTORY

            if (availableRoom < 0x10)
                throw new Exception("First section too small to embed export directory safely.");

            List<ImageSectionHeader>? candidates = pe.ImageSectionHeaders
                .Where(s => s.SizeOfRawData > 0x100 && s.VirtualSize > 0x40)
                .ToList();

            if (candidates.Count == 0)
                throw new Exception("No section large enough to embed export directory.");

            ImageSectionHeader? chosenSection = candidates[rnd.Next(candidates.Count)];

            // Pick a random offset from the start of section
            int offsetInSection = rnd.Next(0x10, (int)Math.Min(chosenSection.VirtualSize, chosenSection.SizeOfRawData) - 0x28);

            uint fakeExportRVA = firstSection.VirtualAddress + (uint)offsetInSection;

            // Calculate the offset for the export directory in the Optional Header
            int exportDirOffset = optStart + 0x60 + 0 * 8;

            // Write the fake export RVA and size (0x28) to the raw bytes at the export directory offset
            BitConverter.GetBytes(fakeExportRVA).CopyTo(raw, exportDirOffset);     // Fake RVA
            BitConverter.GetBytes(0x28u).CopyTo(raw, exportDirOffset + 4);         // Fake size
        }
    }
}
