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
using System.Text;

namespace AstralPE.Obfuscator.Modules {
    public class DelphiLazarusMutator : IAstralPeModule {

        /// <summary>
        /// Applies Delphi/Lazarus meta data cleanup to the PE file.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE structure.</param>
        /// <param name="e_lfanew">The offset of the PE header.</param>
        /// <param name="optStart">The start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">The offset of the section table.</param>
        /// <param name="rnd">Random number generator instance.</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Ensure the section headers are present
            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // Check for the presence of .bss or .CRT sections
            bool markersFound = false;
            for (int i = 0; i < pe.ImageSectionHeaders.Length; i++) {
                string name = pe.ImageSectionHeaders[i].Name;
                if (name == ".bss" || name == ".CRT") {
                    markersFound = true;
                    break;
                }
            }

            if (!markersFound) // No Delphi/Lazarus sections found
                return;

            ImageSectionHeader? rdataSection = null;
            for (int i = 0; i < pe.ImageSectionHeaders.Length; i++) {
                if (pe.ImageSectionHeaders[i].Name == ".rdata") {
                    rdataSection = pe.ImageSectionHeaders[i];
                    break;
                }
            }

            // Ensure the .rdata section is present and has valid data
            if (rdataSection == null || rdataSection.PointerToRawData == 0 || rdataSection.SizeOfRawData == 0)
                return;

            int sectionStart = (int)rdataSection.PointerToRawData,
                sectionSize = (int)rdataSection.SizeOfRawData;
            
            // Ensure the section data is within the bounds of the file
            if (sectionStart + sectionSize > raw.Length)
                throw new IndexOutOfRangeException("Section data goes beyond file bounds.");

            string[] exactMatches = new string[] {
                "Property streamed in older Lazarus revision",
                "Used in a previous version of Lazarus"
            };

            for (int i = 0; i < exactMatches.Length; i++) {
                byte[] pattern = Encoding.ASCII.GetBytes(exactMatches[i]),
                    replacement = new byte[pattern.Length];
                
                Patcher.ReplaceBytesInSection(raw, rdataSection, pattern, replacement);
            }

            byte[] sectionData = new byte[sectionSize];
            Array.Copy(raw, sectionStart, sectionData, 0, sectionSize);

            string[] prefixMatches = [
                "TLazWriterTiff - Lazarus LCL: ",
                "TTiffImage - Lazarus LCL: "
            ];

            // Clear all strings that start with the specified prefixes
            for (int i = 0; i < prefixMatches.Length; i++) {

                byte[] prefixPattern = Encoding.ASCII.GetBytes(prefixMatches[i]);
                int index = Patcher.IndexOf(sectionData, prefixPattern, 0);

                while (index != -1) {

                    int end = index;

                    while (end < sectionData.Length && sectionData[end] != 0)
                        end++;

                    for (int j = index; j < end; j++)
                        sectionData[j] = 0;

                    index = Patcher.IndexOf(sectionData, prefixPattern, end);
                }
            }

            byte[] fpcPattern = Encoding.ASCII.GetBytes("FPC");
            int pos = Patcher.IndexOf(sectionData, fpcPattern, 0);

            // Clear all strings that contain "FPC" and "Win"
            while (pos != -1) {

                int end = pos;
                bool hasWin = false;

                while (end < sectionData.Length && sectionData[end] != 0) {
                    if (end <= sectionData.Length - 3 &&
                        sectionData[end] == (byte)'W' &&
                        sectionData[end + 1] == (byte)'i' &&
                        sectionData[end + 2] == (byte)'n') {
                        hasWin = true;
                    }

                    end++;
                }

                if (hasWin) {
                    for (int j = pos; j < end; j++)
                        sectionData[j] = 0;
                }

                pos = Patcher.IndexOf(sectionData, fpcPattern, end);
            }

            // Clear all strings that contain "Lazarus"
            Array.Copy(sectionData, 0, raw, sectionStart, sectionSize);
        }
    }
}