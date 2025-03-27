/*
 * This file is part of the Astral-PE project.
 * Copyright (c) 2025 DosX. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the “Software”), to deal
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
using System.Text;

namespace AstralPE.Obfuscator.Modules {
    public class ImportMutator : IAstralPeModule {

        /// <summary>
        /// Randomizes the case of imported DLL names and adds random directory prefixes.
        /// This method modifies the import table of the PE file by replacing the original
        /// DLL names with mutated versions, based on the ImageImportDescriptors.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator used for randomizing case and prefixes.</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            if (pe.ImageImportDescriptors == null || pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // Iterate over each import descriptor in the Import Table
            foreach (var descriptor in pe.ImageImportDescriptors) {
                uint nameRva = descriptor.Name,
                     fileOffset = Patcher.RvaToOffset(nameRva, pe.ImageSectionHeaders);

                if (fileOffset == 0 || fileOffset >= raw.Length)
                    continue;

                // Read the original DLL name (null-terminated)
                int length = 0;
                while (fileOffset + length < raw.Length && raw[fileOffset + length] != 0)
                    length++;
                if (length == 0)
                    continue;
                string original = Encoding.ASCII.GetString(raw, (int)fileOffset, length);

                // Prepare the mutated name based on the original name
                string dll = original;
                bool hasDllExtension = dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);

                if (hasDllExtension)
                    dll = dll.Substring(0, dll.Length - 4); // remove ".dll"

                string mutated = StringsWorker.RandomizeCase(dll);
                if (hasDllExtension) {
                    string[] sep = { "./", ".\\" };
                    string prefix = sep[rnd.Next(sep.Length)];
                    if (rnd.Next(2) == 0)
                        prefix += sep[rnd.Next(sep.Length)];
                    mutated = prefix + mutated;
                }

                byte[] mutatedBytes = Encoding.ASCII.GetBytes(mutated + "\0");

                // Prevent potential corruption if the mutated name is too long
                if (mutatedBytes.Length > length + 8)
                    continue;

                // Patch the mutated name into the raw file at the descriptor's location
                Array.Copy(mutatedBytes, 0, raw, (int)fileOffset, mutatedBytes.Length);
            }
        }
    }
}
