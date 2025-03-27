/*
 * This file is part of the Astral-PE project.
 * Copyright (c) 2025 DosX-dev. All rights reserved.
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

using System;
using System.Linq;
using System.Text;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class ImportMutator : IObfuscationModule {

        /// <summary>
        /// Randomizes the case of imported DLL names and adds random directory prefixes.
        /// This method modifies the import table of the PE file by replacing the original
        /// DLL names with the mutated versions.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator used for randomizing case and prefixes.</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            if (pe.ImportedFunctions == null)
                throw new InvalidPeImageException();

            IEnumerable<string>? uniqueDlls = pe.ImportedFunctions
                .Select(x => x.DLL)
                .Where(x => !string.IsNullOrEmpty(x))
                .Distinct(StringComparer.OrdinalIgnoreCase);

            foreach (string dllName in uniqueDlls) {
                string dll = dllName;
                if (dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    dll = dll[..^4];

                string[] sep = { "./", ".\\" };
                string prefix = sep[rnd.Next(2)];

                if (rnd.Next(2) == 0)
                    prefix += sep[rnd.Next(2)];

                string mutated = prefix + StringsWorker.RandomizeCase(dll);

                byte[] orig = Encoding.ASCII.GetBytes(dllName + "\0");
                byte[] repl = Encoding.ASCII.GetBytes(mutated + "\0");

                if (repl.Length > orig.Length * 2)
                    throw new Exception("Mutated import name is too long and might corrupt the import table.");

                // Find index manually
                int index = Patcher.IndexOf(raw, orig);
                if (index != -1) {
                    int writableLength = Math.Min(repl.Length, raw.Length - index);
                    Array.Copy(repl, 0, raw, index, writableLength);
                }
            }
        }
    }
}
