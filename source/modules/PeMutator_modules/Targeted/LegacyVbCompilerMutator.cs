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
using System.Text;

namespace AstralPE.Obfuscator.Modules {
    public class LegacyVbCompilerMutator : IAstralPeModule {

        /// <summary>
        /// Detects legacy VB compiler metadata and removes embedded VB project path.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE structure.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Offset to IMAGE_OPTIONAL_HEADER.</param>
        /// <param name="sectionTableOffset">Offset to section table start.</param>
        /// <param name="rnd">Random instance (unused).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            if (pe.ImportedFunctions == null || pe.ImportedFunctions.Length == 0)
                return;

            // Check for any import from VB5/6 runtimes
            bool isVB = pe.ImportedFunctions.Any(f =>
                f.DLL?.ToLowerInvariant().Contains("vbvm5") == true ||
                f.DLL?.ToLowerInvariant().Contains("vbvm6") == true);

            if (!isVB)
                return;

            // Look for a typical VB project path reference like:
            // "C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB"
            ReadOnlySpan<byte> marker = new byte[] { (byte)'V', (byte)'B', (byte)'6', (byte)'.', (byte)'O', (byte)'L', (byte)'B' };
            Span<byte> span = raw;
            int pos = span.IndexOf(marker);
            while (pos != -1) {
                int start = pos;
                while (start > 0 && span[start - 1] != 0) start--;
                int end = pos + marker.Length;
                while (end < span.Length && span[end] != 0) end++;
                for (int i = start; i < end; i++) span[i] = 0;
                pos = span[end..].IndexOf(marker);
                if (pos != -1) pos += end;
            }
        }
    }
}
