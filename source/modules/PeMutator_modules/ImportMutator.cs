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

using Astral_PE.modules;
using PeNet;
using System.Text;

namespace AstralPE.Obfuscator.Modules {
    public class ImportMutator : IAstralPeModule {
        // Windows XP compatible DLLs that should be handled carefully
        private static readonly HashSet<string> XpCoreDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "kernel32", "user32", "gdi32", "ntdll", "advapi32", "ole32", "oleaut32",
            "shell32", "comctl32", "comdlg32", "ws2_32", "msvcrt", "wininet", "version"
        };

        // DLLs that don't exist on Windows XP and should be avoided
        private static readonly HashSet<string> PostXpDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "api-ms-", "ext-ms-", "kernelbase", "bcrypt", "ncrypt"
        };

        /// <summary>
        /// Applies mutation to the PE file's import table with Windows XP compatibility.
        /// This includes DLL name mutation and noise injection into metadata fields.
        /// </summary>
        /// <param name="raw">Raw byte array representing the PE file.</param>
        /// <param name="pe">Parsed PE file object.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS (unused here).</param>
        /// <param name="optStart">Offset to the Optional Header start (unused here).</param>
        /// <param name="sectionTableOffset">Offset to the section table (unused here).</param>
        /// <param name="rnd">Random number generator instance.</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Basic validation for PE structure presence
            if (pe.ImageNtHeaders == null || pe.ImageSectionHeaders == null ||
                pe.ImageImportDescriptors == null || pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            uint importTableRva = pe.ImageNtHeaders.OptionalHeader.DataDirectory[1].VirtualAddress;
            int descriptorIndex = 0;

            // Check if we're targeting Windows XP compatibility
            bool isWinXpMode = PeMutator.LegacyWinCompatMode || IsWindowsXpTarget(pe);

            // Iterate through each IMAGE_IMPORT_DESCRIPTOR in the import table
            foreach (var descriptor in pe.ImageImportDescriptors) {
                uint nameRva = descriptor.Name,
                     fileOffset = Patcher.RvaToOffset(nameRva, pe.ImageSectionHeaders);

                if (fileOffset == 0 || fileOffset >= raw.Length)
                    continue; // Skip invalid or corrupted entries

                // Calculate the length of the null-terminated DLL name string
                int length = 0;
                
                while (fileOffset + length < raw.Length && raw[fileOffset + length] != 0)
                    length++;

                if (length == 0)
                    continue;

                // Extract original DLL name
                string original = Encoding.ASCII.GetString(raw, (int)fileOffset, length),
                       dll = original;

                // Only mutate DLLs that are compatible with target OS
                bool hasDllExtension = dll.EndsWith(".dll", StringComparison.OrdinalIgnoreCase);

                // Remove ".dll" extension for mutation
                if (hasDllExtension)
                    dll = dll[..^4];

                // Skip mutation for post-XP DLLs when in XP mode
                if (isWinXpMode && IsPostXpDll(dll))
                    continue;

                // Apply conservative mutation for Windows XP
                string mutated = ApplyXpCompatibleMutation(dll, isWinXpMode, rnd);

                // Re-add extension if original had one
                if (hasDllExtension)
                    mutated += ".dll";

                // Encode back to ASCII with null terminator
                byte[] mutatedBytes = Encoding.ASCII.GetBytes(mutated + "\0");

                // Enforce safety limit - more conservative for XP
                int maxExtraBytes = isWinXpMode ? 4 : 8;
                if (mutatedBytes.Length > length + maxExtraBytes) {
                    // Fallback to simple case randomization if mutation is too long
                    mutated = StringsWorker.RandomizeCase(dll);
                    if (hasDllExtension)
                        mutated += ".dll";
                    mutatedBytes = Encoding.ASCII.GetBytes(mutated + "\0");
                }

                // Ensure we don't exceed original length for critical system DLLs on XP
                if (isWinXpMode && XpCoreDlls.Contains(dll) && mutatedBytes.Length > length + 1) {
                    continue; // Skip mutation for critical system DLLs
                }

                // Overwrite original DLL name in-place
                Array.Copy(mutatedBytes, 0, raw, (int)fileOffset, mutatedBytes.Length);

                // Get the raw file offset for this IMAGE_IMPORT_DESCRIPTOR
                uint descriptorRva = importTableRva + (uint)(descriptorIndex * 20),
                     descriptorOffset = Patcher.RvaToOffset(descriptorRva, pe.ImageSectionHeaders);

                // Inject random values into TimeDateStamp and ForwarderChain (fields at offset +4 and +8)
                // Use more conservative values for Windows XP
                if (descriptorOffset + 12 <= raw.Length) {
                    uint timeDateStamp, forwarderChain;
                    
                    if (isWinXpMode) {
                        // Use smaller, more realistic values for XP
                        timeDateStamp = (uint)rnd.Next(0, int.MaxValue);
                        forwarderChain = (uint)rnd.Next(0, 65536); // Smaller range for XP
                    } else {
                        timeDateStamp = (uint)rnd.Next(int.MinValue, int.MaxValue);
                        forwarderChain = (uint)rnd.Next(int.MinValue, int.MaxValue);
                    }

                    // Write TimeDateStamp (offset +4)
                    raw[descriptorOffset + 4] = (byte)(timeDateStamp & 0xFF);
                    raw[descriptorOffset + 5] = (byte)((timeDateStamp >> 8) & 0xFF);
                    raw[descriptorOffset + 6] = (byte)((timeDateStamp >> 16) & 0xFF);
                    raw[descriptorOffset + 7] = (byte)((timeDateStamp >> 24) & 0xFF);

                    // Write ForwarderChain (offset +8)
                    raw[descriptorOffset + 8] = (byte)(forwarderChain & 0xFF);
                    raw[descriptorOffset + 9] = (byte)((forwarderChain >> 8) & 0xFF);
                    raw[descriptorOffset + 10] = (byte)((forwarderChain >> 16) & 0xFF);
                    raw[descriptorOffset + 11] = (byte)((forwarderChain >> 24) & 0xFF);
                }

                descriptorIndex++;
            }
        }

        /// <summary>
        /// Checks if the PE file is targeting Windows XP based on subsystem version
        /// </summary>
        private bool IsWindowsXpTarget(PeFile pe) {
            if (pe.ImageNtHeaders?.OptionalHeader == null)
                return false;

            var majorVersion = pe.ImageNtHeaders.OptionalHeader.MajorSubsystemVersion;
            var minorVersion = pe.ImageNtHeaders.OptionalHeader.MinorSubsystemVersion;

            // Windows XP is version 5.1, anything 5.x or earlier should be treated as XP-compatible
            return majorVersion <= 5;
        }

        /// <summary>
        /// Checks if a DLL name indicates it's from post-XP Windows versions
        /// </summary>
        private bool IsPostXpDll(string dllName) {
            return PostXpDlls.Any(postXpDll => 
                dllName.StartsWith(postXpDll, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Applies mutation compatible with Windows XP
        /// </summary>
        private string ApplyXpCompatibleMutation(string dll, bool isXpMode, Random rnd) {
            // Always apply case randomization
            string mutated = StringsWorker.RandomizeCase(dll);

            // For non-XP mode, apply additional mutations
            if (!isXpMode) {
                // Optionally prepend random path-like prefix (not for api-ms-win-* or core system DLLs)
                if (!dll.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase) &&
                    !XpCoreDlls.Contains(dll)) {
                    
                    string[] sep = ["./", ".\\"];
                    string prefix = sep[rnd.Next(sep.Length)];
                    if (rnd.Next(2) == 0)
                        prefix += sep[rnd.Next(sep.Length)];
                    mutated = prefix + mutated;
                }
            }

            return mutated;
        }
    }
}
