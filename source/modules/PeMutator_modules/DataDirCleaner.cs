using System;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class DataDirCleaner : IObfuscationModule {

        /// <summary>
        /// Clears unused Data Directory entries (where the RVA is 0) in the PE file's Optional Header.
        /// The method checks all directories except the safe ones and removes any entry that has an RVA of 0.
        /// </summary>
        /// <param name="raw">The raw byte array representing the PE file.</param>
        /// <param name="pe">The parsed PE file object, used to access headers and section data.</param>
        /// <param name="e_lfanew">Offset to the IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Offset to the IMAGE_OPTIONAL_HEADER.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator (unused in this method).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Directories that are considered safe and should not be modified (those with known important data).
            int[] safeDirs = { 4, 6, 11, 13, 14 };
            int baseOffset = optStart + 0x60;

            // Sanity check: Optional Header must contain enough data directories
            if (baseOffset + (16 * 8) > raw.Length)
                throw new Exception("Optional Header is too small or malformed. Cannot process Data Directories.");

            // Iterate through each Data Directory index to clear unused directories
            foreach (int i in safeDirs) {
                int off = baseOffset + i * 8;

                // Check if the RVA is 0, indicating an unused Data Directory entry, and clear it
                if (off + 8 <= raw.Length && BitConverter.ToUInt32(raw, off) == 0)
                    Array.Clear(raw, off, 8);
            }
        }
    }
}
