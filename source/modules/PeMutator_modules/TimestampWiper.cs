using System;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class TimestampWiper : IObfuscationModule {

        /// <summary>
        /// Erases the TimeDateStamp from IMAGE_FILE_HEADER at offset (e_lfanew + 8).
        /// This removes the build timestamp metadata used for file versioning.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">Parsed PE file structure (not directly used here).</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Offset to IMAGE_OPTIONAL_HEADER.</param>
        /// <param name="sectionTableOffset">Offset to section headers.</param>
        /// <param name="rnd">Random instance (not used).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            int offset = e_lfanew + 8;

            // Offset sanity check
            if (e_lfanew <= 0 || e_lfanew > raw.Length)
                throw new InvalidPeImageException();

            // Ensure the field lies within bounds
            if (offset + 4 > raw.Length)
                throw new IndexOutOfRangeException("TimeDateStamp offset exceeds file size.");

            // Apply mutation
            Array.Clear(raw, offset, 4);
        }
    }
}
