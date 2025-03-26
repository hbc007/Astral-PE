using System;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class VersionInfoCleaner : IObfuscationModule {

        /// <summary>
        /// Clears version info from the PE Optional Header.
        /// This targets the version resource section to sanitize metadata.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">Parsed PE structure containing headers and sections.</param>
        /// <param name="e_lfanew">Offset to the IMAGE_NT_HEADERS from the file's base.</param>
        /// <param name="optStart">Offset to the IMAGE_OPTIONAL_HEADER.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random instance for potential future mutations.</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            int versionOffset = optStart + 2;

            // Ensure we are not writing out of bounds
            if (versionOffset + 6 > raw.Length)
                throw new IndexOutOfRangeException("Version info offset is outside of file bounds.");

            // Erase version resource bytes.
            Array.Clear(raw, versionOffset, 6);
        }
    }
}
