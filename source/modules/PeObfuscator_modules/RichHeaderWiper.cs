using System;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class RichHeaderWiper : IObfuscationModule {

        /// <summary>
        /// Removes the Rich Header from the PE file if present.
        /// This header contains build metadata and can be used to fingerprint toolchains.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file object.</param>
        /// <param name="e_lfanew">The offset to the IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">The offset to the Optional Header.</param>
        /// <param name="sectionTableOffset">The offset to the section table.</param>
        /// <param name="rnd">Random generator (not used).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            const int richStart = 0x80;

            // Validate that e_lfanew is sane and within file bounds
            if (e_lfanew <= 0 || e_lfanew > raw.Length)
                throw new ArgumentOutOfRangeException(nameof(e_lfanew), "Invalid e_lfanew value: out of bounds.");

            // Ensure the Rich Header region is within bounds before clearing
            if (e_lfanew > richStart)
                Array.Clear(raw, richStart, e_lfanew - richStart);
        }
    }
}
