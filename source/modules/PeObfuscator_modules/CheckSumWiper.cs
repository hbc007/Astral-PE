using System;
using PeNet;
using PeNet.Header.Pe;

namespace AstralPE.Obfuscator.Modules {
    public class ChecksumWiper : IObfuscationModule {

        /// <summary>
        /// Overwrites the 4-byte CheckSum field (offset +0x40) in the optional header with zero, if it is non-zero.
        /// </summary>
        /// <param name="raw">The raw byte buffer of the PE file.</param>
        /// <param name="pe">The parsed PE file structure.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Offset to Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to section headers.</param>
        /// <param name="rnd">Random instance (unused).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Sanity check to ensure header structures are available
            if (pe.ImageNtHeaders == null || pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // Calculate offset to CheckSum field (offset +0x40 in optional header)
            int checksumOffset = optStart + 0x40;

            // Bounds check
            if (checksumOffset + 4 > raw.Length)
                throw new ArgumentOutOfRangeException(nameof(raw), "Checksum offset exceeds buffer length.");

            // If checksum is already zero, skip
            if (pe.ImageNtHeaders.OptionalHeader.CheckSum == 0)
                return;

            // Clear the 4-byte CheckSum field
            BitConverter.GetBytes(0u).CopyTo(raw, checksumOffset);
        }
    }
}