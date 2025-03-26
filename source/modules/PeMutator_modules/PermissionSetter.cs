using System;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class PermissionsSetter : IObfuscationModule {

        /// <summary>
        /// Applies full memory access flags (RWE + code) to all section headers in the PE file.
        /// </summary>
        /// <param name="raw">The raw byte buffer of the PE image.</param>
        /// <param name="pe">The parsed PE structure.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Offset to IMAGE_OPTIONAL_HEADER.</param>
        /// <param name="sectionTableOffset">Offset to section table start.</param>
        /// <param name="rnd">Random generator (unused).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Defensive check: ensure section headers are present
            if (pe.ImageSectionHeaders == null || pe.ImageSectionHeaders.Length == 0)
                throw new InvalidPeImageException();

            const int sectionHeaderSize = 40;         // IMAGE_SECTION_HEADER size is 40 bytes
            const int characteristicsOffset = 36;     // Characteristics field offset within IMAGE_SECTION_HEADER

            // Define the new permissions:
            // R = Read, W = Write, E = Execute, + mark as code section
            const uint perms = (uint)(
                PeNet.Header.Pe.ScnCharacteristicsType.MemRead |
                PeNet.Header.Pe.ScnCharacteristicsType.MemWrite |
                PeNet.Header.Pe.ScnCharacteristicsType.MemExecute |
                PeNet.Header.Pe.ScnCharacteristicsType.CntCode);

            // Loop through all section headers
            for (int i = 0; i < pe.ImageSectionHeaders.Length; i++) {
                // Calculate the start offset of the current section header
                int sectionOffset = sectionTableOffset + i * sectionHeaderSize;

                // Ensure we won't go out of bounds when writing the 4-byte value
                if (sectionOffset + characteristicsOffset + 4 > raw.Length)
                    throw new ArgumentOutOfRangeException(nameof(raw), "Section header characteristics offset exceeds file bounds.");

                // Overwrite the Characteristics field with our RWE + Code flags
                BitConverter.GetBytes(perms).CopyTo(raw, sectionOffset + characteristicsOffset);
            }
        }
    }
}
