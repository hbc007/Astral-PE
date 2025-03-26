using System;
using System.Linq;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class SectionNameWiper : IObfuscationModule {

        // The size of a section header in the PE file format (40 bytes).
        private const int SectionHeaderSize = 40;

        /// <summary>
        /// Wipes the names of all sections in the PE file.
        /// This is done by clearing the first 8 bytes (section name) of each section header.
        /// </summary>
        /// <param name="raw">The raw byte array representing the PE file.</param>
        /// <param name="pe">The parsed PE file object containing section headers.</param>
        /// <param name="e_lfanew">The offset to the IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">The offset to the Optional Header.</param>
        /// <param name="sectionTableOffset">The offset to the section table.</param>
        /// <param name="rnd">Random generator, which is not used in this method.</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Ensure the section headers are present
            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // Check that section table offset is not obviously broken
            if (sectionTableOffset <= 0 || sectionTableOffset > raw.Length)
                throw new ArgumentOutOfRangeException(nameof(sectionTableOffset), "Section table offset is invalid.");

            // Iterate through all section headers in the PE file
            for (int i = 0; i < pe.ImageSectionHeaders.Length; i++) {
                // Calculate the offset of the current section header
                int sectionNameOffset = sectionTableOffset + i * SectionHeaderSize;

                // Bounds check to avoid corrupting memory
                if (sectionNameOffset + 8 > raw.Length)
                    throw new IndexOutOfRangeException("Section name offset exceeds buffer length.");

                // Clear the first 8 bytes of each section header (section name)
                for (int j = 0; j < 8; j++)
                    raw[sectionNameOffset + j] = 0x00;
            }
        }
    }
}
