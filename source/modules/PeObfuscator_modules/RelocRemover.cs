using System;
using System.Linq;
using PeNet;
using PeNet.Header.Pe;

namespace AstralPE.Obfuscator.Modules {
    public class RelocRemover : IObfuscationModule {

        /// <summary>
        /// Removes the relocation directory and section from the PE file if they are not needed.
        /// This operation is skipped for DLL and driver files.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file structure.</param>
        /// <param name="e_lfanew">The offset to the IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">The offset to the Optional Header.</param>
        /// <param name="sectionTableOffset">The offset to the section table.</param>
        /// <param name="rnd">Random generator, unused in this module.</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Skip if the file is a DLL or driver
            if (pe.IsDll || pe.IsDriver)
                return;

            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // The offset of the relocation directory in the DataDirectory array
            int relocDirOffset = optStart + 0x60 + 5 * 8;

            // Ensure the relocation directory entry is within bounds
            if (relocDirOffset + 8 > raw.Length)
                throw new ArgumentOutOfRangeException(nameof(relocDirOffset), "Relocation directory offset is outside file bounds.");

            // Read the relocation RVA and size from the raw data
            uint relocRva = BitConverter.ToUInt32(raw, relocDirOffset),
                 relocSize = BitConverter.ToUInt32(raw, relocDirOffset + 4);

            // Skip if the relocation directory is not present or the size is 0
            if (relocRva == 0 || relocSize == 0)
                return;

            // Try to find the ".reloc" section in the section headers
            ImageSectionHeader? relocSection = pe.ImageSectionHeaders.FirstOrDefault(s =>
                s.Name?.Trim('\0').Equals(".reloc", StringComparison.OrdinalIgnoreCase) == true);

            if (relocSection == null)
                return;

            int offset = (int)relocSection.PointerToRawData,
                size = (int)relocSection.SizeOfRawData;

            // Bounds validation
            if (offset <= 0 || offset + size > raw.Length)
                throw new ArgumentOutOfRangeException(nameof(offset), "Relocation section is outside file bounds.");

            // Skip if the relocation RVA does not point into the .reloc section
            if (relocRva < relocSection.VirtualAddress || relocRva >= relocSection.VirtualAddress + relocSection.VirtualSize)
                return;

            // Clear the .reloc section content
            Array.Clear(raw, offset, size);

            // Clear the relocation entry in the DataDirectory
            Array.Clear(raw, relocDirOffset, 8);
        }
    }
}
