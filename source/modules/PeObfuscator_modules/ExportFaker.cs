using System;
using System.Linq;
using PeNet;
using PeNet.Header.Pe;

namespace AstralPE.Obfuscator.Modules {
    public class ExportFaker : IObfuscationModule {

        /// <summary>
        /// If the PE file has no export directory, this method fakes the export directory
        /// by setting the export RVA to the first section's virtual address and setting a fake size.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator (not used in this method).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // If the PE file already has exports, no need to fake them
            if (pe.ExportedFunctions != null)
                return;

            // Get the first section header to use its Virtual Address for the fake export directory
            ImageSectionHeader? firstSection = pe.ImageSectionHeaders.FirstOrDefault();
            if (firstSection == null)
                throw new Exception("No section headers found. Cannot fake export directory.");

            // Set the fake export RVA to the first section's Virtual Address
            uint fakeExportRVA = firstSection.VirtualAddress;

            // Calculate the offset for the export directory in the Optional Header
            int exportDirOffset = optStart + 0x60 + 0 * 8;

            // Write the fake export RVA and size (0x28) to the raw bytes at the export directory offset
            BitConverter.GetBytes(fakeExportRVA).CopyTo(raw, exportDirOffset);     // Fake RVA
            BitConverter.GetBytes(0x28u).CopyTo(raw, exportDirOffset + 4);         // Fake size
        }
    }
}
