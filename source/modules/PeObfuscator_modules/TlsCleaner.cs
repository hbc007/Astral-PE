using System;
using System.Linq;
using PeNet;
using PeNet.Header.Pe;

namespace AstralPE.Obfuscator.Modules {
    public class TlsCleaner : IObfuscationModule {

        /// <summary>
        /// Cleans the TLS directory entry in the PE file. If the TLS directory is not in use or contains
        /// zero values (indicating no TLS data), it will be cleared.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file object containing the image headers and sections.</param>
        /// <param name="e_lfanew">The offset to the IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">The offset to the IMAGE_OPTIONAL_HEADER.</param>
        /// <param name="sectionTableOffset">The offset to the section table.</param>
        /// <param name="rnd">Random generator (unused in this method).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Ensure section headers are available
            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // Calculate the offset of the TLS Directory entry inside DataDirectory (entry index 9)
            int tlsDirOffset = optStart + 0x60 + 9 * 8;

            // Validate bounds for TLS Directory entry (8 bytes: RVA + Size)
            if (tlsDirOffset + 8 > raw.Length)
                throw new IndexOutOfRangeException("TLS directory offset goes beyond file bounds.");

            // Read TLS Directory RVA and Size from the DataDirectory entry
            uint tlsRva = BitConverter.ToUInt32(raw, tlsDirOffset),
                 tlsSize = BitConverter.ToUInt32(raw, tlsDirOffset + 4);

            // If the TLS directory is not set (both RVA and Size are 0), wipe the entry and return
            if (tlsRva == 0 || tlsSize == 0) {
                Array.Clear(raw, tlsDirOffset, 8); // Wipe TLS entry in DataDirectory
                return;
            }

            // Find the section that contains the TLS directory
            ImageSectionHeader? tlsSection = pe.ImageSectionHeaders.FirstOrDefault(s =>
                                tlsRva >= s.VirtualAddress &&
                                tlsRva < s.VirtualAddress + s.VirtualSize);

            // If no section contains the TLS RVA, this might be invalid
            if (tlsSection == null)
                throw new InvalidOperationException("TLS RVA points to invalid or unmapped section.");

            // Convert TLS RVA to file offset
            uint tlsOffset = tlsRva.RvaToOffset(pe.ImageSectionHeaders);

            // TLS Directory is at least 0x18 bytes long — validate size
            if (tlsOffset + 0x18 > raw.Length)
                throw new IndexOutOfRangeException("TLS offset + 0x18 exceeds raw size.");

            // Check if entire TLS structure is filled with zeros (not used)
            if (raw.Skip((int)tlsOffset).Take(0x18).All(b => b == 0))
                Array.Clear(raw, tlsDirOffset, 8); // Wipe TLS entry from DataDirectory if unused
        }
    }
}
