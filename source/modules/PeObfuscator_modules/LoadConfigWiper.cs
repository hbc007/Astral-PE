using System;
using PeNet;
using PeNet.Header.Pe;

namespace AstralPE.Obfuscator.Modules {
    public class LoadConfigWiper : IObfuscationModule {

        /// <summary>
        /// Applies the logic to wipe the Load Config Directory if safe.
        /// </summary>
        /// <param name="raw">Raw byte buffer of the PE file.</param>
        /// <param name="pe">Parsed PE file structure from PeNet.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Offset to IMAGE_OPTIONAL_HEADER.</param>
        /// <param name="sectionTableOffset">Offset to section table.</param>
        /// <param name="rnd">Random generator (unused).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Verify header structures are present
            if (pe.ImageNtHeaders == null || pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // Locate Load Config Directory
            var loadCfg = pe.ImageNtHeaders.OptionalHeader.DataDirectory[(int)DataDirectoryType.LoadConfig];
            if (loadCfg.VirtualAddress == 0 || loadCfg.Size == 0)
                return;

            // Translate RVA to raw file offset
            uint rva = loadCfg.VirtualAddress;
            uint offset = rva.RvaToOffset(pe.ImageSectionHeaders);
            if (offset == 0 || offset + loadCfg.Size > raw.Length)
                throw new Exception("Load Config Directory points outside of file bounds.");

            // Check GuardFlags to see if CFG is enabled
            if (loadCfg.Size >= 0x48) {
                uint guardFlags = BitConverter.ToUInt32(raw, (int)(offset + 0x40));
                if ((guardFlags & 0x100) != 0) // IMAGE_GUARD_CF
                    throw new Exception("CFG (Control Flow Guard) is enabled. Skipping Load Config wipe.");
            }

            // Clear the Load Config Directory data
            Array.Clear(raw, (int)offset, (int)loadCfg.Size);

            // Clear the DataDirectory entry
            int dataDirOffset = optStart + 0x60 + ((int)DataDirectoryType.LoadConfig * 8);
            if (dataDirOffset + 8 > raw.Length)
                throw new IndexOutOfRangeException("DataDirectory offset is outside of file bounds.");

            Array.Clear(raw, dataDirOffset, 8);
        }
    }
}
