using System;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class EntryPointPatcher : IObfuscationModule {

        /// <summary>
        /// Patches the entry point in the PE file.
        /// 
        /// The first patch is relevant for most packers with the 'pushal' instruction at the entry point.
        /// The second patch handles the entry point for UPX 64-bit files.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Start offset of the Optional Header.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator to shuffle bytes (used in the second patch).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            if (pe.ImageNtHeaders == null || pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            uint epRva = pe.ImageNtHeaders.OptionalHeader.AddressOfEntryPoint;
            uint epOffset = epRva.RvaToOffset(pe.ImageSectionHeaders);

            if (epOffset >= raw.Length)
                throw new Exception("EntryPoint offset is out of file bounds.");

            // First patch: Replace PUSHAD (0x60) with NOP (0x90)
            if (raw[epOffset] == 0x60)
                raw[epOffset] = 0x90;

            // Second patch: Shuffle PUSH instructions in UPX64 signature
            if (epOffset + 4 < raw.Length &&
                raw[epOffset + 0] == 0x53 && raw[epOffset + 1] == 0x56 &&
                raw[epOffset + 2] == 0x57 && raw[epOffset + 3] == 0x55) {

                byte[] pushes = { 0x53, 0x56,
                                  0x57, 0x55 };

                for (int i = pushes.Length - 1; i > 0; i--) {
                    int j = rnd.Next(i + 1);
                    (pushes[i], pushes[j]) = (pushes[j], pushes[i]);
                }

                for (int i = 0; i < pushes.Length; i++)
                    raw[epOffset + i] = pushes[i];
            }
        }
    }
}
