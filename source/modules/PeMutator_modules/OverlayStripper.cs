using System;
using System.Linq;
using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public class OverlayStripper : IObfuscationModule {

        /// <summary>
        /// Applies the overlay stripper to remove the overlay if file signed (WinAuth certificate).
        /// If this pattern is found at the start of the overlay, the overlay is removed.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file.</param>
        /// <param name="pe">The parsed PE file, used to access the section headers and overlay information.</param>
        /// <param name="e_lfanew">The offset to the IMAGE_NT_HEADERS in the PE file.</param>
        /// <param name="optStart">The offset to the Optional Header in the PE file.</param>
        /// <param name="sectionTableOffset">The offset to the section table in the PE file.</param>
        /// <param name="rnd">A random number generator (currently unused in this module, but required by the interface).</param>
        public void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Validate section headers
            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // Calculate the offset to the overlay data (after the last section)
            uint overlayOffset = pe.ImageSectionHeaders.Max(s => s.PointerToRawData + s.SizeOfRawData);

            // Make sure overlayOffset is not beyond the file length
            if (overlayOffset >= raw.Length)
                return;

            // Calculate the length of the overlay and check if it's too short to contain the signature
            if (raw.Length - (int)overlayOffset < 8)
                return;

            // Bounds check before reading overlay signature
            if (overlayOffset + 8 > (uint)raw.Length)
                throw new ArgumentOutOfRangeException("Overlay offset exceeds file bounds.");

            // Check for specific PKI-like signature (used in signed overlays)
            if (raw[overlayOffset + 4] == 0x00 &&
                raw[overlayOffset + 5] == 0x02 &&
                raw[overlayOffset + 6] == 0x02 &&
                raw[overlayOffset + 7] == 0x00) {
                // Resize the original byte array to remove the overlay
                Array.Resize(ref raw, (int)overlayOffset);
            }
        }
    }
}
