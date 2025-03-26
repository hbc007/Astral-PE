using PeNet;
using PeNet.Header.Pe;
using System;
using System.Diagnostics;
using System.Text;

namespace AstralPE.Obfuscator.Modules {
    public class OriginalNameCleaner : IObfuscationModule {

        /// <summary>
        /// Applies the cleaning logic to strip any original file names.
        /// </summary>
        /// <param name="raw">The raw PE byte array.</param>
        /// <param name="pe">Parsed PE file structure.</param>
        /// <param name="e_lfanew">Offset to IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">Offset to IMAGE_OPTIONAL_HEADER.</param>
        /// <param name="sectionTableOffset">Offset to the section table.</param>
        /// <param name="rnd">Random number generator (not used).</param>
        public void Apply(ref byte[] raw, PeNet.PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd) {
            // Validate section headers
            if (pe.ImageSectionHeaders == null)
                throw new InvalidPeImageException();

            // Try to wipe OriginalFilename from end of file

            FileVersionInfo? verInfo = FileVersionInfo.GetVersionInfo(PeMutator.selectedFilePath);
            if (!string.IsNullOrEmpty(verInfo.OriginalFilename)) {
                string orig = verInfo.OriginalFilename;
                byte[] value = Encoding.Unicode.GetBytes(orig + "\0"); // UTF-16 null-terminated

                // Scan the last N bytes of the file for the encoded string (starting from end)
                const int searchWindow = 0x4000; // scan last 16 KB max
                int start = Math.Max(0, raw.Length - searchWindow);

                for (int i = raw.Length - value.Length; i >= start; i--) {
                    bool match = true;
                    for (int j = 0; j < value.Length; j++) {
                        if (raw[i + j] != value[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        Array.Clear(raw, i, value.Length); // zero out the string
                        break;
                    }
                }
            }

            // Wipe export name (if export directory is valid)
            ImageDataDirectory? exportDir = pe.ImageNtHeaders?.OptionalHeader.DataDirectory[0]; // Export is index 0
            if (exportDir == null || exportDir.VirtualAddress == 0 || exportDir.Size == 0)
                return; // No export directory

            uint rva = exportDir.VirtualAddress,
                 exportBaseOffset;

            try {
                exportBaseOffset = rva.RvaToOffset(pe.ImageSectionHeaders);
            } catch {
                // Could not resolve section (e.g., UPX-packed binary)
                return;
            }

            if (exportBaseOffset + 0x10 > raw.Length)
                return; // Structure truncated

            uint nameRva = BitConverter.ToUInt32(raw, (int)(exportBaseOffset + 0x0C));
            if (nameRva == 0)
                return; // No name present

            uint nameOffset;
            try {
                nameOffset = nameRva.RvaToOffset(pe.ImageSectionHeaders);
            } catch {
                return; // Can't map RVA to offset (e.g., section missing)
            }

            if (nameOffset == 0 || nameOffset >= raw.Length)
                return; // Out of bounds

            // Zero out ASCII string name (null-terminated)
            int k = (int)nameOffset;
            while (k < raw.Length && raw[k] != 0) {
                raw[k++] = 0;
            }
        }
    }
}