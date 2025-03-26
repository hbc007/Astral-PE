using PeNet.Header.Pe;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;

namespace AstralPE.Obfuscator.Modules {
    public static class Patcher {

        /// <summary>
        /// Replaces all occurrences of a byte sequence (`find`) with another byte sequence (`replace`) in the given data.
        /// The operation is performed in parallel for performance improvements when working with large files.
        /// </summary>
        /// <param name="data">The byte array to search within and mutate.</param>
        /// <param name="find">The byte sequence to find in the data.</param>
        /// <param name="replace">The byte sequence to replace the `find` sequence with.</param>
        public static void ReplaceBytes(byte[] data, byte[] find, byte[] replace) {
            // If the `find` or `replace` arrays are empty, or the `data` is too small to contain the `find` sequence, exit early
            if (find.Length == 0 || replace.Length == 0 || data.Length < find.Length)
                return;

            ConcurrentBag<int>? matches = new ConcurrentBag<int>(); // Used to store the indices of all matches found
            int len = find.Length; // The length of the `find` sequence
            int limit = data.Length - len; // The last index where a match could occur in the `data` array

            // Parallel processing to find all occurrences of the `find` sequence
            Parallel.ForEach(
                Partitioner.Create(0, limit, 8192), // Divide the data into ranges for parallel processing
                range => {
                    for (int i = range.Item1; i < range.Item2; i++) {
                        int j = 0;
                        while (j < len && data[i + j] == find[j]) j++; // Compare bytes to find a match
                        if (j == len) // If the entire sequence matches, add the starting index to the matches list
                            matches.Add(i);
                    }
                });

            // After collecting all match indices, replace the `find` sequence with `replace`
            foreach (int index in matches.OrderBy(i => i)) { // Ensure replacements are done in order of indices
                Buffer.BlockCopy(replace, 0, data, index, Math.Min(replace.Length, len)); // Replace with the `replace` sequence
            }
        }

        /// <summary>
        /// Finds the first occurrence of a byte pattern within a larger byte array.
        /// </summary>
        /// <param name="haystack">The byte array to search through.</param>
        /// <param name="needle">The byte sequence to search for.</param>
        /// <returns>The index of the first match if found; otherwise -1.</returns>
        public static int IndexOf(byte[] haystack, byte[] needle) {
            // If search target is invalid or longer than the haystack, return not found
            if (needle == null || needle.Length == 0 || haystack.Length < needle.Length)
                return -1;

            int len = needle.Length;
            int limit = haystack.Length - len;

            // Scan the haystack for the needle sequence
            for (int i = 0; i <= limit; i++) {
                bool match = true;
                for (int j = 0; j < len; j++) {
                    if (haystack[i + j] != needle[j]) {
                        match = false;
                        break;
                    }
                }
                if (match)
                    return i;
            }
            return -1; // No match found
        }

        /// <summary>
        /// Converts a raw file offset to a Relative Virtual Address (RVA) based on section headers.
        /// </summary>
        /// <param name="offset">The file offset to convert.</param>
        /// <param name="sections">The section headers from the PE file.</param>
        /// <returns>The calculated RVA, or 0 if not resolvable.</returns>
        public static uint OffsetToRva(uint offset, ImageSectionHeader[] sections) {
            // Validate input
            if (sections == null || sections.Length == 0)
                throw new ArgumentException("Section headers are missing.");

            // Loop through each section to find the one containing the offset
            foreach (var sec in sections) {
                if (offset >= sec.PointerToRawData && offset < sec.PointerToRawData + sec.SizeOfRawData)
                    return sec.VirtualAddress + (offset - sec.PointerToRawData); // Convert offset to RVA
            }
            return 0; // No matching section found
        }
    }
}
