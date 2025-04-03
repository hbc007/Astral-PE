/*
 * This file is part of the Astral-PE project.
 * Copyright (c) 2025 DosX. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Astral-PE is a low-level post-compilation PE header mutator (obfuscator) for native
 * Windows x86/x64 binaries. It modifies structural metadata while preserving execution integrity.
 *
 * For source code, updates, and documentation, visit:
 * https://github.com/DosX-dev/Astral-PE
 */

using Astral_PE.modules;
using AstralPE.Obfuscator;
using PeNet;

namespace AstralPE {
    /// <summary>
    /// The main entry point for the AstralPE obfuscation tool.
    /// Handles command-line arguments, performs obfuscation, and saves the modified PE file.
    /// </summary>
    class Program {
        // Initialize the random number generator for any random operations.
        private readonly static Random rnd = new();

        /// <summary>
        /// Main method of the application. It handles command-line input, performs obfuscation,
        /// and saves the resulting obfuscated PE file.
        /// </summary>
        /// <param name="args">The command-line arguments passed to the application.</param>
        static void Main(string[] args) {
            // Display tool info on start, with colorful terminal output.
            Logging.Write("/CLR(WHITE)\n" +
                " █████╗  ███████╗████████╗██████╗  █████╗ ██╗/CLR(DARKGRAY)        ██████╗ ███████╗/CLR(WHITE)\n" +
                " ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║/CLR(DARKGRAY)        ██╔══██╗██╔════╝/CLR(WHITE)\n" +
                " ███████║███████╗   ██║   ██████╔╝███████║██║/CLR(DARKGRAY) █████╗ ██████╔╝█████╗  /CLR(WHITE)\n" +
                " ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║██║/CLR(DARKGRAY) ╚════╝ ██╔═══╝ ██╔══╝  /CLR(WHITE)\n" +
                " ██║  ██║███████║   ██║   ██║  ██║██║  ██║███████╗/CLR(DARKGRAY)   ██║     ███████╗/CLR(WHITE)\n" +
                " ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝/CLR(DARKGRAY)   ╚═╝     ╚══════╝/CLR(WHITE)\n" +
                "  /CLR(GRAY)Advanced utility for mutation (shallow obfuscation) of PE files.\n" +
                "         GitHub: /CLR(BLUE)https://github.com/DosX-dev/Astral-PE/CLR(WHITE)\n");

            // If no arguments are provided or the user asks for help, show the usage message.
            if (args.Length == 0 || args.Contains("-h") || args.Contains("--help")) {
                Logging.Write("/CLR(CYAN)[?] /CLR(WHITE)Usage: /CLR(YELLOW)<input.exe|dll> [-o|--output <output.exe|dll>] [-l|--legacy-win-compat-mode]\n" +
                              "/CLR(DARKGRAY)    Specify /CLR(DARKYELLOW)--legacy-win-compat-mode/CLR(DARKGRAY) to ensure compatibility with Windows 7, 8, or 8.1.");
                return;
            }

            // Extract input file path from command-line arguments.
            string inputPath = args[0];

            // Check if the user wants to enable legacy compatibility mode.
            bool legacyWinCompatMode = false;

            // Check if the input file exists.
            if (!File.Exists(inputPath)) {
                Logging.Write("/CLR(RED)[!] File not found:/CLR(WHITE) " + inputPath);
                return;
            }

            // Default output path setup.
            string outputPath = Path.Combine(
                Path.GetDirectoryName(inputPath) ?? "",
                Path.GetFileNameWithoutExtension(inputPath) + "_ast" + Path.GetExtension(inputPath)
            );

            // Check if the user provided a custom output path via -o or --output arguments.
            for (int i = 0; i < args.Length; i++) {
                if ((args[i] == "-o" || args[i] == "--output") && i + 1 < args.Length) {
                    outputPath = args[i + 1];
                    i++;
                } else if (args[i] == "-l" || args[i] == "--legacy-win-compat-mode") {
                    legacyWinCompatMode = true;
                } else if (i > 0) {
                    Logging.Write("/CLR(DARKGRAY)[?] Specified flag /CLR(GRAY)" + args[i] + "/CLR(DARKGRAY) is not valid.");
                }
            }



            try {
                // Read the raw bytes from the input file.
                byte[] raw = File.ReadAllBytes(inputPath);

                // Create a PeFile object for PE file parsing and manipulation.
                PeFile pe = new(raw);

                // Log the start of the obfuscation process.
                Logging.Write("/CLR(CYAN)[@] /CLR(WHITE)Obfuscating: /CLR(GRAY)" + inputPath);

                if (legacyWinCompatMode) {
                    Logging.Write("/CLR(DARKYELLOW)[!] Compatibility mode with older versions of Windows is enabled.\n    /CLR(RED)Obfuscation will be less effective!/CLR(DARKYELLOW) Keep this in mind.");
                }

                // Create a PeObfuscator instance and apply obfuscation.
                PeMutator? obfuscator = new(raw, pe, rnd, inputPath, legacyWinCompatMode);
                raw = obfuscator.Apply();

                try {
                    // Write the obfuscated data to the output file.
                    File.WriteAllBytes(outputPath, raw);

                    using (var fs = new FileStream(outputPath, FileMode.Append, FileAccess.Write))
                        fs.WriteByte(0x00);

                    // Log the completion and the output path of the obfuscated file.
                    Logging.Write("/CLR(GREEN)[+] /CLR(WHITE)Saved as: /CLR(GRAY)" + outputPath);
                } catch (Exception ex) {
                    Logging.Write("/CLR(RED)[!] Failed to save the obfuscated file: " + ex.Message);
                }
            } catch (Exception ex) {
                Logging.Write("/CLR(RED)[!] An error occurred during obfuscation: " + ex.Message);
            }
        }
    }
}
