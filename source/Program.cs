using System;
using System.IO;
using PeNet;
using AstralPE.Obfuscator;

namespace AstralPE {
    /// <summary>
    /// The main entry point for the AstralPE obfuscation tool.
    /// Handles command-line arguments, performs obfuscation, and saves the modified PE file.
    /// </summary>
    class Program {
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
                Logging.Write("/CLR(CYAN)[?] /CLR(WHITE)Usage: /CLR(YELLOW)<input.exe|dll> [-o|--output <output.exe|dll>]");
                return;
            }

            // Extract input file path from command-line arguments.
            string inputPath = args[0];

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
            for (int i = 1; i < args.Length - 1; i++) {
                if (args[i] == "-o" || args[i] == "--output") {
                    outputPath = args[i + 1];
                    break;
                }
            }


            try {
                // Read the raw bytes from the input file.
                byte[] raw = File.ReadAllBytes(inputPath);

                // Create a PeFile object for PE file parsing and manipulation.
                PeFile pe = new PeFile(raw);

                // Initialize the random number generator for any random operations.
                Random rnd = new Random();

                // Log the start of the obfuscation process.
                Logging.Write("/CLR(CYAN)[@] /CLR(WHITE)Obfuscating: /CLR(GRAY)" + inputPath);

                // Create a PeObfuscator instance and apply obfuscation.
                PeMutator? obfuscator = new PeMutator(raw, pe, rnd, inputPath);
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
