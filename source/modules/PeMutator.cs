using System;
using System.Collections.Generic;
using PeNet;
using AstralPE.Obfuscator.Modules;

namespace AstralPE.Obfuscator {
    public class PeMutator {
        private byte[] raw;
        private readonly PeFile pe;
        private readonly Random rnd;

        private readonly int e_lfanew;
        private readonly int optStart;
        private readonly int sectionTableOffset;

        private readonly List<IObfuscationModule> modules = new();

        public static string selectedFilePath = String.Empty;

        /// <summary>
        /// Initializes the PE obfuscator and computes important header offsets.
        /// </summary>
        /// <param name="raw">Raw byte array of the PE file.</param>
        /// <param name="pe">Parsed PE structure.</param>
        /// <param name="rnd">Random number generator instance.</param>
        public PeMutator(byte[] raw, PeFile pe, Random rnd, string _selectedFilePath) {
            selectedFilePath = _selectedFilePath;

            this.raw = raw ?? throw new ArgumentNullException(nameof(raw));
            this.pe = pe ?? throw new ArgumentNullException(nameof(pe));
            this.rnd = rnd ?? throw new ArgumentNullException(nameof(rnd));

            if (pe.ImageDosHeader == null || pe.ImageNtHeaders == null || pe.ImageNtHeaders.FileHeader == null)
                throw new InvalidOperationException("Invalid PE structure: headers missing.");

            e_lfanew = (int)pe.ImageDosHeader.E_lfanew;
            optStart = e_lfanew + 0x18;
            sectionTableOffset = e_lfanew + 4 + 20 + pe.ImageNtHeaders.FileHeader.SizeOfOptionalHeader;

            RegisterModules();
        }

        /// <summary>
        /// Registers all mutation modules in the order they should be applied.
        /// </summary>
        private void RegisterModules() {
            var list = new IObfuscationModule[] {
                new LinkerVersionInfoCleaner(),
                new OriginalNameCleaner(),
                new EntryPointPatcher(),
                new PermissionsSetter(),
                new OverlayStripper(),
                new RichHeaderWiper(),
                new LoadConfigWiper(),
                new DosStubPatcher(),
                new DataDirCleaner(),
                new TimestampWiper(),
                new ChecksumWiper(),
                new ImportMutator(),
                new DebugStripper(),
                new RelocRemover(),
                new TlsCleaner(),
                new ExportFaker(),
                new SectionNameWiper() // Must be last
            };

            foreach (var module in list)
                modules.Add(module);
        }


        /// <summary>
        /// Applies all registered transformations to the PE file.
        /// </summary>
        /// <returns>Mutated byte array of the PE file.</returns>
        public byte[] Apply() {
            if (pe.IsDotNet) {
                Logging.Write("/CLR(RED)[!] DotNET files are not supported in this version.");
                Environment.Exit(1);
            }

            foreach (var module in modules) {
                try {
                    module.Apply(ref raw, pe, e_lfanew, optStart, sectionTableOffset, rnd);
                } catch (Exception ex) {
                    Logging.Write($"/CLR(RED)[!] /CLR(GRAY)(SKIP)/CLR(RED) Module {module.GetType().Name} failed: {ex.Message}");
                }
            }

            return raw;
        }
    }
}
