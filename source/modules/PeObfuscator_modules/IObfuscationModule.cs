using PeNet;

namespace AstralPE.Obfuscator.Modules {
    public interface IObfuscationModule {

        /// <summary>
        /// Applies the obfuscation (mutation) to the given PE file's raw bytes.
        /// This method is called to modify the raw byte array of the PE file by applying specific mutations,
        /// such as randomizing imports, modifying headers, or altering sections.
        /// </summary>
        /// <param name="raw">The raw byte array of the PE file that will be mutated.</param>
        /// <param name="pe">The parsed PE file, providing access to the header, sections, imports, and other elements.</param>
        /// <param name="e_lfanew">The offset to the IMAGE_NT_HEADERS.</param>
        /// <param name="optStart">The start offset of the Optional Header in the PE file.</param>
        /// <param name="sectionTableOffset">The offset to the section table in the PE file.</param>
        /// <param name="rnd">A random number generator used for randomization in some mutation processes.</param>
        void Apply(ref byte[] raw, PeFile pe, int e_lfanew, int optStart, int sectionTableOffset, Random rnd);
    }
}
