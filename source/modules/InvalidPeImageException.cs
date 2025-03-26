using System;

namespace AstralPE.Obfuscator {
    /// <summary>
    /// Exception thrown when the PE image is invalid or incomplete.
    /// Used to halt obfuscation safely if a structural inconsistency is detected.
    /// </summary>
    public class InvalidPeImageException : Exception {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidPeImageException"/> class.
        /// </summary>
        public InvalidPeImageException() : base("The PE image is invalid or corrupted.") { }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidPeImageException"/> class with a custom message.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        public InvalidPeImageException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidPeImageException"/> class with a custom message and inner exception.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public InvalidPeImageException(string message, Exception innerException)
            : base(message, innerException) { }
    }
}