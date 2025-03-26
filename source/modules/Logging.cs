using System;

/// <summary>
/// Logger class for printing colored messages to the console.
/// </summary>
public static class Logging {
    // Lock object to ensure thread-safety during logging.
    private static readonly object _lock = new object();

    /// <summary>
    /// Writes a colored message to the console.
    /// The message can include color tags in the format /CLR(COLOR_NAME)TEXT,
    /// where COLOR_NAME is a valid console color (e.g., RED, GREEN, BLUE, etc.).
    /// </summary>
    /// <param name="message">The message to write to the console with embedded color tags.</param>
    public static void Write(string message) {
        // Ensure thread-safety while logging by locking the critical section
        lock (_lock) {
            // Split the message into parts based on the color tag "/CLR("
            string[] parts = message.Split("/CLR(", StringSplitOptions.None);

            // Start with the default white color for text
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(parts[0]);

            // Process each part that follows a color tag
            for (int i = 1; i < parts.Length; i++) {
                // Find the closing parenthesis of the color tag
                int close = parts[i].IndexOf(")");
                if (close > 0) {
                    // Extract the color name (before the closing parenthesis)
                    string colorName = parts[i].Substring(0, close);
                    // Extract the text after the closing parenthesis
                    string text = parts[i].Substring(close + 1);

                    // Try to parse the color name to a valid ConsoleColor
                    if (Enum.TryParse<ConsoleColor>(colorName, true, out var color)) {
                        // Set the console text color
                        Console.ForegroundColor = color;
                    }
                    // Write the colored text to the console
                    Console.Write(text);
                }
            }

            // Print a newline after the message
            Console.WriteLine();
            // Reset the console color back to the default color
            Console.ResetColor();
        }
    }
}
