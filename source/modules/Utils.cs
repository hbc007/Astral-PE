using System;
public static class StringsWorker {
    /// <summary>
    /// Randomizes the case of each character in the provided string.
    /// </summary>
    /// <param name="s">The string whose case will be randomized.</param>
    /// <returns>A new string with randomized case for each character.</returns>
    public static string RandomizeCase(string s) {
        Random rnd = new();
        // Randomly convert each character to upper or lower case.
        return new string(s.Select(c => rnd.Next(2) == 0 ? char.ToLowerInvariant(c) : char.ToUpperInvariant(c)).ToArray());
    }
}
