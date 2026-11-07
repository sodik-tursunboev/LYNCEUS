namespace Lynceus.Agent;

/// <summary>
/// File type by content, never by name. A port of core/sandbox/guest/filetype.py: both are tested
/// against tests/fixtures/filetypes.json, so a change to one without the other fails a test.
/// </summary>
public static class FileSignatures
{
    /// <summary>How many leading bytes the detector can look at (the ISO marker sits at 0x8001).</summary>
    public const int HeadBytes = 0x8006;

    private static readonly (byte[] Signature, string Name)[] Table =
    [
        (Hex("255044462d"), "pdf"), (Hex("504b0304"), "zip"), (Hex("504b0506"), "zip"),
        (Hex("526172211a07"), "rar"), (Hex("377abcaf271c"), "7z"), (Hex("1f8b"), "gz"),
        (Hex("425a68"), "bz2"), (Hex("fd377a585a00"), "xz"), (Hex("4d5a"), "exe"),
        (Hex("7f454c46"), "elf"), (Hex("d0cf11e0"), "ole"), (Hex("7b5c727466"), "rtf"),
        (Hex("89504e47"), "png"), (Hex("ffd8ff"), "jpeg"), (Hex("47494638"), "gif"),
        (Hex("424d"), "bmp"), (Hex("49492a00"), "tiff"), (Hex("4d4d002a"), "tiff"),
        (Hex("4c00000001140200"), "lnk"),
    ];

    private static readonly string[] HtmlStarts = ["<!doctype html", "<html", "<head", "<body", "<script", "<meta"];

    public static string? Detect(ReadOnlySpan<byte> data)
    {
        foreach (var (signature, name) in Table)
        {
            if (data.StartsWith(signature))
            {
                return name;
            }
        }

        if (data.Length >= 12 && data[..4].SequenceEqual("RIFF"u8) && data.Slice(8, 4).SequenceEqual("WEBP"u8))
        {
            return "webp";
        }

        if (data.Length >= 0x8006 && data.Slice(0x8001, 5).SequenceEqual("CD001"u8))
        {
            return "iso";
        }

        if (data.Length >= 262 && data.Slice(257, 5).SequenceEqual("ustar"u8))
        {
            return "tar";
        }

        var head = data[..Math.Min(512, data.Length)];
        var start = 0;
        while (start < head.Length && IsStripped(head[start]))
        {
            start++;
        }

        Span<byte> text = stackalloc byte[head.Length - start];
        for (var i = 0; i < text.Length; i++)
        {
            var b = head[start + i];
            text[i] = b is >= (byte)'A' and <= (byte)'Z' ? (byte)(b + 32) : b;
        }

        foreach (var prefix in HtmlStarts)
        {
            if (StartsWithAscii(text, prefix))
            {
                return "html";
            }
        }

        return text.IndexOf("<svg"u8) >= 0 ? "svg" : null;
    }

    private static bool IsStripped(byte b) => b is 0xef or 0xbb or 0xbf or (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n';

    private static bool StartsWithAscii(ReadOnlySpan<byte> text, string prefix)
    {
        if (text.Length < prefix.Length)
        {
            return false;
        }

        for (var i = 0; i < prefix.Length; i++)
        {
            if (text[i] != prefix[i])
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);
}
