using System;
using System.IO;
using System.Reflection;
using System.Text;

namespace KeePassPasskeyProvider.Plugin;

/// <summary>
/// Loads the embedded SVG logos for light and dark Windows themes.
/// Returned strings are base64-encoded UTF-8 SVG, as required by
/// WebAuthNPluginAddAuthenticator (pwszLightThemeLogoSvg / pwszDarkThemeLogoSvg).
/// </summary>
internal static class LogoResources
{
    public static string DarkThemeSvg  { get; } = Load("logo-dark.svg");
    public static string LightThemeSvg { get; } = Load("logo-light.svg");

    private static string Load(string fileName)
    {
        var asm = Assembly.GetExecutingAssembly();
        using Stream stream = asm.GetManifestResourceStream(
            $"KeePassPasskeyProvider.Resources.{fileName}")!;
        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return Convert.ToBase64String(ms.ToArray());
    }
}
