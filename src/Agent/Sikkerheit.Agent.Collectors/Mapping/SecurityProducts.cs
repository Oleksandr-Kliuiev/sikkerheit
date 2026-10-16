using System.Text.Json.Nodes;

namespace Sikkerheit.Agent.Collectors.Mapping;

/// <summary>Mapping of Windows Security Center and Defender states to the closed enumerations of the contract.</summary>
public static class SecurityProducts
{
    public const int MaxProducts = 10;

    /// <summary>
    /// Decodes the middle byte of <c>productState</c> of root\SecurityCenter2: 0x10 on, 0x00 off, 0x01 snoozed, 0x11 expired.
    /// Another value is "unknown" with the raw state (03, WIN-003); SP-04 confirms the table on real products.
    /// </summary>
    public static string ProductState(uint raw) => ((raw >> 8) & 0xFF) switch
    {
        0x10 => "on",
        0x00 => "off",
        0x01 => "snoozed",
        0x11 => "expired",
        _ => "unknown",
    };

    public static string AmRunningMode(string raw) => raw.Trim().ToLowerInvariant() switch
    {
        "normal" => "normal",
        "passive mode" or "passive" => "passive",
        "edr block mode" or "edr_block" => "edr_block",
        "sxs passive mode" or "sxs_passive" => "sxs_passive",
        "not running" or "not_running" => "not_running",
        _ => "other",
    };

    public static bool IsDefenderName(string name) =>
        name.StartsWith("Windows Defender", StringComparison.OrdinalIgnoreCase)
        || name.StartsWith("Microsoft Defender", StringComparison.OrdinalIgnoreCase);

    /// <summary>The item of products[] for a Security Center product.</summary>
    public static JsonObject AntivirusItem(SecurityProductRaw product)
    {
        var state = ProductState(product.ProductState);
        return new JsonObject
        {
            ["provider"] = Clean(product.DisplayName),
            ["productState"] = state,
            ["statusSource"] = "windows_security_center",
            ["rawState"] = state == "unknown" ? (JsonNode)(long)product.ProductState : null,
        };
    }

    public static JsonObject DefenderItem(DefenderRaw defender) => new()
    {
        ["provider"] = "Microsoft Defender Antivirus",
        ["productState"] = defender.AntivirusEnabled ? "on" : "off",
        ["statusSource"] = "defender",
        ["rawState"] = null,
    };

    public static JsonObject FirewallItem(SecurityProductRaw product) => new()
    {
        ["provider"] = Clean(product.DisplayName),
        ["productState"] = ProductState(product.ProductState),
    };

    /// <summary>A product name is an untrusted string: control characters are removed, the length is limited.</summary>
    public static string Clean(string name)
    {
        var chars = name.Where(c => !char.IsControl(c) && c != '<' && c != '>').ToArray();
        var text = new string(chars).Trim();
        if (text.Length == 0)
        {
            return "unknown";
        }
        return text.Length > 120 ? text[..120] : text;
    }
}
