using System.Globalization;

namespace Sikkerheit.Agent.Collectors.Mapping;

public static class Iso
{
    /// <summary>UTC date-time in the form required by the contracts: <c>2026-10-14T10:01:00Z</c>.</summary>
    public static string Format(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    public static string? FormatOrNull(DateTimeOffset? value) => value is null ? null : Format(value.Value);
}
