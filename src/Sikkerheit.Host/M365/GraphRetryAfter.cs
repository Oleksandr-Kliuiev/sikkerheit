using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;

namespace Sikkerheit.Host.M365;

internal static class GraphRetryAfter
{
    public static TimeSpan? Parse(string? value, DateTimeOffset now)
    {
        value = value?.Trim();
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }
        if (value.All(character => character is >= '0' and <= '9'))
        {
            return !ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
                || seconds > (ulong)(TimeSpan.MaxValue.Ticks / TimeSpan.TicksPerSecond)
                ? TimeSpan.MaxValue : TimeSpan.FromTicks((long)seconds * TimeSpan.TicksPerSecond);
        }
        if (RetryConditionHeaderValue.TryParse(value, out var header) && header.Date is { } date)
        {
            return date > now ? date - now : TimeSpan.Zero;
        }
        return null;
    }

    public static TimeSpan? Parse(JsonElement response, DateTimeOffset now)
    {
        if (response.TryGetProperty("headers", out var headers) && headers.ValueKind == JsonValueKind.Object)
        {
            foreach (var header in headers.EnumerateObject())
            {
                if (header.Name.Equals("Retry-After", StringComparison.OrdinalIgnoreCase))
                {
                    return Parse(header.Value.ValueKind == JsonValueKind.String ? header.Value.GetString()
                        : header.Value.ValueKind == JsonValueKind.Number ? header.Value.GetRawText() : null, now);
                }
            }
        }
        return null;
    }
}
