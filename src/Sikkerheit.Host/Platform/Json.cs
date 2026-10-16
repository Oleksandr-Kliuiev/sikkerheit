using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sikkerheit.Host.Platform;

public static class ApiJson
{
    /// <summary>Wire format of the API: camelCase, nulls written (contract fields are required even when null).</summary>
    public static readonly JsonSerializerOptions Options = Configure(new JsonSerializerOptions(JsonSerializerDefaults.Web));

    public static JsonSerializerOptions Configure(JsonSerializerOptions options)
    {
        options.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.DefaultIgnoreCondition = JsonIgnoreCondition.Never;
        options.Encoder = JavaScriptEncoder.Default;
        if (!options.Converters.OfType<UtcTimeConverter>().Any())
        {
            options.Converters.Add(new UtcTimeConverter());
        }
        return options;
    }

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
}

/// <summary>Writes every DateTimeOffset as UTC with at most microseconds and Z, as the contract patterns require.</summary>
public sealed class UtcTimeConverter : JsonConverter<DateTimeOffset>
{
    public static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'", CultureInfo.InvariantCulture);

    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        DateTimeOffset.Parse(reader.GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal).ToUniversalTime();

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) =>
        writer.WriteStringValue(Format(value));
}
