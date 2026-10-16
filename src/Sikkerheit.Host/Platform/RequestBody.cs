using System.Security.Cryptography;
using System.Text.Json;
using Sikkerheit.Contracts;

namespace Sikkerheit.Host.Platform;

/// <summary>A request body that passed the contract schema; RawHash is SHA-256 of the raw bytes.</summary>
public sealed record ValidatedBody<T>(T Value, JsonElement Json, string RawHash);

/// <summary>
/// Reads a JSON body under the size limit and validates it against the OpenAPI component before binding:
/// 415 media type, 413 size, 400 invalid JSON, 422 schema violation (05 «Ошибки и действия агента»).
/// </summary>
public sealed class RequestBodies(ContractSchemas schemas)
{
    public const int PortalLimit = 65536;

    public async Task<ValidatedBody<T>> ReadAsync<T>(HttpContext context, string component, int limit = PortalLimit)
    {
        var (bytes, json) = await ReadJsonAsync(context, limit);
        var violations = schemas.ValidateComponent(component, json);
        if (violations.Count > 0)
        {
            var first = violations[0];
            throw new ApiProblemException(ProblemCodes.SchemaViolation, $"{first.InstanceLocation} {first.Message}".Trim());
        }
        var value = json.Deserialize<T>(ApiJson.Options)
            ?? throw new ApiProblemException(ProblemCodes.SchemaViolation, "empty body");
        return new ValidatedBody<T>(value, json, Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }

    /// <summary>Media type, size and JSON syntax only (415, 413, 400): the caller validates the content itself.</summary>
    public static async Task<(byte[] Bytes, JsonElement Json)> ReadJsonAsync(HttpContext context, int limit)
    {
        var request = context.Request;
        if (request.Headers.ContentEncoding.Count > 0 || !IsJson(request.ContentType))
        {
            throw new ApiProblemException(ProblemCodes.UnsupportedMediaType);
        }
        if (request.ContentLength > limit)
        {
            throw new ApiProblemException(ProblemCodes.PayloadTooLarge);
        }
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await request.Body.ReadAsync(chunk, context.RequestAborted)) > 0)
        {
            if (buffer.Length + read > limit)
            {
                throw new ApiProblemException(ProblemCodes.PayloadTooLarge);
            }
            buffer.Write(chunk, 0, read);
        }
        var bytes = buffer.ToArray();
        JsonElement json;
        try
        {
            using var document = JsonDocument.Parse(bytes);
            json = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new ApiProblemException(ProblemCodes.InvalidJson);
        }
        return (bytes, json);
    }

    private static bool IsJson(string? contentType) =>
        contentType is not null && contentType.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase);
}
