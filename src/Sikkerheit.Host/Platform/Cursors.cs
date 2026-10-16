using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sikkerheit.Contracts;

namespace Sikkerheit.Host.Platform;

/// <summary>
/// Opaque cursors bound to the operation, the organization and the filter, signed with HMAC-SHA256.
/// A cursor of another operation, organization or filter, or a changed one, gives 400 invalid_cursor.
/// </summary>
public sealed class Cursors(byte[] key)
{
    public string Create(string operation, Guid? organizationId, string filter, IReadOnlyList<string> position)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(new CursorPayload(operation, organizationId, filter, position));
        var signature = HMACSHA256.HashData(key, payload);
        return Base64Url(payload) + "." + Base64Url(signature);
    }

    public IReadOnlyList<string>? Read(string? cursor, string operation, Guid? organizationId, string filter)
    {
        if (string.IsNullOrEmpty(cursor))
        {
            return null;
        }
        var parts = cursor.Split('.');
        if (parts.Length != 2 || cursor.Length > 2048)
        {
            throw new ApiProblemException(ProblemCodes.InvalidCursor);
        }
        try
        {
            var payload = FromBase64Url(parts[0]);
            var expected = HMACSHA256.HashData(key, payload);
            if (!CryptographicOperations.FixedTimeEquals(expected, FromBase64Url(parts[1])))
            {
                throw new ApiProblemException(ProblemCodes.InvalidCursor);
            }
            var value = JsonSerializer.Deserialize<CursorPayload>(payload)!;
            if (value.Operation != operation || value.OrganizationId != organizationId || value.Filter != filter)
            {
                throw new ApiProblemException(ProblemCodes.InvalidCursor);
            }
            return value.Position;
        }
        catch (FormatException)
        {
            throw new ApiProblemException(ProblemCodes.InvalidCursor);
        }
        catch (JsonException)
        {
            throw new ApiProblemException(ProblemCodes.InvalidCursor);
        }
    }

    public static string Filter(params (string Name, string? Value)[] items) =>
        string.Join('&', items.Where(i => i.Value is not null).Select(i => i.Name + "=" + i.Value));

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string text)
    {
        var padded = text.Replace('-', '+').Replace('_', '/');
        padded += new string('=', (4 - padded.Length % 4) % 4);
        return Convert.FromBase64String(padded);
    }

    private sealed record CursorPayload(string Operation, Guid? OrganizationId, string Filter, IReadOnlyList<string> Position);
}

public sealed record Page<T>(IReadOnlyList<T> Items, string? NextCursor);
