using System.Text.Json;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Operations;

/// <summary>Record of the append-only security log (04 «Журнал безопасности»).</summary>
public sealed record SecurityLogRecord(
    Guid Id, string Action, Guid OrganizationId, string TargetType, string TargetId, DateTimeOffset OccurredAt,
    string CorrelationId, Guid? EntraUserId, DateTimeOffset? DeletionDueAt = null, Guid? InstallationId = null,
    string? KeyThumbprint = null, Guid? EnrollmentKeyId = null);

/// <summary>The log could not be written; the restrictive action must not happen (503).</summary>
public sealed class SecurityLogUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

public interface ISecurityLog
{
    /// <summary>Creates one record; never overwrites. Throws SecurityLogUnavailableException on failure.</summary>
    Task AppendAsync(SecurityLogRecord record, CancellationToken ct);

    /// <summary>Records with occurredAt at or after the point, in time order (restore replay).</summary>
    IAsyncEnumerable<SecurityLogRecord> ReadSinceAsync(DateTimeOffset since, CancellationToken ct);
}

/// <summary>
/// File implementation for development and tests: one file per record, created only if absent.
/// Production uses the immutable Blob container of 06.
/// </summary>
public sealed class FileSecurityLog(string directory) : ISecurityLog
{
    public async Task AppendAsync(SecurityLogRecord record, CancellationToken ct)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var name = $"{record.OccurredAt.UtcDateTime:yyyyMMdd'T'HHmmssfffffff'Z'}-{record.Id:N}.json";
            await using var stream = new FileStream(Path.Combine(directory, name), FileMode.CreateNew, FileAccess.Write);
            await JsonSerializer.SerializeAsync(stream, record, ApiJson.Options, ct);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new SecurityLogUnavailableException("security log write failed", error);
        }
    }

    public async IAsyncEnumerable<SecurityLogRecord> ReadSinceAsync(DateTimeOffset since,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        if (!Directory.Exists(directory))
        {
            yield break;
        }
        var records = new List<SecurityLogRecord>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.json"))
        {
            await using var stream = File.OpenRead(file);
            var record = await JsonSerializer.DeserializeAsync<SecurityLogRecord>(stream, ApiJson.Options, ct);
            if (record is not null && record.OccurredAt >= since)
            {
                records.Add(record);
            }
        }
        foreach (var record in records.OrderBy(r => r.OccurredAt).ThenBy(r => r.Id))
        {
            yield return record;
        }
    }
}

/// <summary>
/// Production: the container security-log with a locked time-based immutability policy (06 «Ресурсы»). Every record
/// is its own blob created only when the name is free (If-None-Match: *); the service identity may only create.
/// </summary>
public sealed class BlobSecurityLog(Uri containerUri, Azure.Core.TokenCredential credential) : ISecurityLog
{
    private readonly Azure.Storage.Blobs.BlobContainerClient _container = new(containerUri, credential);

    internal static string Name(SecurityLogRecord record) =>
        $"{record.OccurredAt.UtcDateTime:yyyyMMdd'T'HHmmssfffffff'Z'}-{record.Id:N}.json";

    public async Task AppendAsync(SecurityLogRecord record, CancellationToken ct)
    {
        try
        {
            var content = BinaryData.FromBytes(JsonSerializer.SerializeToUtf8Bytes(record, ApiJson.Options));
            await _container.GetBlobClient(Name(record)).UploadAsync(content, new Azure.Storage.Blobs.Models.BlobUploadOptions
            {
                Conditions = new Azure.Storage.Blobs.Models.BlobRequestConditions { IfNoneMatch = Azure.ETag.All },
                HttpHeaders = new Azure.Storage.Blobs.Models.BlobHttpHeaders { ContentType = "application/json" },
            }, ct);
        }
        catch (Azure.RequestFailedException error)
        {
            throw new SecurityLogUnavailableException("security log write failed: " + error.Status, error);
        }
    }

    public async IAsyncEnumerable<SecurityLogRecord> ReadSinceAsync(DateTimeOffset since,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // Names start with the UTC time, so the listing order is the time order.
        var from = since.UtcDateTime.ToString("yyyyMMdd'T'HHmmssfffffff'Z'", System.Globalization.CultureInfo.InvariantCulture);
        await foreach (var item in _container.GetBlobsAsync(cancellationToken: ct))
        {
            if (string.CompareOrdinal(item.Name, from) < 0)
            {
                continue;
            }
            var content = await _container.GetBlobClient(item.Name).DownloadContentAsync(ct);
            var record = content.Value.Content.ToObjectFromJson<SecurityLogRecord>(ApiJson.Options);
            if (record is not null && record.OccurredAt >= since)
            {
                yield return record;
            }
        }
    }
}

