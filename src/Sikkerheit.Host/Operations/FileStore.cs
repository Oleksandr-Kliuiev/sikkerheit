using Azure;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace Sikkerheit.Host.Operations;

/// <summary>
/// Private files of organizations (06 «Ресурсы Azure»): containers reports and exports, keys under the organization
/// prefix. Files leave only through the service after the scope and role checks.
/// </summary>
public interface IFileStore
{
    Task PutAsync(string container, string key, byte[] content, string contentType, CancellationToken ct);
    Task<byte[]?> GetAsync(string container, string key, CancellationToken ct);
    Task DeleteAsync(string container, string key, CancellationToken ct);
    Task DeletePrefixAsync(string container, string prefix, CancellationToken ct);

    /// <summary>Keys of all files under the prefix, for the restore check of files without database rows.</summary>
    IAsyncEnumerable<string> ListAsync(string container, string prefix, CancellationToken ct);

    /// <summary>Moves a file to another key of the same container; the source is removed after the copy.</summary>
    Task MoveAsync(string container, string fromKey, string toKey, CancellationToken ct);
}

public static class FileContainers
{
    public const string Reports = "reports";
    public const string Exports = "exports";
    public static readonly string[] All = [Reports, Exports];

    public static string OrganizationPrefix(Guid organizationId) => organizationId + "/";

    /// <summary>
    /// Files without database rows after a restore (06, step 5). A storage lifecycle rule deletes them after 30 days;
    /// the organization prefix does not cover them, so a deletion of the organization leaves them to that rule.
    /// </summary>
    public const string QuarantinePrefix = "restore-orphans/";
}

/// <summary>Development and tests: files in a local directory, one subdirectory per container.</summary>
public sealed class LocalFileStore(string root) : IFileStore
{
    private string ContainerDirectory(string container) => FileContainers.All.Contains(container)
        ? Path.GetFullPath(Path.Combine(root, container)) + Path.DirectorySeparatorChar
        : throw new ArgumentOutOfRangeException(nameof(container));

    private string PathOf(string container, string key)
    {
        var baseDirectory = ContainerDirectory(container);
        var full = Path.GetFullPath(Path.Combine(baseDirectory, key));
        if (!full.StartsWith(baseDirectory, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("File key escapes its container");
        }
        return full;
    }

    public async Task PutAsync(string container, string key, byte[] content, string contentType, CancellationToken ct)
    {
        var path = PathOf(container, key);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, content, ct);
    }

    public async Task<byte[]?> GetAsync(string container, string key, CancellationToken ct)
    {
        var path = PathOf(container, key);
        return File.Exists(path) ? await File.ReadAllBytesAsync(path, ct) : null;
    }

    public Task DeleteAsync(string container, string key, CancellationToken ct)
    {
        File.Delete(PathOf(container, key));
        return Task.CompletedTask;
    }

    public Task DeletePrefixAsync(string container, string prefix, CancellationToken ct)
    {
        var path = PathOf(container, prefix);
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
        return Task.CompletedTask;
    }

    public async IAsyncEnumerable<string> ListAsync(string container, string prefix,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var baseDirectory = ContainerDirectory(container);
        if (!Directory.Exists(baseDirectory))
        {
            yield break;
        }
        foreach (var file in Directory.EnumerateFiles(baseDirectory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested();
            var key = Path.GetRelativePath(baseDirectory, file).Replace(Path.DirectorySeparatorChar, '/');
            if (key.StartsWith(prefix, StringComparison.Ordinal))
            {
                yield return key;
            }
        }
        await Task.CompletedTask;
    }

    public Task MoveAsync(string container, string fromKey, string toKey, CancellationToken ct)
    {
        var target = PathOf(container, toKey);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.Move(PathOf(container, fromKey), target, overwrite: true);
        return Task.CompletedTask;
    }
}

/// <summary>Azure: private containers of the storage account by managed identity (no account keys, no public links).</summary>
public sealed class BlobFileStore(Uri accountUri) : IFileStore
{
    private readonly BlobServiceClient _service = new(accountUri, new DefaultAzureCredential());

    private BlobContainerClient Container(string container) => FileContainers.All.Contains(container)
        ? _service.GetBlobContainerClient(container)
        : throw new ArgumentOutOfRangeException(nameof(container));

    public async Task PutAsync(string container, string key, byte[] content, string contentType, CancellationToken ct) =>
        await Container(container).GetBlobClient(key).UploadAsync(new BinaryData(content),
            new BlobUploadOptions { HttpHeaders = new BlobHttpHeaders { ContentType = contentType } }, ct);

    public async Task<byte[]?> GetAsync(string container, string key, CancellationToken ct)
    {
        try
        {
            var result = await Container(container).GetBlobClient(key).DownloadContentAsync(ct);
            return result.Value.Content.ToArray();
        }
        catch (RequestFailedException error) when (error.Status == 404)
        {
            return null;
        }
    }

    public async Task DeleteAsync(string container, string key, CancellationToken ct) =>
        await Container(container).DeleteBlobIfExistsAsync(key, cancellationToken: ct);

    public async Task DeletePrefixAsync(string container, string prefix, CancellationToken ct)
    {
        var client = Container(container);
        await foreach (var blob in client.GetBlobsAsync(BlobTraits.None, BlobStates.None, prefix, ct))
        {
            await client.DeleteBlobIfExistsAsync(blob.Name, cancellationToken: ct);
        }
    }

    public async IAsyncEnumerable<string> ListAsync(string container, string prefix,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var blob in Container(container).GetBlobsAsync(BlobTraits.None, BlobStates.None, prefix, ct))
        {
            yield return blob.Name;
        }
    }

    // A download and upload instead of a server-side copy: the files are small and a copy by URL would need a
    // separately authorized source.
    public async Task MoveAsync(string container, string fromKey, string toKey, CancellationToken ct)
    {
        var client = Container(container);
        var source = await client.GetBlobClient(fromKey).DownloadContentAsync(ct);
        await client.GetBlobClient(toKey).UploadAsync(source.Value.Content, new BlobUploadOptions
        {
            HttpHeaders = new BlobHttpHeaders { ContentType = source.Value.Details.ContentType },
        }, ct);
        await client.DeleteBlobIfExistsAsync(fromKey, cancellationToken: ct);
    }
}
