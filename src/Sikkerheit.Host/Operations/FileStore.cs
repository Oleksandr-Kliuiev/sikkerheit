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
}

public static class FileContainers
{
    public const string Reports = "reports";
    public const string Exports = "exports";
    public static readonly string[] All = [Reports, Exports];

    public static string OrganizationPrefix(Guid organizationId) => organizationId + "/";
}

/// <summary>Development and tests: files in a local directory, one subdirectory per container.</summary>
public sealed class LocalFileStore(string root) : IFileStore
{
    private string PathOf(string container, string key)
    {
        if (!FileContainers.All.Contains(container))
        {
            throw new ArgumentOutOfRangeException(nameof(container));
        }
        var baseDirectory = Path.GetFullPath(Path.Combine(root, container)) + Path.DirectorySeparatorChar;
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
}
