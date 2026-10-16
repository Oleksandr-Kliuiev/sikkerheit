using System.Net;
using System.Text;

namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>The MSRC CVRF API for the tests: documents by month, and the requests that reached it.</summary>
public sealed class FakeMsrc : HttpMessageHandler
{
    public Dictionary<string, string> Documents { get; } = [];
    public List<Uri> Requests { get; } = [];

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        lock (Requests)
        {
            Requests.Add(request.RequestUri!);
        }
        var month = request.RequestUri!.Segments[^1];
        return Task.FromResult(Documents.TryGetValue(month, out var document)
            ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(document, Encoding.UTF8, "application/json") }
            : new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
