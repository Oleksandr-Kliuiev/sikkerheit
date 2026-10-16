using System.Net;

namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>Records outgoing requests (the Teams webhook) and answers 202 like a Workflows trigger.</summary>
public sealed class CapturingHandler : HttpMessageHandler
{
    public List<(Uri Uri, string Body)> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct);
        lock (Requests)
        {
            Requests.Add((request.RequestUri!, body));
        }
        return new HttpResponseMessage(HttpStatusCode.Accepted);
    }
}
