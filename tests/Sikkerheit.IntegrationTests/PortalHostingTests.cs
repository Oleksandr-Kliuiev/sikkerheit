using System.Net;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Platform;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>04 «Недоверенные строки и выдача отчёта»: CSP and the other portal headers on every response.</summary>
public sealed class PortalHostingTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ApiFactory _factory = null!;

    public async ValueTask InitializeAsync() => _factory = await ApiFactory.CreateAsync(postgres);

    public async ValueTask DisposeAsync() => await _factory.DisposeAsync();

    [Theory]
    [InlineData("/api/v1/me", HttpStatusCode.Unauthorized)]
    [InlineData("/api/v1/no-such-operation", HttpStatusCode.NotFound)]
    [InlineData("/auth/no-such-route", HttpStatusCode.NotFound)]
    [InlineData("/health", HttpStatusCode.OK)]
    public async Task Every_response_carries_the_portal_security_headers(string path, HttpStatusCode status)
    {
        using var client = StaffClient.Anonymous(_factory);
        using var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        Assert.Equal(status, response.StatusCode);
        Assert.Equal(SecurityHeadersMiddleware.PortalPolicy, response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("same-origin", response.Headers.GetValues("Referrer-Policy").Single());
        if (status == HttpStatusCode.NotFound)
        {
            var answer = await StaffClient.Answer.ReadAsync(response, null);
            Assert.Equal(ProblemCodes.NotFound, answer.Code);
        }
    }
}
