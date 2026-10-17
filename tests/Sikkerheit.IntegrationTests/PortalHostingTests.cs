using System.Net;
using System.Net.Http.Json;
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

    [Fact]
    public async Task Azure_agent_smoke_uses_the_real_contract_and_keeps_portal_and_agent_hosts_separate()
    {
        _factory.Settings["Hosting:PortalHosts:0"] = "portal.test";
        _factory.Settings["Hosting:AgentHosts:0"] = "agent.test";
        using var client = StaffClient.Anonymous(_factory);
        using var challenge = await client.PostAsJsonAsync("https://agent.test/api/v1/agent/challenges",
            new { purpose = "enroll" }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Created, challenge.StatusCode);
        using var portalChallenge = await client.PostAsJsonAsync("https://portal.test/api/v1/agent/challenges",
            new { purpose = "enroll" }, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, portalChallenge.StatusCode);
        using var agentPortal = await client.GetAsync("https://agent.test/api/v1/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, agentPortal.StatusCode);
        using var portal = await client.GetAsync("https://portal.test/api/v1/me", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, portal.StatusCode);
    }

    [Fact]
    public async Task M365_only_deployment_keeps_the_agent_routes_closed()
    {
        _factory.Settings["Hosting:PortalHosts:0"] = "localhost";
        _factory.Settings["Hosting:AgentHosts:0"] = "disabled.invalid";
        using var client = StaffClient.Anonymous(_factory);
        using var challenge = await client.PostAsJsonAsync("/api/v1/agent/challenges", new { purpose = "enroll" },
            TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, challenge.StatusCode);
    }
}
