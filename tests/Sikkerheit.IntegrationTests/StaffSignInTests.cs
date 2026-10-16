using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Access;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.IntegrationTests;

/// <summary>FR-02: staff sign-in with Entra (code flow + PKCE on the server), MFA proof, roles and hourly refresh.</summary>
public sealed class StaffSignInTests(PostgresFixture postgres) : IAsyncLifetime
{
    private ApiFactory _factory = null!;

    public async ValueTask InitializeAsync()
    {
        _factory = await ApiFactory.CreateAsync(postgres);
        _factory.Clock.SetLocal("Europe/Oslo", 2026, 10, 7, 9);
    }

    public async ValueTask DisposeAsync() => await _factory.DisposeAsync();

    private CancellationToken Ct => TestContext.Current.CancellationToken;

    private HttpClient Browser() => _factory.CreateClient(new()
    {
        BaseAddress = new Uri("https://localhost"), HandleCookies = true, AllowAutoRedirect = false,
    });

    private static StaffIdentity Staff(Guid id, params string[] roles) => new(id, "Kari Tekniker", roles, [1, 2, 3]);

    /// <summary>/auth/login → (Entra) → /auth/callback with the issued code; returns the final redirect.</summary>
    private async Task<HttpResponseMessage> SignInAsync(HttpClient browser, string code, string returnUrl = "/organizations",
        Func<string, string>? tamperState = null)
    {
        var login = await browser.GetAsync("/auth/login?returnUrl=" + Uri.EscapeDataString(returnUrl), Ct);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        var authorize = QueryHelpers.ParseQuery(login.Headers.Location!.Query);
        var state = authorize["state"].ToString();
        Assert.False(string.IsNullOrEmpty(authorize["nonce"].ToString()));
        return await browser.GetAsync($"/auth/callback?code={code}&state={Uri.EscapeDataString(tamperState?.Invoke(state) ?? state)}", Ct);
    }

    private async Task<StaffClient.Answer> MeAsync(HttpClient browser) =>
        await StaffClient.Answer.ReadAsync(await browser.GetAsync("/api/v1/me", Ct), "CurrentStaff");

    [Fact]
    public async Task Sign_in_creates_a_server_session_and_returns_to_the_local_page()
    {
        var id = Guid.NewGuid();
        _factory.StaffIdentity.Issue("good", Staff(id, "Technician"));
        using var browser = Browser();
        var callback = await SignInAsync(browser, "good");
        Assert.Equal("/organizations", callback.Headers.Location!.ToString());
        var cookie = callback.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith(StaffSessions.CookieName, StringComparison.Ordinal));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(_factory.StaffIdentity.LastVerifier);

        var me = await MeAsync(browser);
        Assert.Equal(HttpStatusCode.OK, me.Status);
        Assert.Equal(id.ToString(), me.Body.GetProperty("entraUserId").GetString());
        Assert.Equal(["Technician"], me.Body.GetProperty("roles").EnumerateArray().Select(r => r.GetString()!));
    }

    [Fact]
    public async Task Callback_needs_the_state_of_this_browser_once_and_mfa()
    {
        var id = Guid.NewGuid();
        _factory.StaffIdentity.Issue("good", Staff(id, "Admin"));
        using var browser = Browser();
        var tampered = await SignInAsync(browser, "good", tamperState: s => s + "x");
        Assert.Equal("/?signin=failed&reason=error", tampered.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await MeAsync(browser)).Status);

        // Another browser without the attempt cookie cannot use a stolen state and code.
        var login = await browser.GetAsync("/auth/login", Ct);
        var state = QueryHelpers.ParseQuery(login.Headers.Location!.Query)["state"].ToString();
        using var other = Browser();
        var injected = await other.GetAsync($"/auth/callback?code=good&state={Uri.EscapeDataString(state)}", Ct);
        Assert.Equal("/?signin=failed&reason=error", injected.Headers.Location!.ToString());

        _factory.StaffIdentity.Refuse("nomfa", "mfa_required");
        var noMfa = await SignInAsync(browser, "nomfa");
        Assert.Equal("/?signin=failed&reason=mfa_required", noMfa.Headers.Location!.ToString());
        _factory.StaffIdentity.Refuse("norole", "no_role");
        Assert.Equal("/?signin=failed&reason=no_role", (await SignInAsync(browser, "norole")).Headers.Location!.ToString());

        var denied = await browser.GetAsync("/auth/callback?error=access_denied&state=x", Ct);
        Assert.Equal("/?signin=failed&reason=cancelled", denied.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData("//evil.example/x", "/")]
    [InlineData("https://evil.example", "/")]
    [InlineData("/\\evil.example", "/")]
    [InlineData("/findings?severity=critical", "/findings?severity=critical")]
    public async Task Return_address_is_only_a_local_path(string returnUrl, string expected)
    {
        _factory.StaffIdentity.Issue("good", Staff(Guid.NewGuid(), "Reader"));
        using var browser = Browser();
        var callback = await SignInAsync(browser, "good", returnUrl);
        Assert.Equal(expected, callback.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Hourly_refresh_takes_new_roles_and_a_refusal_ends_the_session()
    {
        var id = Guid.NewGuid();
        _factory.StaffIdentity.Issue("good", Staff(id, "Admin"));
        using var browser = Browser();
        await SignInAsync(browser, "good");
        Assert.Equal(HttpStatusCode.OK, (await MeAsync(browser)).Status);

        _factory.StaffIdentity.Refresh = user => Staff(user, "Reader");
        _factory.Clock.SetLocal("Europe/Oslo", 2026, 10, 7, 9, 40);
        Assert.Equal(["Admin"], (await MeAsync(browser)).Body.GetProperty("roles").EnumerateArray().Select(r => r.GetString()!));
        _factory.Clock.SetLocal("Europe/Oslo", 2026, 10, 7, 10, 5);
        Assert.Equal(["Reader"], (await MeAsync(browser)).Body.GetProperty("roles").EnumerateArray().Select(r => r.GetString()!));

        // The account is disabled in Entra: the next refresh fails, the session ends and the staff member is inactive.
        _factory.StaffIdentity.Refresh = _ => throw new StaffSignInException("refresh_failed", "AADSTS50057");
        _factory.Clock.SetLocal("Europe/Oslo", 2026, 10, 7, 10, 40);
        Assert.Equal(HttpStatusCode.OK, (await MeAsync(browser)).Status);
        _factory.Clock.SetLocal("Europe/Oslo", 2026, 10, 7, 11, 6);
        var ended = await MeAsync(browser);
        Assert.Equal((HttpStatusCode.Unauthorized, ProblemCodes.SessionRequired), (ended.Status, ended.Code));
        var admin = await StaffClient.SignInAsync(_factory, "Admin");
        var staff = await admin.GetAsync("/api/v1/staff?limit=100", "StaffUserPage");
        var row = staff.Body.GetProperty("items").EnumerateArray().Single(s => s.GetProperty("entraUserId").GetString() == id.ToString());
        Assert.False(row.GetProperty("active").GetBoolean());
        _ = JsonValueKind.Null;
    }
}
