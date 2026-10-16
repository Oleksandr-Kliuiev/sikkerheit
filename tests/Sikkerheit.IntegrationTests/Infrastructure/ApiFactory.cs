using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sikkerheit.Host.M365;

namespace Sikkerheit.IntegrationTests.Infrastructure;

/// <summary>The service in the Testing environment on the shared PostgreSQL, with the development login enabled.</summary>
public sealed class ApiFactory(string connectionString, string? securityLogDirectory = null, string? filesDirectory = null)
    : WebApplicationFactory<Program>
{
    /// <summary>A service instance on its own database copied from the migrated template.</summary>
    public static async Task<ApiFactory> CreateAsync(PostgresFixture postgres, string? securityLogDirectory = null) =>
        new(await postgres.CreateDatabaseAsync(), securityLogDirectory);

    /// <summary>The app role connection string of this instance's database.</summary>
    public string ConnectionString => connectionString;

    /// <summary>The fake Graph shared by this factory: tenants, requests and token provider.</summary>
    public FakeGraph Graph { get; } = new();

    public string SecurityLogDirectory { get; } =
        securityLogDirectory ?? Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"));

    /// <summary>Report and export files of this factory; a restore test shares them between the instances before and after.</summary>
    public string FilesDirectory { get; } =
        filesDirectory ?? Path.Combine(Path.GetTempPath(), "sikkerheit-tests", Guid.NewGuid().ToString("N"), "files");

    /// <summary>«Now» of the service; tests move it to run scenarios over days and weeks.</summary>
    public TestClock Clock { get; } = new();

    /// <summary>Entra stand-in for the staff sign-in.</summary>
    public FakeStaffIdentity StaffIdentity { get; } = new();

    /// <summary>The Teams webhook: captured digest messages.</summary>
    public CapturingHandler Teams { get; } = new();

    /// <summary>The MSRC CVRF API: release documents by month (release_import).</summary>
    public FakeMsrc Msrc { get; } = new();

    public const string TeamsWebhook = "https://teams.test/workflows/digest";

    /// <summary>Extra configuration of this instance (for example M365:CompanyTenantId); set before the first request.</summary>
    public Dictionary<string, string?> Settings { get; } = [];

    /// <summary>Log records of this instance: errors are what the alerts of 06 react to.</summary>
    public LogCapture Logs { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:Sikkerheit", connectionString);
        builder.UseSetting("Auth:DevelopmentLogin", "true");
        builder.UseSetting("SecurityLog:Directory", SecurityLogDirectory);
        builder.UseSetting("Storage:LocalDirectory", FilesDirectory);
        builder.UseSetting("Teams:WebhookUrl", TeamsWebhook);
        builder.UseSetting("Auth:Entra:TenantId", "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        builder.UseSetting("Auth:Entra:ClientId", "99999999-8888-4777-8666-555555555555");
        builder.UseSetting("Auth:Entra:RedirectUri", "https://localhost/auth/callback");
        builder.UseSetting("Teams:PortalUrl", "https://portal.test");
        builder.UseSetting("Database:MigrateOnStart", "false");
        builder.UseSetting("M365:ClientId", "11111111-2222-4333-8444-555555555555");
        builder.UseSetting("M365:ConsentRedirectUri", "https://localhost/consent-complete");
        foreach (var (key, value) in Settings)
        {
            builder.UseSetting(key, value);
        }
        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<Microsoft.Extensions.Logging.ILoggerProvider>(Logs);
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider>(Clock);
            services.RemoveAll<Sikkerheit.Host.Access.IStaffIdentityProvider>();
            services.AddSingleton<Sikkerheit.Host.Access.IStaffIdentityProvider>(StaffIdentity);
            services.AddHttpClient(Sikkerheit.Host.Reports.TeamsDigestJob.HttpClientName)
                .ConfigurePrimaryHttpMessageHandler(() => Teams);
            services.AddHttpClient(Sikkerheit.Host.Assessment.ReleaseImportJob.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => Msrc);
            services.AddHttpClient<GraphClient>().ConfigurePrimaryHttpMessageHandler(() => Graph);
            services.RemoveAll<IGraphTokenProvider>();
            services.AddSingleton<IGraphTokenProvider>(new FakeGraphTokens(Graph));
            services.RemoveAll<ITenantResolver>();
            services.AddSingleton<ITenantResolver>(new FakeTenantResolver(Graph));
            services.RemoveAll<GraphRetryPolicy>();
            services.AddSingleton(new GraphRetryPolicy { BaseDelay = TimeSpan.FromMilliseconds(10) });
        });
    }
}
