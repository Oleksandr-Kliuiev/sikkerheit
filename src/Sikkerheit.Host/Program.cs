using Azure.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Npgsql;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Access;
using Sikkerheit.Host.Agents;
using Sikkerheit.Host.Assessment;
using Sikkerheit.Host.Data;
using Sikkerheit.Host.Jobs;
using Sikkerheit.Host.M365;
using Sikkerheit.Host.Operations;
using Sikkerheit.Host.Organizations;
using Sikkerheit.Host.Platform;
using Sikkerheit.Host.Reports;

// Maintenance commands run with the configuration of the service but without its web server and jobs (RB-05).
var maintenance = RestoreReplayCommand.Matches(args);
var configurationCheck = args is ["check-configuration"];
var builder = WebApplication.CreateBuilder(maintenance || configurationCheck ? [] : args);
var configuration = builder.Configuration;
var environment = builder.Environment;
ProductionConfiguration.Validate(configuration, environment);
if (maintenance)
{
    // The JSON report goes to stdout; every log line goes to stderr.
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
}

var developmentLogin = configuration.GetValue("Auth:DevelopmentLogin", false);
if (developmentLogin && !(environment.IsDevelopment() || environment.IsEnvironment("Testing")))
{
    throw new InvalidOperationException("Auth:DevelopmentLogin is allowed only in Development or Testing");
}
var appConnection = configuration.GetConnectionString("Sikkerheit")
    ?? throw new InvalidOperationException("ConnectionStrings:Sikkerheit is required");
var entraDatabase = configuration.GetValue("Database:EntraAuth", false);

builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 1024 * 1024);
builder.Services.ConfigureHttpJsonOptions(options => ApiJson.Configure(options.SerializerOptions));
builder.Services.AddSingleton(TimeProvider.System);
Telemetry.Add(builder.Services, configuration);
builder.Services.AddSingleton(_ =>
    DatabaseConnections.Create(appConnection, entraDatabase, configuration["Database:ManagedIdentityClientId"]));
builder.Services.AddSingleton<DbScopes>();
builder.Services.AddSingleton<SchemaMigrator>();
builder.Services.AddSingleton<ContractSchemas>();
builder.Services.AddSingleton<RequestBodies>();
builder.Services.AddSingleton<PolicyRules>();
builder.Services.AddSingleton<StaffSessions>();
var entra = configuration.GetSection("Auth:Entra").Get<EntraOptions>() ?? new EntraOptions();
builder.Services.AddSingleton(entra);
builder.Services.AddSingleton<IStaffIdentityProvider>(sp => entra.Configured
    ? new EntraStaffIdentityProvider(entra, sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<ILogger<EntraStaffIdentityProvider>>())
    : new UnconfiguredStaffIdentityProvider());
ConfigureDataProtection(builder.Services, configuration, environment);
builder.Services.AddSingleton(_ => new Cursors(ProductionConfiguration.HmacKey(configuration, environment, "Cursors:Key")));
builder.Services.AddSingleton(SecurityLog(configuration, environment));
builder.Services.AddSingleton(FileStore(configuration, environment));
var m365 = configuration.GetSection("M365").Get<M365Options>() ?? new M365Options();
builder.Services.AddSingleton(m365);
builder.Services.AddSingleton(new GraphRetryPolicy());
builder.Services.AddSingleton<IGraphRateStore, PostgresGraphRateStore>();
builder.Services.AddSingleton<GraphLimiter>();
builder.Services.AddSingleton(new CollectorOptions { PerUserMfa = m365.PerUserMfa });
builder.Services.AddHttpClient<GraphClient>().ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
{
    AllowAutoRedirect = false,
    // Handlers are retained by JobRunner. Refresh connections so Graph DNS changes are still observed.
    PooledConnectionLifetime = TimeSpan.FromMinutes(5),
});
builder.Services.AddHttpClient<ITenantResolver, OpenIdTenantResolver>();
builder.Services.AddSingleton<IGraphTokenProvider>(sp => string.IsNullOrEmpty(m365.ClientId) || string.IsNullOrEmpty(m365.KeyVaultUri)
    ? new UnconfiguredGraphTokenProvider()
    : new KeyVaultGraphTokenProvider(m365, sp.GetRequiredService<TimeProvider>()));
builder.Services.AddTransient<M365Collector>();
builder.Services.AddTransient<IJobHandler, M365CollectionJob>();
builder.Services.AddTransient<IJobHandler, Sikkerheit.Host.Assessment.FreshnessSweepJob>();
builder.Services.AddTransient<IJobHandler, Sikkerheit.Host.Assessment.ReviewExpiryJob>();
builder.Services.AddTransient<IJobHandler, Sikkerheit.Host.Assessment.RecalculatePolicyJob>();
builder.Services.AddSingleton(new AgentOptions
{
    NonceKey = ProductionConfiguration.HmacKey(configuration, environment, "Agents:NonceKey"),
    MinimumAgentVersion = configuration["Agents:MinimumAgentVersion"] ?? "0.1.0",
});
builder.Services.AddSingleton(sp => new Nonces(sp.GetRequiredService<AgentOptions>().NonceKey, sp.GetRequiredService<TimeProvider>()));
builder.Services.AddSingleton<AgentLimits>();
builder.Services.AddHttpClient(ReleaseImportJob.HttpClientName, client =>
{
    client.BaseAddress = new Uri("https://" + ReleaseImportJob.Host);
    client.Timeout = TimeSpan.FromSeconds(60);
});
builder.Services.AddTransient<IJobHandler, PatchLevelSweepJob>();
builder.Services.AddTransient<IJobHandler, ScanRequestExpiryJob>();
builder.Services.AddTransient<IJobHandler, AgentHealthJob>();
builder.Services.AddTransient<IJobHandler, ReleaseImportJob>();
builder.Services.AddTransient<IJobHandler, ReleaseCatalogCheckJob>();
builder.Services.AddTransient<ReportService>();
builder.Services.AddTransient<IJobHandler>(sp => sp.GetRequiredService<ReportService>());
builder.Services.AddTransient<IJobHandler, WeeklyReportJob>();
builder.Services.AddTransient<IJobHandler, Sikkerheit.Host.Exports.OrganizationExportJob>();
builder.Services.AddTransient<IJobHandler, OrganizationDeleteJob>();
builder.Services.AddTransient<IJobHandler, RetentionPurgeJob>();
builder.Services.AddTransient<IJobHandler, TeamsDigestJob>();
builder.Services.AddSingleton(configuration.GetSection("Teams").Get<TeamsOptions>() ?? new TeamsOptions());
builder.Services.AddHttpClient(TeamsDigestJob.HttpClientName, client => client.Timeout = TimeSpan.FromSeconds(30));
var jobOptions = configuration.GetSection("Jobs").Get<JobExecutionOptions>() ?? new JobExecutionOptions();
jobOptions.Validate();
builder.Services.AddSingleton(jobOptions);
builder.Services.AddSingleton<JobRunner>();
builder.Services.AddSingleton<RestoreReplay>();
builder.Services.AddSingleton<Scheduler>();
if (configuration.GetValue("Jobs:Enabled", false))
{
    // Only the production slot runs jobs (02 «Развёртывание и окружения»). Development may run queued jobs
    // (reports, exports) without the scheduler.
    builder.Services.AddHostedService(sp => sp.GetRequiredService<JobRunner>());
    builder.Services.AddHostedService<JobMonitor>();
    if (configuration.GetValue("Jobs:SchedulerEnabled", true))
    {
        builder.Services.AddHostedService(sp => sp.GetRequiredService<Scheduler>());
    }
}
builder.Services.AddAuthentication(SessionAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, SessionAuthenticationHandler>(SessionAuthenticationHandler.SchemeName, null);
builder.Services.AddAuthorization();

var app = builder.Build();

if (configurationCheck)
{
    Console.WriteLine("Configuration is valid; database, Azure access and tenant consent are not checked.");
    await app.DisposeAsync();
    return;
}

if (maintenance)
{
    Environment.ExitCode = await RestoreReplayCommand.RunAsync(app.Services, args[1..], Console.Out, Console.Error,
        CancellationToken.None);
    await app.DisposeAsync();
    return;
}

if (configuration.GetValue("Database:MigrateOnStart", false))
{
    var owner = configuration.GetConnectionString("SikkerheitOwner")
        ?? throw new InvalidOperationException("ConnectionStrings:SikkerheitOwner is required to migrate");
    await using var ownerSource = DatabaseConnections.Create(owner, entraDatabase, configuration["Database:OwnerIdentityClientId"]);
    var principals = configuration.GetSection("Database:AppPrincipals").Get<DatabasePrincipal[]>() ?? [];
    await app.Services.GetRequiredService<SchemaMigrator>()
        .MigrateAsync(ownerSource, configuration["Database:AppRole"] ?? "sikkerheit_app", principals, CancellationToken.None);
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<ProblemMiddleware>();
app.UseMiddleware<HostRoutingMiddleware>();
if (!environment.IsDevelopment() && !environment.IsEnvironment("Testing"))
{
    app.UseHsts();
}
PortalFiles.Use(app);
app.UseAuthentication();
app.UseMiddleware<CsrfMiddleware>();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));
AccessEndpoints.Map(app, developmentLogin);
if (entra.Configured)
{
    LoginEndpoints.Map(app);
}
else if (environment.IsProduction())
{
    throw new InvalidOperationException("Auth:Entra (TenantId, ClientId, RedirectUri) is required in Production");
}
OrganizationEndpoints.Map(app);
PolicyTemplateEndpoints.Map(app);
PolicyTemplateApplications.Map(app);
ConnectionEndpoints.Map(app);
AgentEndpoints.Map(app);
ReleaseCatalog.Map(app);
Sikkerheit.Host.Assessment.FindingEndpoints.Map(app);
ReportEndpoints.Map(app);
Sikkerheit.Host.Exports.OrganizationExports.Map(app);
app.MapFallback("/api/{**path}", (HttpContext http) => Problems.Result(http, ProblemCodes.NotFound));
app.MapFallback("/auth/{**path}", (HttpContext http) => Problems.Result(http, ProblemCodes.NotFound));
PortalFiles.MapFallback(app);

app.Run();

// The security log: an immutable Blob container in Azure (06), files in development and tests.
static ISecurityLog SecurityLog(IConfiguration configuration, IHostEnvironment environment)
{
    var container = configuration["SecurityLog:ContainerUri"];
    if (!string.IsNullOrEmpty(container))
    {
        return new BlobSecurityLog(new Uri(container), new DefaultAzureCredential());
    }
    if (environment.IsProduction())
    {
        throw new InvalidOperationException("SecurityLog:ContainerUri is required in Production");
    }
    return new FileSecurityLog(configuration["SecurityLog:Directory"] ?? Path.Combine(Path.GetTempPath(), "sikkerheit-security-log"));
}

// Keys protecting the staff token caches: a private Blob with keys wrapped by Key Vault in Azure (06).
static void ConfigureDataProtection(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
{
    var dataProtection = services.AddDataProtection().SetApplicationName("Sikkerheit");
    var blob = configuration["DataProtection:BlobUri"];
    var key = configuration["DataProtection:KeyVaultKeyId"];
    if (!string.IsNullOrEmpty(blob) && !string.IsNullOrEmpty(key))
    {
        var credential = new DefaultAzureCredential();
        dataProtection.PersistKeysToAzureBlobStorage(new Uri(blob), credential).ProtectKeysWithAzureKeyVault(new Uri(key), credential);
    }
    else if (environment.IsProduction())
    {
        throw new InvalidOperationException("DataProtection:BlobUri and DataProtection:KeyVaultKeyId are required in Production");
    }
}

// Reports and exports: private Blob containers by managed identity in Azure, a local directory in development.
static IFileStore FileStore(IConfiguration configuration, IHostEnvironment environment)
{
    var account = configuration["Storage:BlobServiceUri"];
    if (!string.IsNullOrEmpty(account))
    {
        return new BlobFileStore(new Uri(account), new DefaultAzureCredential());
    }
    if (environment.IsProduction())
    {
        throw new InvalidOperationException("Storage:BlobServiceUri is required in Production");
    }
    return new LocalFileStore(configuration["Storage:LocalDirectory"] ?? Path.Combine(Path.GetTempPath(), "sikkerheit-files"));
}

public partial class Program;
