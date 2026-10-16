using System.Net;
using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sikkerheit.Agent.Api;
using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Collectors.Runtime;
using Sikkerheit.Agent.Collectors.Windows;
using Sikkerheit.Agent.Config;
using Sikkerheit.Agent.Runtime;
using Sikkerheit.Agent.Scan;
using Sikkerheit.Agent.Storage;
using Sikkerheit.Agent.Windows;
using Sikkerheit.Contracts;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Sikkerheit.Agent runs as a Windows service only.");
    return 2;
}

return AgentHost.Run(args);

/// <summary>Composition of the service. The Windows parts are created here and only here.</summary>
internal static class AgentHost
{
    public const string ServiceName = "Sikkerheit.Agent";

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static int Run(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
            // The working directory of a service is System32: files are read from the directory of the installation only.
            ContentRootPath = AppContext.BaseDirectory,
        });
        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);
        builder.Configuration.AddEnvironmentVariables("SIKKERHEIT_");
        var options = builder.Configuration.GetSection(AgentOptions.Section).Get<AgentOptions>() ?? new AgentOptions();
        options.Validate();

        DataDirectorySecurity.Restrict(options.DataDirectory);
        var paths = new AgentPaths(options.DataDirectory);
        var database = new AgentDatabase(paths.Database);
        var state = new AgentStateStore(database);
        var buffer = new BatchBuffer(database, state);
        var schemas = new ContractSchemas();
        var readers = WindowsReaderFactory.Create();
        var time = TimeProvider.System;

        builder.Services.AddSingleton(sp => new AgentEngine(
            new AgentServices(
                paths, state, buffer,
                new AgentApiClient(CreateHttpClient(options), schemas),
                new CngDeviceKeyStore(), new DpapiSecretProtector(),
                readers.MachineIdentity, readers.OsVolume,
                CollectorSet.Create(readers), new CollectorRunner(time), CollectorLimits.Default,
                new ScanBatchBuilder(schemas, sp.GetRequiredService<ILogger<ScanBatchBuilder>>()),
                new ConfigurationParser(schemas), new ProcessProbe(time), time, Version()),
            sp.GetRequiredService<ILogger<AgentEngine>>()));
        builder.Services.AddHostedService<AgentWorker>();
        builder.Build().Run();
        return 0;
    }

    /// <summary>Only HTTPS to the hostname of the agent; the certificate is checked by the trust store of Windows (02).</summary>
    private static HttpClient CreateHttpClient(AgentOptions options)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
        };
        if (options.Proxy is not null)
        {
            handler.Proxy = new WebProxy(options.Proxy);
        }
        return new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = new Uri(options.ServerUrl),
            Timeout = TimeSpan.FromSeconds(100),
        };
    }

    private static string Version()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 1, 0);
        return $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
    }
}
