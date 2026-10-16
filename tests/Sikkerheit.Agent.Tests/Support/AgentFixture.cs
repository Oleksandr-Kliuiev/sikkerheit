using Microsoft.Extensions.Logging.Abstractions;
using Sikkerheit.Agent.Api;
using Sikkerheit.Agent.Collectors;
using Sikkerheit.Agent.Collectors.Runtime;
using Sikkerheit.Agent.Config;
using Sikkerheit.Agent.Runtime;
using Sikkerheit.Agent.Scan;
using Sikkerheit.Agent.Storage;
using Sikkerheit.Contracts;

namespace Sikkerheit.Agent.Tests;

/// <summary>The agent with a fake server, a software key, a manual clock and a data directory in the temporary folder.</summary>
public sealed class AgentFixture : IDisposable
{
    public static readonly DateTimeOffset Start = new(2026, 10, 16, 8, 0, 0, TimeSpan.Zero);
    public static readonly ContractSchemas Schemas = new();

    public AgentFixture(Func<List<ICollector>>? collectors = null, CollectorLimits? limits = null)
    {
        Directory = Path.Combine(Path.GetTempPath(), "sikkerheit-agent-tests-" + Guid.NewGuid().ToString("N"));
        System.IO.Directory.CreateDirectory(Directory);
        Time = new ManualTimeProvider(Start);
        Server = new FakeServer(() => Time.GetUtcNow());
        Probe = new FakeProbe(Start - TimeSpan.FromHours(2));
        CollectorFactory = collectors ?? StubCollectors.All;
        Limits = limits ?? CollectorLimits.Default;
        OrganizationKey = FakeServer.NewEnrollmentKey();
        Server.ValidKeys.Add(OrganizationKey);
        Restart();
    }

    public string Directory { get; }

    public ManualTimeProvider Time { get; }

    public FakeServer Server { get; }

    public SoftwareKeyStore Keys { get; } = new();

    public FakeProbe Probe { get; }

    public FakeIdentity Identity { get; } = new();

    public FakeVolume Volume { get; } = new();

    public Func<List<ICollector>> CollectorFactory { get; set; }

    public CollectorLimits Limits { get; set; }

    public string OrganizationKey { get; }

    public AgentEngine Engine { get; private set; } = null!;

    public AgentStateStore State { get; private set; } = null!;

    public BatchBuffer Buffer => Engine.Buffer;

    public CollectorRunner Runner { get; private set; } = null!;

    public AgentPaths Paths => new(Directory);

    /// <summary>Start of the service: a new engine on the same data directory.</summary>
    public void Restart()
    {
        var paths = new AgentPaths(Directory);
        var database = new AgentDatabase(paths.Database);
        State = new AgentStateStore(database);
        var buffer = new BatchBuffer(database, State);
        var client = new HttpClient(Server, disposeHandler: false) { BaseAddress = new Uri("https://agent.test") };
        Runner = new CollectorRunner();
        Engine = new AgentEngine(
            new AgentServices(
                paths, State, buffer, new AgentApiClient(client, Schemas), Keys, new ReversingProtector(), Identity, Volume,
                CollectorFactory(), Runner, Limits,
                new ScanBatchBuilder(Schemas, NullLogger<ScanBatchBuilder>.Instance), new ConfigurationParser(Schemas),
                Probe, Time, "0.1.0"),
            NullLogger<AgentEngine>.Instance, new Random(1));
        Engine.Initialize();
    }

    /// <summary>The key file as RMM writes it.</summary>
    public void DropKeyFile(string? key = null) => File.WriteAllText(Paths.IncomingKeyFile, key ?? OrganizationKey);

    public async Task StepAsync(int times = 1)
    {
        for (var i = 0; i < times; i++)
        {
            await Engine.StepAsync(CancellationToken.None);
        }
    }

    /// <summary>The device is registered, the configuration is received and the first batch is sent.</summary>
    public async Task EnrolledAsync()
    {
        DropKeyFile();
        await StepAsync(4);
    }

    public void Advance(TimeSpan by) => Time.Advance(by);

    public IEnumerable<SeenRequest> Seen(string path) => Server.Requests.Where(r => r.Path == path);

    public int Count(string path) => Seen(path).Count();

    public void Dispose()
    {
        try
        {
            System.IO.Directory.Delete(Directory, recursive: true);
        }
        catch (IOException)
        {
            // The temporary folder is cleaned by the system.
        }
    }
}
