using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sikkerheit.Agent.Runtime;

/// <summary>The loop of the service: one step of the engine every few seconds. The service has no listeners and no pipes (02).</summary>
public sealed class AgentWorker(AgentEngine engine, ILogger<AgentWorker> log) : BackgroundService
{
    private static readonly TimeSpan Tick = TimeSpan.FromSeconds(15);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        engine.Initialize();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await engine.StepAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    log.LogError(exception, "The step of the agent failed");
                }
                if (engine.ShouldExit)
                {
                    log.LogCritical("Three collectors are abandoned: the service ends with an error, SCM restarts it by the recovery actions");
                    // A process that ends without the STOPPED status of the service is a failure for SCM (recovery actions of the MSI).
                    Environment.Exit(1);
                }
                await Task.Delay(Tick, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Stop of the service.
        }
        finally
        {
            engine.Shutdown();
        }
    }
}
