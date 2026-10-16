using Sikkerheit.Contracts;

namespace Sikkerheit.Host.Platform;

/// <summary>
/// Portal paths answer only on portal hostnames and /api/v1/agent only on agent hostnames; anything else is 404
/// (02 «Развёртывание и окружения»). Empty lists (development, tests) allow every host.
/// </summary>
public sealed class HostRoutingMiddleware(RequestDelegate next, IConfiguration configuration)
{
    private readonly string[] _portal = configuration.GetSection("Hosting:PortalHosts").Get<string[]>() ?? [];
    private readonly string[] _agent = configuration.GetSection("Hosting:AgentHosts").Get<string[]>() ?? [];

    public async Task InvokeAsync(HttpContext context)
    {
        var host = context.Request.Host.Host;
        var agentPath = context.Request.Path.StartsWithSegments("/api/v1/agent");
        var allowed = agentPath
            ? _agent.Length == 0 || _agent.Contains(host, StringComparer.OrdinalIgnoreCase)
            : _portal.Length == 0 || _portal.Contains(host, StringComparer.OrdinalIgnoreCase)
              || context.Request.Path.StartsWithSegments("/health");
        if (!allowed)
        {
            await Problems.WriteAsync(context, ProblemCodes.NotFound);
            return;
        }
        await next(context);
    }
}
