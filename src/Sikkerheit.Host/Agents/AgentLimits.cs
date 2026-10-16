using System.Collections.Concurrent;
using System.Security.Cryptography;
using Sikkerheit.Contracts;
using Sikkerheit.Host.Platform;

namespace Sikkerheit.Host.Agents;

/// <summary>Settings of the agent API: the HMAC key of nonces and the oldest agent version the service accepts.</summary>
public sealed class AgentOptions
{
    public byte[] NonceKey { get; init; } = RandomNumberGenerator.GetBytes(32);

    /// <summary>minimumAgentVersion of the configuration; batches of older agents are refused (05 «Порядок приёма пакета»).</summary>
    public string MinimumAgentVersion { get; init; } = "0.1.0";

    /// <summary>The largest version of the configuration schema this service knows (05 «API агента»).</summary>
    public int ConfigSchemaVersion { get; init; } = 1;

    public const int MaxBatchBytes = 262144;
    public const int MaxBufferBytes = 104857600;
}

/// <summary>
/// Rate limits of the anonymous agent operations (05 «API агента»): 60 per minute from one address and 1 200 per minute for
/// the service; registrations also 20 per hour and 200 per day per enrollment key. Sliding windows in memory of the
/// instance; exceeding one gives 429 rate_limited with Retry-After.
/// </summary>
public sealed class AgentLimits(TimeProvider clock)
{
    public const int PerAddressPerMinute = 60;
    public const int PerServicePerMinute = 1200;
    public const int PerKeyPerHour = 20;
    public const int PerKeyPerDay = 200;

    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _windows = new(StringComparer.Ordinal);

    /// <summary>Counts an anonymous request from the address against the address and service limits.</summary>
    public void HitAnonymous(HttpContext http)
    {
        var address = http.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        Hit("ip:" + address, PerAddressPerMinute, TimeSpan.FromMinutes(1));
        Hit("service", PerServicePerMinute, TimeSpan.FromMinutes(1));
    }

    /// <summary>Counts a registration of the enrollment key (its hash identifies it).</summary>
    public void HitRegistration(string keyHash)
    {
        Hit("key-hour:" + keyHash, PerKeyPerHour, TimeSpan.FromHours(1));
        Hit("key-day:" + keyHash, PerKeyPerDay, TimeSpan.FromDays(1));
    }

    private void Hit(string bucket, int limit, TimeSpan window)
    {
        var now = clock.GetUtcNow();
        var queue = _windows.GetOrAdd(bucket, _ => new Queue<DateTimeOffset>());
        lock (queue)
        {
            while (queue.Count > 0 && queue.Peek() <= now - window)
            {
                queue.Dequeue();
            }
            if (queue.Count >= limit)
            {
                var wait = (int)Math.Ceiling((queue.Peek() + window - now).TotalSeconds);
                throw new ApiProblemException(ProblemCodes.RateLimited, retryAfterSeconds: Math.Max(1, wait));
            }
            queue.Enqueue(now);
        }
        if (_windows.Count > 20_000)
        {
            foreach (var (key, value) in _windows)
            {
                lock (value)
                {
                    if (value.Count == 0 || value.Peek() <= now - TimeSpan.FromDays(1))
                    {
                        _windows.TryRemove(key, out _);
                    }
                }
            }
        }
    }
}
