using System.Text.Json;
using Sikkerheit.Contracts;

namespace Sikkerheit.Host.Platform;

/// <summary>Raised anywhere in a request to answer with a Problem of the closed catalog (05).</summary>
public sealed class ApiProblemException(string code, string? detail = null, IReadOnlyDictionary<string, object?>? extensions = null,
    int? retryAfterSeconds = null) : Exception(detail ?? code)
{
    public string Code { get; } = code;
    public string? Detail { get; } = detail;
    public int Status { get; } = Catalog.StatusOf(code);

    /// <summary>Members of Problem beyond the common ones, e.g. minimumAgentVersion (05 «Ошибки и действия агента»).</summary>
    public IReadOnlyDictionary<string, object?>? Extensions { get; } = extensions;

    /// <summary>Retry-After in seconds for 429 rate_limited and 503.</summary>
    public int? RetryAfterSeconds { get; } = retryAfterSeconds;
}

public static class Problems
{
    public const string ContentType = "application/problem+json";

    public static IResult Result(HttpContext context, string code, string? detail = null,
        IReadOnlyDictionary<string, object?>? extensions = null, int? retryAfterSeconds = null)
    {
        var status = Catalog.StatusOf(code);
        if (retryAfterSeconds is { } seconds)
        {
            context.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        return Results.Json(Body(context, code, status, detail, extensions), ApiJson.Options, ContentType, status);
    }

    public static Dictionary<string, object?> Body(HttpContext context, string code, int status, string? detail,
        IReadOnlyDictionary<string, object?>? extensions = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["type"] = "urn:sikkerheit:problem:" + code,
            ["title"] = code.Replace('_', ' '),
            ["status"] = status,
            ["code"] = code,
            ["correlationId"] = context.TraceIdentifier,
        };
        if (!string.IsNullOrEmpty(detail))
        {
            body["detail"] = detail.Length > 1000 ? detail[..1000] : detail;
        }
        foreach (var (name, value) in extensions ?? new Dictionary<string, object?>())
        {
            body[name] = value;
        }
        return body;
    }

    public static async Task WriteAsync(HttpContext context, string code, string? detail = null,
        IReadOnlyDictionary<string, object?>? extensions = null, int? retryAfterSeconds = null)
    {
        var status = Catalog.StatusOf(code);
        context.Response.StatusCode = status;
        context.Response.ContentType = ContentType;
        if (retryAfterSeconds is { } seconds)
        {
            context.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        await JsonSerializer.SerializeAsync(context.Response.Body, Body(context, code, status, detail, extensions), ApiJson.Options);
    }
}

/// <summary>Turns ApiProblemException and unexpected failures into Problem responses.</summary>
public sealed class ProblemMiddleware(RequestDelegate next, ILogger<ProblemMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await next(context);
        }
        catch (ApiProblemException problem) when (!context.Response.HasStarted)
        {
            await Problems.WriteAsync(context, problem.Code, problem.Detail, problem.Extensions, problem.RetryAfterSeconds);
        }
        catch (BadHttpRequestException bad) when (!context.Response.HasStarted && bad.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            await Problems.WriteAsync(context, ProblemCodes.PayloadTooLarge);
        }
        catch (Exception error) when (!context.Response.HasStarted && error is not OperationCanceledException)
        {
            // Problem.code has no internal-error value: an unexpected failure is reported as a temporary one.
            logger.LogError(error, "Unhandled failure {CorrelationId}", context.TraceIdentifier);
            await Problems.WriteAsync(context, ProblemCodes.TemporarilyUnavailable);
        }
    }
}
