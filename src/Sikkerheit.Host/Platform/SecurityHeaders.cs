namespace Sikkerheit.Host.Platform;

/// <summary>
/// Response headers of the portal (04 «Недоверенные строки и выдача отчёта»): CSP without inline scripts or styles,
/// no framing, no MIME sniffing. A response that sets its own CSP (the report download) keeps it.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public const string PortalPolicy =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
        + "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;
            headers.TryAdd("Content-Security-Policy", PortalPolicy);
            headers.TryAdd("X-Content-Type-Options", "nosniff");
            headers.TryAdd("Referrer-Policy", "same-origin");
            headers.TryAdd("X-Frame-Options", "DENY");
            headers.TryAdd("Cross-Origin-Opener-Policy", "same-origin");
            headers.TryAdd("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
            return Task.CompletedTask;
        });
        return next(context);
    }
}

/// <summary>Static files of the portal: hashed assets are immutable, index.html is always revalidated.</summary>
public static class PortalFiles
{
    public static void Use(WebApplication app)
    {
        app.UseStaticFiles(new StaticFileOptions
        {
            OnPrepareResponse = context =>
            {
                context.Context.Response.Headers.CacheControl = context.Context.Request.Path.StartsWithSegments("/assets")
                    ? "public, max-age=31536000, immutable"
                    : "no-cache";
            },
        });
    }

    /// <summary>Client routes of the SPA return index.html; API, sign-in and health paths never do.</summary>
    public static void MapFallback(WebApplication app)
    {
        app.MapFallbackToFile("index.html", new StaticFileOptions
        {
            OnPrepareResponse = context => context.Context.Response.Headers.CacheControl = "no-cache",
        });
    }
}
