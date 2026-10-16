using System.Security.Claims;
using Sikkerheit.Contracts;

namespace Sikkerheit.Host.Platform;

public static class StaffRoles
{
    public const string Admin = "Admin";
    public const string Technician = "Technician";
    public const string Reader = "Reader";
    public static readonly string[] All = [Admin, Technician, Reader];
    public static readonly string[] Work = [Admin, Technician];
    public static readonly string[] AdminOnly = [Admin];
}

/// <summary>The signed-in staff member of the request.</summary>
public sealed record Actor(Guid EntraUserId, IReadOnlyList<string> Roles, string CsrfToken)
{
    public const string CsrfClaim = "sikkerheit:csrf";

    public static Actor From(ClaimsPrincipal user)
    {
        var id = user.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? throw new ApiProblemException(ProblemCodes.SessionRequired);
        return new Actor(Guid.Parse(id), user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList(),
            user.FindFirstValue(CsrfClaim) ?? "");
    }

    public bool HasAny(IEnumerable<string> roles) => roles.Any(Roles.Contains);
}

public static class EndpointRoleExtensions
{
    /// <summary>Requires a staff session and one of the roles; 401 session_required, 403 forbidden.</summary>
    public static TBuilder RequireStaff<TBuilder>(this TBuilder builder, params string[] roles) where TBuilder : IEndpointConventionBuilder
    {
        builder.AddEndpointFilter(async (context, next) =>
        {
            var user = context.HttpContext.User;
            if (user.Identity?.IsAuthenticated != true)
            {
                return Problems.Result(context.HttpContext, ProblemCodes.SessionRequired);
            }
            if (!Actor.From(user).HasAny(roles))
            {
                return Problems.Result(context.HttpContext, ProblemCodes.Forbidden);
            }
            return await next(context);
        });
        return builder;
    }
}
