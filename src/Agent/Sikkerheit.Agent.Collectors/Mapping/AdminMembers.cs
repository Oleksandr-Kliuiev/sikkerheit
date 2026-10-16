using System.Text.Json.Nodes;

namespace Sikkerheit.Agent.Collectors.Mapping;

/// <summary>Class and RID of a direct member of the local Administrators group (03, "Правило WIN-008").</summary>
public static class AdminMembers
{
    public const int MaxMembers = 100;

    public static JsonObject Describe(string sid, string? machineSid, string? domainSid)
    {
        var (kind, rid) = Classify(sid, machineSid, domainSid);
        return new JsonObject { ["sid"] = sid, ["kind"] = kind, ["relativeId"] = rid };
    }

    public static (string Kind, int? RelativeId) Classify(string sid, string? machineSid, string? domainSid)
    {
        if (sid.StartsWith("S-1-12-1-", StringComparison.Ordinal))
        {
            return ("entra", null);
        }
        if (sid.StartsWith("S-1-5-21-", StringComparison.Ordinal))
        {
            var cut = sid.LastIndexOf('-');
            var domain = sid[..cut];
            var rid = int.TryParse(sid[(cut + 1)..], System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var value) ? value : (int?)null;
            if (rid is null)
            {
                return ("unknown", null);
            }
            if (machineSid is not null && string.Equals(domain, machineSid, StringComparison.OrdinalIgnoreCase))
            {
                return rid == 500 ? ("builtin_administrator", 500) : ("local_account", rid);
            }
            if (domainSid is not null && string.Equals(domain, domainSid, StringComparison.OrdinalIgnoreCase))
            {
                return ("domain", rid);
            }
            return ("unknown", null);
        }
        // S-1-1-0 (Everyone), S-1-5-18 (SYSTEM), S-1-5-32-* (BUILTIN) and other authorities with fixed SIDs.
        return IsWellKnownShape(sid) ? ("well_known", null) : ("unknown", null);
    }

    private static bool IsWellKnownShape(string sid) =>
        sid.StartsWith("S-1-1-", StringComparison.Ordinal)
        || sid.StartsWith("S-1-2-", StringComparison.Ordinal)
        || sid.StartsWith("S-1-3-", StringComparison.Ordinal)
        || sid.StartsWith("S-1-5-32-", StringComparison.Ordinal)
        || (sid.StartsWith("S-1-5-", StringComparison.Ordinal) && sid.Count(c => c == '-') <= 3);
}
