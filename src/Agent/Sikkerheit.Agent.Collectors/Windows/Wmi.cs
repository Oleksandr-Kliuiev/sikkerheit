using System.Management;
using System.Runtime.Versioning;

namespace Sikkerheit.Agent.Collectors.Windows;

/// <summary>WMI queries with their own timeout (02): a failed query becomes a reason of the unavailable observation.</summary>
[SupportedOSPlatform("windows")]
internal static class Wmi
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(20);

    /// <summary>Runs a query and maps every row; an absent namespace or class gives an empty list.</summary>
    public static List<T> Select<T>(string scope, string query, Func<ManagementObject, T> map)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                new ManagementScope(scope), new ObjectQuery(query), new System.Management.EnumerationOptions { Timeout = QueryTimeout });
            var rows = new List<T>();
            foreach (ManagementObject row in searcher.Get())
            {
                using (row)
                {
                    rows.Add(map(row));
                }
            }
            return rows;
        }
        catch (ManagementException exception) when (IsAbsent(exception))
        {
            return [];
        }
        catch (ManagementException exception) when (exception.ErrorCode == ManagementStatus.AccessDenied)
        {
            throw new CollectorException(ReasonCodes.PermissionDenied, "WMI access denied: " + scope, exception);
        }
    }

    /// <summary>True when the class or the namespace does not exist on this edition.</summary>
    public static bool IsAbsent(ManagementException exception) =>
        exception.ErrorCode is ManagementStatus.InvalidNamespace or ManagementStatus.InvalidClass or ManagementStatus.NotFound;

    public static DateTimeOffset? Date(object? cimDate)
    {
        if (cimDate is not string text || text.Length < 14)
        {
            return null;
        }
        var value = ManagementDateTimeConverter.ToDateTime(text);
        return value.Year < 2000 ? null : new DateTimeOffset(value);
    }
}
