using System.Text.RegularExpressions;
using Azure.Core;
using Azure.Identity;
using Npgsql;

namespace Sikkerheit.Host.Data;

/// <summary>A managed identity that must exist as a database role and belong to the application role group.</summary>
public sealed record DatabasePrincipal(string Name, Guid ObjectId);

/// <summary>
/// Data sources of the service. In Azure the passwordless sign-in to PostgreSQL uses an Entra token of the slot's
/// managed identity (02 «Развёртывание и окружения»: «вход по managed identity, без паролей»).
/// </summary>
public static partial class DatabaseConnections
{
    private static readonly TokenRequestContext Database = new(["https://ossrdbms-aad.database.windows.net/.default"]);

    public static NpgsqlDataSource Create(string connectionString, bool entraAuth, string? managedIdentityClientId)
    {
        var builder = new NpgsqlDataSourceBuilder(connectionString);
        if (entraAuth)
        {
            TokenCredential credential = string.IsNullOrEmpty(managedIdentityClientId)
                ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(managedIdentityClientId));
            // Tokens live about an hour; a new one is fetched every 30 minutes and on failure retried after 5 seconds.
            builder.UsePeriodicPasswordProvider(
                async (_, ct) => (await credential.GetTokenAsync(Database, ct)).Token, TimeSpan.FromMinutes(30), TimeSpan.FromSeconds(5));
        }
        return builder.Build();
    }

    public static bool IsPlainRoleName(string name) => RoleName().IsMatch(name);

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")]
    private static partial Regex RoleName();
}
