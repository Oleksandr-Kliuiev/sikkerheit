using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Host.M365;

namespace Sikkerheit.IntegrationTests.Infrastructure;

public sealed record FakeUser(Guid Id, string Upn, bool Enabled = true, string? UserType = "Member", string[]? Methods = null);

/// <summary>A synthetic tenant served by the fake Graph: no customer data, shapes as in Graph v1.0 and beta.</summary>
public sealed class FakeTenant
{
    public Guid TenantId { get; } = Guid.NewGuid();
    public string DisplayName { get; set; } = "Fjord Test AS";
    public bool EntraP1 { get; set; } = true;
    public bool SecurityDefaults { get; set; }
    public bool Consented { get; set; } = true;
    public List<FakeUser> Users { get; } = [];
    public List<(Guid Principal, string Role, bool IsGroup)> Assignments { get; } = [];
    public Dictionary<Guid, List<Guid>> GroupMembers { get; } = [];
    public List<JsonObject> ConditionalAccessPolicies { get; } = [];
    public List<string> GrantPolicies { get; } = ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"];
    public Dictionary<Guid, string> PerUserMfa { get; } = [];
    public int UsersPageSize { get; set; } = 999;
    public HashSet<string> Forbidden { get; } = [];

    /// <summary>Entra ID P2 (PIM): roleAssignmentScheduleInstances lists the activations below.</summary>
    public bool EntraP2 { get; set; }

    /// <summary>Assignments that exist only as a PIM activation (assignmentType=Activated).</summary>
    public HashSet<(Guid Principal, string Role)> Activations { get; } = [];

    /// <summary>/organization answers with this id instead of the tenant's own (the token went to another tenant).</summary>
    public Guid? OrganizationIdOverride { get; set; }

    /// <summary>The @odata.nextLink of the first /users page, when the test wants a link to another host.</summary>
    public string? UsersNextLink { get; set; }

    /// <summary>Path prefix → remaining 429 answers and their Retry-After in seconds.</summary>
    public Dictionary<string, (int Remaining, int RetryAfterSeconds)> Throttled { get; } = [];

    public FakeUser AddUser(string name, bool enabled = true, string? type = "Member", params string[] methods)
    {
        var user = new FakeUser(Guid.NewGuid(), $"{name}@fjord.example", enabled, type, methods);
        Users.Add(user);
        return user;
    }
}

public sealed class FakeGraphTokens(FakeGraph graph) : IGraphTokenProvider
{
    public Task<string> GetTokenAsync(Guid tenantId, CancellationToken ct) =>
        graph.Tenants.TryGetValue(tenantId, out var tenant) && tenant.Consented
            ? Task.FromResult("fake:" + tenantId)
            : throw new GraphTokenException("consent_missing", "AADSTS700016 application not found in the directory");
}

public sealed class FakeTenantResolver(FakeGraph graph) : ITenantResolver
{
    public Task<Guid?> ResolveAsync(string tenantHint, CancellationToken ct)
    {
        if (Guid.TryParse(tenantHint, out var id))
        {
            return Task.FromResult<Guid?>(id);
        }
        var match = graph.Tenants.Values.FirstOrDefault(t => tenantHint.Equals(t.DisplayName.Split(' ')[0].ToLowerInvariant() + ".example",
            StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(match?.TenantId);
    }
}

/// <summary>In-process Graph: routes by path, answers pages, JSON batch and beta per-user MFA.</summary>
public sealed class FakeGraph : HttpMessageHandler
{
    public Dictionary<Guid, FakeTenant> Tenants { get; } = [];
    public List<string> Requests { get; } = [];

    /// <summary>Times of the requests, in the same order as Requests.</summary>
    public List<DateTimeOffset> RequestTimes { get; } = [];

    /// <summary>Called before a request is answered, e.g. to disconnect the tenant in the middle of a run.</summary>
    public Func<string, Task>? OnRequest { get; set; }

    public FakeTenant AddTenant()
    {
        var tenant = new FakeTenant();
        Tenants[tenant.TenantId] = tenant;
        return tenant;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var token = request.Headers.Authorization?.Parameter ?? "";
        var tenant = Tenants[Guid.Parse(token["fake:".Length..])];
        var path = request.RequestUri!.AbsolutePath;
        lock (Requests)
        {
            Requests.Add(request.Method + " " + request.RequestUri.PathAndQuery);
            RequestTimes.Add(DateTimeOffset.UtcNow);
        }
        var relative = path.StartsWith("/v1.0", StringComparison.Ordinal) ? path[5..] : path;
        if (OnRequest is { } hook)
        {
            await hook(relative);
        }
        var throttled = tenant.Throttled.Keys.FirstOrDefault(p => relative.StartsWith(p, StringComparison.Ordinal));
        if (throttled is not null && tenant.Throttled[throttled] is { Remaining: > 0 } limit)
        {
            tenant.Throttled[throttled] = (limit.Remaining - 1, limit.RetryAfterSeconds);
            var tooMany = Json(429, new JsonObject { ["error"] = new JsonObject { ["code"] = "TooManyRequests" } });
            tooMany.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(limit.RetryAfterSeconds));
            return tooMany;
        }
        if (request.Method == HttpMethod.Post && path == "/v1.0/$batch")
        {
            var body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(ct))!;
            var responses = new JsonArray();
            foreach (var item in body["requests"]!.AsArray())
            {
                var (status, payload) = Answer(tenant, item!["url"]!.GetValue<string>(), "");
                responses.Add(new JsonObject { ["id"] = item["id"]!.GetValue<string>(), ["status"] = status, ["body"] = payload });
            }
            return Json(200, new JsonObject { ["responses"] = responses });
        }
        var (code, json) = Answer(tenant, path, request.RequestUri.Query);
        return Json(code, json);
    }

    private static (int, JsonNode?) Answer(FakeTenant tenant, string path, string query)
    {
        path = path.StartsWith("/v1.0", StringComparison.Ordinal) ? path[5..] : path;
        foreach (var forbidden in tenant.Forbidden)
        {
            if (path.StartsWith(forbidden, StringComparison.Ordinal))
            {
                return (403, new JsonObject { ["error"] = new JsonObject { ["code"] = "Authorization_RequestDenied" } });
            }
        }
        if (path == "/organization")
        {
            return (200, Value(new JsonObject
            {
                ["id"] = (tenant.OrganizationIdOverride ?? tenant.TenantId).ToString(), ["displayName"] = tenant.DisplayName,
                ["verifiedDomains"] = new JsonArray(new JsonObject { ["name"] = "fjord.example", ["isDefault"] = true }),
            }));
        }
        if (path == "/subscribedSkus")
        {
            var plans = tenant.EntraP1
                ? new JsonArray(new JsonObject { ["servicePlanId"] = "41781fb2-bc02-4b7c-bd55-b576c07bb09d" })
                : new JsonArray(new JsonObject { ["servicePlanId"] = "57ff2da0-773e-42df-b2af-ffb7a2317929" });
            if (tenant.EntraP2)
            {
                plans.Add(new JsonObject { ["servicePlanId"] = "eec0eb4f-6444-4f95-aba0-50c24d67f998" });
            }
            return (200, Value(new JsonObject { ["capabilityStatus"] = "Enabled", ["servicePlans"] = plans }));
        }
        if (path == "/users")
        {
            var skip = query.Contains("skip=", StringComparison.Ordinal)
                ? int.Parse(query.Split("skip=")[1].Split('&')[0], System.Globalization.CultureInfo.InvariantCulture) : 0;
            var page = tenant.Users.Skip(skip).Take(tenant.UsersPageSize).Select(u => (JsonNode)new JsonObject
            {
                ["id"] = u.Id.ToString(), ["userPrincipalName"] = u.Upn, ["accountEnabled"] = u.Enabled, ["userType"] = u.UserType,
                ["createdDateTime"] = "2024-01-01T00:00:00Z",
            }).ToArray();
            var result = new JsonObject { ["value"] = new JsonArray(page) };
            if (skip + tenant.UsersPageSize < tenant.Users.Count)
            {
                result["@odata.nextLink"] = skip == 0 && tenant.UsersNextLink is { } link ? link
                    : $"https://graph.microsoft.com/v1.0/users?$top={tenant.UsersPageSize}&skip={skip + tenant.UsersPageSize}";
            }
            return (200, result);
        }
        if (path == "/roleManagement/directory/roleAssignments")
        {
            return (200, new JsonObject
            {
                ["value"] = new JsonArray(tenant.Assignments.Select((a, i) => (JsonNode)new JsonObject
                {
                    ["id"] = "ra-" + i, ["principalId"] = a.Principal.ToString(), ["roleDefinitionId"] = a.Role, ["directoryScopeId"] = "/",
                    ["principal"] = new JsonObject
                    {
                        ["@odata.type"] = a.IsGroup ? "#microsoft.graph.group" : "#microsoft.graph.user", ["id"] = a.Principal.ToString(),
                    },
                }).ToArray()),
            });
        }
        if (path == "/roleManagement/directory/roleAssignmentScheduleInstances")
        {
            if (!tenant.EntraP2 || !query.Contains("assignmentType%20eq%20'Activated'", StringComparison.Ordinal))
            {
                return (400, new JsonObject { ["error"] = new JsonObject { ["code"] = "AadPremiumLicenseRequired" } });
            }
            return (200, new JsonObject
            {
                ["value"] = new JsonArray(tenant.Assignments.Select((a, i) => (a, i))
                    .Where(x => tenant.Activations.Contains((x.a.Principal, x.a.Role)))
                    .Select(x => (JsonNode)new JsonObject
                    {
                        ["roleAssignmentOriginId"] = "ra-" + x.i, ["assignmentType"] = "Activated",
                    }).ToArray()),
            });
        }
        if (path.StartsWith("/groups/", StringComparison.Ordinal) && path.EndsWith("/transitiveMembers", StringComparison.Ordinal))
        {
            var group = Guid.Parse(path.Split('/')[2]);
            return (200, new JsonObject
            {
                ["value"] = new JsonArray((tenant.GroupMembers.GetValueOrDefault(group) ?? []).Select(m => (JsonNode)new JsonObject
                {
                    ["@odata.type"] = "#microsoft.graph.user", ["id"] = m.ToString(),
                }).ToArray()),
            });
        }
        if (path.StartsWith("/users/", StringComparison.Ordinal) && path.EndsWith("/authentication/methods", StringComparison.Ordinal))
        {
            var user = tenant.Users.Single(u => u.Id == Guid.Parse(path.Split('/')[2]));
            var methods = new JsonArray(new JsonObject { ["@odata.type"] = "#microsoft.graph.passwordAuthenticationMethod" });
            foreach (var kind in user.Methods ?? [])
            {
                // «untyped» stands for an element of a 200 answer without the required @odata.type.
                methods.Add(kind == "untyped" ? new JsonObject { ["id"] = Guid.NewGuid().ToString() }
                    : new JsonObject { ["@odata.type"] = "#microsoft.graph." + kind + "AuthenticationMethod" });
            }
            return (200, new JsonObject { ["value"] = methods });
        }
        if (path == "/policies/identitySecurityDefaultsEnforcementPolicy")
        {
            return (200, new JsonObject { ["isEnabled"] = tenant.SecurityDefaults });
        }
        if (path == "/identity/conditionalAccess/policies")
        {
            return (200, new JsonObject { ["value"] = new JsonArray(tenant.ConditionalAccessPolicies.Select(p => p.DeepClone()).ToArray()) });
        }
        if (path == "/policies/authorizationPolicy")
        {
            return (200, new JsonObject
            {
                ["defaultUserRolePermissions"] = new JsonObject
                {
                    ["permissionGrantPoliciesAssigned"] = new JsonArray(tenant.GrantPolicies.Select(p => (JsonNode)p).ToArray()),
                },
            });
        }
        if (path.StartsWith("/beta/users/", StringComparison.Ordinal))
        {
            var user = Guid.Parse(path.Split('/')[3]);
            return (200, new JsonObject { ["perUserMfaState"] = tenant.PerUserMfa.GetValueOrDefault(user, "disabled") });
        }
        return (404, new JsonObject { ["error"] = new JsonObject { ["code"] = "Request_ResourceNotFound" } });
    }

    private static JsonObject Value(JsonObject item) => new() { ["value"] = new JsonArray(item) };

    private static HttpResponseMessage Json(int status, JsonNode? body) => new((HttpStatusCode)status)
    {
        Content = new StringContent(body?.ToJsonString() ?? "", Encoding.UTF8, "application/json"),
    };
}

public static class ConditionalAccess
{
    public static JsonObject MfaPolicy(string state, bool allUsers = true, string[]? excludeUsers = null) => new()
    {
        ["id"] = Guid.NewGuid().ToString(), ["displayName"] = "Require MFA", ["state"] = state,
        ["conditions"] = new JsonObject
        {
            ["users"] = new JsonObject
            {
                ["includeUsers"] = new JsonArray(allUsers ? "All" : Guid.NewGuid().ToString()),
                ["excludeUsers"] = new JsonArray((excludeUsers ?? []).Select(u => (JsonNode)u).ToArray()),
                ["excludeGroups"] = new JsonArray(), ["excludeRoles"] = new JsonArray(),
            },
            ["applications"] = new JsonObject { ["includeApplications"] = new JsonArray("All"), ["excludeApplications"] = new JsonArray() },
            ["clientAppTypes"] = new JsonArray("all"),
        },
        ["grantControls"] = new JsonObject { ["operator"] = "OR", ["builtInControls"] = new JsonArray("mfa") },
    };
}
