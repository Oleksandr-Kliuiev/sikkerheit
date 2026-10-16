using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sikkerheit.Contracts;

namespace Sikkerheit.Host.M365;

/// <summary>Policy inputs the collector needs (05 «Политика клиента»).</summary>
public sealed record CollectorPolicy(
    IReadOnlySet<Guid> ExcludedUserIds, IReadOnlySet<string> PrivilegedRoleTemplateIds, IReadOnlySet<string> ActiveCheckIds,
    bool DeviceAlternativeAccepted = false, bool TrustedLocationsExclusionAccepted = false)
{
    public static CollectorPolicy From(JsonElement configuration)
    {
        var excluded = configuration.GetProperty("m365").GetProperty("excludedUserIds").EnumerateArray()
            .Select(e => Guid.Parse(e.GetString()!)).ToHashSet();
        var roles = configuration.GetProperty("checks").GetProperty("M365-002").GetProperty("parameters")
            .GetProperty("privilegedRoleTemplateIds").EnumerateArray().Select(e => e.GetString()!.ToLowerInvariant()).ToHashSet();
        var active = configuration.GetProperty("activeCheckIds").EnumerateArray().Select(e => e.GetString()!).ToHashSet();
        var mfa = configuration.GetProperty("checks").GetProperty("M365-003").GetProperty("parameters");
        return new CollectorPolicy(excluded, roles, active, mfa.GetProperty("deviceAlternativeAccepted").GetBoolean(),
            mfa.GetProperty("trustedLocationsExclusionAccepted").GetBoolean());
    }
}

public sealed record CollectorOptions
{
    /// <summary>Per-user MFA via Graph beta (H-MFA1); when off the module is skipped and M365-003 cannot use it.</summary>
    public bool PerUserMfa { get; init; } = true;

    /// <summary>M365-007 and AuditLog.Read.All are deferred (owner decision after the external review).</summary>
    public bool SignInActivity { get; init; }

    public TimeSpan RunTimeout { get; init; } = TimeSpan.FromMinutes(30);
}

/// <summary>Result of one collection run before evaluation.</summary>
public sealed record CollectionOutcome(
    string State, string? FailureCode, bool? EntraP1, bool UsersComplete, string? TenantDisplayName, string? PrimaryDomain,
    IReadOnlyDictionary<string, string> Modules, IReadOnlyList<JsonObject> Observations, IReadOnlyList<Guid> PrivilegedUserIds,
    IReadOnlyList<Guid> SeenUserIds)
{
    public static CollectionOutcome Failed(string failureCode) => new("failed", failureCode, null, false, null, null,
        Catalog.GraphModules.ToDictionary(m => m, _ => "temporary_error"), [], [], []);
}

/// <summary>
/// Collects one tenant (02 «Сбор данных Microsoft 365», 03 «Возможности подключения»): module statuses, observations
/// by the allowlist schema, failed/partial/completed state. It reads only; it never changes the tenant.
/// </summary>
public sealed class M365Collector(GraphClient graph, ContractSchemas schemas, CollectorOptions options, TimeProvider clock)
{
    private const string GlobalAdministrator = "62e90394-69f5-4237-9190-012177145e10";
    private const string P2Plan = "eec0eb4f-6444-4f95-aba0-50c24d67f998";
    private static readonly string[] P1Plans = ["41781fb2-bc02-4b7c-bd55-b576c07bb09d", P2Plan];

    private static readonly Dictionary<string, string> MethodTypes = new(StringComparer.Ordinal)
    {
        ["#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"] = "microsoft_authenticator",
        ["#microsoft.graph.fido2AuthenticationMethod"] = "fido2",
        ["#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"] = "windows_hello_for_business",
        ["#microsoft.graph.platformCredentialAuthenticationMethod"] = "platform_credential",
        ["#microsoft.graph.softwareOathAuthenticationMethod"] = "software_oath",
        ["#microsoft.graph.hardwareOathAuthenticationMethod"] = "hardware_oath",
        ["#microsoft.graph.phoneAuthenticationMethod"] = "phone",
        ["#microsoft.graph.externalAuthenticationMethod"] = "external",
        ["#microsoft.graph.emailAuthenticationMethod"] = "email",
        ["#microsoft.graph.temporaryAccessPassAuthenticationMethod"] = "temporary_access_pass",
        ["#microsoft.graph.passwordAuthenticationMethod"] = "password",
        ["#microsoft.graph.qrCodePinAuthenticationMethod"] = "qr_code_pin",
    };

    public async Task<CollectionOutcome> CollectAsync(Guid tenantId, CollectorPolicy policy,
        IReadOnlySet<Guid> previouslyPrivileged, CancellationToken ct)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(options.RunTimeout);
        var run = new RunState(clock.GetUtcNow());
        try
        {
            await CollectTenantAsync(tenantId, run, deadline.Token);
            await CollectUsersAsync(tenantId, run, deadline.Token);
        }
        catch (GraphTokenException error)
        {
            return CollectionOutcome.Failed(error.FailureCode);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return CollectionOutcome.Failed("run_timeout");
        }
        catch (TenantMismatchException)
        {
            return CollectionOutcome.Failed("tenant_mismatch");
        }
        catch (GraphException)
        {
            return CollectionOutcome.Failed("temporary_error");
        }

        try
        {
            await CollectLicensesAsync(tenantId, run, deadline.Token);
            await CollectRolesAsync(tenantId, policy, run, deadline.Token);
            await CollectMethodsAsync(tenantId, policy, previouslyPrivileged, run, deadline.Token);
            await CollectSecurityDefaultsAsync(tenantId, run, deadline.Token);
            await CollectConditionalAccessAsync(tenantId, policy, run, deadline.Token);
            await CollectAuthorizationPolicyAsync(tenantId, run, deadline.Token);
            await CollectPerUserMfaAsync(tenantId, policy, run, deadline.Token);
        }
        catch (GraphTokenException error)
        {
            return CollectionOutcome.Failed(error.FailureCode);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Timeout after users were read: unfinished modules are temporary_error, the run is partial.
            foreach (var module in Catalog.GraphModules.Where(m => !run.Modules.ContainsKey(m)))
            {
                run.Modules[module] = "temporary_error";
            }
        }
        run.Modules.TryAdd("sign_in_activity", "skipped");
        run.Modules.TryAdd("per_user_mfa", "skipped");

        var observations = BuildObservations(tenantId, policy, previouslyPrivileged, run);
        var complete = run.Modules.Values.All(s => s is "available" or "license_missing" or "skipped");
        return new CollectionOutcome(complete ? "completed" : "partial", null, run.EntraP1, run.UsersComplete,
            run.DisplayName, run.PrimaryDomain, run.Modules, observations,
            run.Privileged.Keys.ToList(), run.Users.Keys.ToList());
    }

    private sealed class TenantMismatchException : Exception;

    private sealed class UserRecord
    {
        public Guid Id { get; init; }
        public string Upn { get; init; } = "";
        public bool AccountEnabled { get; init; }
        public string? UserType { get; init; }
        public string? CreatedAt { get; init; }
    }

    private sealed class RunState(DateTimeOffset started)
    {
        public DateTimeOffset Started { get; } = started;
        public Dictionary<string, string> Modules { get; } = new(StringComparer.Ordinal);
        public string? DisplayName { get; set; }
        public string? PrimaryDomain { get; set; }
        public bool? EntraP1 { get; set; }
        public bool? EntraP2 { get; set; }

        /// <summary>PIM activations could not be read: the global administrator count is not reliable (M365-005).</summary>
        public bool ActivationsUnknown { get; set; }
        public bool UsersComplete { get; set; }
        public Dictionary<Guid, UserRecord> Users { get; } = [];
        public HashSet<Guid> SyncAccounts { get; } = [];
        public Dictionary<Guid, PrivilegedRoles> Privileged { get; } = [];

        /// <summary>Members of some group with a role could not be read: a missing role is not proof of its removal.</summary>
        public bool GroupMembersIncomplete { get; set; }
        public HashSet<Guid> GlobalAdmins { get; } = [];
        public int UnresolvedGroups { get; set; }
        public bool RoleAssignmentsComplete { get; set; } = true;
        public Dictionary<Guid, List<string>> Methods { get; } = [];
        public Dictionary<Guid, string> MethodFailures { get; } = [];
        public bool? SecurityDefaults { get; set; }
        public JsonArray MfaPolicies { get; } = [];
        public JsonArray LegacyPolicies { get; } = [];
        public JsonArray? GrantPolicies { get; set; }
        public JsonObject? PerUserMfa { get; set; }
        public Dictionary<Guid, HashSet<string>> RoleMembers { get; } = [];
    }

    /// <summary>Roles of privileged role templates of one user: standing assignments and PIM activations apart (03).</summary>
    private sealed class PrivilegedRoles
    {
        public HashSet<string> Roles { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Standing { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Activated { get; } = new(StringComparer.Ordinal);
        public bool Direct { get; set; }
        public bool Group { get; set; }

        /// <summary>Roles that act only as an activation (no standing assignment of the same role).</summary>
        public IEnumerable<string> Temporary => Activated.Except(Standing);
    }

    private async Task CollectTenantAsync(Guid tenantId, RunState run, CancellationToken ct)
    {
        var body = await graph.GetAsync(tenantId, "v1.0/organization?$select=id,displayName,verifiedDomains", GraphLimit.Default, ct);
        var organization = body.GetProperty("value").EnumerateArray().FirstOrDefault();
        if (organization.ValueKind != JsonValueKind.Object
            || !Guid.TryParse(organization.GetProperty("id").GetString(), out var id) || id != tenantId)
        {
            throw new TenantMismatchException();
        }
        run.DisplayName = Clean(organization.TryGetProperty("displayName", out var name) ? name.GetString() : null);
        if (organization.TryGetProperty("verifiedDomains", out var domains))
        {
            run.PrimaryDomain = Clean(domains.EnumerateArray()
                .FirstOrDefault(d => d.TryGetProperty("isDefault", out var isDefault) && isDefault.GetBoolean())
                .TryGetProperty("name", out var domain) ? domain.GetString() : null);
        }
        run.Modules["tenant"] = "available";
    }

    private async Task CollectUsersAsync(Guid tenantId, RunState run, CancellationToken ct)
    {
        var pages = await graph.GetAllPagesAsync(tenantId,
            "v1.0/users?$select=id,userPrincipalName,accountEnabled,userType,createdDateTime&$top=999", GraphLimit.Default, ct);
        var complete = pages.Complete;
        foreach (var user in pages.Items)
        {
            if (!user.TryGetProperty("id", out var id) || !Guid.TryParse(id.GetString(), out var userId)
                || !user.TryGetProperty("accountEnabled", out var enabled) || enabled.ValueKind is not (JsonValueKind.True or JsonValueKind.False)
                || !user.TryGetProperty("userPrincipalName", out var upn) || upn.ValueKind != JsonValueKind.String)
            {
                complete = false; // 200 without a required property is not a complete answer.
                continue;
            }
            run.Users[userId] = new UserRecord
            {
                Id = userId, Upn = Clean(upn.GetString())!, AccountEnabled = enabled.GetBoolean(),
                UserType = user.TryGetProperty("userType", out var type) && type.ValueKind == JsonValueKind.String ? type.GetString() : null,
                CreatedAt = user.TryGetProperty("createdDateTime", out var created) && created.ValueKind == JsonValueKind.String
                    ? created.GetString() : null,
            };
        }
        run.UsersComplete = complete;
        run.Modules["users"] = complete ? "available" : "partial";
    }

    private async Task CollectLicensesAsync(Guid tenantId, RunState run, CancellationToken ct)
    {
        try
        {
            var body = await graph.GetAsync(tenantId, "v1.0/subscribedSkus?$select=capabilityStatus,servicePlans", GraphLimit.Default, ct);
            bool Has(params string[] plansWanted) => body.GetProperty("value").EnumerateArray().Any(sku =>
                sku.TryGetProperty("capabilityStatus", out var status) && status.GetString() is "Enabled" or "Warning"
                && sku.TryGetProperty("servicePlans", out var plans)
                && plans.EnumerateArray().Any(p => p.TryGetProperty("servicePlanId", out var plan)
                                                   && plansWanted.Contains(plan.GetString(), StringComparer.OrdinalIgnoreCase)));
            run.EntraP1 = Has(P1Plans);
            run.EntraP2 = Has(P2Plan);
            run.Modules["licenses"] = "available";
        }
        catch (GraphException error)
        {
            run.Modules["licenses"] = Status(error);
        }
    }

    private async Task CollectRolesAsync(Guid tenantId, CollectorPolicy policy, RunState run, CancellationToken ct)
    {
        try
        {
            var assignments = await graph.GetAllPagesAsync(tenantId,
                "v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId&$expand=principal($select=id)",
                GraphLimit.Default, ct);
            var partial = !assignments.Complete;
            run.RoleAssignmentsComplete = assignments.Complete;
            var activations = await ActivationsAsync(tenantId, run, ct);
            partial |= run.ActivationsUnknown;
            foreach (var assignment in assignments.Items)
            {
                var role = assignment.GetProperty("roleDefinitionId").GetString()!.ToLowerInvariant();
                var activated = assignment.TryGetProperty("id", out var assignmentId) && assignmentId.ValueKind == JsonValueKind.String
                                && activations.Contains(assignmentId.GetString()!);
                if (!Guid.TryParse(assignment.GetProperty("principalId").GetString(), out var principal))
                {
                    partial = true;
                    run.RoleAssignmentsComplete = false;
                    continue;
                }
                var type = assignment.TryGetProperty("principal", out var p) && p.TryGetProperty("@odata.type", out var t)
                    ? t.GetString() : null;
                IEnumerable<Guid> members;
                bool viaGroup;
                if (type == "#microsoft.graph.group")
                {
                    viaGroup = true;
                    try
                    {
                        var groupMembers = await graph.GetAllPagesAsync(tenantId,
                            $"v1.0/groups/{principal}/transitiveMembers?$select=id", GraphLimit.Default, ct);
                        members = groupMembers.Items
                            .Where(m => m.TryGetProperty("@odata.type", out var mt) && mt.GetString() == "#microsoft.graph.user")
                            .Select(m => Guid.Parse(m.GetProperty("id").GetString()!)).ToList();
                        if (!groupMembers.Complete)
                        {
                            partial = true;
                            run.GroupMembersIncomplete = true;
                            if (role == GlobalAdministrator)
                            {
                                run.UnresolvedGroups++;
                            }
                        }
                    }
                    catch (GraphException)
                    {
                        partial = true;
                        run.GroupMembersIncomplete = true;
                        if (role == GlobalAdministrator)
                        {
                            run.UnresolvedGroups++;
                        }
                        continue;
                    }
                }
                else if (type is null or "#microsoft.graph.user")
                {
                    viaGroup = false;
                    members = [principal];
                }
                else
                {
                    continue; // Service principals are not counted.
                }
                foreach (var member in members)
                {
                    if (!run.RoleMembers.TryGetValue(member, out var roles))
                    {
                        roles = new HashSet<string>(StringComparer.Ordinal);
                        run.RoleMembers[member] = roles;
                    }
                    roles.Add(role);
                    if (role == Catalog.DirectorySyncRole)
                    {
                        run.SyncAccounts.Add(member);
                    }
                    // A PIM activation counts for M365-002 as its own kind of assignment, never for M365-005 (03).
                    if (role == GlobalAdministrator && !activated)
                    {
                        run.GlobalAdmins.Add(member);
                    }
                    if (policy.PrivilegedRoleTemplateIds.Contains(role))
                    {
                        if (!run.Privileged.TryGetValue(member, out var entry))
                        {
                            entry = new PrivilegedRoles();
                            run.Privileged[member] = entry;
                        }
                        entry.Roles.Add(role);
                        (activated ? entry.Activated : entry.Standing).Add(role);
                        entry.Direct |= !viaGroup;
                        entry.Group |= viaGroup;
                    }
                }
            }
            run.Modules["roles"] = partial ? "partial" : "available";
        }
        catch (GraphException error)
        {
            run.Modules["roles"] = Status(error);
        }
    }

    /// <summary>
    /// With Entra ID P2 the active assignments that exist only as a PIM activation (assignmentType=Activated) are read from
    /// roleAssignmentScheduleInstances: roleAssignmentOriginId names the assignment (02 «Сбор данных Microsoft 365», 03).
    /// </summary>
    private async Task<HashSet<string>> ActivationsAsync(Guid tenantId, RunState run, CancellationToken ct)
    {
        var activated = new HashSet<string>(StringComparer.Ordinal);
        if (run.EntraP2 != true)
        {
            return activated;
        }
        try
        {
            var instances = await graph.GetAllPagesAsync(tenantId,
                "v1.0/roleManagement/directory/roleAssignmentScheduleInstances?$filter=assignmentType%20eq%20'Activated'"
                + "&$select=roleAssignmentOriginId,assignmentType", GraphLimit.Default, ct);
            foreach (var instance in instances.Items)
            {
                if (instance.TryGetProperty("roleAssignmentOriginId", out var origin) && origin.ValueKind == JsonValueKind.String)
                {
                    activated.Add(origin.GetString()!);
                }
                else
                {
                    run.ActivationsUnknown = true;
                }
            }
            run.ActivationsUnknown |= !instances.Complete;
        }
        catch (GraphException)
        {
            run.ActivationsUnknown = true;
        }
        return activated;
    }

    private async Task CollectMethodsAsync(Guid tenantId, CollectorPolicy policy, IReadOnlySet<Guid> previouslyPrivileged,
        RunState run, CancellationToken ct)
    {
        var targets = run.Users.Values.Where(u => NeedsMethods(u, policy, run) || run.Privileged.ContainsKey(u.Id)
                                                  || previouslyPrivileged.Contains(u.Id))
            .Select(u => u.Id).ToList();
        if (targets.Count == 0)
        {
            run.Modules["auth_methods"] = "available";
            return;
        }
        // Users whose methods were read longest ago go first in later runs; within one run the order is stable.
        var answers = await graph.BatchGetAsync(tenantId,
            targets.Select(id => $"/users/{id}/authentication/methods").ToList(), GraphLimit.AuthMethods, ct);
        var forbidden = 0;
        var failed = 0;
        foreach (var answer in answers)
        {
            var id = Guid.Parse(answer.Url.Split('/')[2]);
            if (answer.Status == 200 && answer.Body.ValueKind == JsonValueKind.Object
                && answer.Body.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
            {
                if (value.EnumerateArray().Any(m => m.ValueKind != JsonValueKind.Object
                        || !m.TryGetProperty("@odata.type", out var type) || type.ValueKind != JsonValueKind.String))
                {
                    // 200 without a required property is not a complete answer (03): the user's methods are unknown.
                    failed++;
                    run.MethodFailures[id] = "partial_data";
                    continue;
                }
                run.Methods[id] = value.EnumerateArray()
                    .Select(m => m.GetProperty("@odata.type").GetString()!)
                    .Select(type => MethodTypes.TryGetValue(type, out var kind) ? kind : "other")
                    .Distinct().OrderBy(k => Catalog.MethodKinds.ToList().IndexOf(k)).ToList();
            }
            else if (answer.Status == 403)
            {
                forbidden++;
                run.MethodFailures[id] = "permission_denied";
            }
            else
            {
                failed++;
                run.MethodFailures[id] = "temporary_error";
            }
        }
        run.Modules["auth_methods"] = forbidden == answers.Count ? "permission_missing"
            : forbidden + failed > 0 ? "partial" : "available";
    }

    private async Task CollectSecurityDefaultsAsync(Guid tenantId, RunState run, CancellationToken ct)
    {
        try
        {
            var body = await graph.GetAsync(tenantId, "v1.0/policies/identitySecurityDefaultsEnforcementPolicy", GraphLimit.Default, ct);
            if (body.TryGetProperty("isEnabled", out var enabled) && enabled.ValueKind is JsonValueKind.True or JsonValueKind.False)
            {
                run.SecurityDefaults = enabled.GetBoolean();
                run.Modules["security_defaults"] = "available";
            }
            else
            {
                run.Modules["security_defaults"] = "partial";
            }
        }
        catch (GraphException error)
        {
            run.Modules["security_defaults"] = Status(error);
        }
    }

    private async Task CollectConditionalAccessAsync(Guid tenantId, CollectorPolicy policy, RunState run, CancellationToken ct)
    {
        if (run.EntraP1 == false)
        {
            run.Modules["conditional_access"] = "license_missing";
            return;
        }
        try
        {
            var pages = await graph.GetAllPagesAsync(tenantId, "v1.0/identity/conditionalAccess/policies",
                GraphLimit.ConditionalAccess, ct);
            var partial = !pages.Complete;
            foreach (var item in pages.Items)
            {
                var summary = await SummarizePolicyAsync(tenantId, item, policy, run, ct);
                if (summary is null)
                {
                    partial = true; // A condition or control outside the closed list is not normalized away.
                    continue;
                }
                if (summary.Value.Mfa is { } mfa)
                {
                    run.MfaPolicies.Add(mfa);
                }
                if (summary.Value.Legacy is { } legacy)
                {
                    run.LegacyPolicies.Add(legacy);
                }
            }
            run.Modules["conditional_access"] = partial ? "partial" : "available";
        }
        catch (GraphException error)
        {
            run.Modules["conditional_access"] = Status(error);
        }
    }

    private async Task<(JsonObject? Mfa, JsonObject? Legacy)?> SummarizePolicyAsync(Guid tenantId, JsonElement item,
        CollectorPolicy policy, RunState run, CancellationToken ct)
    {
        var state = item.GetProperty("state").GetString();
        if (state is not ("enabled" or "enabledForReportingButNotEnforced" or "disabled"))
        {
            return null;
        }
        var conditions = item.GetProperty("conditions");
        var users = conditions.GetProperty("users");
        var applications = conditions.GetProperty("applications");
        var clientAppTypes = conditions.TryGetProperty("clientAppTypes", out var cat) ? Strings(cat) : [];
        var grant = item.TryGetProperty("grantControls", out var g) && g.ValueKind == JsonValueKind.Object ? g : default;
        var builtIn = grant.ValueKind == JsonValueKind.Object && grant.TryGetProperty("builtInControls", out var b) ? Strings(b) : [];
        var strength = grant.ValueKind == JsonValueKind.Object && grant.TryGetProperty("authenticationStrength", out var s)
                       && s.ValueKind == JsonValueKind.Object ? s : default;
        var requiresMfaControl = builtIn.Contains("mfa") || strength.ValueKind == JsonValueKind.Object;
        var blocks = builtIn.Contains("block");
        if (!requiresMfaControl && !blocks)
        {
            return (null, null);
        }

        var conditionKinds = Conditions(conditions);
        if (conditionKinds is null)
        {
            return null;
        }
        var excluded = await ExclusionsAsync(tenantId, users, policy, run, ct);
        var scope = new JsonObject
        {
            ["policyId"] = item.GetProperty("id").GetString(),
            ["state"] = state,
            ["allUsers"] = Strings(users.GetProperty("includeUsers")).Contains("All"),
            ["allApplications"] = Strings(applications.GetProperty("includeApplications")).Contains("All"),
            ["excludedApplications"] = applications.TryGetProperty("excludeApplications", out var ex) ? Strings(ex).Count : 0,
            ["conditions"] = new JsonArray(conditionKinds.Select(c => (JsonNode)c).ToArray()),
            ["excludedUsersOutsidePolicy"] = excluded.Outside,
            ["unresolvedExclusions"] = excluded.Unresolved,
        };
        JsonObject? mfa = null;
        JsonObject? legacy = null;
        if (requiresMfaControl)
        {
            var controls = new List<string>();
            foreach (var control in builtIn)
            {
                var mapped = control switch
                {
                    "mfa" => "mfa",
                    "compliantDevice" => "compliant_device",
                    "domainJoinedDevice" => "domain_joined_device",
                    "approvedApplication" => "approved_application",
                    "compliantApplication" => "compliant_application",
                    "passwordChange" => "password_change",
                    "block" => null,
                    _ => "other",
                };
                if (mapped is not null && !controls.Contains(mapped))
                {
                    controls.Add(mapped);
                }
            }
            if (grant.TryGetProperty("termsOfUse", out var terms) && Strings(terms).Count > 0)
            {
                controls.Add("terms_of_use");
            }
            if (grant.TryGetProperty("customAuthenticationFactors", out var custom) && Strings(custom).Count > 0 && !controls.Contains("other"))
            {
                controls.Add("other");
            }
            bool? strengthMfa = null;
            if (strength.ValueKind == JsonValueKind.Object)
            {
                controls.Add("authentication_strength");
                strengthMfa = strength.TryGetProperty("requirementsSatisfied", out var satisfied)
                              && string.Equals(satisfied.GetString(), "mfa", StringComparison.OrdinalIgnoreCase);
            }
            mfa = new JsonObject
            {
                ["allClientAppTypes"] = clientAppTypes.Count == 0 || clientAppTypes.Contains("all"),
                ["grantOperator"] = grant.TryGetProperty("operator", out var op) && op.GetString() == "AND" ? "AND" : "OR",
                ["grantControls"] = new JsonArray(controls.Select(c => (JsonNode)c).ToArray()),
                ["authStrengthRequiresMfa"] = strengthMfa,
            };
            foreach (var pair in scope)
            {
                mfa[pair.Key] = pair.Value?.DeepClone();
            }
        }
        if (blocks && (clientAppTypes.Contains("exchangeActiveSync") || clientAppTypes.Contains("other")))
        {
            legacy = new JsonObject
            {
                ["coversExchangeActiveSync"] = clientAppTypes.Contains("exchangeActiveSync"),
                ["coversOtherClients"] = clientAppTypes.Contains("other"),
            };
            foreach (var pair in scope)
            {
                legacy[pair.Key] = pair.Value?.DeepClone();
            }
        }
        return (mfa, legacy);
    }

    /// <summary>Conditions that narrow a policy; null when a set condition is outside the closed list (F02 → unknown).</summary>
    private static List<string>? Conditions(JsonElement conditions)
    {
        var kinds = new List<string>();
        foreach (var (name, kind) in new[] { ("userRiskLevels", "user_risk"), ("signInRiskLevels", "sign_in_risk"), ("insiderRiskLevels", "insider_risk") })
        {
            switch (RiskLevels(conditions, name))
            {
                case null:
                    return null;
                case true:
                    kinds.Add(kind);
                    break;
            }
        }
        if (conditions.TryGetProperty("locations", out var locations) && locations.ValueKind == JsonValueKind.Object)
        {
            var include = locations.TryGetProperty("includeLocations", out var il) ? Strings(il) : [];
            var exclude = locations.TryGetProperty("excludeLocations", out var el) ? Strings(el) : [];
            if (include.SequenceEqual(["All"]) && exclude.SequenceEqual(["AllTrusted"]))
            {
                kinds.Add("locations_trusted_excluded");
            }
            else if (include.Count > 0 || exclude.Count > 0)
            {
                kinds.Add("locations_other");
            }
        }
        if (conditions.TryGetProperty("platforms", out var platforms) && platforms.ValueKind == JsonValueKind.Object) { kinds.Add("platforms"); }
        if (conditions.TryGetProperty("devices", out var devices) && devices.ValueKind == JsonValueKind.Object) { kinds.Add("devices"); }
        if (conditions.TryGetProperty("authenticationFlows", out var flows) && flows.ValueKind == JsonValueKind.Object) { kinds.Add("authentication_flows"); }
        if (conditions.TryGetProperty("clientApplications", out var apps) && apps.ValueKind == JsonValueKind.Object) { kinds.Add("client_applications"); }
        var known = new HashSet<string>(StringComparer.Ordinal)
        {
            "users", "applications", "clientAppTypes", "userRiskLevels", "signInRiskLevels", "insiderRiskLevels",
            "servicePrincipalRiskLevels", "locations", "platforms", "devices", "authenticationFlows", "clientApplications",
            "times", "deviceStates",
        };
        foreach (var property in conditions.EnumerateObject())
        {
            if (property.Value.ValueKind is JsonValueKind.Null
                || (property.Value.ValueKind == JsonValueKind.Array && property.Value.GetArrayLength() == 0)
                || (property.Value.ValueKind == JsonValueKind.String && RiskLevels(conditions, property.Name) == false))
            {
                continue;
            }
            if (!known.Contains(property.Name) || property.Name is "servicePrincipalRiskLevels" or "times" or "deviceStates")
            {
                return null;
            }
        }
        return kinds;
    }

    private async Task<(int Outside, int Unresolved)> ExclusionsAsync(Guid tenantId, JsonElement users, CollectorPolicy policy,
        RunState run, CancellationToken ct)
    {
        var excluded = new HashSet<Guid>();
        var unresolved = 0;
        foreach (var id in users.TryGetProperty("excludeUsers", out var eu) ? Strings(eu) : [])
        {
            if (Guid.TryParse(id, out var user))
            {
                excluded.Add(user);
            }
        }
        foreach (var group in users.TryGetProperty("excludeGroups", out var eg) ? Strings(eg) : [])
        {
            try
            {
                var members = await graph.GetAllPagesAsync(tenantId, $"v1.0/groups/{group}/transitiveMembers?$select=id",
                    GraphLimit.Default, ct);
                if (!members.Complete)
                {
                    unresolved++;
                }
                foreach (var member in members.Items)
                {
                    if (Guid.TryParse(member.GetProperty("id").GetString(), out var user))
                    {
                        excluded.Add(user);
                    }
                }
            }
            catch (GraphException)
            {
                unresolved++;
            }
        }
        foreach (var role in users.TryGetProperty("excludeRoles", out var er) ? Strings(er) : [])
        {
            foreach (var (member, roles) in run.RoleMembers)
            {
                if (roles.Contains(role.ToLowerInvariant()))
                {
                    excluded.Add(member);
                }
            }
        }
        if (users.TryGetProperty("excludeGuestsOrExternalUsers", out var guests) && guests.ValueKind == JsonValueKind.Object)
        {
            // Excluding guests and external users does not matter: M365-001 does not assess them.
        }
        return (excluded.Count(u => !policy.ExcludedUserIds.Contains(u)), unresolved);
    }

    private async Task CollectAuthorizationPolicyAsync(Guid tenantId, RunState run, CancellationToken ct)
    {
        try
        {
            var body = await graph.GetAsync(tenantId, "v1.0/policies/authorizationPolicy", GraphLimit.Default, ct);
            var policyBody = body.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array
                ? value.EnumerateArray().FirstOrDefault() : body;
            if (!policyBody.TryGetProperty("defaultUserRolePermissions", out var permissions)
                || !permissions.TryGetProperty("permissionGrantPoliciesAssigned", out var assigned))
            {
                run.Modules["authorization_policy"] = "partial";
                return;
            }
            const string prefix = "ManagePermissionGrantsForSelf.";
            run.GrantPolicies = new JsonArray(Strings(assigned)
                .Where(p => p.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                .Select(p => (JsonNode)(prefix + p[prefix.Length..]))
                .ToArray());
            run.Modules["authorization_policy"] = "available";
        }
        catch (GraphException error)
        {
            run.Modules["authorization_policy"] = Status(error);
        }
    }

    private async Task CollectPerUserMfaAsync(Guid tenantId, CollectorPolicy policy, RunState run, CancellationToken ct)
    {
        var needed = run.SecurityDefaults != true && !HasUnconditionalPolicy(run, policy);
        if (!options.PerUserMfa || !needed)
        {
            run.Modules["per_user_mfa"] = "skipped";
            return;
        }
        var users = run.Users.Values.Where(u => NeedsMethods(u, policy, run)).Select(u => u.Id).ToList();
        int enforced = 0, notRequired = 0, enabled = 0, unknown = 0, forbidden = 0, failed = 0;
        foreach (var user in users)
        {
            try
            {
                var body = await graph.GetAsync(tenantId, $"beta/users/{user}/authentication/requirements", GraphLimit.AuthMethods, ct);
                switch (body.TryGetProperty("perUserMfaState", out var state) ? state.GetString() : null)
                {
                    case "enforced":
                        enforced++;
                        break;
                    case "disabled":
                        notRequired++;
                        break;
                    case "enabled":
                        // Not proof of enforcement until SP-01 confirms it; the rule gives unknown (03, F01).
                        enabled++;
                        break;
                    default:
                        unknown++;
                        break;
                }
            }
            catch (GraphException error)
            {
                if (error.Failure == GraphFailure.Forbidden)
                {
                    forbidden++;
                }
                else
                {
                    failed++;
                }
            }
        }
        if (users.Count > 0 && forbidden == users.Count)
        {
            run.Modules["per_user_mfa"] = "permission_missing";
            return;
        }
        if (forbidden + failed > 0)
        {
            run.Modules["per_user_mfa"] = "partial";
            return;
        }
        run.PerUserMfa = new JsonObject
        {
            ["required"] = enforced, ["notRequired"] = notRequired, ["unknown"] = unknown, ["enabled"] = enabled,
        };
        run.Modules["per_user_mfa"] = "available";
    }

    /// <summary>The criterion of the rule itself (03 «Правило M365-003»): per-user MFA is skipped only when M365-003 passes.</summary>
    private static bool HasUnconditionalPolicy(RunState run, CollectorPolicy policy) =>
        run.Modules.GetValueOrDefault("conditional_access") == "available"
        && run.MfaPolicies.Any(p =>
        {
            using var document = JsonDocument.Parse(p!.ToJsonString());
            return Assessment.M365Rules.IsUnconditional(document.RootElement, policy.DeviceAlternativeAccepted,
                policy.TrustedLocationsExclusionAccepted);
        });

    private static bool NeedsMethods(UserRecord user, CollectorPolicy policy, RunState run) =>
        user.AccountEnabled && (user.UserType ?? "Member") == "Member" && !policy.ExcludedUserIds.Contains(user.Id)
        && !run.SyncAccounts.Contains(user.Id);

    private List<JsonObject> BuildObservations(Guid tenantId, CollectorPolicy policy, IReadOnlySet<Guid> previouslyPrivileged,
        RunState run)
    {
        var observedAt = UtcTimeConverterFormat(clock.GetUtcNow());
        var result = new List<JsonObject>();
        var tenantSubject = new JsonObject { ["type"] = "tenant", ["key"] = tenantId.ToString() };
        // Unresolved group members affect only M365-005; incomplete role assignments could hide admins and sync accounts.
        var rolesStatus = run.Modules.GetValueOrDefault("roles");
        var rolesFailure = rolesStatus == "partial" ? (run.RoleAssignmentsComplete ? null : "partial_data") : Reason(rolesStatus);

        foreach (var user in run.Users.Values)
        {
            var subject = new JsonObject { ["type"] = "user", ["key"] = user.Id.ToString(), ["userPrincipalName"] = user.Upn };
            if (policy.ActiveCheckIds.Contains("M365-001"))
            {
                var needs = NeedsMethods(user, policy, run);
                var failure = rolesFailure ?? (needs ? MethodFailure(user.Id, run) : null);
                result.Add(failure is not null
                    ? Unavailable("M365-001", subject, observedAt, failure)
                    : Collected("M365-001", subject, observedAt, new JsonObject
                    {
                        ["accountEnabled"] = user.AccountEnabled, ["userType"] = user.UserType,
                        ["directorySyncAccount"] = run.SyncAccounts.Contains(user.Id),
                        ["methodKinds"] = needs ? MethodArray(run.Methods[user.Id]) : null,
                    }));
            }
            var privileged = run.Privileged.TryGetValue(user.Id, out var roles);
            if (policy.ActiveCheckIds.Contains("M365-002") && (privileged || previouslyPrivileged.Contains(user.Id)))
            {
                // A role may hide in a group whose members could not be read: no false «role removed» (03).
                var failure = rolesFailure ?? (!privileged && run.GroupMembersIncomplete ? "partial_data" : null)
                              ?? MethodFailure(user.Id, run);
                var evidence = new JsonObject
                {
                    ["accountEnabled"] = user.AccountEnabled, ["userType"] = user.UserType,
                    ["roleTemplateIds"] = new JsonArray((privileged ? roles!.Roles.Order() : Enumerable.Empty<string>())
                        .Select(r => (JsonNode)r).ToArray()),
                    ["assignment"] = !privileged ? "none" : roles!.Direct && roles.Group ? "direct_and_group"
                        : roles.Group ? "group" : "direct",
                    ["methodKinds"] = failure is null ? MethodArray(run.Methods[user.Id]) : null,
                };
                // Without the field the activations were not told apart (no Entra ID P2 or unreadable activations).
                if (run.EntraP2 == true && !run.ActivationsUnknown)
                {
                    evidence["temporaryRoleTemplateIds"] = new JsonArray((privileged ? roles!.Temporary.Order() : Enumerable.Empty<string>())
                        .Select(r => (JsonNode)r).ToArray());
                }
                result.Add(failure is not null
                    ? Unavailable("M365-002", subject, observedAt, failure)
                    : Collected("M365-002", subject, observedAt, evidence));
            }
        }

        var licensesFailure = Reason(run.Modules.GetValueOrDefault("licenses"));
        var sdFailure = Reason(run.Modules.GetValueOrDefault("security_defaults"));
        var caStatus = run.Modules.GetValueOrDefault("conditional_access");
        var caFailure = caStatus == "license_missing" ? null : Reason(caStatus);
        var conditionalAccess = caStatus == "license_missing" ? "license_missing" : "available";
        if (policy.ActiveCheckIds.Contains("M365-003"))
        {
            var pumFailure = Reason(run.Modules.GetValueOrDefault("per_user_mfa"));
            var failure = licensesFailure ?? sdFailure ?? caFailure ?? pumFailure;
            result.Add(failure is not null
                ? Unavailable("M365-003", tenantSubject, observedAt, failure)
                : Collected("M365-003", tenantSubject, observedAt, new JsonObject
                {
                    ["securityDefaults"] = run.SecurityDefaults == true ? "enabled" : "disabled",
                    ["conditionalAccess"] = conditionalAccess,
                    ["mfaPolicies"] = (JsonArray)run.MfaPolicies.DeepClone(),
                    ["perUserMfa"] = run.PerUserMfa?.DeepClone(),
                }));
        }
        if (policy.ActiveCheckIds.Contains("M365-004"))
        {
            var failure = licensesFailure ?? sdFailure ?? caFailure;
            result.Add(failure is not null
                ? Unavailable("M365-004", tenantSubject, observedAt, failure)
                : Collected("M365-004", tenantSubject, observedAt, new JsonObject
                {
                    ["securityDefaults"] = run.SecurityDefaults == true ? "enabled" : "disabled",
                    ["conditionalAccess"] = conditionalAccess,
                    ["legacyBlockPolicies"] = (JsonArray)run.LegacyPolicies.DeepClone(),
                }));
        }
        if (policy.ActiveCheckIds.Contains("M365-005"))
        {
            var failure = rolesFailure ?? (run.ActivationsUnknown ? "partial_data" : null);
            var enabledAdmins = run.GlobalAdmins.Where(id => run.Users.TryGetValue(id, out var u) && u.AccountEnabled).Order().ToList();
            var disabledAdmins = run.GlobalAdmins.Where(id => run.Users.TryGetValue(id, out var u) && !u.AccountEnabled).Order().ToList();
            // Roles of the catalog outside the policy, held by enabled users: shown, never counted (03 «Правило M365-005»).
            var uncovered = run.RoleMembers.Where(m => run.Users.TryGetValue(m.Key, out var u) && u.AccountEnabled)
                .SelectMany(m => m.Value).Where(r => !policy.PrivilegedRoleTemplateIds.Contains(r)).Distinct().Order().Take(200).ToList();
            result.Add(failure is not null
                ? Unavailable("M365-005", tenantSubject, observedAt, failure)
                : Collected("M365-005", tenantSubject, observedAt, new JsonObject
                {
                    ["globalAdminUserIds"] = new JsonArray(enabledAdmins.Select(i => (JsonNode)i.ToString()).ToArray()),
                    ["disabledGlobalAdminUserIds"] = new JsonArray(disabledAdmins.Select(i => (JsonNode)i.ToString()).ToArray()),
                    ["unresolvedGroupAssignments"] = run.UnresolvedGroups,
                    ["uncoveredRoleTemplateIds"] = new JsonArray(uncovered.Select(r => (JsonNode)r).ToArray()),
                }));
        }
        if (policy.ActiveCheckIds.Contains("M365-006"))
        {
            var failure = Reason(run.Modules.GetValueOrDefault("authorization_policy"));
            result.Add(failure is not null || run.GrantPolicies is null
                ? Unavailable("M365-006", tenantSubject, observedAt, failure ?? "partial_data")
                : Collected("M365-006", tenantSubject, observedAt, new JsonObject
                {
                    ["permissionGrantPolicies"] = (JsonArray)run.GrantPolicies.DeepClone(),
                }));
        }

        // Every observation passes the allowlist schema; one outside it is kept as unavailable/partial_data.
        for (var i = 0; i < result.Count; i++)
        {
            using var document = JsonDocument.Parse(result[i].ToJsonString());
            if (schemas.ValidateStandalone("graph-observation.schema.json", document.RootElement).Count > 0)
            {
                var checkId = result[i]["checkId"]!.GetValue<string>();
                result[i] = Unavailable(checkId, result[i]["subject"]!.DeepClone().AsObject(), observedAt, "partial_data");
                run.Modules[ModuleOf(checkId)] = "partial";
            }
        }
        return result;
    }

    private static string ModuleOf(string checkId) => checkId switch
    {
        "M365-001" or "M365-002" => "auth_methods",
        "M365-003" or "M365-004" => "conditional_access",
        "M365-005" => "roles",
        _ => "authorization_policy",
    };

    private static string? MethodFailure(Guid user, RunState run) =>
        run.MethodFailures.TryGetValue(user, out var failure) ? failure
        : run.Methods.ContainsKey(user) ? null
        : Reason(run.Modules.GetValueOrDefault("auth_methods")) ?? "temporary_error";

    private static JsonArray MethodArray(List<string> kinds) => new(kinds.Select(k => (JsonNode)k).ToArray());

    /// <summary>Module status → observation reason (03): permission_missing → permission_denied, partial → partial_data.</summary>
    private static string? Reason(string? status) => status switch
    {
        null => "temporary_error",
        "available" or "skipped" => null,
        "permission_missing" => "permission_denied",
        "license_missing" => "license_missing",
        "partial" => "partial_data",
        _ => "temporary_error",
    };

    private static string Status(GraphException error) => error.Failure switch
    {
        GraphFailure.Forbidden => "permission_missing",
        _ => "temporary_error",
    };

    private static JsonObject Collected(string checkId, JsonObject subject, string observedAt, JsonObject evidence) => new()
    {
        ["checkId"] = checkId, ["collectorVersion"] = CollectorVersion, ["subject"] = subject.DeepClone(),
        ["observedAt"] = observedAt, ["collectionStatus"] = "collected", ["evidence"] = evidence,
    };

    private static JsonObject Unavailable(string checkId, JsonObject subject, string observedAt, string reason) => new()
    {
        ["checkId"] = checkId, ["collectorVersion"] = CollectorVersion, ["subject"] = subject.DeepClone(),
        ["observedAt"] = observedAt, ["collectionStatus"] = "unavailable", ["reasonCode"] = reason,
    };

    public const string CollectorVersion = "1.0.0";

    private static string UtcTimeConverterFormat(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.FFFFFF'Z'", CultureInfo.InvariantCulture);

    /// <summary>
    /// A risk condition is set when it is a non-empty array or, like insiderRiskLevels, a flags string other than «none»;
    /// any other shape is unknown (null), so the policy cannot look unconditional (F02).
    /// </summary>
    private static bool? RiskLevels(JsonElement conditions, string name)
    {
        if (!conditions.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)
        {
            return false;
        }
        return value.ValueKind switch
        {
            JsonValueKind.Array => value.GetArrayLength() > 0,
            JsonValueKind.String => !string.IsNullOrWhiteSpace(value.GetString())
                                    && !string.Equals(value.GetString(), "none", StringComparison.OrdinalIgnoreCase),
            _ => null,
        };
    }

    private static List<string> Strings(JsonElement array) =>
        array.ValueKind == JsonValueKind.Array
            ? array.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList()
            : [];

    /// <summary>Control characters, &lt; and &gt; in Graph strings are replaced by U+FFFD (03).</summary>
    public static string? Clean(string? value)
    {
        if (value is null)
        {
            return null;
        }
        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            builder.Append(char.IsControl(c) || c is '<' or '>' || (c >= '\u200B' && c <= '\u200F')
                           || (c >= '\u202A' && c <= '\u202E') || (c >= '\u2066' && c <= '\u2069') ? '\uFFFD' : c);
        }
        return builder.ToString();
    }
}
