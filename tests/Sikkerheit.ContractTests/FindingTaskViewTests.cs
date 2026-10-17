using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sikkerheit.Contracts;
using Sikkerheit.ContractTests.Support;
using Sikkerheit.IntegrationTests.Infrastructure;

namespace Sikkerheit.ContractTests;

public sealed class FindingTaskViewTests(PostgresFixture postgres)
{
    [Fact]
    public async Task Work_filters_intersect_before_pagination_and_bind_mine_cursor_to_the_session()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var firstOrg = await host.OrganizationAsync("First AS");
        var secondOrg = await host.OrganizationAsync("Second AS");
        var other = await host.SignInAsync("Technician");
        var mine1 = await TaskAsync(host, firstOrg, host.Admin.EntraUserId, -1);
        var mine2 = await TaskAsync(host, secondOrg, host.Admin.EntraUserId, -1);
        var noDue = await TaskAsync(host, firstOrg, host.Admin.EntraUserId, null);
        var otherDue = await TaskAsync(host, firstOrg, other.EntraUserId, -1);
        await TaskAsync(host, firstOrg, host.Admin.EntraUserId, -1, workflow: "risk_accepted");
        await TaskAsync(host, firstOrg, host.Admin.EntraUserId, -1, workflow: "suppressed");
        await TaskAsync(host, firstOrg, host.Admin.EntraUserId, -1, technical: "resolved");
        await TaskAsync(host, firstOrg, host.Admin.EntraUserId, -1, retired: true);
        var disabled = await host.OrganizationAsync("Disabled AS");
        await TaskAsync(host, disabled, host.Admin.EntraUserId, -1);
        await host.LifecycleAsync(disabled, "disable");

        var expected = new HashSet<Guid> { mine1, mine2 };
        const string url = "/api/v1/findings?assignedTo=me&overdue=true&limit=1";
        var first = await host.Admin.GetAsync(url, "FindingPage");
        var firstId = Ids(first.Body).Single();
        Assert.Contains(firstId, expected);
        var cursor = Uri.EscapeDataString(first.Body.GetProperty("nextCursor").GetString()!);
        var next = await host.Admin.GetAsync(url + "&cursor=" + cursor, "FindingPage");
        Assert.Equal(expected.Order(), Ids(first.Body).Concat(Ids(next.Body)).Order());
        Assert.Equal(JsonValueKind.Null, next.Body.GetProperty("nextCursor").ValueKind);
        Assert.Equal(ProblemCodes.InvalidCursor, (await other.GetAsync(url + "&cursor=" + cursor)).Code);
        Assert.Equal(ProblemCodes.InvalidCursor,
            (await host.Admin.GetAsync("/api/v1/findings?assignedTo=me&limit=1&cursor=" + cursor)).Code);

        var mine = await host.Admin.GetAsync("/api/v1/findings?assignedTo=me", "FindingPage");
        Assert.Equal(new[] { mine1, mine2, noDue }.Order(), Ids(mine.Body).Order());
        var allDue = await host.Admin.GetAsync("/api/v1/findings?overdue=true", "FindingPage");
        Assert.Equal(new[] { mine1, mine2, otherDue }.Order(), Ids(allDue.Body).Order());
        var scoped = await host.Admin.GetAsync($"/api/v1/organizations/{firstOrg}/findings?assignedTo=me&overdue=true", "FindingPage");
        Assert.Equal([mine1], Ids(scoped.Body));
        var contradictory = await host.Admin.GetAsync("/api/v1/findings?overdue=true&technicalState=resolved", "FindingPage");
        Assert.Empty(Ids(contradictory.Body));
        var reader = await host.SignInAsync("Reader");
        Assert.Empty(Ids((await reader.GetAsync("/api/v1/findings?assignedTo=me", "FindingPage")).Body));
    }

    [Fact]
    public async Task Overdue_uses_server_clock_strict_boundary_and_rechecks_after_time_passes()
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        host.Clock.Freeze(host.Clock.GetUtcNow());
        var equalNow = await TaskAsync(host, org, null, 0);
        var future = await TaskAsync(host, org, null, 1.0 / 86400);
        var url = $"/api/v1/organizations/{org}/findings?overdue=true";
        Assert.Empty(Ids((await host.Admin.GetAsync(url, "FindingPage")).Body));
        host.Clock.Freeze(host.Clock.GetUtcNow().AddMilliseconds(1));
        Assert.Equal([equalNow], Ids((await host.Admin.GetAsync(url, "FindingPage")).Body));
        host.Clock.Freeze(host.Clock.GetUtcNow().AddSeconds(2));
        Assert.Equal(new[] { equalNow, future }.Order(), Ids((await host.Admin.GetAsync(url, "FindingPage")).Body).Order());
    }

    [Theory]
    [InlineData("assignedTo=someone")]
    [InlineData("assignedTo=11111111-1111-4111-8111-111111111111")]
    [InlineData("overdue=false")]
    [InlineData("overdue=1")]
    [InlineData("overdue=True")]
    public async Task Unknown_work_filters_are_rejected(string query)
    {
        await using var host = await ContractHost.StartAsync(postgres);
        var org = await host.OrganizationAsync();
        Assert.Equal(ProblemCodes.SchemaViolation, (await host.Admin.GetAsync("/api/v1/findings?" + query)).Code);
        Assert.Equal(ProblemCodes.SchemaViolation,
            (await host.Admin.GetAsync($"/api/v1/organizations/{org}/findings?" + query)).Code);
    }

    private static Guid[] Ids(JsonElement body) => body.GetProperty("items").EnumerateArray()
        .Select(item => item.GetProperty("id").GetGuid()).ToArray();

    private static async Task<Guid> TaskAsync(ContractHost host, Guid org, Guid? assignee, double? dueDays,
        string workflow = "new", string technical = "open", bool retired = false)
    {
        var id = await host.InsertFindingAsync(org, technicalState: technical);
        await using var scope = await host.Scopes.OrganizationAsync(org, ContractHost.Ct);
        var finding = await scope.Db.Findings.SingleAsync(f => f.Id == id, ContractHost.Ct);
        finding.AssigneeId = assignee;
        finding.DueAt = dueDays is { } days ? host.Clock.GetUtcNow().AddDays(days) : null;
        finding.WorkflowState = workflow;
        if (retired) (await scope.Db.Subjects.SingleAsync(s => s.Id == finding.SubjectId, ContractHost.Ct)).RetiredAt = host.Clock.GetUtcNow();
        await scope.CommitAsync(ContractHost.Ct);
        return id;
    }
}
